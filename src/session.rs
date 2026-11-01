//! Shared mixed-initiative investigation sessions (ADR 0015), stage 1a: the
//! signed, append-only log, operator entries, directives and closure.
//!
//! Every entry is one canonical JSON line signed under its own namespace by
//! the principal it names, stored with its signature in one record file that
//! appears atomically. An entry is admitted only if re-rendering it reproduces
//! its exact bytes, so MIRA reads its own format without a general JSON
//! parser. Roles come from the operator-signed header, never from the entry
//! that claims one.
use crate::session_capability::{self, Outcome};
use crate::signature::{self, Failure, Trust};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const SESSION_VERSION: u32 = 1;
pub const MAX_ENTRIES: u64 = 4096;
const MAX_ENTRY_BYTES: u64 = 8192;
/// One record: the entry line followed by its armored SSHSIG signature.
pub(crate) const MAX_RECORD_BYTES: u64 = MAX_ENTRY_BYTES + signature::MAX_SIGNATURE_BYTES as u64;
pub const MAX_TEXT_BYTES: usize = 1024;
/// Entries the agent can never cause to be written, kept for the operator's
/// stop, abandon and close and for pending results: an agent flooding the
/// inbox can never leave the operator unable to end the session.
pub const OPERATOR_RESERVE: u64 = 64;
const ENTRIES: &str = "entries";
const PENDING: &str = ".pending-";
const APPEND_ATTEMPTS: usize = 8;

/// The agent's autonomy for evidence acquisition (ADR 0015). Decisions are
/// the operator's at every level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Manual,
    Advisory,
    Assisted,
    Delegated,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Advisory => "advisory",
            Self::Assisted => "assisted",
            Self::Delegated => "delegated",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "manual" => Some(Self::Manual),
            "advisory" => Some(Self::Advisory),
            "assisted" => Some(Self::Assisted),
            "delegated" => Some(Self::Delegated),
            _ => None,
        }
    }

    /// Levels an operator may set directly; delegation needs an expiry.
    pub fn settable(text: &str) -> Option<Self> {
        Self::parse(text).filter(|level| *level != Self::Delegated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Separation {
    SameUser,
    SeparateUser,
}

impl Separation {
    fn as_str(self) -> &'static str {
        match self {
            Self::SameUser => "same_user",
            Self::SeparateUser => "separate_user",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "same_user" => Some(Self::SameUser),
            "separate_user" => Some(Self::SeparateUser),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub operator: String,
    pub agent: String,
    pub collector: String,
    pub separation: Separation,
    pub autonomy: Level,
    pub budget: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directive {
    /// The agent stops: the level becomes `manual` from this entry on.
    Stop,
    SetLevel(Level),
    SetBudget(u64),
    /// `delegated` until (and including) this sequence number, then `assisted`.
    DelegateUntil(u64),
}

/// Why the broker refused an agent request. Each is a fixed reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Signature,
    Malformed,
    SessionMismatch,
    Replayed,
    Stale,
    Autonomy,
    SupersededByDirective,
    Capability,
    OperatorOnly,
    Owner,
}

impl Refusal {
    const ALL: [Self; 10] = [
        Self::Signature,
        Self::Malformed,
        Self::SessionMismatch,
        Self::Replayed,
        Self::Stale,
        Self::Autonomy,
        Self::SupersededByDirective,
        Self::Capability,
        Self::OperatorOnly,
        Self::Owner,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Malformed => "malformed",
            Self::SessionMismatch => "session_mismatch",
            Self::Replayed => "replayed",
            Self::Stale => "stale",
            Self::Autonomy => "autonomy",
            Self::SupersededByDirective => "superseded_by_directive",
            Self::Capability => "capability",
            Self::OperatorOnly => "operator_only",
            Self::Owner => "owner",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == text)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Header(Header),
    /// From the operator (no request), or relayed by the collector for an
    /// agent request stored under `requests/`.
    Question {
        request_id: Option<String>,
    },
    /// An operator question in the stage 1a layout, which had no `request_id`;
    /// accepted so signed 1a records keep verifying byte for byte.
    LegacyQuestion,
    Directive(Directive),
    /// One closed capability: the operator's own (no request), or an agent
    /// request the broker admitted and relays.
    Action {
        request_id: Option<String>,
        capability: String,
        arguments: String,
    },
    /// The executed action's exit status and fixed outcome. When there is a
    /// document, `documents/<action_seq>.json`, the entry commits to it by
    /// carrying the collector's exact armored signature over its bytes.
    Result {
        action_seq: u64,
        exit_status: Option<u64>,
        outcome: Outcome,
        document_signature: Option<String>,
    },
    /// The operator finalizes a pending action that will get no result, for
    /// example after an interrupted broker, so the session can close honestly.
    Abandon {
        action_seq: u64,
    },
    /// An agent request the broker refused, with a fixed reason.
    Refusal {
        request_id: String,
        reason: Refusal,
    },
    /// The operator's conclusion is the note; the count includes this entry.
    Close {
        entry_count: u64,
    },
}

impl Body {
    fn kind(&self) -> &'static str {
        match self {
            Self::Header(_) => "header",
            Self::Question { .. } | Self::LegacyQuestion => "question",
            Self::Abandon { .. } => "abandon",
            Self::Directive(_) => "directive",
            Self::Action { .. } => "action",
            Self::Result { .. } => "result",
            Self::Refusal { .. } => "refusal",
            Self::Close { .. } => "close",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub session_id: String,
    pub seq: u64,
    pub principal: String,
    pub based_on: Option<u64>,
    pub body: Body,
    /// Bounded free text, always last; never the basis of any check.
    pub note: String,
}

fn quoted(text: &str) -> String {
    crate::evidence_json::quoted(text)
}

fn number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn optional_quoted(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), quoted)
}

impl Entry {
    /// The canonical bytes, with the trailing newline that is signed.
    pub fn render(&self) -> String {
        let fields = match &self.body {
            Body::Header(header) => format!(
                "\"operator\":{},\"agent\":{},\"collector\":{},\"separation\":{},\"autonomy\":{},\"budget\":{},",
                quoted(&header.operator),
                quoted(&header.agent),
                quoted(&header.collector),
                quoted(header.separation.as_str()),
                quoted(header.autonomy.as_str()),
                header.budget
            ),
            Body::Question { request_id } => {
                format!("\"request_id\":{},", optional_quoted(request_id.as_deref()))
            }
            Body::LegacyQuestion => String::new(),
            Body::Abandon { action_seq } => format!("\"action_seq\":{action_seq},"),
            Body::Action {
                request_id,
                capability,
                arguments,
            } => format!(
                "\"request_id\":{},\"capability\":{},\"arguments\":{},",
                optional_quoted(request_id.as_deref()),
                quoted(capability),
                quoted(arguments)
            ),
            Body::Result {
                action_seq,
                exit_status,
                outcome,
                document_signature,
            } => format!(
                "\"action_seq\":{action_seq},\"exit_status\":{},\"outcome\":{},\"document_signature\":{},",
                number(*exit_status),
                quoted(outcome.as_str()),
                optional_quoted(document_signature.as_deref())
            ),
            Body::Refusal { request_id, reason } => format!(
                "\"request_id\":{},\"reason\":{},",
                quoted(request_id),
                quoted(reason.as_str())
            ),
            Body::Directive(directive) => {
                let (name, level, budget, until) = match directive {
                    Directive::Stop => ("stop", None, None, None),
                    Directive::SetLevel(level) => ("set_level", Some(*level), None, None),
                    Directive::SetBudget(budget) => ("set_budget", None, Some(*budget), None),
                    Directive::DelegateUntil(until) => ("delegate", None, None, Some(*until)),
                };
                format!(
                    "\"directive\":{},\"level\":{},\"budget\":{},\"until_seq\":{},",
                    quoted(name),
                    level.map_or_else(|| "null".to_owned(), |level| quoted(level.as_str())),
                    number(budget),
                    number(until)
                )
            }
            Body::Close { entry_count } => format!("\"entry_count\":{entry_count},"),
        };
        format!(
            "{{\"session_version\":{SESSION_VERSION},\"session_id\":{},\"seq\":{},\"kind\":{},\"principal\":{},\"based_on\":{},{fields}\"note\":{}}}\n",
            quoted(&self.session_id),
            self.seq,
            quoted(self.body.kind()),
            quoted(&self.principal),
            number(self.based_on),
            quoted(&self.note)
        )
    }

    /// Admit exactly the canonical layout `render` produces.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let fields = parse_flat(text.strip_suffix('\n')?)?;
        let string = |key: &str| match fields.get(key)? {
            Value::Str(value) => Some(value.clone()),
            _ => None,
        };
        let uint = |key: &str| match fields.get(key)? {
            Value::Uint(value) => Some(*value),
            _ => None,
        };
        let optional = |key: &str| match fields.get(key)? {
            Value::Uint(value) => Some(Some(*value)),
            Value::Null => Some(None),
            Value::Str(_) => None,
        };
        let optional_string = |key: &str| match fields.get(key)? {
            Value::Str(value) => Some(Some(value.clone())),
            Value::Null => Some(None),
            Value::Uint(_) => None,
        };
        let body = match string("kind")?.as_str() {
            "header" => Body::Header(Header {
                operator: string("operator")?,
                agent: string("agent")?,
                collector: string("collector")?,
                separation: Separation::parse(&string("separation")?)?,
                autonomy: Level::parse(&string("autonomy")?)?,
                budget: uint("budget")?,
            }),
            "question" if !fields.contains_key("request_id") => Body::LegacyQuestion,
            "question" => Body::Question {
                request_id: optional_string("request_id")?,
            },
            "abandon" => Body::Abandon {
                action_seq: uint("action_seq")?,
            },
            "action" => Body::Action {
                request_id: optional_string("request_id")?,
                capability: string("capability")?,
                arguments: string("arguments")?,
            },
            "result" => Body::Result {
                action_seq: uint("action_seq")?,
                exit_status: optional("exit_status")?,
                outcome: Outcome::parse(&string("outcome")?)?,
                document_signature: optional_string("document_signature")?,
            },
            "refusal" => Body::Refusal {
                request_id: string("request_id")?,
                reason: Refusal::parse(&string("reason")?)?,
            },
            "directive" => {
                let level = match fields.get("level")? {
                    Value::Str(level) => Some(Level::parse(level)?),
                    Value::Null => None,
                    Value::Uint(_) => return None,
                };
                let directive = match (
                    string("directive")?.as_str(),
                    level,
                    optional("budget")?,
                    optional("until_seq")?,
                ) {
                    ("stop", None, None, None) => Directive::Stop,
                    ("set_level", Some(level), None, None) => Directive::SetLevel(level),
                    ("set_budget", None, Some(budget), None) => Directive::SetBudget(budget),
                    ("delegate", None, None, Some(until)) => Directive::DelegateUntil(until),
                    _ => return None,
                };
                Body::Directive(directive)
            }
            "close" => Body::Close {
                entry_count: uint("entry_count")?,
            },
            _ => return None,
        };
        let entry = Self {
            session_id: string("session_id")?,
            seq: uint("seq")?,
            principal: string("principal")?,
            based_on: optional("based_on")?,
            body,
            note: string("note")?,
        };
        (uint("session_version")? == u64::from(SESSION_VERSION)
            && is_session_id(&entry.session_id)
            && validate_text(&entry.note).is_ok()
            && entry.render().as_bytes() == bytes)
            .then_some(entry)
    }
}

/// An armored SSHSIG signature as `ssh-keygen -Y sign` writes it.
pub fn is_armored_signature(text: &str) -> bool {
    text.len() <= 4096
        && text.starts_with("-----BEGIN SSH SIGNATURE-----\n")
        && text.ends_with("-----END SSH SIGNATURE-----\n")
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=-\n ".contains(&byte))
}

pub fn is_session_id(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| b"0123456789abcdef".contains(&byte))
}

/// Free text is single-line and cannot steer a terminal or reorder display:
/// no C0/C1 controls, DEL, or bidirectional embedding/override/isolate marks.
pub fn validate_text(text: &str) -> io::Result<()> {
    let forbidden = |c: char| {
        c.is_control()
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}')
    };
    if text.len() > MAX_TEXT_BYTES || text.chars().any(forbidden) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "text must be at most 1 KiB without control or bidirectional characters",
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Str(String),
    Uint(u64),
    Null,
}

/// A strict parser for one flat JSON object of strings, unsigned integers and
/// nulls. Duplicate keys, nesting, signs, fractions and whitespace are refused;
/// the canonical re-render check in `Entry::parse` fixes the order.
pub(crate) fn parse_flat(text: &str) -> Option<BTreeMap<String, Value>> {
    let mut chars = text.char_indices().peekable();
    let mut fields = BTreeMap::new();
    if chars.next()?.1 != '{' {
        return None;
    }
    loop {
        let key = parse_string(&mut chars)?;
        if chars.next()?.1 != ':' {
            return None;
        }
        let value = match chars.peek()?.1 {
            '"' => Value::Str(parse_string(&mut chars)?),
            'n' => {
                for expected in "null".chars() {
                    if chars.next()?.1 != expected {
                        return None;
                    }
                }
                Value::Null
            }
            '0'..='9' => {
                let mut digits = String::new();
                while let Some(&(_, c)) = chars.peek() {
                    if !c.is_ascii_digit() {
                        break;
                    }
                    digits.push(c);
                    chars.next();
                }
                if digits.len() > 1 && digits.starts_with('0') {
                    return None;
                }
                Value::Uint(digits.parse().ok()?)
            }
            _ => return None,
        };
        if fields.insert(key, value).is_some() {
            return None;
        }
        match chars.next()?.1 {
            ',' => continue,
            '}' => return chars.next().is_none().then_some(fields),
            _ => return None,
        }
    }
}

fn parse_string(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> Option<String> {
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    loop {
        match chars.next()?.1 {
            '"' => return Some(out),
            '\\' => match chars.next()?.1 {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        code = code * 16 + chars.next()?.1.to_digit(16)?;
                    }
                    // MIRA escapes only C0 controls this way; nothing else is canonical.
                    if code > 0x1f {
                        return None;
                    }
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            },
            c if c <= '\u{001f}' => return None,
            c => out.push(c),
        }
    }
}

/// The session as folded from its entries, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub session_id: String,
    pub header: Header,
    pub entries: u64,
    pub level: Level,
    /// Agent actions remaining; each admitted agent action consumes one.
    pub budget: u64,
    pub delegated_until: Option<u64>,
    pub closed: bool,
    /// The last directive that changed the level or budget.
    pub last_directive: Option<u64>,
    /// Actions without a result yet, by sequence number.
    pub pending: BTreeMap<u64, (String, String)>,
    /// Every agent request ID already admitted or refused.
    pub requests: BTreeSet<String>,
}

/// Why a session is not valid or an append is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Problem {
    /// An entry file is missing, out of order or has no signature.
    Gap(u64),
    /// An entry is not in the canonical layout or exceeds its bounds.
    Malformed(u64),
    /// An entry names another session, or its seq disagrees with its file.
    Mismatch(u64),
    /// An entry's principal is not the role allowed to write its kind.
    Role(u64),
    /// An entry follows the close entry, or the close count is wrong.
    AfterClose(u64),
    /// A file that is not an entry, signature or pending write.
    UnexpectedFile,
    /// The signature does not verify for the entry's principal.
    Signature(u64),
    /// The session is closed; nothing may be appended.
    Closed,
    /// The directive contradicts the session state.
    InvalidDirective,
    /// More than the bounded number of entries.
    Full,
    /// A note with control or bidirectional characters, or over 1 KiB.
    Text,
    /// The close receipt does not match the session.
    Receipt,
    /// The header names another operator than the verifier expects.
    Operator,
    /// A relayed entry's stored agent request is missing, unsigned or differs.
    Request(u64),
    /// A result's document is missing or not signed by the collector.
    Document(u64),
    /// The request ID already has an entry; the request is discarded.
    Replayed,
    /// The action was abandoned before its result could be recorded.
    Abandoned,
    /// Actions are still running; close needs each finished or abandoned.
    Pending,
    /// No budget is left, or only the operator's reserve: nothing the agent
    /// asks for can be recorded.
    Unchargeable,
    /// The session directory was replaced, or an entry the broker already
    /// verified changed or disappeared.
    Moved,
    /// An ancestor of the session directory lets another user replace it.
    UnsafePath,
    /// The session directory or a file in it could not be read or written.
    Io,
    /// `ssh-keygen` is missing or failed to run.
    Tool,
}

impl State {
    /// The level that applies to the entry about to be written: a delegation
    /// covers entries up to `delegated_until` only, as `fold` applies it.
    pub fn effective_level(&self) -> Level {
        match self.delegated_until {
            Some(until) if self.entries > until => Level::Assisted,
            _ => self.level,
        }
    }
}

impl Problem {
    pub fn reason(&self) -> String {
        match self {
            Self::Gap(seq) => format!("gap at entry {seq}"),
            Self::Malformed(seq) => format!("malformed entry {seq}"),
            Self::Mismatch(seq) => format!("entry {seq} belongs to another session or position"),
            Self::Role(seq) => format!("entry {seq} written by a principal without that role"),
            Self::AfterClose(seq) => format!("entry {seq} contradicts the close entry"),
            Self::UnexpectedFile => "unexpected file in the session log".to_owned(),
            Self::Signature(seq) => format!("signature of entry {seq} not verified"),
            Self::Closed => "session is closed".to_owned(),
            Self::InvalidDirective => "directive contradicts the session state".to_owned(),
            Self::Full => "session has reached its entry limit".to_owned(),
            Self::Text => {
                "note exceeds 1 KiB or contains control or bidirectional characters".to_owned()
            }
            Self::Receipt => "close receipt does not match the session".to_owned(),
            Self::Operator => "session operator is not the expected principal".to_owned(),
            Self::Request(seq) => {
                format!("agent request relayed by entry {seq} missing or altered")
            }
            Self::Document(seq) => {
                format!("document of result {seq} missing or not signed by the collector")
            }
            Self::Replayed => "request already recorded".to_owned(),
            Self::Abandoned => "action abandoned before its result".to_owned(),
            Self::Unchargeable => "no budget left, or only the operator's reserve".to_owned(),
            Self::Moved => {
                "session directory or a verified entry changed underneath the broker".to_owned()
            }
            Self::UnsafePath => {
                "another user could replace the session directory through a writable parent"
                    .to_owned()
            }
            Self::Pending => {
                "actions are still pending; wait for their results or close with --abandon-pending"
                    .to_owned()
            }
            Self::Io => "session directory unreadable or unwritable".to_owned(),
            Self::Tool => "ssh-keygen unavailable".to_owned(),
        }
    }
}

fn entry_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(ENTRIES).join(format!("{seq:06}.entry"))
}

/// One stored entry: the parsed entry, its exact signed bytes and its signature.
pub struct Stored {
    pub entry: Entry,
    pub bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

pub type Log = Vec<Stored>;

/// Split a record into the entry line (with its newline) and the signature.
pub(crate) fn split_record(record: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = record.iter().position(|byte| *byte == b'\n')? + 1;
    let (bytes, signature) = record.split_at(end);
    (signature.starts_with(signature::ARMOR)
        && signature.len() <= signature::MAX_SIGNATURE_BYTES
        && bytes.len() as u64 <= MAX_ENTRY_BYTES)
        .then_some((bytes, signature))
}

fn read_record(path: &Path) -> Option<(Entry, Vec<u8>, Vec<u8>)> {
    let record = signature::read_regular(path, MAX_RECORD_BYTES).ok()?;
    let (bytes, signature) = split_record(&record)?;
    Some((Entry::parse(bytes)?, bytes.to_vec(), signature.to_vec()))
}

/// Read every entry in sequence order, checking file names, contiguity,
/// layout, session identity and roles. Signatures are checked by `verify`.
/// Records appear atomically, so a concurrent reader never sees half an entry.
pub fn load(dir: &Path) -> Result<(Log, State), Problem> {
    let mut seqs = Vec::new();
    for item in fs::read_dir(dir.join(ENTRIES)).map_err(|_| Problem::Io)? {
        let name = item.map_err(|_| Problem::Io)?.file_name();
        let name = name.to_str().ok_or(Problem::UnexpectedFile)?;
        if name.starts_with(PENDING) {
            continue;
        }
        let stem = name.strip_suffix(".entry").ok_or(Problem::UnexpectedFile)?;
        if stem.len() != 6 || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Problem::UnexpectedFile);
        }
        seqs.push(stem.parse::<u64>().map_err(|_| Problem::UnexpectedFile)?);
    }
    seqs.sort_unstable();
    if seqs.len() as u64 > MAX_ENTRIES {
        return Err(Problem::Full);
    }
    let mut log = Vec::with_capacity(seqs.len());
    let mut state: Option<State> = None;
    for (index, seq) in seqs.iter().enumerate() {
        let seq = *seq;
        if seq != index as u64 {
            return Err(Problem::Gap(index as u64));
        }
        let (entry, bytes, signature) =
            read_record(&entry_path(dir, seq)).ok_or(Problem::Malformed(seq))?;
        if entry.seq != seq {
            return Err(Problem::Mismatch(seq));
        }
        state = Some(fold(state, &entry)?);
        log.push(Stored {
            entry,
            bytes,
            signature,
        });
    }
    let state = state.ok_or(Problem::Gap(0))?;
    Ok((log, state))
}

/// Whether one more agent-attributable entry (relayed request or refusal)
/// may be written at `seq`: budget left, and outside the operator's reserve.
pub fn chargeable(state: &State, seq: u64) -> bool {
    state.budget > 0 && seq < MAX_ENTRIES - OPERATOR_RESERVE
}

/// Apply one entry to the state. Entry 0 must be the header; nothing follows
/// the close entry; each kind may be written only by its role.
pub fn fold(state: Option<State>, entry: &Entry) -> Result<State, Problem> {
    let seq = entry.seq;
    let Some(mut state) = state else {
        let Body::Header(header) = &entry.body else {
            return Err(Problem::Malformed(seq));
        };
        if seq != 0
            || entry.based_on.is_some()
            || entry.principal != header.operator
            || header.autonomy == Level::Delegated
            || [&header.operator, &header.agent, &header.collector]
                .iter()
                .any(|name| signature::validate_principal(name).is_err())
            || header.operator == header.agent
            || header.operator == header.collector
            || header.agent == header.collector
        {
            return Err(Problem::Malformed(seq));
        }
        return Ok(State {
            session_id: entry.session_id.clone(),
            header: header.clone(),
            entries: 1,
            level: header.autonomy,
            budget: header.budget,
            delegated_until: None,
            closed: false,
            last_directive: None,
            pending: BTreeMap::new(),
            requests: BTreeSet::new(),
        });
    };
    if entry.session_id != state.session_id {
        return Err(Problem::Mismatch(seq));
    }
    if state.closed {
        return Err(Problem::AfterClose(seq));
    }
    if entry.based_on.is_some_and(|based_on| based_on >= seq) {
        return Err(Problem::Malformed(seq));
    }
    // Delegation lapses after its last covered entry.
    if state.delegated_until.is_some_and(|until| seq > until) {
        state.level = Level::Assisted;
        state.delegated_until = None;
    }
    let operator = entry.principal == state.header.operator;
    let collector = entry.principal == state.header.collector;
    // A relayed request ID must be well formed and never seen before.
    let fresh = |state: &State, id: &str| is_session_id(id) && !state.requests.contains(id);
    match &entry.body {
        Body::Header(_) => return Err(Problem::Malformed(seq)),
        Body::Question { request_id: None } | Body::LegacyQuestion if operator => {}
        Body::Question {
            request_id: Some(id),
        } if collector => {
            if !fresh(&state, id) || state.level == Level::Manual || !chargeable(&state, seq) {
                return Err(Problem::Malformed(seq));
            }
            state.budget -= 1;
            state.requests.insert(id.clone());
        }
        Body::Directive(directive) if operator => {
            match directive {
                Directive::Stop => {
                    state.level = Level::Manual;
                    state.delegated_until = None;
                }
                Directive::SetLevel(level) if *level != Level::Delegated => {
                    state.level = *level;
                    state.delegated_until = None;
                }
                Directive::SetBudget(budget) => state.budget = *budget,
                Directive::DelegateUntil(until) if *until > seq => {
                    state.level = Level::Delegated;
                    state.delegated_until = Some(*until);
                }
                _ => return Err(Problem::Malformed(seq)),
            }
            state.last_directive = Some(seq);
        }
        Body::Action {
            request_id,
            capability,
            arguments,
        } => {
            let plan =
                session_capability::plan(capability, arguments).ok_or(Problem::Malformed(seq))?;
            match request_id {
                None if operator => {}
                Some(id) if collector => {
                    let allowed = match state.level {
                        Level::Assisted => !plan.operator_only,
                        Level::Delegated => true,
                        Level::Manual | Level::Advisory => false,
                    };
                    if !fresh(&state, id) || !allowed || !chargeable(&state, seq) {
                        return Err(Problem::Malformed(seq));
                    }
                    state.budget -= 1;
                    state.requests.insert(id.clone());
                }
                _ => return Err(Problem::Role(seq)),
            }
            state
                .pending
                .insert(seq, (capability.clone(), arguments.clone()));
        }
        Body::Result {
            action_seq,
            exit_status,
            outcome,
            document_signature,
        } if collector => {
            // A document exists exactly when the outcome has one, and the entry
            // then carries its signature.
            if outcome.has_document()
                != document_signature
                    .as_deref()
                    .is_some_and(is_armored_signature)
            {
                return Err(Problem::Malformed(seq));
            }
            let (capability, arguments) = state
                .pending
                .remove(action_seq)
                .ok_or(Problem::Malformed(seq))?;
            let family = session_capability::plan(&capability, &arguments)
                .ok_or(Problem::Malformed(seq))?
                .family;
            let status = exit_status.and_then(|status| i32::try_from(status).ok());
            if Outcome::of(family, status) != *outcome {
                return Err(Problem::Malformed(seq));
            }
        }
        Body::Refusal { request_id, .. } if collector => {
            // A refusal is still agent activity in the log: it costs budget.
            if !fresh(&state, request_id) || !chargeable(&state, seq) {
                return Err(Problem::Malformed(seq));
            }
            state.budget -= 1;
            state.requests.insert(request_id.clone());
        }
        Body::Abandon { action_seq } if operator => {
            state
                .pending
                .remove(action_seq)
                .ok_or(Problem::Malformed(seq))?;
        }
        Body::Close { entry_count } if operator => {
            // Nothing may be left running: every action has a result or was
            // explicitly abandoned.
            if *entry_count != seq + 1 || !state.pending.is_empty() {
                return Err(Problem::AfterClose(seq));
            }
            state.closed = true;
        }
        _ => return Err(Problem::Role(seq)),
    }
    state.entries = seq + 1;
    Ok(state)
}

/// The operator's trust inputs and key for one writing command.
pub struct Writer<'a> {
    pub allowed_signers: &'a Path,
    pub key: &'a Path,
    pub principal: &'a str,
}

pub(crate) fn verify_signature(
    bytes: &[u8],
    signature: &[u8],
    allowed: &Path,
    principal: &str,
    seq: u64,
) -> Result<(), Problem> {
    let trust = Trust {
        allowed_signers: allowed,
        principal,
        revocations: None,
    };
    match signature::verify_staged(bytes, signature, &trust) {
        Ok(signature::Kind::Session) => Ok(()),
        Ok(_) | Err(Failure::Refused | Failure::Output | Failure::Document) => {
            Err(Problem::Signature(seq))
        }
        Err(Failure::Tool) => Err(Problem::Tool),
    }
}

/// A fresh pending name inside `directory` (one of the session's directories).
pub(crate) fn pending_name(directory: &Path, extension: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    directory.join(format!(
        "{PENDING}{}-{}-{}.{extension}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos())
    ))
}

/// Files are readable by the session's group, so a separate agent user in it
/// can read the log and documents; directory modes keep everyone else out.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with_mode(path, bytes, 0o640)
}

/// Create `path` exclusively with exactly `mode`: the creation mode is masked
/// by the umask, so it is set again through the descriptor.
fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Sign `entry` as the writer, check that signature against the operator's
/// `allowed_signers` before anything becomes visible, then claim its sequence
/// number by an exclusive hard link. A wrong key or a lost race never leaves
/// a partial entry: the loser re-reads the state and retries at the next seq.
pub fn append(
    dir: &Path,
    writer: &Writer,
    build: impl Fn(&State) -> Result<(Body, Option<u64>, String), Problem>,
) -> Result<Entry, Problem> {
    append_checked(dir, writer, &mut |_| Ok(()), build)
}

/// As [`append`], with `check` run on exactly the log each attempt decides
/// on, before `build` sees its state: a caller that trusts only entries it
/// has verified can refuse anything else without a gap between check and use.
pub fn append_checked(
    dir: &Path,
    writer: &Writer,
    check: &mut dyn FnMut(&Log) -> Result<(), Problem>,
    build: impl Fn(&State) -> Result<(Body, Option<u64>, String), Problem>,
) -> Result<Entry, Problem> {
    for _ in 0..APPEND_ATTEMPTS {
        let (log, state) = load(dir)?;
        check(&log)?;
        if state.closed {
            return Err(Problem::Closed);
        }
        if state.entries >= MAX_ENTRIES {
            return Err(Problem::Full);
        }
        let (body, based_on, note) = build(&state)?;
        validate_text(&note).map_err(|_| Problem::Text)?;
        let entry = Entry {
            session_id: state.session_id.clone(),
            seq: state.entries,
            principal: writer.principal.to_owned(),
            based_on,
            body,
            note,
        };
        // The state transition itself must be admissible before signing.
        fold(Some(state), &entry).map_err(|problem| match problem {
            Problem::Malformed(_) | Problem::AfterClose(_) => Problem::InvalidDirective,
            other => other,
        })?;
        match claim(dir, writer, &entry)? {
            true => return Ok(entry),
            false => continue,
        }
    }
    Err(Problem::Io)
}

/// Sign and check the entry, then publish entry and signature together as one
/// record by an exclusive hard link. Returns false when another writer
/// claimed this sequence number first.
fn claim(dir: &Path, writer: &Writer, entry: &Entry) -> Result<bool, Problem> {
    let bytes = entry.render();
    let pending_sig = pending_name(&dir.join(ENTRIES), "sig");
    let pending_record = pending_name(&dir.join(ENTRIES), "entry");
    let result = (|| {
        signature::sign(bytes.as_bytes(), writer.key, &pending_sig).map_err(
            |failure| match failure {
                Failure::Tool => Problem::Tool,
                _ => Problem::Signature(entry.seq),
            },
        )?;
        let signature =
            signature::read_regular(&pending_sig, signature::MAX_SIGNATURE_BYTES as u64)
                .map_err(|_| Problem::Io)?;
        verify_signature(
            bytes.as_bytes(),
            &signature,
            writer.allowed_signers,
            writer.principal,
            entry.seq,
        )?;
        let mut record = bytes.into_bytes();
        record.extend_from_slice(&signature);
        write_new(&pending_record, &record).map_err(|_| Problem::Io)?;
        match fs::hard_link(&pending_record, entry_path(dir, entry.seq)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => Err(Problem::Io),
        }
    })();
    let _ = fs::remove_file(&pending_sig);
    let _ = fs::remove_file(&pending_record);
    result
}

pub const DOCUMENTS: &str = "documents";
pub const REQUESTS: &str = "requests";
pub const INBOX: &str = "inbox";

/// The numeric ID of a group from `/etc/group`, read bounded.
pub fn group_id(name: &str) -> Option<u32> {
    let bytes = signature::read_regular(Path::new("/etc/group"), 1024 * 1024).ok()?;
    std::str::from_utf8(&bytes).ok()?.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then(|| fields.nth(1)?.parse().ok())?
    })
}

/// Create the session directory exclusively, with its layout, and write the
/// operator-signed header as entry 0. The header must verify for the operator.
///
/// `same_user`: every directory is 0700. `separate_user`: the session belongs
/// to `group`; the agent's group can read the log, documents and stored
/// requests (setgid 2750) and write only to `inbox/` (setgid 2770).
pub fn start(
    dir: &Path,
    writer: &Writer,
    header: Header,
    question: String,
    group: Option<u32>,
) -> Result<Entry, Problem> {
    validate_text(&question).map_err(|_| Problem::Text)?;
    if (header.separation == Separation::SeparateUser) != group.is_some() {
        return Err(Problem::InvalidDirective);
    }
    let session_id = crate::challenge::random_hex().map_err(|_| Problem::Io)?;
    let entry = Entry {
        session_id,
        seq: 0,
        principal: writer.principal.to_owned(),
        based_on: None,
        body: Body::Header(header),
        note: question,
    };
    fold(None, &entry).map_err(|_| Problem::InvalidDirective)?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(dir).map_err(|_| Problem::Io)?;
    let subdirectories = [ENTRIES, DOCUMENTS, REQUESTS, INBOX];
    let layout = || -> Result<(), Problem> {
        for name in subdirectories {
            builder.create(dir.join(name)).map_err(|_| Problem::Io)?;
        }
        if let Some(group) = group {
            use std::os::unix::fs::{PermissionsExt, chown};
            let modes = [
                (dir.to_path_buf(), 0o750),
                (dir.join(ENTRIES), 0o2750),
                (dir.join(DOCUMENTS), 0o2750),
                (dir.join(REQUESTS), 0o2750),
                (dir.join(INBOX), 0o2770),
            ];
            for (path, mode) in modes {
                chown(&path, None, Some(group)).map_err(|_| Problem::Io)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .map_err(|_| Problem::Io)?;
            }
        }
        Ok(())
    };
    let result = layout()
        .and_then(|()| claim(dir, writer, &entry))
        .and_then(|claimed| claimed.then_some(entry).ok_or(Problem::Io));
    if result.is_err() {
        // Only the directories this call created, and only if empty:
        // remove_dir never deletes contents or follows a substituted link.
        for name in subdirectories {
            let _ = fs::remove_dir(dir.join(name));
        }
        let _ = fs::remove_dir(dir);
    }
    result
}

/// Verify the whole log: structure, roles and every signature under the
/// operator's `allowed_signers`. The operator comes from the verifier, never
/// from the header: any listed key could otherwise write a header naming
/// itself operator and sign a counterfeit session. With a receipt, the close
/// record it holds must be the session's last record, byte for byte.
pub fn verify(
    dir: &Path,
    allowed: &Path,
    operator: &str,
    receipt: Option<&Path>,
) -> Result<(Log, State), Problem> {
    let (log, state) = load(dir)?;
    if state.header.operator != operator {
        return Err(Problem::Operator);
    }
    for stored in &log {
        verify_signature(
            &stored.bytes,
            &stored.signature,
            allowed,
            &stored.entry.principal,
            stored.entry.seq,
        )?;
    }
    if let Some(receipt) = receipt {
        let (close, bytes, signature) = read_record(receipt).ok_or(Problem::Receipt)?;
        verify_signature(
            &bytes,
            &signature,
            allowed,
            &state.header.operator,
            close.seq,
        )
        .map_err(|problem| match problem {
            Problem::Tool => Problem::Tool,
            _ => Problem::Receipt,
        })?;
        let matches = matches!(close.body, Body::Close { .. })
            && close.session_id == state.session_id
            && log
                .get(close.seq as usize)
                .is_some_and(|stored| stored.bytes == bytes && stored.signature == signature)
            && state.closed
            && state.entries == close.seq + 1;
        if !matches {
            return Err(Problem::Receipt);
        }
    }
    // The authenticated snapshot: later checks must use it, never a re-read.
    Ok((log, state))
}

/// Whether `receipt` would be written outside the session directory, with
/// both paths resolved through any symbolic links.
pub fn receipt_outside(dir: &Path, receipt: &Path) -> bool {
    let parent = match receipt.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    match (fs::canonicalize(dir), fs::canonicalize(parent)) {
        (Ok(dir), Ok(parent)) => !parent.starts_with(&dir),
        _ => false,
    }
}

/// Write the close record (entry and signature) to an external receipt,
/// created exclusively, never overwriting.
pub fn write_receipt(dir: &Path, close: &Entry, receipt: &Path) -> Result<(), Problem> {
    let record = signature::read_regular(&entry_path(dir, close.seq), MAX_RECORD_BYTES)
        .map_err(|_| Problem::Io)?;
    // A receipt lives outside the shared session: owner-only, whatever the umask.
    write_with_mode(receipt, &record, 0o600).map_err(|_| Problem::Receipt)
}

/// A fixed, escaped human timeline.
pub fn render_timeline(log: &[Stored], state: &State) -> String {
    let mut out = format!(
        "MIRA session\nautonomy {} budget {} entries {} {}\n",
        state.level.as_str(),
        state.budget,
        state.entries,
        if state.closed { "closed" } else { "open" }
    );
    for Stored { entry, .. } in log {
        let detail = match &entry.body {
            Body::Header(header) => format!(
                "header operator={} agent={} collector={} separation={}",
                header.operator,
                header.agent,
                header.collector,
                header.separation.as_str()
            ),
            Body::Question { request_id: None } | Body::LegacyQuestion => "question".to_owned(),
            Body::Abandon { action_seq } => format!("abandon {action_seq:06}"),
            Body::Question {
                request_id: Some(_),
            } => "question (agent request)".to_owned(),
            Body::Action {
                request_id,
                capability,
                arguments,
            } => format!(
                "action {capability} {arguments}{}",
                if request_id.is_some() {
                    " (agent request)"
                } else {
                    ""
                }
            ),
            Body::Result {
                action_seq,
                outcome,
                ..
            } => format!("result of {action_seq:06}: {}", outcome.as_str()),
            Body::Refusal { reason, .. } => format!("refusal {}", reason.as_str()),
            Body::Directive(Directive::Stop) => "directive stop".to_owned(),
            Body::Directive(Directive::SetLevel(level)) => {
                format!("directive level {}", level.as_str())
            }
            Body::Directive(Directive::SetBudget(budget)) => format!("directive budget {budget}"),
            Body::Directive(Directive::DelegateUntil(until)) => {
                format!("directive delegate until {until}")
            }
            Body::Close { .. } => "close".to_owned(),
        };
        // Text was validated free of controls when written, and re-checked here.
        let note = if validate_text(&entry.note).is_ok() {
            entry.note.clone()
        } else {
            "(unprintable note)".to_owned()
        };
        out.push_str(&format!(
            "{:06} {} {detail}: {note}\n",
            entry.seq, entry.principal
        ));
    }
    out
}

pub fn state_json(state: &State) -> String {
    format!(
        "{{\"session_version\":{SESSION_VERSION},\"entries\":{},\"closed\":{},\"autonomy\":{},\"budget\":{},\"delegated_until\":{}}}",
        state.entries,
        state.closed,
        quoted(state.level.as_str()),
        state.budget,
        number(state.delegated_until)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SIGNATURE: &str =
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";

    fn header() -> Entry {
        Entry {
            session_id: ID.to_owned(),
            seq: 0,
            principal: "operator".to_owned(),
            based_on: None,
            body: Body::Header(Header {
                operator: "operator".to_owned(),
                agent: "agent".to_owned(),
                collector: "collector".to_owned(),
                separation: Separation::SameUser,
                autonomy: Level::Assisted,
                budget: 10,
            }),
            note: "Why did \"svc\" restart? \\ check".to_owned(),
        }
    }

    fn next(seq: u64, principal: &str, body: Body) -> Entry {
        Entry {
            session_id: ID.to_owned(),
            seq,
            principal: principal.to_owned(),
            based_on: Some(seq - 1),
            body,
            note: String::new(),
        }
    }

    #[test]
    fn every_kind_round_trips_canonically() {
        let entries = [
            header(),
            next(1, "operator", Body::Question { request_id: None }),
            next(2, "operator", Body::Directive(Directive::Stop)),
            next(
                3,
                "operator",
                Body::Directive(Directive::SetLevel(Level::Advisory)),
            ),
            next(4, "operator", Body::Directive(Directive::SetBudget(0))),
            next(5, "operator", Body::Directive(Directive::DelegateUntil(9))),
            next(6, "operator", Body::Close { entry_count: 7 }),
        ];
        for entry in &entries {
            let text = entry.render();
            assert!(text.starts_with("{\"session_version\":1,\"session_id\":\""));
            assert!(text.ends_with("}\n"));
            assert_eq!(
                Entry::parse(text.as_bytes()).as_ref(),
                Some(entry),
                "{text}"
            );
        }
    }

    #[test]
    fn non_canonical_bytes_are_refused() {
        let text = header().render();
        let variants = [
            text.trim_end().to_owned(),
            format!("{text}\n"),
            text.replacen(',', ", ", 1),
            text.replacen("\"seq\":0", "\"seq\":00", 1),
            text.replacen("\"seq\":0", "\"seq\":-0", 1),
            text.replacen("\"budget\":10", "\"budget\":1e1", 1),
            text.replacen("\"budget\":10", "\"budget\":10.0", 1),
            text.replacen("\"budget\":10", "\"budget\":\"10\"", 1),
            text.replacen("\"session_version\":1", "\"session_version\":2", 1),
            text.replacen(ID, &ID.to_uppercase(), 1),
            text.replacen(
                "\"kind\":\"header\"",
                "\"kind\":\"header\",\"kind\":\"header\"",
                1,
            ),
            text.replacen("\"note\":", "\"extra\":{},\"note\":", 1),
            text.replacen("\"autonomy\":\"assisted\"", "\"autonomy\":\"delegated\"", 1),
            text.replacen("\"note\":\"", "\"note\":\"\\u0041", 1),
            text.replacen("\"note\":\"", "\"note\":\"\\/", 1),
            text.replacen("\"budget\":10,", "", 1),
        ];
        for variant in variants {
            let parsed = Entry::parse(variant.as_bytes());
            // Delegated autonomy parses but is refused by fold, not by the layout.
            if variant.contains("\"autonomy\":\"delegated\"") {
                assert!(fold(None, &parsed.unwrap()).is_err());
            } else {
                assert_eq!(parsed, None, "{variant:?}");
            }
        }
        let directive = next(1, "operator", Body::Directive(Directive::Stop)).render();
        for bad in [
            directive.replacen("\"level\":null", "\"level\":\"manual\"", 1),
            directive.replacen("\"directive\":\"stop\"", "\"directive\":\"halt\"", 1),
            directive.replacen("\"until_seq\":null", "\"until_seq\":3", 1),
        ] {
            assert_eq!(Entry::parse(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn canonical_entries_with_invalid_notes_are_refused_on_read() {
        // Each is canonically encoded; only the note breaks the contract.
        for note in [
            "line\nbreak".to_owned(),
            "rlo\u{202e}".to_owned(),
            "a".repeat(MAX_TEXT_BYTES + 1),
        ] {
            let mut entry = header();
            entry.note = note.clone();
            assert_eq!(Entry::parse(entry.render().as_bytes()), None, "{note:?}");
        }
    }

    #[test]
    fn records_split_into_entry_and_signature() {
        let line = header().render();
        let record =
            format!("{line}-----BEGIN SSH SIGNATURE-----\nabc\n-----END SSH SIGNATURE-----\n");
        let (bytes, signature) = split_record(record.as_bytes()).unwrap();
        assert_eq!(bytes, line.as_bytes());
        assert!(signature.starts_with(signature::ARMOR));
        assert_eq!(split_record(line.as_bytes()), None);
        assert_eq!(split_record(format!("{line}garbage").as_bytes()), None);
        assert_eq!(split_record(b"no newline"), None);
    }

    #[test]
    fn text_refuses_controls_bidi_and_oversize() {
        assert!(validate_text("ok: \"quoted\" \\ and ünïcode").is_ok());
        assert!(validate_text(&"a".repeat(MAX_TEXT_BYTES)).is_ok());
        for bad in [
            "line\nbreak".to_owned(),
            "esc\u{1b}[2J".to_owned(),
            "del\u{7f}".to_owned(),
            "c1\u{85}".to_owned(),
            "rlo\u{202e}txt".to_owned(),
            "isolate\u{2066}".to_owned(),
            "mark\u{200f}".to_owned(),
            "a".repeat(MAX_TEXT_BYTES + 1),
        ] {
            assert!(validate_text(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_state_follows_directives_roles_and_closure() {
        let mut state = fold(None, &header()).unwrap();
        assert_eq!((state.level, state.budget), (Level::Assisted, 10));
        let steps = [
            (
                next(1, "operator", Body::Directive(Directive::SetBudget(3))),
                Level::Assisted,
                3,
            ),
            (
                next(2, "operator", Body::Directive(Directive::DelegateUntil(3))),
                Level::Delegated,
                3,
            ),
            (
                next(3, "operator", Body::Question { request_id: None }),
                Level::Delegated,
                3,
            ),
            // Delegation covered entries up to 3 and lapses at 4.
            (
                next(4, "operator", Body::Question { request_id: None }),
                Level::Assisted,
                3,
            ),
            (
                next(5, "operator", Body::Directive(Directive::Stop)),
                Level::Manual,
                3,
            ),
            (
                next(
                    6,
                    "operator",
                    Body::Directive(Directive::SetLevel(Level::Advisory)),
                ),
                Level::Advisory,
                3,
            ),
        ];
        for (entry, level, budget) in steps {
            state = fold(Some(state), &entry).unwrap();
            assert_eq!((state.level, state.budget), (level, budget), "{entry:?}");
        }
        assert_eq!(
            fold(
                Some(state.clone()),
                &next(7, "agent", Body::Directive(Directive::Stop))
            ),
            Err(Problem::Role(7))
        );
        assert_eq!(
            fold(
                Some(state.clone()),
                &next(7, "collector", Body::Question { request_id: None })
            ),
            Err(Problem::Role(7))
        );
        assert_eq!(
            fold(
                Some(state.clone()),
                &next(
                    7,
                    "operator",
                    Body::Directive(Directive::SetLevel(Level::Delegated))
                )
            ),
            Err(Problem::Malformed(7))
        );
        assert_eq!(
            fold(
                Some(state.clone()),
                &next(7, "operator", Body::Directive(Directive::DelegateUntil(7)))
            ),
            Err(Problem::Malformed(7))
        );
        assert_eq!(
            fold(
                Some(state.clone()),
                &next(7, "operator", Body::Close { entry_count: 9 })
            ),
            Err(Problem::AfterClose(7))
        );
        let closed = fold(
            Some(state),
            &next(7, "operator", Body::Close { entry_count: 8 }),
        )
        .unwrap();
        assert!(closed.closed);
        assert_eq!(
            fold(
                Some(closed),
                &next(8, "operator", Body::Question { request_id: None })
            ),
            Err(Problem::AfterClose(8))
        );
    }

    #[test]
    fn headers_are_only_first_and_well_formed() {
        let mut other = header();
        other.seq = 1;
        let state = fold(None, &header()).unwrap();
        assert_eq!(fold(Some(state), &other), Err(Problem::Malformed(1)));
        assert_eq!(
            fold(
                None,
                &next(1, "operator", Body::Question { request_id: None })
            ),
            Err(Problem::Malformed(1))
        );
        for change in [
            |h: &mut Header| h.agent = "operator".to_owned(),
            |h: &mut Header| h.collector = "agent".to_owned(),
            |h: &mut Header| h.operator = "-bad".to_owned(),
        ] {
            let mut entry = header();
            if let Body::Header(h) = &mut entry.body {
                change(h);
            }
            assert!(fold(None, &entry).is_err());
        }
        let mut agent_signed = header();
        agent_signed.principal = "agent".to_owned();
        assert_eq!(fold(None, &agent_signed), Err(Problem::Malformed(0)));
    }

    #[test]
    fn entries_must_reference_earlier_entries_and_this_session() {
        let state = fold(None, &header()).unwrap();
        let mut forward = next(1, "operator", Body::Question { request_id: None });
        forward.based_on = Some(1);
        assert_eq!(
            fold(Some(state.clone()), &forward),
            Err(Problem::Malformed(1))
        );
        let mut foreign = next(1, "operator", Body::Question { request_id: None });
        foreign.session_id = ID.replace('0', "1");
        assert_eq!(fold(Some(state), &foreign), Err(Problem::Mismatch(1)));
    }

    fn request(n: u8) -> Option<String> {
        Some(format!("{n:02x}").repeat(32))
    }

    fn action(
        seq: u64,
        principal: &str,
        request_id: Option<String>,
        capability: &str,
        arguments: &str,
    ) -> Entry {
        next(
            seq,
            principal,
            Body::Action {
                request_id,
                capability: capability.to_owned(),
                arguments: arguments.to_owned(),
            },
        )
    }

    #[test]
    fn new_kinds_round_trip_canonically() {
        for body in [
            Body::Question {
                request_id: request(1),
            },
            Body::Action {
                request_id: request(2),
                capability: "memory-headroom".to_owned(),
                arguments: "1024".to_owned(),
            },
            Body::Action {
                request_id: None,
                capability: "capture".to_owned(),
                arguments: "host bind-boot".to_owned(),
            },
            Body::Result {
                action_seq: 3,
                exit_status: Some(1),
                outcome: Outcome::NotSatisfied,
                document_signature: Some(SIGNATURE.to_owned()),
            },
            Body::Result {
                action_seq: 3,
                exit_status: None,
                outcome: Outcome::RunnerError,
                document_signature: None,
            },
            Body::Abandon { action_seq: 3 },
            Body::Refusal {
                request_id: request(4).unwrap(),
                reason: Refusal::SupersededByDirective,
            },
        ] {
            let entry = next(5, "collector", body);
            let text = entry.render();
            assert_eq!(
                Entry::parse(text.as_bytes()).as_ref(),
                Some(&entry),
                "{text}"
            );
        }
        let refusal = next(
            5,
            "collector",
            Body::Refusal {
                request_id: request(4).unwrap(),
                reason: Refusal::Capability,
            },
        )
        .render();
        assert_eq!(
            Entry::parse(refusal.replace("\"capability\"", "\"bribe\"").as_bytes()),
            None
        );
    }

    #[test]
    fn agent_actions_follow_autonomy_budget_and_capability() {
        let mut header_entry = header();
        if let Body::Header(h) = &mut header_entry.body {
            h.budget = 1;
        }
        let state = fold(None, &header_entry).unwrap();
        // The agent never writes the log itself.
        assert_eq!(
            fold(
                Some(state.clone()),
                &action(1, "agent", request(1), "memory-headroom", "1")
            ),
            Err(Problem::Role(1))
        );
        // Relayed by the collector, within budget: admitted and charged.
        let after = fold(
            Some(state.clone()),
            &action(1, "collector", request(1), "memory-headroom", "1"),
        )
        .unwrap();
        assert_eq!(after.budget, 0);
        assert!(after.pending.contains_key(&1));
        // Budget exhausted.
        assert_eq!(
            fold(
                Some(after.clone()),
                &action(2, "collector", request(2), "memory-headroom", "1")
            ),
            Err(Problem::Malformed(2))
        );
        // A replayed request ID, a capability outside the set, and an
        // operator-only capture are refused at the state level too.
        assert_eq!(
            fold(
                Some(state.clone()),
                &action(1, "collector", None, "memory-headroom", "1")
            ),
            Err(Problem::Role(1))
        );
        assert!(
            fold(
                Some(state.clone()),
                &action(1, "collector", request(1), "inspect", "")
            )
            .is_err()
        );
        assert!(
            fold(
                Some(state.clone()),
                &action(1, "collector", request(1), "capture", "host bind-boot")
            )
            .is_err()
        );
        let replay = fold(
            Some(after),
            &next(2, "operator", Body::Directive(Directive::SetBudget(5))),
        )
        .unwrap();
        assert!(
            fold(
                Some(replay),
                &action(3, "collector", request(1), "memory-headroom", "1")
            )
            .is_err()
        );
        // Advisory and manual allow no agent actions; delegation allows bind-boot.
        for level in [Level::Advisory, Level::Manual] {
            let set = fold(
                Some(state.clone()),
                &next(1, "operator", Body::Directive(Directive::SetLevel(level))),
            )
            .unwrap();
            assert!(
                fold(
                    Some(set),
                    &action(2, "collector", request(1), "memory-headroom", "1")
                )
                .is_err()
            );
        }
        let delegated = fold(
            Some(state.clone()),
            &next(1, "operator", Body::Directive(Directive::DelegateUntil(5))),
        )
        .unwrap();
        assert!(
            fold(
                Some(delegated),
                &action(2, "collector", request(1), "capture", "host bind-boot")
            )
            .is_ok()
        );
        // The operator's own actions need no budget and may be operator-only.
        let own = fold(
            Some(state),
            &action(1, "operator", None, "capture", "host bind-boot"),
        )
        .unwrap();
        assert_eq!(own.budget, 1);
    }

    #[test]
    fn results_must_answer_a_pending_action_with_the_fixed_outcome() {
        let state = fold(None, &header()).unwrap();
        let state = fold(
            Some(state),
            &action(1, "operator", None, "memory-headroom", "1"),
        )
        .unwrap();
        let result = |seq, action_seq, exit_status, outcome| {
            next(
                seq,
                "collector",
                Body::Result {
                    action_seq,
                    exit_status,
                    outcome,
                    document_signature: outcome.has_document().then(|| SIGNATURE.to_owned()),
                },
            )
        };
        // The outcome must be the one the exit status maps to.
        assert!(
            fold(
                Some(state.clone()),
                &result(2, 1, Some(0), Outcome::NotSatisfied)
            )
            .is_err()
        );
        assert!(
            fold(
                Some(state.clone()),
                &result(2, 1, Some(0), Outcome::CompleteAvailable)
            )
            .is_err()
        );
        // Only the collector writes results, and only for a pending action.
        let mut forged = result(2, 1, Some(0), Outcome::Satisfied);
        forged.principal = "operator".to_owned();
        assert_eq!(fold(Some(state.clone()), &forged), Err(Problem::Role(2)));
        assert!(
            fold(
                Some(state.clone()),
                &result(2, 7, Some(0), Outcome::Satisfied)
            )
            .is_err()
        );
        let done = fold(Some(state), &result(2, 1, Some(0), Outcome::Satisfied)).unwrap();
        assert!(done.pending.is_empty());
        assert!(fold(Some(done), &result(3, 1, Some(0), Outcome::Satisfied)).is_err());
    }

    #[test]
    fn relayed_questions_and_refusals_consume_their_request_ids() {
        let state = fold(None, &header()).unwrap();
        let asked = fold(
            Some(state.clone()),
            &next(
                1,
                "collector",
                Body::Question {
                    request_id: request(1),
                },
            ),
        )
        .unwrap();
        let refusal = |seq, id: Option<String>| {
            next(
                seq,
                "collector",
                Body::Refusal {
                    request_id: id.unwrap(),
                    reason: Refusal::Capability,
                },
            )
        };
        assert!(fold(Some(asked.clone()), &refusal(2, request(1))).is_err());
        assert!(fold(Some(asked), &refusal(2, request(2))).is_ok());
        // Questions relay only above manual; the operator's carry no request.
        let manual = fold(
            Some(state.clone()),
            &next(1, "operator", Body::Directive(Directive::Stop)),
        )
        .unwrap();
        assert!(
            fold(
                Some(manual),
                &next(
                    2,
                    "collector",
                    Body::Question {
                        request_id: request(1)
                    }
                )
            )
            .is_err()
        );
        assert_eq!(
            fold(
                Some(state),
                &next(
                    1,
                    "operator",
                    Body::Question {
                        request_id: request(1)
                    }
                )
            ),
            Err(Problem::Role(1))
        );
    }

    #[test]
    fn stage_1a_questions_keep_their_signed_layout() {
        // The exact layout stage 1a wrote, before questions had a request_id.
        let old = format!(
            "{{\"session_version\":1,\"session_id\":\"{ID}\",\"seq\":1,\"kind\":\"question\",\"principal\":\"operator\",\"based_on\":0,\"note\":\"journal visible?\"}}\n"
        );
        let entry = Entry::parse(old.as_bytes()).expect("1a question admitted");
        assert_eq!(entry.body, Body::LegacyQuestion);
        assert_eq!(entry.render(), old);
        let state = fold(Some(fold(None, &header()).unwrap()), &entry).unwrap();
        assert_eq!(state.entries, 2);
        // Only the operator wrote 1a questions.
        let mut relayed = entry.clone();
        relayed.principal = "collector".to_owned();
        assert!(fold(Some(fold(None, &header()).unwrap()), &relayed).is_err());
    }

    #[test]
    fn results_commit_to_their_document_exactly_when_one_exists() {
        let state = fold(None, &header()).unwrap();
        let state = fold(
            Some(state),
            &action(1, "operator", None, "memory-headroom", "1"),
        )
        .unwrap();
        let result = |outcome, document_signature: Option<&str>| {
            next(
                2,
                "collector",
                Body::Result {
                    action_seq: 1,
                    exit_status: Some(0),
                    outcome,
                    document_signature: document_signature.map(str::to_owned),
                },
            )
        };
        assert!(
            fold(
                Some(state.clone()),
                &result(Outcome::Satisfied, Some(SIGNATURE))
            )
            .is_ok()
        );
        // A document outcome without its signature, or with something else.
        assert!(fold(Some(state.clone()), &result(Outcome::Satisfied, None)).is_err());
        assert!(
            fold(
                Some(state.clone()),
                &result(Outcome::Satisfied, Some("not armored"))
            )
            .is_err()
        );
        let mut refused_arguments = result(Outcome::RefusedArguments, Some(SIGNATURE));
        if let Body::Result { exit_status, .. } = &mut refused_arguments.body {
            *exit_status = Some(2);
        }
        // No document, so no signature may be claimed.
        assert!(fold(Some(state), &refused_arguments).is_err());
    }

    #[test]
    fn close_waits_for_pending_actions_or_their_abandonment() {
        let state = fold(None, &header()).unwrap();
        let pending = fold(
            Some(state),
            &action(1, "operator", None, "uptime-minimum", "1"),
        )
        .unwrap();
        assert_eq!(
            fold(
                Some(pending.clone()),
                &next(2, "operator", Body::Close { entry_count: 3 })
            ),
            Err(Problem::AfterClose(2))
        );
        // Only the operator abandons, and only a pending action.
        assert_eq!(
            fold(
                Some(pending.clone()),
                &next(2, "collector", Body::Abandon { action_seq: 1 })
            ),
            Err(Problem::Role(2))
        );
        assert!(
            fold(
                Some(pending.clone()),
                &next(2, "operator", Body::Abandon { action_seq: 7 })
            )
            .is_err()
        );
        let abandoned = fold(
            Some(pending),
            &next(2, "operator", Body::Abandon { action_seq: 1 }),
        )
        .unwrap();
        assert!(abandoned.pending.is_empty());
        // A result can no longer arrive for it, and the session can close.
        let late = next(
            3,
            "collector",
            Body::Result {
                action_seq: 1,
                exit_status: Some(0),
                outcome: Outcome::Satisfied,
                document_signature: Some(SIGNATURE.to_owned()),
            },
        );
        assert!(fold(Some(abandoned.clone()), &late).is_err());
        assert!(
            fold(
                Some(abandoned),
                &next(3, "operator", Body::Close { entry_count: 4 })
            )
            .is_ok()
        );
    }

    #[test]
    fn the_effective_level_lapses_with_delegation() {
        let state = fold(None, &header()).unwrap();
        let delegated = fold(
            Some(state),
            &next(1, "operator", Body::Directive(Directive::DelegateUntil(2))),
        )
        .unwrap();
        // The next entry is 2: still covered.
        assert_eq!(delegated.effective_level(), Level::Delegated);
        let covered = fold(
            Some(delegated),
            &next(2, "operator", Body::Question { request_id: None }),
        )
        .unwrap();
        // The next entry is 3: outside the grant, although the folded state
        // has not lapsed yet.
        assert_eq!(covered.level, Level::Delegated);
        assert_eq!(covered.effective_level(), Level::Assisted);
    }

    #[test]
    fn every_agent_attributable_entry_costs_budget_outside_the_reserve() {
        let mut header_entry = header();
        if let Body::Header(h) = &mut header_entry.body {
            h.budget = 2;
        }
        let state = fold(None, &header_entry).unwrap();
        let asked = fold(
            Some(state.clone()),
            &next(
                1,
                "collector",
                Body::Question {
                    request_id: request(1),
                },
            ),
        )
        .unwrap();
        assert_eq!(asked.budget, 1);
        let refused = fold(
            Some(asked),
            &next(
                2,
                "collector",
                Body::Refusal {
                    request_id: request(2).unwrap(),
                    reason: Refusal::Capability,
                },
            ),
        )
        .unwrap();
        assert_eq!(refused.budget, 0);
        // At zero, neither a question nor a refusal can be recorded.
        assert!(
            fold(
                Some(refused.clone()),
                &next(
                    3,
                    "collector",
                    Body::Question {
                        request_id: request(3)
                    }
                )
            )
            .is_err()
        );
        assert!(
            fold(
                Some(refused.clone()),
                &next(
                    3,
                    "collector",
                    Body::Refusal {
                        request_id: request(3).unwrap(),
                        reason: Refusal::Capability
                    }
                ),
            )
            .is_err()
        );
        // The operator's own entries are never charged.
        assert!(
            fold(
                Some(refused),
                &next(3, "operator", Body::Directive(Directive::Stop))
            )
            .is_ok()
        );
        // Inside the reserve, even a funded agent entry is refused.
        let mut late = state;
        late.budget = 5;
        let edge = MAX_ENTRIES - OPERATOR_RESERVE;
        assert!(chargeable(&late, edge - 1));
        assert!(!chargeable(&late, edge));
        late.entries = edge;
        assert!(
            fold(
                Some(late),
                &next(
                    edge,
                    "collector",
                    Body::Question {
                        request_id: request(4)
                    }
                )
            )
            .is_err()
        );
    }
}
