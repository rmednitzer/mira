//! The session broker (ADR 0015 stage 1b). The agent never writes the log:
//! it drops signed request records into `inbox/`. `mira session run`, which
//! the operator starts and the agent does not control, verifies each request,
//! enforces autonomy, budget and the closed capability set, and records the
//! outcome. It runs admitted actions itself, signing every result document
//! with the collector key, which the agent cannot use.
use crate::process::{Stderr, run_drained};
use crate::session::{
    self, Body, DOCUMENTS, Entry, INBOX, Level, Problem, REQUESTS, Refusal, Separation, State,
    Writer,
};
use crate::session_capability::{self, Family, Outcome};
use crate::signature::{self, Kind, Trust};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const ACTION_TIMEOUT: Duration = Duration::from_secs(120);
/// Directory entries the broker reads from `inbox/` in one pass, and requests
/// it handles: an agent flooding the inbox cannot make a pass unbounded.
const MAX_SCAN: usize = 4096;
const MAX_PER_PASS: usize = 64;
/// How long an agent's pending (not yet published) request may sit.
const PENDING_GRACE: Duration = Duration::from_secs(60);
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// What an agent asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    Action {
        capability: String,
        arguments: String,
    },
    Question,
}

/// An agent request: one canonical line, signed by the agent under the session
/// namespace. Its `kind` is `request`, which is never a log entry kind, so a
/// request can never be passed off as an entry or the reverse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub session_id: String,
    pub request_id: String,
    pub principal: String,
    pub based_on: u64,
    pub ask: Ask,
    pub note: String,
}

fn quoted(text: &str) -> String {
    crate::evidence_json::quoted(text)
}

impl Request {
    pub fn render(&self) -> String {
        let (ask, capability, arguments) = match &self.ask {
            Ask::Action {
                capability,
                arguments,
            } => ("action", quoted(capability), quoted(arguments)),
            Ask::Question => ("question", "null".to_owned(), "null".to_owned()),
        };
        format!(
            "{{\"session_version\":{},\"session_id\":{},\"kind\":\"request\",\"request_id\":{},\"principal\":{},\"based_on\":{},\"request\":\"{ask}\",\"capability\":{capability},\"arguments\":{arguments},\"note\":{}}}\n",
            session::SESSION_VERSION,
            quoted(&self.session_id),
            quoted(&self.request_id),
            quoted(&self.principal),
            self.based_on,
            quoted(&self.note)
        )
    }

    /// Admit only the canonical layout, through the session's strict parser.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        use session::Value;
        let text = std::str::from_utf8(bytes).ok()?;
        let fields = session::parse_flat(text.strip_suffix('\n')?)?;
        let string = |key: &str| match fields.get(key)? {
            Value::Str(value) => Some(value.clone()),
            _ => None,
        };
        let ask = match string("request")?.as_str() {
            "action" => Ask::Action {
                capability: string("capability")?,
                arguments: string("arguments")?,
            },
            "question" => Ask::Question,
            _ => return None,
        };
        let based_on = match fields.get("based_on")? {
            Value::Uint(value) => *value,
            _ => return None,
        };
        let request = Self {
            session_id: string("session_id")?,
            request_id: string("request_id")?,
            principal: string("principal")?,
            based_on,
            ask,
            note: string("note")?,
        };
        (string("kind")? == "request"
            && matches!(fields.get("session_version")?, Value::Uint(1))
            && session::is_session_id(&request.session_id)
            && session::is_session_id(&request.request_id)
            && signature::validate_principal(&request.principal).is_ok()
            && session::validate_text(&request.note).is_ok()
            && request.render().as_bytes() == bytes)
            .then_some(request)
    }
}

fn inbox(dir: &Path) -> PathBuf {
    dir.join(INBOX)
}

fn stored_request(dir: &Path, request_id: &str) -> PathBuf {
    dir.join(REQUESTS).join(format!("{request_id}.request"))
}

pub fn document_path(dir: &Path, action_seq: u64) -> PathBuf {
    dir.join(DOCUMENTS).join(format!("{action_seq:06}.json"))
}

fn sign_record(bytes: &str, writer: &Writer, pending_dir: &Path) -> Result<Vec<u8>, Problem> {
    let pending_sig = session::pending_name(pending_dir, "sig");
    let result = (|| {
        signature::sign(bytes.as_bytes(), writer.key, &pending_sig).map_err(
            |failure| match failure {
                signature::Failure::Tool => Problem::Tool,
                _ => Problem::Signature(0),
            },
        )?;
        let signature =
            signature::read_regular(&pending_sig, signature::MAX_SIGNATURE_BYTES as u64)
                .map_err(|_| Problem::Io)?;
        session::verify_signature(
            bytes.as_bytes(),
            &signature,
            writer.allowed_signers,
            writer.principal,
            0,
        )?;
        let mut record = bytes.as_bytes().to_vec();
        record.extend_from_slice(&signature);
        Ok(record)
    })();
    let _ = fs::remove_file(&pending_sig);
    result
}

/// The agent side: sign a request as the header's agent and publish it in
/// the inbox by one exclusive hard link. Nothing it writes is trusted until
/// the broker has verified and recorded it.
pub fn submit(dir: &Path, writer: &Writer, ask: Ask, note: String) -> Result<String, Problem> {
    session::validate_text(&note).map_err(|_| Problem::Text)?;
    let (_, state) = session::load(dir)?;
    if state.closed {
        return Err(Problem::Closed);
    }
    if writer.principal != state.header.agent {
        return Err(Problem::Role(state.entries));
    }
    let request = Request {
        session_id: state.session_id.clone(),
        request_id: crate::challenge::random_hex().map_err(|_| Problem::Io)?,
        principal: writer.principal.to_owned(),
        based_on: state.entries - 1,
        ask,
        note,
    };
    let record = sign_record(&request.render(), writer, &inbox(dir))?;
    let pending = session::pending_name(&inbox(dir), "request");
    let result = session::write_new(&pending, &record)
        .and_then(|()| {
            fs::hard_link(
                &pending,
                inbox(dir).join(format!("{}.request", request.request_id)),
            )
        })
        .map_err(|_| Problem::Io);
    let _ = fs::remove_file(&pending);
    result.map(|()| request.request_id)
}

/// The admission decision for one verified request against the current state.
fn decide(state: &State, request: &Request) -> Result<Body, Refusal> {
    if request.session_id != state.session_id {
        return Err(Refusal::SessionMismatch);
    }
    if request.based_on >= state.entries {
        return Err(Refusal::Stale);
    }
    if state.requests.contains(&request.request_id) {
        return Err(Refusal::Replayed);
    }
    // A directive after the request was written takes precedence over it.
    let refused_by_level = || {
        if state
            .last_directive
            .is_some_and(|seq| seq > request.based_on)
        {
            Refusal::SupersededByDirective
        } else {
            Refusal::Autonomy
        }
    };
    match &request.ask {
        Ask::Question => {
            if state.effective_level() == Level::Manual {
                return Err(refused_by_level());
            }
            Ok(Body::Question {
                request_id: Some(request.request_id.clone()),
            })
        }
        Ask::Action {
            capability,
            arguments,
        } => {
            let plan =
                session_capability::plan(capability, arguments).ok_or(Refusal::Capability)?;
            // The level that applies to the entry about to be written.
            match state.effective_level() {
                Level::Manual | Level::Advisory => return Err(refused_by_level()),
                Level::Assisted if plan.operator_only => return Err(Refusal::OperatorOnly),
                _ => {}
            }
            Ok(Body::Action {
                request_id: Some(request.request_id.clone()),
                capability: capability.clone(),
                arguments: arguments.clone(),
            })
        }
    }
}

/// Run one planned action as `mira` itself with a fixed argument vector, the
/// collector key signing the document, stdout drained under one deadline.
fn execute(
    dir: &Path,
    collector_key: &Path,
    action_seq: u64,
    capability: &str,
    arguments: &str,
) -> Result<(Option<u64>, Outcome, Option<String>), Problem> {
    let plan = session_capability::plan(capability, arguments).ok_or(Problem::Io)?;
    let document = document_path(dir, action_seq);
    let mut signature_path = document.clone().into_os_string();
    signature_path.push(".sig");
    let exe = std::env::current_exe().map_err(|_| Problem::Io)?;
    let mut command = Command::new(exe);
    command
        .args(&plan.argv)
        .arg("--signature")
        .arg(&signature_path)
        .arg("--sign-with")
        .arg(collector_key);
    let (code, stdout) = match run_drained(
        &mut command,
        Stderr::Inherit,
        ACTION_TIMEOUT,
        MAX_DOCUMENT_BYTES,
    ) {
        Ok((status, stdout)) => (status.code(), stdout),
        Err(_) => (None, Vec::new()),
    };
    let outcome = Outcome::of(plan.family, code);
    let exit_status = code.and_then(|code| u64::try_from(code).ok());
    if !outcome.has_document() {
        return Ok((exit_status, outcome, None));
    }
    session::write_new(&document, &stdout).map_err(|_| Problem::Io)?;
    // The result commits to this document through the collector's signature.
    // The signature file is made group-readable whatever the umask.
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&signature_path, fs::Permissions::from_mode(0o640));
    let signature = signature::read_regular(Path::new(&signature_path), 4096)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|text| session::is_armored_signature(text))
        .ok_or(Problem::Io)?;
    Ok((exit_status, outcome, Some(signature)))
}

/// Why a request was dropped without any entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discard {
    /// Its ID already has an entry; it is never recorded twice.
    Replayed,
    /// No budget is left, or only the operator's reserve of entries.
    Unchargeable,
}

/// The broker's result for one inbox file.
#[derive(Debug, PartialEq, Eq)]
pub enum Handled {
    Admitted(Entry),
    Refused(Refusal),
    Discarded(Discard),
}

/// Check before any work that `collector.key` verifies as the header's
/// collector, so a misconfigured broker refuses to start instead of failing
/// midway through a request.
pub fn check_key(dir: &Path, collector: &Writer) -> Result<(), Problem> {
    let (_, state) = session::load(dir)?;
    if collector.principal != state.header.collector {
        return Err(Problem::Role(state.entries));
    }
    let probe = format!(
        "{{\"session_version\":{},\"session_id\":{},\"kind\":\"broker_probe\"}}\n",
        session::SESSION_VERSION,
        quoted(&state.session_id)
    );
    sign_record(&probe, collector, &dir.join(DOCUMENTS)).map(|_| ())
}

/// What the broker trusts across passes: the session directory it started on,
/// and the entries whose signatures it has verified. It acts only on a log
/// that extends that verified prefix byte for byte, so neither a replaced
/// directory nor an unsigned or rolled-back entry can change its decisions.
pub struct Guard {
    identity: (u64, u64),
    allowed: PathBuf,
    verified: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Guard {
    /// Pin the session directory and verify every entry it holds now. Under
    /// `separate_user`, refuse a path another user could replace.
    pub fn new(dir: &Path, allowed: &Path) -> Result<Self, Problem> {
        let (_, state) = session::load(dir)?;
        if state.header.separation == Separation::SeparateUser {
            check_path(dir)?;
        }
        let mut guard = Self {
            identity: identity(dir)?,
            allowed: allowed.to_path_buf(),
            verified: Vec::new(),
        };
        let (log, _) = session::load(dir)?;
        guard.check(dir, &log)?;
        Ok(guard)
    }

    /// Accept `log` only if it is the same directory and extends the verified
    /// prefix unchanged; verify any new entries' signatures and remember them.
    pub fn check(&mut self, dir: &Path, log: &session::Log) -> Result<(), Problem> {
        if identity(dir)? != self.identity || log.len() < self.verified.len() {
            return Err(Problem::Moved);
        }
        for (stored, (bytes, signature)) in log.iter().zip(&self.verified) {
            if stored.bytes != *bytes || stored.signature != *signature {
                return Err(Problem::Moved);
            }
        }
        for stored in &log[self.verified.len()..] {
            session::verify_signature(
                &stored.bytes,
                &stored.signature,
                &self.allowed,
                &stored.entry.principal,
                stored.entry.seq,
            )?;
            self.verified
                .push((stored.bytes.clone(), stored.signature.clone()));
        }
        Ok(())
    }
}

fn identity(dir: &Path) -> Result<(u64, u64), Problem> {
    let metadata = fs::symlink_metadata(dir).map_err(|_| Problem::Moved)?;
    if !metadata.is_dir() {
        return Err(Problem::Moved);
    }
    Ok((metadata.dev(), metadata.ino()))
}

/// Whether one ancestor is safe: unwritable by others, or sticky and owned by
/// the session's owner or root (a sticky directory's owner may still rename
/// any child) with the next component owned by the session's owner or root.
fn ancestor_ok(mode: u32, ancestor_uid: u32, child_uid: u32, owner: u32) -> bool {
    let trusted = |uid: u32| uid == owner || uid == 0;
    mode & 0o022 == 0 || (mode & 0o1000 != 0 && trusted(ancestor_uid) && trusted(child_uid))
}

/// Every ancestor of the session directory must pass [`ancestor_ok`], so
/// nobody else can rename the session away and put another in its place.
fn check_path(dir: &Path) -> Result<(), Problem> {
    let canonical = fs::canonicalize(dir).map_err(|_| Problem::Io)?;
    let owner = fs::metadata(&canonical).map_err(|_| Problem::Io)?.uid();
    let mut child = canonical.clone();
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = fs::metadata(ancestor).map_err(|_| Problem::Io)?;
        let child_owner = fs::symlink_metadata(&child).map_err(|_| Problem::Io)?.uid();
        if !ancestor_ok(metadata.mode(), metadata.uid(), child_owner, owner) {
            return Err(Problem::UnsafePath);
        }
        child = ancestor.to_path_buf();
    }
    Ok(())
}

/// Process every request currently in the inbox once, in name order.
pub fn run_once(
    dir: &Path,
    collector: &Writer,
    guard: &mut Guard,
) -> Result<Vec<Handled>, Problem> {
    let (log, state) = session::load(dir)?;
    guard.check(dir, &log)?;
    if state.closed {
        return Err(Problem::Closed);
    }
    if collector.principal != state.header.collector {
        return Err(Problem::Role(state.entries));
    }
    // Stream the agent-writable inbox with hard caps, and purge anything that
    // is not a request so it cannot accumulate or fill the filesystem.
    let mut names = Vec::new();
    for item in fs::read_dir(inbox(dir))
        .map_err(|_| Problem::Io)?
        .take(MAX_SCAN)
    {
        let Ok(item) = item else { continue };
        let path = item.path();
        let name = item.file_name();
        let name = name.to_str().unwrap_or_default();
        if name
            .strip_suffix(".request")
            .is_some_and(session::is_session_id)
        {
            if names.len() < MAX_PER_PASS {
                names.push(name.to_owned());
            }
            continue;
        }
        let fresh_pending = name.starts_with(".pending-")
            && fs::symlink_metadata(&path)
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age < PENDING_GRACE);
        if !fresh_pending {
            purge(&path);
        }
    }
    names.sort();
    let guard = std::cell::RefCell::new(guard);
    let mut handled = Vec::new();
    for name in names {
        handled.push(handle(dir, collector, &state, &name, &guard)?);
    }
    Ok(handled)
}

/// Remove an inbox object the agent left: a file or link, or an empty
/// directory. A non-empty directory is left; its contents are the agent's
/// to manage, under the quota its account should have.
fn purge(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            let _ = fs::remove_dir(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}

fn handle(
    dir: &Path,
    collector: &Writer,
    start: &State,
    name: &str,
    guard: &std::cell::RefCell<&mut Guard>,
) -> Result<Handled, Problem> {
    let checked = |log: &session::Log| guard.borrow_mut().check(dir, log);
    let path = inbox(dir).join(name);
    let request_id = name.trim_end_matches(".request").to_owned();
    let remove = || purge(&path);
    if start.requests.contains(&request_id) {
        remove();
        return Ok(Handled::Discarded(Discard::Replayed));
    }
    // Every agent-attributable entry costs budget and stays outside the
    // operator's reserve; past that, requests are dropped unrecorded.
    if !session::chargeable(start, start.entries) {
        remove();
        return Ok(Handled::Discarded(Discard::Unchargeable));
    }
    let refuse = |reason: Refusal| -> Result<Handled, Problem> {
        let appended = session::append_checked(dir, collector, &mut |log| checked(log), |state| {
            if !session::chargeable(state, state.entries) {
                return Err(Problem::Unchargeable);
            }
            Ok((
                Body::Refusal {
                    request_id: request_id.clone(),
                    reason,
                },
                Some(state.entries - 1),
                String::new(),
            ))
        });
        remove();
        match appended {
            Ok(_) => Ok(Handled::Refused(reason)),
            Err(Problem::Unchargeable) => Ok(Handled::Discarded(Discard::Unchargeable)),
            Err(problem) => Err(problem),
        }
    };
    // Under separate_user an inbox file owned by the broker's own account was
    // not written by the agent's user, so it is refused before it is read.
    if start.header.separation == Separation::SeparateUser {
        let own = fs::metadata(dir.join("entries"))
            .map_err(|_| Problem::Io)?
            .uid();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && metadata.uid() != own => {}
            _ => return refuse(Refusal::Owner),
        }
    }
    let Ok(record) = signature::read_regular(&path, session::MAX_RECORD_BYTES) else {
        return refuse(Refusal::Malformed);
    };
    let Some((bytes, signature)) = session::split_record(&record) else {
        return refuse(Refusal::Malformed);
    };
    let Some(request) = Request::parse(bytes) else {
        return refuse(Refusal::Malformed);
    };
    if request.request_id != request_id || request.principal != start.header.agent {
        return refuse(Refusal::Malformed);
    }
    match session::verify_signature(
        bytes,
        signature,
        collector.allowed_signers,
        &start.header.agent,
        0,
    ) {
        Ok(()) => {}
        Err(Problem::Tool) => return Err(Problem::Tool),
        Err(_) => return refuse(Refusal::Signature),
    }
    // Keep the agent's exact signed record where the agent cannot change it.
    // A stored copy without a log entry is a request a previous broker stored
    // but never recorded, for example after an interruption: resume it.
    match session::write_new(&stored_request(dir, &request_id), &record) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let (_, current) = session::load(dir)?;
            if current.requests.contains(&request_id) {
                remove();
                return Ok(Handled::Discarded(Discard::Replayed));
            }
            let stored = signature::read_regular(
                &stored_request(dir, &request_id),
                session::MAX_RECORD_BYTES,
            )
            .map_err(|_| Problem::Io)?;
            if stored != record {
                return refuse(Refusal::Malformed);
            }
        }
        Err(_) => return Err(Problem::Io),
    }
    // Decide against the state current at append time, so a directive that
    // lands meanwhile takes precedence.
    let appended = session::append_checked(dir, collector, &mut |log| checked(log), |state| {
        // Recorded meanwhile by another broker pass: never record it twice.
        if state.requests.contains(&request_id) {
            return Err(Problem::Replayed);
        }
        if !session::chargeable(state, state.entries) {
            return Err(Problem::Unchargeable);
        }
        let body = decide(state, &request).unwrap_or_else(|reason| Body::Refusal {
            request_id: request_id.clone(),
            reason,
        });
        let note = match body {
            Body::Refusal { .. } => String::new(),
            _ => request.note.clone(),
        };
        let based_on = match body {
            Body::Refusal { .. } => Some(state.entries - 1),
            _ => Some(request.based_on),
        };
        Ok((body, based_on, note))
    });
    let entry = match appended {
        Ok(entry) => entry,
        Err(Problem::Replayed) => {
            remove();
            return Ok(Handled::Discarded(Discard::Replayed));
        }
        Err(Problem::Unchargeable) => {
            remove();
            return Ok(Handled::Discarded(Discard::Unchargeable));
        }
        Err(problem) => {
            // Not recorded: drop the stored copy so the inbox request is
            // retried, rather than discarded later as a replay.
            let _ = fs::remove_file(stored_request(dir, &request_id));
            return Err(problem);
        }
    };
    remove();
    match &entry.body {
        Body::Refusal { reason, .. } => Ok(Handled::Refused(*reason)),
        Body::Action {
            capability,
            arguments,
            ..
        } => {
            record_result(
                dir,
                collector,
                entry.seq,
                capability,
                arguments,
                &mut |log| checked(log),
            )?;
            Ok(Handled::Admitted(entry))
        }
        _ => Ok(Handled::Admitted(entry)),
    }
}

fn record_result(
    dir: &Path,
    collector: &Writer,
    action_seq: u64,
    capability: &str,
    arguments: &str,
    check: &mut dyn FnMut(&session::Log) -> Result<(), Problem>,
) -> Result<Option<Entry>, Problem> {
    let (exit_status, outcome, document_signature) =
        execute(dir, collector.key, action_seq, capability, arguments)?;
    let appended = session::append_checked(dir, collector, check, |state| {
        // Abandoned by the operator while it ran: there is nothing to record.
        if !state.pending.contains_key(&action_seq) {
            return Err(Problem::Abandoned);
        }
        Ok((
            Body::Result {
                action_seq,
                exit_status,
                outcome,
                document_signature: document_signature.clone(),
            },
            Some(state.entries - 1),
            String::new(),
        ))
    });
    match appended {
        Ok(entry) => Ok(Some(entry)),
        // Closing requires every action to be finished or abandoned first.
        Err(Problem::Abandoned | Problem::Closed) => Ok(None),
        Err(problem) => Err(problem),
    }
}

/// The operator's own action: recorded by the operator, run immediately, its
/// result signed by the collector. No budget applies.
pub fn act(
    dir: &Path,
    operator: &Writer,
    collector: &Writer,
    capability: &str,
    arguments: &str,
    note: String,
) -> Result<(Entry, Option<Entry>), Problem> {
    if session_capability::plan(capability, arguments).is_none() {
        return Err(Problem::InvalidDirective);
    }
    let action = session::append(dir, operator, |state| {
        Ok((
            Body::Action {
                request_id: None,
                capability: capability.to_owned(),
                arguments: arguments.to_owned(),
            },
            Some(state.entries - 1),
            note.clone(),
        ))
    })?;
    let result = record_result(
        dir,
        collector,
        action.seq,
        capability,
        arguments,
        &mut |_| Ok(()),
    )?;
    Ok((action, result))
}

/// `session::verify`, plus every relayed request and every result document:
/// a relayed entry must match the agent's stored, agent-signed request field
/// for field, and a result's document must verify as the collector's.
pub fn verify(
    dir: &Path,
    allowed: &Path,
    operator: &str,
    receipt: Option<&Path>,
) -> Result<State, Problem> {
    let (log, state) = session::verify(dir, allowed, operator, receipt)?;
    verify_relays(dir, &log, &state, allowed)?;
    Ok(state)
}

/// Check relayed requests and result documents for an already authenticated
/// log. It never re-reads the entries: a snapshot taken after their
/// signatures were checked could have been replaced in between.
pub fn verify_relays(
    dir: &Path,
    log: &session::Log,
    state: &State,
    allowed: &Path,
) -> Result<(), Problem> {
    let mut actions = std::collections::BTreeMap::new();
    for stored in log {
        let entry = &stored.entry;
        let relayed = match &entry.body {
            Body::Question {
                request_id: Some(id),
            } => Some((id, Ask::Question)),
            Body::Action {
                request_id,
                capability,
                arguments,
            } => {
                actions.insert(entry.seq, (capability.clone(), arguments.clone()));
                request_id.as_ref().map(|id| {
                    (
                        id,
                        Ask::Action {
                            capability: capability.clone(),
                            arguments: arguments.clone(),
                        },
                    )
                })
            }
            _ => None,
        };
        if let Some((id, ask)) = relayed {
            let record =
                signature::read_regular(&stored_request(dir, id), session::MAX_RECORD_BYTES)
                    .map_err(|_| Problem::Request(entry.seq))?;
            let (bytes, signature) =
                session::split_record(&record).ok_or(Problem::Request(entry.seq))?;
            let request = Request::parse(bytes).ok_or(Problem::Request(entry.seq))?;
            session::verify_signature(bytes, signature, allowed, &state.header.agent, entry.seq)
                .map_err(|problem| match problem {
                    Problem::Tool => Problem::Tool,
                    _ => Problem::Request(entry.seq),
                })?;
            let matches = request.session_id == state.session_id
                && request.request_id == *id
                && request.principal == state.header.agent
                && Some(request.based_on) == entry.based_on
                && request.ask == ask
                && request.note == entry.note;
            if !matches {
                return Err(Problem::Request(entry.seq));
            }
        }
        if let Body::Result {
            action_seq,
            document_signature: Some(committed),
            ..
        } = &entry.body
        {
            let (capability, arguments) = actions
                .get(action_seq)
                .ok_or(Problem::Document(entry.seq))?;
            let family = session_capability::plan(capability, arguments)
                .ok_or(Problem::Document(entry.seq))?
                .family;
            let expected = match family {
                Family::Capture => Kind::Capture,
                Family::Investigation => Kind::Investigation,
            };
            let path = document_path(dir, *action_seq);
            let document =
                signature::read_document(&path).map_err(|_| Problem::Document(entry.seq))?;
            // The signature file must be the one the collector-signed result
            // commits to, and that signature must cover these exact bytes.
            let mut signature_path = path.into_os_string();
            signature_path.push(".sig");
            let on_disk = signature::read_regular(Path::new(&signature_path), 4096)
                .map_err(|_| Problem::Document(entry.seq))?;
            if on_disk != committed.as_bytes() {
                return Err(Problem::Document(entry.seq));
            }
            let trust = Trust {
                allowed_signers: allowed,
                principal: &state.header.collector,
                revocations: None,
            };
            match signature::verify_staged(&document, committed.as_bytes(), &trust) {
                Ok(kind) if kind == expected => {}
                Err(signature::Failure::Tool) => return Err(Problem::Tool),
                _ => return Err(Problem::Document(entry.seq)),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            session_id: "ab".repeat(32),
            request_id: "cd".repeat(32),
            principal: "agent".to_owned(),
            based_on: 3,
            ask: Ask::Action {
                capability: "memory-headroom".to_owned(),
                arguments: "1024".to_owned(),
            },
            note: "check \"headroom\" \\ first".to_owned(),
        }
    }

    #[test]
    fn requests_round_trip_and_refuse_anything_else() {
        let action = request();
        let question = Request {
            ask: Ask::Question,
            ..request()
        };
        for item in [&action, &question] {
            let text = item.render();
            assert!(text.contains("\"kind\":\"request\""));
            assert_eq!(
                Request::parse(text.as_bytes()).as_ref(),
                Some(item),
                "{text}"
            );
        }
        let text = action.render();
        for bad in [
            text.replacen("\"kind\":\"request\"", "\"kind\":\"action\"", 1),
            text.replacen("\"request\":\"action\"", "\"request\":\"close\"", 1),
            text.replacen("\"based_on\":3", "\"based_on\":03", 1),
            text.replacen(",", ", ", 1),
            text.trim_end().to_owned(),
            text.replacen("\"note\":\"", "\"note\":\"\\u001b", 1),
            text.replacen(&"cd".repeat(32), "short", 1),
            text.replacen("\"principal\":\"agent\"", "\"principal\":\"-agent\"", 1),
            text.replacen("\"capability\":", "\"extra\":1,\"capability\":", 1),
        ] {
            assert_eq!(Request::parse(bad.as_bytes()), None, "{bad:?}");
        }
        // A request is never an admissible log entry.
        assert_eq!(session::Entry::parse(text.as_bytes()), None);
    }

    fn state(level: Level, budget: u64) -> State {
        let header = session::Header {
            operator: "operator".to_owned(),
            agent: "agent".to_owned(),
            collector: "collector".to_owned(),
            separation: Separation::SameUser,
            autonomy: Level::Assisted,
            budget,
        };
        State {
            session_id: "ab".repeat(32),
            header,
            entries: 5,
            level,
            budget,
            delegated_until: None,
            closed: false,
            last_directive: None,
            pending: Default::default(),
            requests: Default::default(),
        }
    }

    #[test]
    fn decisions_follow_level_budget_capability_and_precedence() {
        let admit = |state: &State, request: &Request| decide(state, request).is_ok();
        assert!(admit(&state(Level::Assisted, 1), &request()));
        assert_eq!(
            decide(&state(Level::Advisory, 1), &request()),
            Err(Refusal::Autonomy)
        );
        assert_eq!(
            decide(&state(Level::Manual, 1), &request()),
            Err(Refusal::Autonomy)
        );
        let mut stopped = state(Level::Manual, 1);
        stopped.last_directive = Some(4);
        assert_eq!(
            decide(&stopped, &request()),
            Err(Refusal::SupersededByDirective)
        );
        let bind = Request {
            ask: Ask::Action {
                capability: "capture".to_owned(),
                arguments: "host bind-boot".to_owned(),
            },
            ..request()
        };
        assert_eq!(
            decide(&state(Level::Assisted, 1), &bind),
            Err(Refusal::OperatorOnly)
        );
        assert!(admit(&state(Level::Delegated, 1), &bind));
        let shell = Request {
            ask: Ask::Action {
                capability: "inspect".to_owned(),
                arguments: String::new(),
            },
            ..request()
        };
        assert_eq!(
            decide(&state(Level::Delegated, 9), &shell),
            Err(Refusal::Capability)
        );
        let future = Request {
            based_on: 5,
            ..request()
        };
        assert_eq!(
            decide(&state(Level::Assisted, 1), &future),
            Err(Refusal::Stale)
        );
        let foreign = Request {
            session_id: "ef".repeat(32),
            ..request()
        };
        assert_eq!(
            decide(&state(Level::Assisted, 1), &foreign),
            Err(Refusal::SessionMismatch)
        );
        let mut seen = state(Level::Assisted, 1);
        seen.requests.insert("cd".repeat(32));
        assert_eq!(decide(&seen, &request()), Err(Refusal::Replayed));
        let question = Request {
            ask: Ask::Question,
            ..request()
        };
        assert!(admit(&state(Level::Advisory, 0), &question));
        assert_eq!(
            decide(&state(Level::Manual, 0), &question),
            Err(Refusal::Autonomy)
        );
    }

    #[test]
    fn decisions_use_the_level_of_the_entry_being_written() {
        // Delegation covers entries up to 4; the next entry would be 5.
        let mut lapsing = state(Level::Delegated, 1);
        lapsing.delegated_until = Some(4);
        let bind = Request {
            ask: Ask::Action {
                capability: "capture".to_owned(),
                arguments: "host bind-boot".to_owned(),
            },
            ..request()
        };
        assert_eq!(decide(&lapsing, &bind), Err(Refusal::OperatorOnly));
        assert!(decide(&lapsing, &request()).is_ok());
        lapsing.delegated_until = Some(5);
        assert!(decide(&lapsing, &bind).is_ok());
    }

    #[test]
    fn ancestors_must_not_let_another_user_rename_the_session() {
        let (owner, other) = (1000, 1001);
        // Not writable by others: always safe.
        assert!(ancestor_ok(0o40755, other, other, owner));
        // Writable by others without the sticky bit: never safe.
        assert!(!ancestor_ok(0o40777, owner, owner, owner));
        assert!(!ancestor_ok(0o40775, 0, owner, owner));
        // Sticky and owned by the operator or root, with the next component theirs.
        assert!(ancestor_ok(0o41777, 0, owner, owner));
        assert!(ancestor_ok(0o41777, owner, owner, owner));
        assert!(ancestor_ok(0o41777, 0, 0, owner));
        // A sticky directory owned by another user can rename any child.
        assert!(!ancestor_ok(0o41777, other, owner, owner));
        // A next component owned by another user can be renamed by them.
        assert!(!ancestor_ok(0o41777, 0, other, owner));
    }
}
