//! `mira session` subcommands (ADR 0015 stage 1). Exit codes: 0 done
//! or verified, 1 refused by the session state or not verified, 2 usage, 4
//! tool, signing or I/O failure.
use mira::session::{
    self, Body, Claim, Confidence, Directive, Header, Level, Open, Problem, Separation, Verdict,
    Writer,
};
use mira::session_broker::{self, Ask, Handled};
use std::{collections::BTreeMap, path::Path};

pub const USAGE: &str = "mira session start DIR --allowed-signers FILE --key KEY --operator NAME --agent NAME --collector NAME [--separation same_user | --separation separate_user --agent-group GROUP] [--autonomy manual|advisory|assisted] [--budget N] --question TEXT | mira session run DIR --allowed-signers FILE --key COLLECTOR-KEY [--once] | mira session act DIR --allowed-signers FILE --key KEY --collector-key COLLECTOR-KEY --capability NAME [--arguments TOKENS] [--text TEXT] | mira session request DIR --allowed-signers FILE --key AGENT-KEY ([--propose] --capability NAME [--arguments TOKENS] | --question | --claim CLAIM [--confidence low|medium|high] [--cites SEQ,...]) --text TEXT | mira session find DIR --allowed-signers FILE --key KEY --claim CLAIM [--confidence low|medium|high] [--cites SEQ,...] --text TEXT | mira session decide DIR --allowed-signers FILE --key KEY --target SEQ (--approve [--despite-stale] --collector-key COLLECTOR-KEY | --reject | --accept | --uncertain) [--text TEXT] | mira session ask DIR --allowed-signers FILE --key KEY --text TEXT | mira session direct DIR --allowed-signers FILE --key KEY (--stop | --level manual|advisory|assisted | --budget N | --delegate-until SEQ) [--text TEXT] | mira session close DIR --allowed-signers FILE --key KEY --conclusion TEXT [--receipt PATH] [--abandon-pending] | mira session show DIR [--json] | mira session verify DIR --allowed-signers FILE --operator NAME [--expect-close PATH]";

fn usage() -> ! {
    eprintln!("Usage: {USAGE}");
    std::process::exit(2);
}

fn fail(message: &str, code: i32) -> ! {
    eprintln!("MIRA: {message}");
    std::process::exit(code);
}

/// Options are `--name VALUE` or bare `--name` flags, each at most once, in
/// any order; anything unknown or repeated is a usage error.
struct Options(BTreeMap<String, Option<String>>);

impl Options {
    fn parse(args: &[String], valued: &[&str], flags: &[&str]) -> Self {
        let mut map = BTreeMap::new();
        let mut rest = args.iter();
        while let Some(name) = rest.next() {
            let value = if valued.contains(&name.as_str()) {
                match rest.next() {
                    Some(value) if !value.starts_with("--") => Some(value.clone()),
                    _ => usage(),
                }
            } else if flags.contains(&name.as_str()) {
                None
            } else {
                usage()
            };
            if map.insert(name.clone(), value).is_some() {
                usage();
            }
        }
        Self(map)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(|value| value.as_deref())
    }

    fn required(&self, name: &str) -> &str {
        self.get(name).unwrap_or_else(|| usage())
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

fn text(value: &str) -> String {
    if session::validate_text(value).is_err() {
        fail(
            "text must be at most 1 KiB without control or bidirectional characters",
            2,
        );
    }
    value.to_owned()
}

fn principal(value: &str) -> String {
    if mira::signature::validate_principal(value).is_err() {
        fail(
            "principal must be 1-128 characters from A-Za-z0-9._@+- starting alphanumeric",
            2,
        );
    }
    value.to_owned()
}

fn find(dir: &Path, rest: &[String]) {
    let options = Options::parse(
        rest,
        &[
            "--allowed-signers",
            "--key",
            "--claim",
            "--confidence",
            "--cites",
            "--text",
        ],
        &[],
    );
    let (claim, confidence, cites) = claim(&options);
    let note = text(options.required("--text"));
    let entry = as_operator(dir, &options, |state| {
        if !session::supports(state, claim, confidence, &cites) {
            return Err(Problem::Unsupported);
        }
        Ok((
            Body::Finding {
                request_id: None,
                claim,
                confidence,
                cites: cites.clone(),
            },
            Some(state.entries - 1),
            note.clone(),
        ))
    });
    println!("MIRA session: finding {:06}", entry.seq);
}

/// Decide on an open proposal or agent finding. Approving a proposal runs
/// its action at once as the operator's own, with the collector key.
fn decide(dir: &Path, rest: &[String]) {
    let dir = &canonical(dir);
    let options = Options::parse(
        rest,
        &[
            "--allowed-signers",
            "--key",
            "--target",
            "--collector-key",
            "--text",
        ],
        &[
            "--approve",
            "--despite-stale",
            "--reject",
            "--accept",
            "--uncertain",
        ],
    );
    let chosen: Vec<_> = ["--approve", "--reject", "--accept", "--uncertain"]
        .into_iter()
        .filter(|name| options.has(name))
        .collect();
    let approve = chosen == ["--approve"];
    if chosen.len() != 1
        || (options.has("--despite-stale") && !approve)
        || options.has("--collector-key") != approve
    {
        usage();
    }
    let verdict = match chosen[0] {
        "--approve" if options.has("--despite-stale") => Verdict::ApproveDespiteStale,
        "--approve" => Verdict::Approve,
        "--reject" => Verdict::Reject,
        "--accept" => Verdict::Accept,
        _ => Verdict::Uncertain,
    };
    let target = decimal(options.required("--target"));
    let note = options.get("--text").map(text).unwrap_or_default();
    let state = session::load(dir)
        .map(|(_, state)| state)
        .unwrap_or_else(|problem| write_failure(problem));
    let allowed = Path::new(options.required("--allowed-signers"));
    let operator = Writer {
        allowed_signers: allowed,
        key: Path::new(options.required("--key")),
        principal: &state.header.operator,
    };
    let collector_key = options.get("--collector-key").map(Path::new);
    let collector = collector_key.map(|key| Writer {
        allowed_signers: allowed,
        key,
        principal: &state.header.collector,
    });
    // An approval must be able to run its action: a wrong collector key
    // fails before the decision is written.
    if let Some(collector) = &collector
        && let Err(problem) = session_broker::check_key(dir, collector)
    {
        write_failure(problem);
    }
    let build = |state: &session::State| {
        let fits = match state.open.get(&target) {
            None => return Err(Problem::NotOpen),
            Some(Open::Proposal {
                capability,
                arguments,
                based_on,
            }) => match verdict {
                Verdict::Approve if session::stale(state, capability, arguments, *based_on) => {
                    return Err(Problem::Stale);
                }
                Verdict::Approve | Verdict::ApproveDespiteStale | Verdict::Reject => true,
                _ => false,
            },
            Some(Open::Finding) => {
                !matches!(verdict, Verdict::Approve | Verdict::ApproveDespiteStale)
            }
        };
        if !fits {
            return Err(Problem::InvalidDirective);
        }
        Ok((
            Body::Decision {
                target_seq: target,
                verdict,
            },
            Some(state.entries - 1),
            note.clone(),
        ))
    };
    let decision =
        session::append(dir, &operator, build).unwrap_or_else(|problem| write_failure(problem));
    println!(
        "MIRA session: decision {:06} {} {target:06}",
        decision.seq,
        verdict.as_str()
    );
    let Some(collector) = collector else { return };
    // The approved action is the proposal's, read from the log the decision
    // was appended to.
    let (log, _) = session::load(dir).unwrap_or_else(|problem| write_failure(problem));
    let Some(Body::Proposal {
        capability,
        arguments,
        ..
    }) = log.get(target as usize).map(|stored| &stored.entry.body)
    else {
        write_failure(Problem::NotOpen)
    };
    match session_broker::act(
        dir,
        &operator,
        &collector,
        capability,
        arguments,
        format!("approved proposal {target:06}"),
    ) {
        Ok((action, result)) => report_action(&action, result.as_ref()),
        Err(problem) => write_failure(problem),
    }
}

fn report_action(action: &session::Entry, result: Option<&session::Entry>) {
    match result {
        Some(result) => {
            let outcome = match &result.body {
                Body::Result { outcome, .. } => outcome.as_str(),
                _ => "unknown",
            };
            println!(
                "MIRA session: action {:06} result {:06} {outcome}",
                action.seq, result.seq
            );
        }
        None => println!(
            "MIRA session: action {:06} abandoned before its result",
            action.seq
        ),
    }
}

fn decimal(value: &str) -> u64 {
    mira::challenge::parse_decimal(value.as_bytes())
        .unwrap_or_else(|| fail("numbers must be decimal integers of at most 16 digits", 2))
}

/// Map a write-side problem to its fixed diagnostic and exit status.
fn write_failure(problem: Problem) -> ! {
    match problem {
        Problem::Closed
        | Problem::InvalidDirective
        | Problem::Full
        | Problem::Text
        | Problem::Pending
        | Problem::Unsupported
        | Problem::Stale
        | Problem::NotOpen => {
            println!("MIRA session: refused ({})", problem.reason());
            std::process::exit(1)
        }
        Problem::Signature(_) => fail(
            "signing failed, or the key is not listed for this principal in allowed_signers; nothing written",
            4,
        ),
        Problem::Tool => fail("ssh-keygen unavailable; nothing written", 4),
        Problem::Io | Problem::Receipt => fail("session directory or receipt path unwritable", 4),
        other => {
            println!(
                "MIRA session: refused (session invalid: {})",
                other.reason()
            );
            std::process::exit(1)
        }
    }
}

pub fn run(args: &[String]) {
    let [sub, dir, rest @ ..] = args else { usage() };
    let dir = Path::new(dir);
    match sub.as_str() {
        "start" => start(dir, rest),
        "ask" => ask(dir, rest),
        "find" => find(dir, rest),
        "decide" => decide(dir, rest),
        "direct" => direct(dir, rest),
        "close" => close(dir, rest),
        "request" => request(dir, rest),
        "run" => run_broker(dir, rest),
        "act" => act(dir, rest),
        "show" => show(dir, rest),
        "verify" => verify(dir, rest),
        _ => usage(),
    }
}

fn start(dir: &Path, rest: &[String]) {
    let options = Options::parse(
        rest,
        &[
            "--allowed-signers",
            "--key",
            "--operator",
            "--agent",
            "--collector",
            "--autonomy",
            "--budget",
            "--question",
            "--separation",
            "--agent-group",
        ],
        &[],
    );
    let operator = principal(options.required("--operator"));
    let (separation, group) = match (options.get("--separation"), options.get("--agent-group")) {
        (None | Some("same_user"), None) => (Separation::SameUser, None),
        (Some("separate_user"), Some(name)) => (
            Separation::SeparateUser,
            Some(
                session::group_id(name)
                    .unwrap_or_else(|| fail("agent group not found in /etc/group", 2)),
            ),
        ),
        _ => fail(
            "--separation separate_user requires --agent-group GROUP, and only it",
            2,
        ),
    };
    let header = Header {
        operator: operator.clone(),
        agent: principal(options.required("--agent")),
        collector: principal(options.required("--collector")),
        separation,
        autonomy: options.get("--autonomy").map_or(Level::Assisted, |level| {
            Level::settable(level)
                .unwrap_or_else(|| fail("autonomy must be manual, advisory or assisted", 2))
        }),
        budget: options.get("--budget").map_or(10, decimal),
    };
    if [&header.agent, &header.collector].contains(&&header.operator)
        || header.agent == header.collector
    {
        fail(
            "operator, agent and collector must be three distinct principals",
            2,
        );
    }
    let question = text(options.required("--question"));
    let writer = Writer {
        allowed_signers: Path::new(options.required("--allowed-signers")),
        key: Path::new(options.required("--key")),
        principal: &operator,
    };
    match session::start(dir, &writer, header, question, group) {
        Ok(_) => println!("MIRA session: started at {}", dir.display()),
        Err(Problem::Io) => fail("session directory exists or cannot be created", 4),
        Err(problem) => write_failure(problem),
    }
}

/// Load the state to learn the operator's name, then append as that operator.
fn as_operator(
    dir: &Path,
    options: &Options,
    build: impl Fn(&session::State) -> Result<(Body, Option<u64>, String), Problem>,
) -> session::Entry {
    let state = session::load(dir)
        .map(|(_, state)| state)
        .unwrap_or_else(|problem| write_failure(problem));
    let writer = Writer {
        allowed_signers: Path::new(options.required("--allowed-signers")),
        key: Path::new(options.required("--key")),
        principal: &state.header.operator,
    };
    session::append(dir, &writer, build).unwrap_or_else(|problem| write_failure(problem))
}

fn ask(dir: &Path, rest: &[String]) {
    let options = Options::parse(rest, &["--allowed-signers", "--key", "--text"], &[]);
    let note = text(options.required("--text"));
    let entry = as_operator(dir, &options, |state| {
        Ok((
            Body::Question { request_id: None },
            Some(state.entries - 1),
            note.clone(),
        ))
    });
    println!("MIRA session: question {:06}", entry.seq);
}

fn direct(dir: &Path, rest: &[String]) {
    let options = Options::parse(
        rest,
        &[
            "--allowed-signers",
            "--key",
            "--level",
            "--budget",
            "--delegate-until",
            "--text",
        ],
        &["--stop"],
    );
    let chosen: Vec<_> = ["--stop", "--level", "--budget", "--delegate-until"]
        .into_iter()
        .filter(|name| options.has(name))
        .collect();
    let directive = match chosen.as_slice() {
        ["--stop"] => Directive::Stop,
        ["--level"] => Directive::SetLevel(
            Level::settable(options.required("--level")).unwrap_or_else(|| {
                fail(
                    "level must be manual, advisory or assisted; use --delegate-until to delegate",
                    2,
                )
            }),
        ),
        ["--budget"] => Directive::SetBudget(decimal(options.required("--budget"))),
        ["--delegate-until"] => {
            Directive::DelegateUntil(decimal(options.required("--delegate-until")))
        }
        _ => usage(),
    };
    let note = options.get("--text").map(text).unwrap_or_default();
    let entry = as_operator(dir, &options, |state| {
        Ok((
            Body::Directive(directive.clone()),
            Some(state.entries - 1),
            note.clone(),
        ))
    });
    println!("MIRA session: directive {:06}", entry.seq);
}

fn close(dir: &Path, rest: &[String]) {
    let options = Options::parse(
        rest,
        &["--allowed-signers", "--key", "--conclusion", "--receipt"],
        &["--abandon-pending"],
    );
    let note = text(options.required("--conclusion"));
    // Refuse an existing receipt path before closing, so the close never
    // succeeds without the receipt that was asked for.
    if let Some(receipt) = options.get("--receipt") {
        if Path::new(receipt).symlink_metadata().is_ok() {
            fail("receipt path exists; nothing written", 2);
        }
        if !session::receipt_outside(dir, Path::new(receipt)) {
            fail(
                "receipt must be in an existing directory outside the session; nothing written",
                2,
            );
        }
    }
    // Close needs every action finished or explicitly abandoned, so no result
    // can arrive after the immutable close entry.
    let (_, state) = session::load(dir).unwrap_or_else(|problem| write_failure(problem));
    if !state.pending.is_empty() {
        if !options.has("--abandon-pending") {
            write_failure(Problem::Pending);
        }
        for action_seq in state.pending.keys().copied().collect::<Vec<_>>() {
            let entry = as_operator(dir, &options, |state| {
                Ok((
                    Body::Abandon { action_seq },
                    Some(state.entries - 1),
                    String::new(),
                ))
            });
            println!(
                "MIRA session: abandoned {action_seq:06} at {:06}",
                entry.seq
            );
        }
    }
    let entry = as_operator(dir, &options, |state| {
        Ok((
            Body::Close {
                entry_count: state.entries + 1,
            },
            Some(state.entries - 1),
            note.clone(),
        ))
    });
    if let Some(receipt) = options.get("--receipt")
        && session::write_receipt(dir, &entry, Path::new(receipt)).is_err()
    {
        fail("session closed, but the receipt could not be written", 4);
    }
    println!("MIRA session: closed at {:06}", entry.seq);
}

fn show(dir: &Path, rest: &[String]) {
    let options = Options::parse(rest, &[], &["--json"]);
    let (entries, state) = session::load(dir).unwrap_or_else(|problem| {
        println!("MIRA session: invalid ({})", problem.reason());
        std::process::exit(1)
    });
    if options.has("--json") {
        println!("{}", session::state_json(&state));
    } else {
        print!("{}", session::render_timeline(&entries, &state));
        println!("signatures not checked here; run mira session verify");
    }
}

fn verify(dir: &Path, rest: &[String]) {
    let options = Options::parse(
        rest,
        &["--allowed-signers", "--operator", "--expect-close"],
        &[],
    );
    let allowed = Path::new(options.required("--allowed-signers"));
    let operator = principal(options.required("--operator"));
    match session_broker::verify(
        dir,
        allowed,
        &operator,
        options.get("--expect-close").map(Path::new),
    ) {
        Ok(state) => println!(
            "MIRA session: verified entries {} {}",
            state.entries,
            if state.closed { "closed" } else { "open" }
        ),
        Err(Problem::Tool) => fail("ssh-keygen unavailable; nothing verified", 4),
        Err(problem) => {
            println!("MIRA session: not verified ({})", problem.reason());
            std::process::exit(1)
        }
    }
}

fn capability(options: &Options) -> (String, String) {
    let capability = options.required("--capability").to_owned();
    let arguments = options.get("--arguments").unwrap_or_default().to_owned();
    if mira::session_capability::plan(&capability, &arguments).is_none() {
        fail(
            "capability or arguments outside the closed set; see mira session documentation",
            2,
        );
    }
    (capability, arguments)
}

/// A claim with its labels and citations, from `--claim`, `--confidence`
/// and `--cites`.
fn claim(options: &Options) -> (Claim, Option<Confidence>, Vec<u64>) {
    let claim = Claim::parse(options.required("--claim")).unwrap_or_else(|| {
        fail(
            "claim must be expectation_satisfied, expectation_not_satisfied, expectation_indeterminate, evidence_unavailable, hypothesis or no_finding",
            2,
        )
    });
    let confidence = options.get("--confidence").map(|value| {
        Confidence::parse(value)
            .unwrap_or_else(|| fail("confidence must be low, medium or high", 2))
    });
    let cites =
        session::parse_cites(options.get("--cites").unwrap_or_default()).unwrap_or_else(|| {
            fail(
                "cites must be at most 16 ascending entry numbers separated by commas",
                2,
            )
        });
    (claim, confidence, cites)
}

fn request(dir: &Path, rest: &[String]) {
    let options = Options::parse(
        rest,
        &[
            "--allowed-signers",
            "--key",
            "--capability",
            "--arguments",
            "--claim",
            "--confidence",
            "--cites",
            "--text",
        ],
        &["--question", "--propose"],
    );
    let finding_options = ["--claim", "--confidence", "--cites"]
        .iter()
        .any(|name| options.has(name));
    let ask = match (
        options.has("--question"),
        options.has("--capability"),
        options.has("--claim"),
    ) {
        (true, false, false) if !options.has("--arguments") && !finding_options => Ask::Question,
        (false, true, false) if !finding_options => {
            let (capability, arguments) = capability(&options);
            if options.has("--propose") {
                Ask::Proposal {
                    capability,
                    arguments,
                }
            } else {
                Ask::Action {
                    capability,
                    arguments,
                }
            }
        }
        (false, false, true) if !options.has("--arguments") => {
            let (claim, confidence, cites) = claim(&options);
            Ask::Finding {
                claim,
                confidence,
                cites,
            }
        }
        _ => usage(),
    };
    if options.has("--propose") && !matches!(ask, Ask::Proposal { .. }) {
        usage();
    }
    let note = text(options.required("--text"));
    let state = session::load(dir)
        .map(|(_, state)| state)
        .unwrap_or_else(|problem| write_failure(problem));
    let writer = Writer {
        allowed_signers: Path::new(options.required("--allowed-signers")),
        key: Path::new(options.required("--key")),
        principal: &state.header.agent,
    };
    match session_broker::submit(dir, &writer, ask, note) {
        Ok(_) => println!("MIRA session: request submitted"),
        Err(problem) => write_failure(problem),
    }
}

/// Resolve the session path once; every later operation uses this canonical
/// path, so a symbolic link switched mid-run cannot redirect anything.
fn canonical(dir: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| write_failure(Problem::Io))
}

fn run_broker(dir: &Path, rest: &[String]) {
    let options = Options::parse(rest, &["--allowed-signers", "--key"], &["--once"]);
    let dir = &canonical(dir);
    let state = session::load(dir)
        .map(|(_, state)| state)
        .unwrap_or_else(|problem| write_failure(problem));
    let writer = Writer {
        allowed_signers: Path::new(options.required("--allowed-signers")),
        key: Path::new(options.required("--key")),
        principal: &state.header.collector,
    };
    if let Err(problem) = session_broker::check_key(dir, &writer) {
        write_failure(problem);
    }
    let mut guard = session_broker::Guard::new(dir, writer.allowed_signers)
        .unwrap_or_else(|problem| write_failure(problem));
    loop {
        match session_broker::run_once(dir, &writer, &mut guard) {
            Ok(handled) => {
                for item in handled {
                    match item {
                        Handled::Admitted(entry) => {
                            println!("MIRA session: admitted request as {:06}", entry.seq)
                        }
                        Handled::Refused(reason) => {
                            println!("MIRA session: refused request ({})", reason.as_str())
                        }
                        Handled::Discarded(session_broker::Discard::Replayed) => {
                            println!("MIRA session: discarded replayed request")
                        }
                        Handled::Discarded(session_broker::Discard::Unchargeable) => println!(
                            "MIRA session: discarded request (no budget left, or only the operator's reserve)"
                        ),
                    }
                }
            }
            Err(Problem::Closed) => {
                println!("MIRA session: closed; broker stopped");
                return;
            }
            Err(problem) => write_failure(problem),
        }
        if options.has("--once") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn act(dir: &Path, rest: &[String]) {
    let dir = &canonical(dir);
    let options = Options::parse(
        rest,
        &[
            "--allowed-signers",
            "--key",
            "--collector-key",
            "--capability",
            "--arguments",
            "--text",
        ],
        &[],
    );
    let (capability, arguments) = capability(&options);
    let note = options.get("--text").map(text).unwrap_or_default();
    let state = session::load(dir)
        .map(|(_, state)| state)
        .unwrap_or_else(|problem| write_failure(problem));
    let allowed = Path::new(options.required("--allowed-signers"));
    let operator = Writer {
        allowed_signers: allowed,
        key: Path::new(options.required("--key")),
        principal: &state.header.operator,
    };
    let collector = Writer {
        allowed_signers: allowed,
        key: Path::new(options.required("--collector-key")),
        principal: &state.header.collector,
    };
    match session_broker::act(dir, &operator, &collector, &capability, &arguments, note) {
        Ok((action, result)) => report_action(&action, result.as_ref()),
        Err(problem) => write_failure(problem),
    }
}
