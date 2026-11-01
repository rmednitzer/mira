//! `mira session` subcommands (ADR 0015 stage 1a). Exit codes: 0 done or
//! verified, 1 refused by the session state or not verified, 2 usage, 4 tool,
//! signing or I/O failure.
use mira::session::{self, Body, Directive, Header, Level, Problem, Separation, Writer};
use std::{collections::BTreeMap, path::Path};

pub const USAGE: &str = "mira session start DIR --allowed-signers FILE --key KEY --operator NAME --agent NAME --collector NAME [--autonomy manual|advisory|assisted] [--budget N] --question TEXT | mira session ask DIR --allowed-signers FILE --key KEY --text TEXT | mira session direct DIR --allowed-signers FILE --key KEY (--stop | --level manual|advisory|assisted | --budget N | --delegate-until SEQ) [--text TEXT] | mira session close DIR --allowed-signers FILE --key KEY --conclusion TEXT [--receipt PATH] | mira session show DIR [--json] | mira session verify DIR --allowed-signers FILE [--expect-close PATH]";

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

fn decimal(value: &str) -> u64 {
    mira::challenge::parse_decimal(value.as_bytes())
        .unwrap_or_else(|| fail("numbers must be decimal integers of at most 16 digits", 2))
}

/// Map a write-side problem to its fixed diagnostic and exit status.
fn write_failure(problem: Problem) -> ! {
    match problem {
        Problem::Closed | Problem::InvalidDirective | Problem::Full => {
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
        "direct" => direct(dir, rest),
        "close" => close(dir, rest),
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
        ],
        &[],
    );
    let operator = principal(options.required("--operator"));
    let header = Header {
        operator: operator.clone(),
        agent: principal(options.required("--agent")),
        collector: principal(options.required("--collector")),
        separation: Separation::SameUser,
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
    match session::start(dir, &writer, header, question) {
        Ok(entry) => println!(
            "MIRA session: started {} at {}",
            entry.session_id,
            dir.display()
        ),
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
        Ok((Body::Question, Some(state.entries - 1), note.clone()))
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
        &[],
    );
    let note = text(options.required("--conclusion"));
    // Refuse an existing receipt path before closing, so the close never
    // succeeds without the receipt that was asked for.
    if let Some(receipt) = options.get("--receipt") {
        let signature = format!("{receipt}.sig");
        if Path::new(receipt).symlink_metadata().is_ok()
            || Path::new(&signature).symlink_metadata().is_ok()
        {
            fail("receipt path exists; nothing written", 2);
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
    let options = Options::parse(rest, &["--allowed-signers", "--expect-close"], &[]);
    let allowed = Path::new(options.required("--allowed-signers"));
    match session::verify(dir, allowed, options.get("--expect-close").map(Path::new)) {
        Ok(state) => println!(
            "MIRA session: verified {} entries {} {}",
            state.session_id,
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
