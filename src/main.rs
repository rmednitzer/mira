mod session_cli;

use mira::{Actor, Engine, Mode, Move, Outcome, Proposal, demo_scenario};

fn main() {
    let args: Vec<String> = match std::env::args_os()
        .map(|argument| argument.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!("MIRA: arguments must be valid UTF-8");
            std::process::exit(2);
        }
    };
    // Signing options come last and only on JSON-producing commands (ADR 0011).
    let (args, signing) = split_signing(args);
    if let Some(signing) = signing {
        let json = match args.get(1).map(String::as_str) {
            Some("capture") => true,
            Some("investigate") => args.last().is_some_and(|last| last == "--json"),
            _ => false,
        };
        if !json {
            eprintln!(
                "MIRA: --signature and --sign-with apply only to capture or investigate --json"
            );
            std::process::exit(2);
        }
        let _ = SIGNING.set(signing);
    }
    match args.as_slice() {
        [_, command, template, option, minimum]
            if command == "investigate"
                && template == "memory-headroom"
                && option == "--min-available-kib" =>
        {
            memory_headroom(minimum, false)
        }
        [_, command, template, option, minimum, format]
            if command == "investigate"
                && template == "memory-headroom"
                && option == "--min-available-kib"
                && format == "--json" =>
        {
            memory_headroom(minimum, true)
        }
        // A registered template with a malformed invocation is a usage error for
        // that template, never an unknown template or a service-name scope.
        [_, command, template, ..] if command == "investigate" && template == "memory-headroom" => {
            eprintln!("Usage: mira investigate memory-headroom --min-available-kib N [--json]");
            std::process::exit(2);
        }
        [
            _,
            command,
            template,
            resource_option,
            resource,
            ceiling_option,
            maximum,
        ] if command == "investigate"
            && template == "pressure-ceiling"
            && resource_option == "--resource"
            && ceiling_option == "--max-some-avg10-basis-points" =>
        {
            pressure_ceiling(resource, maximum, false)
        }
        [
            _,
            command,
            template,
            resource_option,
            resource,
            ceiling_option,
            maximum,
            format,
        ] if command == "investigate"
            && template == "pressure-ceiling"
            && resource_option == "--resource"
            && ceiling_option == "--max-some-avg10-basis-points"
            && format == "--json" =>
        {
            pressure_ceiling(resource, maximum, true)
        }
        [_, command, template, ..]
            if command == "investigate" && template == "pressure-ceiling" =>
        {
            eprintln!("Usage: {PRESSURE_USAGE}");
            std::process::exit(2);
        }
        [_, command, template, selector]
            if command == "investigate" && template == "package-installed" =>
        {
            package_installed(selector, false)
        }
        [_, command, template, selector, format]
            if command == "investigate"
                && template == "package-installed"
                && format == "--json" =>
        {
            package_installed(selector, true)
        }
        [_, command, template, ..]
            if command == "investigate" && template == "package-installed" =>
        {
            eprintln!("Usage: {PACKAGE_USAGE}");
            std::process::exit(2);
        }
        [_, command, template, option, minimum]
            if command == "investigate"
                && template == "uptime-minimum"
                && option == "--min-uptime-seconds" =>
        {
            uptime_minimum(minimum, false)
        }
        [_, command, template, option, minimum, format]
            if command == "investigate"
                && template == "uptime-minimum"
                && option == "--min-uptime-seconds"
                && format == "--json" =>
        {
            uptime_minimum(minimum, true)
        }
        [_, command, template, ..] if command == "investigate" && template == "uptime-minimum" => {
            eprintln!("Usage: {UPTIME_USAGE}");
            std::process::exit(2);
        }
        [_, command, template, option, release]
            if command == "investigate" && template == "kernel-release" && option == "--expect" =>
        {
            kernel_release(release, false)
        }
        [_, command, template, option, release, format]
            if command == "investigate"
                && template == "kernel-release"
                && option == "--expect"
                && format == "--json" =>
        {
            kernel_release(release, true)
        }
        [_, command, template, ..] if command == "investigate" && template == "kernel-release" => {
            eprintln!("Usage: {KERNEL_USAGE}");
            std::process::exit(2);
        }
        [_, command, template, absent, classes, rest @ ..]
            if command == "investigate" && template == "journal-events" && absent == "--absent" =>
        {
            let (boot, json) = match rest {
                [] => (Some("current"), false),
                [format] if format == "--json" => (Some("current"), true),
                [option, boot] if option == "--boot" => (Some(boot.as_str()), false),
                [option, boot, format] if option == "--boot" && format == "--json" => {
                    (Some(boot.as_str()), true)
                }
                _ => (None, false),
            };
            match boot {
                Some(boot) => journal_events(classes, boot, json),
                None => {
                    eprintln!("Usage: {JOURNAL_USAGE}");
                    std::process::exit(2);
                }
            }
        }
        [_, command, template, ..] if command == "investigate" && template == "journal-events" => {
            eprintln!("Usage: {JOURNAL_USAGE}");
            std::process::exit(2);
        }
        [_, command, label, options @ ..] if command == "capture" => {
            match CaptureOptions::parse(options) {
                Some(options) => capture(label, options),
                None => usage(),
            }
        }
        [_, command] if command == "inspect" => inspect(),
        [_, command, format] if command == "inspect" && format == "--json" => inspect_json(),
        [_, command, template, unit] if command == "investigate" => {
            investigate(template, unit, false)
        }
        [_, command, template, unit, format] if command == "investigate" && format == "--json" => {
            investigate(template, unit, true)
        }
        [_, command, file, rest @ ..] if command == "verify" => match VerifyOptions::parse(rest) {
            Some(options) => verify(file, options),
            None => {
                eprintln!("Usage: {VERIFY_USAGE}");
                std::process::exit(2);
            }
        },
        [_, command] if command == "challenge" => challenge(),
        [_, command, rest @ ..] if command == "session" => session_cli::run(rest),
        [_, command, ..] if command == "verify" => {
            eprintln!("Usage: {VERIFY_USAGE}");
            std::process::exit(2);
        }
        [_, command] if command == "demo" => demo(),
        [_, command, unit] if command == "service" => service(unit),
        [_, command, unit, format] if command == "service" && format == "--json" => {
            service_json(unit)
        }
        _ => usage(),
    }
}

struct Signing {
    path: std::path::PathBuf,
    key: std::path::PathBuf,
}

static SIGNING: std::sync::OnceLock<Signing> = std::sync::OnceLock::new();

const VERIFY_USAGE: &str = "mira verify FILE --signature SIG --allowed-signers SIGNERS --principal NAME [--revocations KRL] [--challenge-file FILE --max-age-ms N]";

struct VerifyOptions<'a> {
    signature: &'a str,
    allowed: &'a str,
    principal: &'a str,
    revocations: Option<&'a str>,
    freshness: Option<(&'a str, &'a str)>,
}

impl<'a> VerifyOptions<'a> {
    /// Fixed option order; optional groups may only be absent, never reordered.
    fn parse(rest: &'a [String]) -> Option<Self> {
        let [signature, sig, signers, allowed, principal, name, rest @ ..] = rest else {
            return None;
        };
        if signature != "--signature"
            || signers != "--allowed-signers"
            || principal != "--principal"
        {
            return None;
        }
        let (revocations, rest) = match rest {
            [option, krl, rest @ ..] if option == "--revocations" => (Some(krl.as_str()), rest),
            _ => (None, rest),
        };
        let freshness = match rest {
            [] => None,
            [challenge, file, age, maximum]
                if challenge == "--challenge-file" && age == "--max-age-ms" =>
            {
                Some((file.as_str(), maximum.as_str()))
            }
            _ => return None,
        };
        Some(Self {
            signature: sig,
            allowed,
            principal: name,
            revocations,
            freshness,
        })
    }
}

/// Remove a trailing `--signature PATH --sign-with KEY` pair, if present.
fn split_signing(mut args: Vec<String>) -> (Vec<String>, Option<Signing>) {
    match args.as_slice() {
        [.., signature, path, sign_with, key]
            if signature == "--signature" && sign_with == "--sign-with" =>
        {
            let signing = Signing {
                path: path.into(),
                key: key.into(),
            };
            args.truncate(args.len() - 4);
            (args, Some(signing))
        }
        _ => (args, None),
    }
}

/// Print one JSON document. When signing was requested, sign the exact bytes
/// first; on any failure print nothing and exit 4 (ADR 0011).
fn emit_json(json: &str) {
    let document = format!("{json}\n");
    if let Some(signing) = SIGNING.get()
        && let Err(failure) =
            mira::signature::sign(document.as_bytes(), &signing.key, &signing.path)
    {
        use mira::signature::Failure;
        let reason = match failure {
            Failure::Tool => "ssh-keygen unavailable or produced an unusable signature",
            Failure::Refused => "ssh-keygen refused to sign with this key",
            Failure::Output => "signature path exists or cannot be created",
            Failure::Document => "document kind cannot be signed",
        };
        eprintln!("MIRA: signing failed: {reason}; no document emitted");
        std::process::exit(4);
    }
    print!("{document}");
}

fn verify(file: &str, options: VerifyOptions) {
    use mira::challenge;
    use mira::signature::{self, Failure, Trust};
    if signature::validate_principal(options.principal).is_err() {
        eprintln!(
            "MIRA: principal must be 1-128 characters from A-Za-z0-9._@+- starting alphanumeric"
        );
        std::process::exit(2);
    }
    let maximum = match options.freshness {
        Some((_, maximum)) => match challenge::parse_decimal(maximum.as_bytes()) {
            Some(maximum) => Some(maximum),
            None => {
                eprintln!("MIRA: --max-age-ms must be a decimal integer of at most 16 digits");
                std::process::exit(2);
            }
        },
        None => None,
    };
    // With a freshness check, every signature-stage refusal has one fixed reason.
    let refused = |detail: &str| -> ! {
        if options.freshness.is_some() {
            println!("MIRA verify: not verified (signature)");
        } else if detail.is_empty() {
            println!("MIRA verify: not verified");
        } else {
            println!("MIRA verify: not verified ({detail})");
        }
        std::process::exit(1);
    };
    let Ok(document) = signature::read_document(std::path::Path::new(file)) else {
        refused("document unreadable or larger than 1 MiB");
    };
    let trust = Trust {
        allowed_signers: std::path::Path::new(options.allowed),
        principal: options.principal,
        revocations: options.revocations.map(std::path::Path::new),
    };
    let kind = match signature::verify(&document, std::path::Path::new(options.signature), &trust) {
        Ok(kind) => kind,
        Err(Failure::Tool) => {
            eprintln!("MIRA: ssh-keygen unavailable; nothing verified");
            std::process::exit(4);
        }
        Err(Failure::Document) => refused("not a MIRA capture or investigation report"),
        Err(Failure::Refused | Failure::Output) => refused(""),
    };
    let (Some((challenge_file, _)), Some(maximum)) = (options.freshness, maximum) else {
        println!(
            "MIRA verify: verified namespace={} principal={}",
            kind.namespace(),
            options.principal
        );
        return;
    };
    // The challenge file is read only after the signature verified (ADR 0014).
    let issued = match signature::read_regular(
        std::path::Path::new(challenge_file),
        challenge::MAX_CHALLENGE_FILE_BYTES,
    ) {
        Ok(bytes) => match challenge::parse_issued(&bytes) {
            Some(issued) => issued,
            None => {
                eprintln!("MIRA: challenge file is not a challenge-v1 document");
                std::process::exit(2);
            }
        },
        // Oversized or not a regular file is the operator's input, hence usage.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
            ) =>
        {
            eprintln!("MIRA: challenge file must be a regular file of at most 4 KiB");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("MIRA: challenge file unreadable; freshness not checked");
            std::process::exit(4);
        }
    };
    let Some(now) = mira_now_unix_ms() else {
        eprintln!("MIRA: verifier wall clock unavailable; freshness not checked");
        std::process::exit(4);
    };
    match challenge::check(&document, &issued, now, maximum) {
        Ok(age) => println!(
            "MIRA verify: verified namespace={} principal={} age_bound_ms={age}",
            kind.namespace(),
            options.principal
        ),
        Err(stale) => {
            println!("MIRA verify: not verified ({})", stale.reason());
            std::process::exit(1);
        }
    }
}

/// The verifier's own wall clock, the only clock ADR 0014 trusts.
fn mira_now_unix_ms() -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    u64::try_from(now.as_millis()).ok()
}

fn challenge() {
    match mira::challenge::issue() {
        Ok(document) => println!("{document}"),
        Err(_) => {
            eprintln!("MIRA: challenge unavailable (random source or wall clock); nothing issued");
            std::process::exit(4);
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "Usage: mira capture LABEL [--pressure] [--timeline] [--bind-boot] [--challenge HEX] [--signature PATH --sign-with KEY] | mira challenge | mira inspect [--json] | mira demo | mira service UNIT.service [--json] | mira investigate service-active[/v1|/v2] UNIT.service [--json] | mira investigate memory-headroom --min-available-kib N [--json] | {PRESSURE_USAGE} | {PACKAGE_USAGE} | {UPTIME_USAGE} | {KERNEL_USAGE} | {JOURNAL_USAGE} | {VERIFY_USAGE} | {} (investigate --json also accepts --signature PATH --sign-with KEY)",
        session_cli::USAGE
    );
    std::process::exit(2);
}

const JOURNAL_USAGE: &str = "mira investigate journal-events --absent oom-kill|unit-failure|coredump[,...] [--boot current|previous-retained] [--json]";

fn journal_events(classes: &str, boot: &str, json: bool) {
    use mira::journal::{self, Boot, ClassEvidence};
    // Both criteria are refused before journalctl runs.
    let (Ok(classes), Some(boot)) = (journal::parse_classes(classes), Boot::from_name(boot)) else {
        eprintln!(
            "MIRA: --absent takes oom-kill, unit-failure and coredump without repetition; --boot is current or previous-retained"
        );
        std::process::exit(2);
    };
    let report = journal::investigate(&classes, boot, &journal::Paths::for_cli());
    let reason = report.reason();
    if json {
        emit_json(&report.to_json());
    } else {
        let collection = report.collection();
        println!(
            "MIRA journal-events/v1 scope=local/journal boot={}",
            collection.boot.report_name()
        );
        println!(
            "outcome={} reason={}",
            reason.outcome().as_str(),
            reason.as_str()
        );
        println!(
            "journal_visible={} journal_access_complete={}",
            collection
                .visible
                .map_or("unknown", |v| if v { "yes" } else { "no" }),
            collection
                .access_complete
                .map_or("unknown", |v| if v { "yes" } else { "no" })
        );
        for (class, evidence) in &collection.classes {
            match evidence {
                ClassEvidence::Recorded {
                    count,
                    truncated,
                    units,
                    ..
                } => println!(
                    "{}: {}{count} recorded units={}",
                    class.name(),
                    if *truncated { "at least " } else { "" },
                    if units.is_empty() {
                        "none".to_owned()
                    } else {
                        units.join(",")
                    }
                ),
                ClassEvidence::None => println!("{}: none recorded", class.name()),
                ClassEvidence::Unavailable(reason) => {
                    println!("{}: unavailable ({reason})", class.name());
                }
                ClassEvidence::NotQueried => println!("{}: not queried", class.name()),
            }
        }
        println!(
            "Catalog events only, no message text; none recorded does not mean none occurred."
        );
    }
    std::process::exit(reason.outcome().exit_code());
}

const UPTIME_USAGE: &str = "mira investigate uptime-minimum --min-uptime-seconds N [--json]";
const KERNEL_USAGE: &str = "mira investigate kernel-release --expect RELEASE [--json]";

fn uptime_minimum(minimum: &str, json: bool) {
    use mira::host_investigation as host;
    let report = host::parse_minimum_uptime(minimum)
        .and_then(|minimum| host::collect_uptime(minimum, std::path::Path::new("/proc")));
    let Ok(report) = report else {
        eprintln!("MIRA: uptime minimum must be a positive integer number of seconds");
        std::process::exit(2);
    };
    if json {
        emit_json(&report.to_json());
    } else {
        println!(
            "MIRA uptime-minimum/v1 scope=local/procfs minimum_uptime_seconds={}",
            report.minimum()
        );
        println!(
            "outcome={} reason={}",
            report.outcome().as_str(),
            report.reason()
        );
        host_evidence_lines(report.evidence(), |seconds| {
            format!("uptime_seconds={seconds}")
        });
        println!(
            "Time since boot only; reboot cause, service restarts and health are not assessed."
        );
    }
    std::process::exit(report.outcome().exit_code());
}

fn kernel_release(expected: &str, json: bool) {
    use mira::host_investigation as host;
    let Ok(report) = host::collect_kernel(expected, std::path::Path::new("/proc")) else {
        eprintln!(
            "MIRA: expected kernel release must be 1-256 characters from A-Za-z0-9._+- starting with a letter or digit"
        );
        std::process::exit(2);
    };
    if json {
        emit_json(&report.to_json());
    } else {
        println!(
            "MIRA kernel-release/v1 scope=local/procfs expected={}",
            report.expected()
        );
        println!(
            "outcome={} reason={}",
            report.outcome().as_str(),
            report.reason()
        );
        host_evidence_lines(report.evidence(), |release| format!("release={release}"));
        println!(
            "Running release name only; build identity, livepatch state, packages and vulnerability exposure are not assessed."
        );
    }
    std::process::exit(report.outcome().exit_code());
}

/// Shared human evidence lines; observed values are already lexically validated.
fn host_evidence_lines<T>(
    evidence: &mira::evidence::Evidence<T>,
    describe: impl FnOnce(&T) -> String,
) {
    println!(
        "source={} recorded_unix_ms={} clock_trust=unverified freshness=unknown",
        evidence.source,
        recorded(evidence.collected_unix_ms)
    );
    match &evidence.status {
        mira::evidence::EvidenceStatus::Observed(value) => println!("{}", describe(value)),
        mira::evidence::EvidenceStatus::Unavailable { reason, .. } => {
            println!("failure_reason={reason}");
        }
    }
}

const PACKAGE_USAGE: &str = "mira investigate package-installed PACKAGE[:ARCH] [--json]";

fn package_installed(selector: &str, json: bool) {
    use mira::package_investigation::{self as package, Selector};
    // The selector is refused before the status database is opened.
    let Ok(selector) = Selector::parse(selector) else {
        eprintln!("MIRA: package must be a Debian package name, optionally :ARCH");
        std::process::exit(2);
    };
    let report = package::collect(selector, std::path::Path::new("/var/lib/dpkg/status"));
    let assessment = report.assessment();
    if json {
        emit_json(&report.to_json());
    } else {
        let selector = report.selector();
        println!(
            "MIRA package-installed/v1 scope=local/dpkg package={} architecture={}",
            selector.package(),
            selector.architecture().unwrap_or("any")
        );
        println!(
            "outcome={} reason={}",
            assessment.outcome().as_str(),
            assessment.reason()
        );
        let evidence = report.evidence();
        println!(
            "source={} recorded_unix_ms={} clock_trust=unverified freshness=unknown",
            evidence.source,
            recorded(evidence.collected_unix_ms)
        );
        match &evidence.status {
            mira::evidence::EvidenceStatus::Observed(records) => {
                println!("matching_records={}", records.len());
                for record in records {
                    // Debug formatting escapes control characters in untrusted database text.
                    let literal = |value: Option<&str>| {
                        value.map_or_else(|| "absent".to_owned(), |value| format!("{value:?}"))
                    };
                    println!(
                        "Architecture={} Version={} Status=\"{} {} {}\"",
                        literal(record.architecture.as_deref()),
                        literal(record.version.as_deref()),
                        record.selection,
                        record.flag,
                        record.state
                    );
                }
            }
            mira::evidence::EvidenceStatus::Unavailable { reason, .. } => {
                println!("failure_reason={reason}");
            }
        }
        println!(
            "dpkg bookkeeping only; vulnerability exposure, file integrity, service health and root cause are not assessed."
        );
    }
    std::process::exit(assessment.outcome().exit_code());
}

const PRESSURE_USAGE: &str = "mira investigate pressure-ceiling --resource cpu|memory|io --max-some-avg10-basis-points N [--json]";

fn pressure_ceiling(resource: &str, maximum: &str, json: bool) {
    use mira::pressure_investigation as pressure;
    // Both criteria are refused before any acquisition.
    let Ok(resource) = pressure::parse_resource(resource) else {
        eprintln!("MIRA: pressure resource must be cpu, memory or io");
        std::process::exit(2);
    };
    let report = pressure::parse_maximum(maximum)
        .and_then(|maximum| pressure::collect(resource, maximum, std::path::Path::new("/proc")));
    let Ok(report) = report else {
        eprintln!("MIRA: pressure ceiling must be an integer from 0 to 10000 basis points");
        std::process::exit(2);
    };
    if json {
        emit_json(&report.to_json());
    } else {
        println!(
            "MIRA pressure-ceiling/v1 scope=local/procfs resource={} max_some_avg10_basis_points={}",
            report.resource().name(),
            report.maximum()
        );
        println!(
            "outcome={} reason={}",
            report.outcome().as_str(),
            report.reason()
        );
        let evidence = report.evidence();
        println!(
            "source={} recorded_unix_ms={} clock_trust=unverified freshness=unknown",
            evidence.source,
            recorded(evidence.collected_unix_ms)
        );
        match &evidence.status {
            mira::evidence::EvidenceStatus::Observed(pressure) => println!(
                "some_avg10_basis_points={} full_avg10_basis_points={}",
                pressure.some_avg10_basis_points,
                pressure
                    .full_avg10_basis_points
                    .map_or_else(|| "absent".to_owned(), |value| value.to_string())
            ),
            mira::evidence::EvidenceStatus::Unavailable { reason, .. } => {
                println!("failure_reason={reason}");
            }
        }
        println!(
            "Smoothed 10-second stall share only; workload health, latency and root cause are not assessed."
        );
    }
    std::process::exit(report.outcome().exit_code());
}

/// Human-readable recording time: Unix milliseconds, or `unknown` without a clock reading.
/// JSON output keeps its own `null` encoding.
fn recorded(time: Option<u128>) -> String {
    time.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

fn memory_headroom(minimum: &str, json: bool) {
    let report = mira::memory_investigation::parse_minimum(minimum).and_then(|minimum| {
        mira::memory_investigation::collect(minimum, std::path::Path::new("/proc"))
    });
    let report = match report {
        Ok(report) => report,
        Err(_) => {
            eprintln!("MIRA: memory minimum must be a positive integer KiB value");
            std::process::exit(2);
        }
    };
    if json {
        emit_json(&report.to_json());
    } else {
        println!(
            "MIRA memory-headroom/v1 scope=local/procfs minimum_available_kib={}",
            report.minimum()
        );
        println!(
            "outcome={} reason={}",
            report.outcome().as_str(),
            report.reason()
        );
        println!(
            "source=/proc/meminfo recorded_unix_ms={} clock_trust=unverified freshness=unknown",
            recorded(report.evidence().collected_unix_ms)
        );
        match &report.evidence().status {
            mira::evidence::EvidenceStatus::Observed(memory) => {
                println!(
                    "available_kib={} total_kib={}",
                    memory.available_kib, memory.total_kib
                );
            }
            mira::evidence::EvidenceStatus::Unavailable { kind, .. } => {
                println!("error_kind={kind:?}");
            }
        }
        println!(
            "Procfs estimate only; application health, cgroup limits and root cause are not assessed."
        );
    }
    std::process::exit(report.outcome().exit_code());
}

fn inspect() {
    use mira::evidence::{Evidence, EvidenceStatus};
    let snapshot = mira::evidence::collect(std::path::Path::new("/proc"));
    println!("MIRA read-only host evidence (observations only)");
    fn show<T: std::fmt::Debug>(entry: &Evidence<T>) {
        let timestamp = recorded(entry.collected_unix_ms);
        match &entry.status {
            EvidenceStatus::Observed(value) => {
                println!(
                    "{}: observed {:?} recorded_unix_ms={timestamp}",
                    entry.source, value
                );
            }
            EvidenceStatus::Unavailable { kind, message, .. } => {
                println!(
                    "{}: unknown ({kind:?}: {message:?}) recorded_unix_ms={timestamp}",
                    entry.source
                );
            }
        }
    }
    show(&snapshot.memory);
    show(&snapshot.uptime);
    show(&snapshot.kernel_release);
    show(&snapshot.cpu_pressure);
    let packages = mira::evidence::collect_packages(std::path::Path::new("/var/lib/dpkg/status"));
    match &packages.status {
        EvidenceStatus::Observed(installed) => println!(
            "{}: observed {} installed packages (not vulnerability findings) recorded_unix_ms={}",
            packages.source,
            installed.len(),
            recorded(packages.collected_unix_ms)
        ),
        EvidenceStatus::Unavailable { kind, message, .. } => println!(
            "{}: unknown ({kind:?}: {message:?}) recorded_unix_ms={}",
            packages.source,
            recorded(packages.collected_unix_ms)
        ),
    }
    let incomplete = !snapshot.complete() || !packages.is_available();
    if incomplete {
        eprintln!("MIRA: incomplete host evidence");
        std::process::exit(1);
    }
}

fn demo() {
    let mut engine = Engine::new(demo_scenario()).expect("valid demo");
    for tick in 0..8 {
        if engine.outcome() != Outcome::Running {
            break;
        }
        let command = Proposal {
            actor: Actor::Human,
            command: Move::East,
            tick,
        };
        let event = engine
            .step(Mode::Manual, Some(command), None, None)
            .expect("step");
        println!("{event:?}");
    }
}

fn service(unit: &str) {
    use mira::evidence::EvidenceStatus;
    let observation = mira::evidence::collect_service(unit);
    match observation.status {
        EvidenceStatus::Observed(state) => println!(
            "{}: Id={:?} LoadState={:?} ActiveState={:?} SubState={:?} recorded_unix_ms={} (observation only)",
            observation.source,
            state.id,
            state.load_state,
            state.active_state,
            state.sub_state,
            recorded(observation.collected_unix_ms)
        ),
        EvidenceStatus::Unavailable { kind, message, .. } => {
            eprintln!("{}: unknown ({kind:?}: {message:?})", observation.source);
            std::process::exit(1);
        }
    }
}

fn inspect_json() {
    let snapshot = mira::evidence::collect(std::path::Path::new("/proc"));
    let packages = mira::evidence::collect_packages(std::path::Path::new("/var/lib/dpkg/status"));
    for record in mira::evidence_json::host_records(&snapshot, &packages) {
        println!("{record}");
    }
    if !snapshot.complete() || !packages.is_available() {
        std::process::exit(1);
    }
}

fn service_json(unit: &str) {
    let observation = mira::evidence::collect_service(unit);
    println!(
        "{}",
        mira::evidence_json::service_record(unit, &observation)
    );
    if !observation.is_available() {
        std::process::exit(1);
    }
}

fn investigate(name: &str, unit: &str, json: bool) {
    use mira::evidence::EvidenceStatus;
    use mira::investigation::{self, Template};
    let Some(template) = Template::from_name(name) else {
        eprintln!("MIRA: unknown investigation template");
        std::process::exit(2);
    };
    let report = match investigation::run(template, unit) {
        Ok(report) => report,
        Err(_) => {
            eprintln!("MIRA: invalid investigation scope");
            std::process::exit(2);
        }
    };
    if json {
        emit_json(&report.to_json());
    } else {
        println!("MIRA {} scope={:?}", report.template().id(), report.scope());
        println!(
            "outcome={} reason={} evidence_ref=#/evidence",
            report.assessment().outcome().as_str(),
            report.assessment().reason()
        );
        println!(
            "source={} recorded_unix_ms={} clock_trust=unverified freshness=unknown",
            report.evidence().source,
            recorded(report.evidence().collected_unix_ms)
        );
        if let EvidenceStatus::Observed(state) = &report.evidence().status {
            // Debug formatting escapes control characters in untrusted state strings.
            println!(
                "Id={:?} LoadState={:?} ActiveState={:?} SubState={:?}",
                state.id, state.load_state, state.active_state, state.sub_state
            );
        }
        println!("Reported activation only; application health and root cause are not assessed.");
    }
    std::process::exit(report.assessment().outcome().exit_code());
}

/// Capture options in their one documented order: [--pressure] [--timeline] [--bind-boot].
/// `--bind-boot` implies `--timeline` (ADR 0010).
struct CaptureOptions {
    pressure: bool,
    timeline: bool,
    bind_boot: bool,
    challenge: Option<String>,
}

impl CaptureOptions {
    fn parse(options: &[String]) -> Option<Self> {
        let mut rest = options;
        let mut take = |flag: &str| match rest.split_first() {
            Some((first, tail)) if first == flag => {
                rest = tail;
                true
            }
            _ => false,
        };
        let pressure = take("--pressure");
        let timeline = take("--timeline");
        let bind_boot = take("--bind-boot");
        let challenge = match rest {
            [option, value] if option == "--challenge" => {
                let value = value.clone();
                rest = &[];
                Some(value)
            }
            _ => None,
        };
        rest.is_empty().then_some(Self {
            pressure,
            timeline: timeline || bind_boot || challenge.is_some(),
            bind_boot,
            challenge,
        })
    }
}

fn capture(label: &str, options: CaptureOptions) {
    use mira::capture::{self, Profile};
    // The challenge is checked before any acquisition and only counts when
    // signed: an unsigned one could be pasted into any old file (ADR 0014).
    let challenge = match options.challenge.as_deref() {
        Some(_) if SIGNING.get().is_none() => {
            eprintln!("MIRA: --challenge requires --signature and --sign-with");
            std::process::exit(2);
        }
        Some(text) => match mira::challenge::Challenge::parse(text) {
            Some(challenge) => Some(challenge),
            None => {
                eprintln!("MIRA: --challenge must be exactly 64 lowercase hex characters");
                std::process::exit(2);
            }
        },
        None => None,
    };
    let profile = if options.pressure {
        Profile::HostPressure
    } else {
        Profile::Host
    };
    let collect = if options.bind_boot {
        capture::collect_with_boot
    } else {
        capture::collect
    };
    let report = match collect(
        label,
        profile,
        std::path::Path::new("/proc"),
        std::path::Path::new("/var/lib/dpkg/status"),
    ) {
        Ok(report) => report,
        Err(_) => {
            eprintln!("MIRA: invalid capture label");
            std::process::exit(2);
        }
    };
    // capture-v1 stays the default; --timeline opts into capture-v2 (ADR 0010).
    if let Some(challenge) = &challenge {
        emit_json(&report.to_challenge_json(challenge));
    } else if options.timeline {
        emit_json(&report.to_timeline_json());
    } else {
        emit_json(&report.to_json());
    }
    if !report.all_available() {
        std::process::exit(1);
    }
}
