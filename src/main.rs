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
        [_, command] if command == "demo" => demo(),
        [_, command, unit] if command == "service" => service(unit),
        [_, command, unit, format] if command == "service" && format == "--json" => {
            service_json(unit)
        }
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "Usage: mira capture LABEL [--pressure] [--timeline] [--bind-boot] | mira inspect [--json] | mira demo | mira service UNIT.service [--json] | mira investigate service-active[/v1|/v2] UNIT.service [--json] | mira investigate memory-headroom --min-available-kib N [--json] | {PRESSURE_USAGE} | {PACKAGE_USAGE} | {UPTIME_USAGE} | {KERNEL_USAGE}"
    );
    std::process::exit(2);
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
        println!("{}", report.to_json());
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
        println!("{}", report.to_json());
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
        println!("{}", report.to_json());
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
        println!("{}", report.to_json());
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
        println!("{}", report.to_json());
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
        println!("{}", report.to_json());
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
        rest.is_empty().then_some(Self {
            pressure,
            timeline: timeline || bind_boot,
            bind_boot,
        })
    }
}

fn capture(label: &str, options: CaptureOptions) {
    use mira::capture::{self, Profile};
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
    if options.timeline {
        println!("{}", report.to_timeline_json());
    } else {
        println!("{}", report.to_json());
    }
    if !report.all_available() {
        std::process::exit(1);
    }
}
