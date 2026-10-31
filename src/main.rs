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
        [_, command, label] if command == "capture" => capture(label, false),
        [_, command, label, option] if command == "capture" && option == "--pressure" => {
            capture(label, true)
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
        _ => {
            eprintln!(
                "Usage: mira capture LABEL [--pressure] | mira inspect [--json] | mira demo | mira service UNIT.service [--json] | mira investigate service-active UNIT.service [--json] | mira investigate memory-headroom --min-available-kib N [--json]"
            );
            std::process::exit(2);
        }
    }
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

fn capture(label: &str, pressure: bool) {
    use mira::capture::{self, Profile};
    let profile = if pressure {
        Profile::HostPressure
    } else {
        Profile::Host
    };
    let report = match capture::collect(
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
    println!("{}", report.to_json());
    if !report.all_available() {
        std::process::exit(1);
    }
}
