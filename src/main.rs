use mira::{Actor, Engine, Mode, Move, Outcome, Proposal, demo_scenario};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
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
                "Usage: mira inspect [--json] | mira demo | mira service UNIT.service [--json] | mira investigate service-active UNIT.service [--json]"
            );
            std::process::exit(2);
        }
    }
}

fn inspect() {
    use mira::evidence::{Evidence, EvidenceStatus};
    let snapshot = mira::evidence::collect(std::path::Path::new("/proc"));
    println!("MIRA read-only host evidence (observations only)");
    fn show<T: std::fmt::Debug>(entry: &Evidence<T>) {
        let timestamp = entry
            .collected_unix_ms
            .map_or_else(|| "unknown".to_string(), |v| v.to_string());
        match &entry.status {
            EvidenceStatus::Observed(value) => {
                println!(
                    "{}: observed {:?} recorded_unix_ms={timestamp}",
                    entry.source, value
                );
            }
            EvidenceStatus::Unavailable { kind, message } => {
                println!(
                    "{}: unknown ({kind:?}: {message}) recorded_unix_ms={timestamp}",
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
            "{}: observed {} installed packages (not vulnerability findings) recorded_unix_ms={:?}",
            packages.source,
            installed.len(),
            packages.collected_unix_ms
        ),
        EvidenceStatus::Unavailable { kind, message } => println!(
            "{}: unknown ({kind:?}: {message}) recorded_unix_ms={:?}",
            packages.source, packages.collected_unix_ms
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
            "{}: Id={:?} LoadState={:?} ActiveState={:?} SubState={:?} recorded_unix_ms={:?} (observation only)",
            observation.source,
            state.id,
            state.load_state,
            state.active_state,
            state.sub_state,
            observation.collected_unix_ms
        ),
        EvidenceStatus::Unavailable { kind, message } => {
            eprintln!("{}: unknown ({kind:?}: {message})", observation.source);
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
        println!("outcome={} reason={} evidence_ref=#/evidence", report.assessment().outcome().as_str(), report.assessment().reason());
        println!("source={} recorded_unix_ms={:?} clock_trust=unverified freshness=unknown", report.evidence().source, report.evidence().collected_unix_ms);
        if let EvidenceStatus::Observed(state) = &report.evidence().status {
            // Debug formatting escapes control characters in untrusted state strings.
            println!("Id={:?} LoadState={:?} ActiveState={:?} SubState={:?}", state.id, state.load_state, state.active_state, state.sub_state);
        }
        println!("Reported activation only; application health and root cause are not assessed.");
    }
    std::process::exit(report.assessment().outcome().exit_code());
}
