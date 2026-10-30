use mira::{Actor, Engine, Mode, Move, Outcome, Proposal, demo_scenario};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, command] if command == "inspect" => inspect(),
        [_, command] if command == "demo" => demo(),
        _ => {
            eprintln!("Usage: mira inspect | mira demo");
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
    let mut incomplete = !snapshot.complete();
    match mira::packages::collect(std::path::Path::new("/var/lib/dpkg/status")) {
        Ok(packages) => println!(
            "/var/lib/dpkg/status: observed {} installed package records (not vulnerability findings)",
            packages.len()
        ),
        Err(error) => {
            incomplete = true;
            println!("/var/lib/dpkg/status: unknown ({error})");
        }
    }
    if !snapshot.complete() {
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
