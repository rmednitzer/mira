use mira::linux;
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
    let report = linux::report(std::path::Path::new("/proc"));
    println!("MIRA Linux host evidence (read-only; no security conclusions)");
    let mut incomplete = false;
    match report.memory.result {
        Ok(m) => println!(
            "{}: MemTotal={} KiB MemAvailable={} KiB",
            report.memory.source, m.total_kib, m.available_kib
        ),
        Err(e) => {
            incomplete = true;
            println!("{}: unknown ({e})", report.memory.source);
        }
    }
    match report.uptime.result {
        Ok(seconds) => println!("{}: uptime={} s", report.uptime.source, seconds),
        Err(e) => {
            incomplete = true;
            println!("{}: unknown ({e})", report.uptime.source);
        }
    }
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
