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
    let additional = mira::host_extra::inspect(std::path::Path::new("/proc"));
    match additional.kernel_release.result {
        Ok(release) => println!("{}: {}", additional.kernel_release.source, release),
        Err(e) => {
            incomplete = true;
            println!("{}: unknown ({e})", additional.kernel_release.source);
        }
    }
    match additional.cpu_pressure.result {
        Ok(pressure) => println!(
            "{}: some.avg10={}.{:02}%{}",
            additional.cpu_pressure.source,
            pressure.some_avg10_basis_points / 100,
            pressure.some_avg10_basis_points % 100,
            pressure
                .full_avg10_basis_points
                .map_or(String::new(), |v| format!(
                    " full.avg10={}.{:02}%",
                    v / 100,
                    v % 100
                ))
        ),
        Err(e) => {
            incomplete = true;
            println!("{}: unknown ({e})", additional.cpu_pressure.source);
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
