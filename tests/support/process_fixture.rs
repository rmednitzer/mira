//! Native adversarial subprocess fixture. Never installed or enabled by default.
use std::{
    env,
    io::{self, Write},
    process::{self, Command},
    thread,
    time::Duration,
};

fn state_output(id: &str, load: &str, active: &str, sub: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Id={id}")?;
    writeln!(
        stdout,
        "Names={id} ssh.service {}",
        "alias.service ".repeat(500)
    )?;
    writeln!(
        stdout,
        "LoadState={load}\nActiveState={active}\nSubState={sub}"
    )?;
    stdout.flush()
}

fn valid_output() -> io::Result<()> {
    state_output("ssh.service", "loaded", "active", "running")
}

fn main() -> io::Result<()> {
    let mode = env::var("MIRA_PROCESS_FIXTURE_MODE").unwrap_or_default();
    if mode == "keep-stdout" {
        // The parent exits first. Keep the inherited stdout open for a finite
        // lifetime exceeding the production collector's three-second deadline.
        thread::sleep(Duration::from_secs(5));
        return Ok(());
    }
    let expected = [
        "--system",
        "--no-pager",
        "--no-ask-password",
        "show",
        "--property=Id,Names,LoadState,ActiveState,SubState",
        "--",
        "ssh.service",
    ];
    if env::args().skip(1).ne(expected.iter().copied()) {
        process::exit(64);
    }
    match mode.as_str() {
        "valid" => valid_output(),
        "reported-failed" => state_output("ssh.service", "loaded", "failed", "failed"),
        "reported-inactive" => state_output("ssh.service", "loaded", "inactive", "dead"),
        "reloading" => state_output("ssh.service", "loaded", "reloading", "reload"),
        "refreshing" => state_output("ssh.service", "loaded", "refreshing", "refreshing"),
        "activating" => state_output("ssh.service", "loaded", "activating", "start"),
        "deactivating" => state_output("ssh.service", "loaded", "deactivating", "stop"),
        "maintenance" => state_output("ssh.service", "loaded", "maintenance", "cleaning"),
        "future-state" => state_output("ssh.service", "loaded", "future-state", "future-sub"),
        "masked-active" => state_output("ssh.service", "masked", "active", "running"),
        "alias-active" => state_output("canonical.service", "loaded", "active", "running"),
        "control-state" => state_output("ssh.service", "loaded", "future-\u{1b}[2J", "future-sub"),
        "oversized" => io::stdout().write_all(&vec![b'x'; 100_000]),
        "timeout" => {
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
        "inherited-stdout" => {
            // Drop deliberately does not wait. This test-only descendant exits
            // by itself; production collection only owns the direct child.
            #[allow(
                clippy::zombie_processes,
                reason = "bounded inherited-stdout fixture must outlive its parent"
            )]
            let _keeper = Command::new(env::current_exe()?)
                .env("MIRA_PROCESS_FIXTURE_MODE", "keep-stdout")
                .spawn()?;
            valid_output()
        }
        "malformed" => io::stdout().write_all(b"Id=ssh.service\n"),
        "invalid-utf8" => io::stdout().write_all(&[0xff]),
        "failure" => process::exit(7),
        _ => process::exit(64),
    }
}
