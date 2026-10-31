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

/// Stand-in for `ssh-keygen -Y`. Each subcommand's exact argv shape is checked;
/// any deviation exits 64, which MIRA must surface as a failure.
fn ssh_keygen(mode: &str) -> io::Result<()> {
    const CAPTURE: &str = "mira-capture-v1@rmednitzer.github.io";
    const INVESTIGATION: &str = "mira-investigation-v1@rmednitzer.github.io";
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let namespace_ok = |namespace: &str| namespace == CAPTURE || namespace == INVESTIGATION;
    match args.as_slice() {
        ["-Y", "sign", "-f", key, "-n", namespace]
            if !key.is_empty() && namespace_ok(namespace) =>
        {
            match mode {
                "keygen-ok"
                | "keygen-check-fails"
                | "keygen-check-record"
                | "keygen-check-swap" => io::stdout().write_all(
                    b"-----BEGIN SSH SIGNATURE-----\nZml4dHVyZQ==\n-----END SSH SIGNATURE-----\n",
                ),
                "keygen-unarmored" => io::stdout().write_all(b"not a signature\n"),
                "keygen-oversized" => io::stdout().write_all(&vec![b'x'; 100_000]),
                "keygen-refuses" => process::exit(255),
                _ => process::exit(64),
            }
        }
        ["-Y", "check-novalidate", "-n", namespace, "-s", signature]
            if namespace_ok(namespace) && !signature.is_empty() =>
        {
            match mode {
                "keygen-check-fails" => process::exit(255),
                "keygen-check-record" => {
                    // Record where the self-check read its signature from.
                    use std::os::unix::fs::PermissionsExt;
                    let parent = std::path::Path::new(signature).parent().unwrap();
                    let mode = std::fs::metadata(parent)?.permissions().mode() & 0o777;
                    std::fs::write(
                        env::var_os("MIRA_FIXTURE_RECORD").unwrap(),
                        format!("{signature}\n{}\n{mode:o}\n", parent.display()),
                    )?;
                    Ok(())
                }
                "keygen-check-swap" => {
                    // The reported attack: swap the output's parent for a
                    // symlink into a victim directory, then fail the check.
                    let from = env::var_os("MIRA_FIXTURE_SWAP_FROM").unwrap();
                    let to = env::var_os("MIRA_FIXTURE_SWAP_TO").unwrap();
                    let aside = std::path::PathBuf::from(&from).with_extension("aside");
                    std::fs::rename(&from, aside)?;
                    std::os::unix::fs::symlink(to, &from)?;
                    process::exit(255)
                }
                _ => Ok(()),
            }
        }
        [
            "-Y",
            "verify",
            "-f",
            signers,
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            signature,
        ]
        | [
            "-Y",
            "verify",
            "-f",
            signers,
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            signature,
            "-r",
            _,
        ] if namespace_ok(namespace)
            && !signers.is_empty()
            && !principal.is_empty()
            && !signature.is_empty() =>
        {
            if mode == "keygen-ok" {
                Ok(())
            } else {
                process::exit(255)
            }
        }
        _ => process::exit(64),
    }
}

fn main() -> io::Result<()> {
    let mode = env::var("MIRA_PROCESS_FIXTURE_MODE").unwrap_or_default();
    if mode.starts_with("keygen-") {
        return ssh_keygen(&mode);
    }
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
        "not-found" => state_output("ssh.service", "not-found", "inactive", "dead"),
        "not-found-active" => state_output("ssh.service", "not-found", "active", "running"),
        "not-found-failed" => state_output("ssh.service", "not-found", "failed", "failed"),
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
