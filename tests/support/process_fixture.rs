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

/// Stand-in for `journalctl`. Expected argv is written out independently of
/// MIRA's code; any deviation exits 64. Outputs are export-format entries.
fn journalctl(mode: &str) -> io::Result<()> {
    const BASE: [&str; 3] = ["--system", "--no-pager", "--quiet"];
    const SENTINEL: [&str; 6] = ["-n", "1", "-o", "export", "--output-fields=_PID", "_PID=1"];
    const FIELDS: &str = "--output-fields=MESSAGE_ID,UNIT,USER_UNIT,COREDUMP_UNIT,COREDUMP_USER_UNIT,_UID,_EXE,_SYSTEMD_UNIT,_SYSTEMD_SLICE";
    const MANAGER: [&str; 2] = ["_UID=0", "_EXE=/usr/lib/systemd/systemd"];
    let args: Vec<String> = env::args().skip(1).collect();
    if let Some(record) = env::var_os("MIRA_FIXTURE_RECORD") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(record)?;
        writeln!(file, "{}", args.join(" "))?;
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if args.len() < 4 || args[..3] != BASE {
        process::exit(64);
    }
    let (previous, rest) = match &args[3..] {
        ["--boot", rest @ ..] => (false, rest),
        ["-b", "-1", rest @ ..] => (true, rest),
        _ => process::exit(64),
    };
    let mut out = io::stdout().lock();
    if rest == SENTINEL {
        let visible = match mode {
            "journal-no-current" => previous,
            "journal-no-previous" if previous => process::exit(1),
            _ => true,
        };
        if visible {
            out.write_all(b"__CURSOR=s=1\n__MONOTONIC_TIMESTAMP=1\n_BOOT_ID=e7\n_PID=1\n\n")?;
        }
        return out.flush();
    }
    let ["-o", "export", fields, "-n", "1001", matches @ ..] = rest else {
        process::exit(64);
    };
    if *fields != FIELDS {
        process::exit(64);
    }
    let group = |ids: &[&str], binding: &[&str]| -> Vec<String> {
        let mut args = Vec::new();
        for (index, id) in ids.iter().enumerate() {
            if index > 0 {
                args.push("+".to_owned());
            }
            args.push(format!("MESSAGE_ID={id}"));
            args.extend(binding.iter().map(|arg| (*arg).to_owned()));
        }
        args
    };
    let oom = group(
        &[
            "fe6faa94e7774663a0da52717891d8ef",
            "d989611b15e44c9dbf31e3c81256e4ed",
        ],
        &MANAGER,
    );
    let failure = group(
        &[
            "d9b373ed55a64feb8242e02dbe79a49c",
            "be02cf6855d2428ba40df7e9d022f03d",
        ],
        &MANAGER,
    );
    let core = group(
        &["fc2e22bc6ee647b6b90729ab34a250b1"],
        &[
            "_EXE=/usr/lib/systemd/systemd-coredump",
            r"_SYSTEMD_SLICE=system-systemd\x2dcoredump.slice",
        ],
    );
    let matches: Vec<String> = matches.iter().map(|arg| (*arg).to_owned()).collect();
    let class = if matches == oom {
        "oom"
    } else if matches == failure {
        "failure"
    } else if matches == core {
        "core"
    } else {
        process::exit(64)
    };
    let manager_entry = |id: &str, unit: &str, account: &str, time: u32| {
        format!(
            "__CURSOR=s=1\n__MONOTONIC_TIMESTAMP={time}\nMESSAGE_ID={id}\nUNIT={unit}\n_UID={account}\n_EXE=/usr/lib/systemd/systemd\n_SYSTEMD_UNIT=init.scope\n\n"
        )
    };
    let core_entry = |unit: &str, cgroup: &str, time: u32| {
        format!(
            "__MONOTONIC_TIMESTAMP={time}\nMESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1\nCOREDUMP_UNIT={unit}\n_UID=989\n_EXE=/usr/lib/systemd/systemd-coredump\n_SYSTEMD_UNIT={cgroup}\n_SYSTEMD_SLICE=system-systemd\\x2dcoredump.slice\n\n"
        )
    };
    let id = if class == "oom" {
        "fe6faa94e7774663a0da52717891d8ef"
    } else {
        "d9b373ed55a64feb8242e02dbe79a49c"
    };
    let body = match (mode, class) {
        ("journal-events", "oom") => manager_entry(id, "db.service", "0", 20) + &manager_entry(id, "home.mount", "0", 10),
        ("journal-events", "failure") => {
            manager_entry(id, "session-3.scope", "0", 30) + &manager_entry(id, r"systemd-fsck@dev-disk-by\x2duuid-1.service", "0", 31)
        }
        ("journal-events", "core") => core_entry("nginx.service", "systemd-coredump@0-77-0.service", 40),
        ("journal-decoys-full", "failure") => manager_entry(id, "forged.service", "33", 5).repeat(1001),
        ("journal-decoys-one-valid", "failure") => {
            manager_entry(id, "forged.service", "33", 5).repeat(1000) + &manager_entry(id, "real.service", "0", 6)
        }
        ("journal-wrong-origin", "failure") => manager_entry(id, "forged.service", "1000", 5),
        ("journal-backtrace", "core") => core_entry("victim.service", "attacker.service", 5),
        ("journal-missing-field", "failure") => {
            "__MONOTONIC_TIMESTAMP=5\nMESSAGE_ID=d9b373ed55a64feb8242e02dbe79a49c\n_UID=0\nUNIT=a.service\n\n".to_owned()
        }
        ("journal-binary", "failure") => "MESSAGE\n\u{5}\0\0\0\0\0\0\0hello\n\n".to_owned(),
        ("journal-bad-unit", "failure") => manager_entry(id, "x.notaunit", "0", 5),
        ("journal-oversized", "failure") => "X".repeat(3 * 1024 * 1024),
        ("journal-fail", "failure") => process::exit(1),
        _ => String::new(),
    };
    out.write_all(body.as_bytes())?;
    out.flush()
}

fn main() -> io::Result<()> {
    let mode = env::var("MIRA_PROCESS_FIXTURE_MODE").unwrap_or_default();
    if mode.starts_with("keygen-") {
        return ssh_keygen(&mode);
    }
    if mode.starts_with("journal-") {
        return journalctl(&mode);
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
