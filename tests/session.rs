//! Shared-workspace session core (ADR 0015 stage 1a) end to end, against the
//! real /usr/bin/ssh-keygen with throwaway keys.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const NAMESPACE: &str = "mira-session-v1@rmednitzer.github.io";

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mira-session-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let dir = Self(path);
        let mut signers = String::new();
        for name in ["operator", "agent", "collector", "stranger"] {
            let key = dir.path(name);
            assert!(
                Command::new("/usr/bin/ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
                    .arg(&key)
                    .stdin(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            // The stranger's key is deliberately not listed.
            if name != "stranger" {
                let public = fs::read_to_string(key.with_extension("pub")).unwrap();
                let public: Vec<_> = public.split_whitespace().take(2).collect();
                signers.push_str(&format!(
                    "{name} namespaces=\"{NAMESPACE}\" {}\n",
                    public.join(" ")
                ));
            }
        }
        fs::write(dir.path("signers"), signers).unwrap();
        dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn session(&self) -> PathBuf {
        self.path("session")
    }

    fn mira(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// `mira session SUB SESSION --allowed-signers S --key KEY extra...`
    fn write(&self, sub: &str, key: &str, extra: &[&str]) -> Output {
        let session = self.session();
        let signers = self.path("signers");
        let key = self.path(key);
        let mut args = vec![
            "session",
            sub,
            session.to_str().unwrap(),
            "--allowed-signers",
            signers.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ];
        args.extend(extra);
        self.mira(&args)
    }

    fn start(&self) -> Output {
        self.write(
            "start",
            "operator",
            &[
                "--operator",
                "operator",
                "--agent",
                "agent",
                "--collector",
                "collector",
                "--budget",
                "5",
                "--question",
                "Why did \"web\" restart? \\ check",
            ],
        )
    }

    fn verify(&self, receipt: Option<&Path>) -> Output {
        let session = self.session();
        let signers = self.path("signers");
        let mut args = vec![
            "session",
            "verify",
            session.to_str().unwrap(),
            "--allowed-signers",
            signers.to_str().unwrap(),
        ];
        if let Some(receipt) = receipt {
            args.extend(["--expect-close", receipt.to_str().unwrap()]);
        }
        self.mira(&args)
    }

    fn state(&self) -> String {
        let session = self.session();
        let output = self.mira(&["session", "show", session.to_str().unwrap(), "--json"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        stdout(&output)
    }

    fn entry(&self, seq: u64) -> PathBuf {
        self.session()
            .join("entries")
            .join(format!("{seq:06}.json"))
    }

    fn raw_sign(&self, bytes: &[u8], key: &str, signature: &Path) {
        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(self.path(key))
            .args(["-n", NAMESPACE])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(bytes)?;
                child.wait_with_output()
            })
            .unwrap();
        assert!(output.status.success());
        let _ = fs::remove_file(signature);
        fs::write(signature, output.stdout).unwrap();
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && !std::thread::panicking()
        {
            panic!("fixture cleanup failed: {error}");
        }
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn not_verified(output: &Output, reason: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        stdout(output),
        format!("MIRA session: not verified ({reason})\n"),
        "{output:?}"
    );
}

#[test]
fn a_session_records_operator_entries_and_verifies() {
    let dir = Dir::new();
    let started = dir.start();
    assert_eq!(started.status.code(), Some(0), "{started:?}");
    assert!(stdout(&started).starts_with("MIRA session: started "));
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(dir.session()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let header = fs::read_to_string(dir.entry(0)).unwrap();
    assert!(header.starts_with("{\"session_version\":1,\"session_id\":\""));
    assert!(header.contains("\"kind\":\"header\",\"principal\":\"operator\",\"based_on\":null,\"operator\":\"operator\",\"agent\":\"agent\",\"collector\":\"collector\",\"separation\":\"same_user\",\"autonomy\":\"assisted\",\"budget\":5,"));
    assert!(header.ends_with("\"note\":\"Why did \\\"web\\\" restart? \\\\ check\"}\n"));
    for (sub, extra) in [
        ("ask", vec!["--text", "Is the journal visible?"]),
        ("direct", vec!["--budget", "2", "--text", "keep it short"]),
        ("direct", vec!["--level", "advisory"]),
    ] {
        let output = dir.write(sub, "operator", &extra);
        assert_eq!(output.status.code(), Some(0), "{sub} {output:?}");
    }
    let state = dir.state();
    assert!(state.contains("\"entries\":4,\"closed\":false,\"autonomy\":\"advisory\",\"budget\":2,\"delegated_until\":null}"), "{state}");
    let verified = dir.verify(None);
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
    assert!(stdout(&verified).ends_with(" entries 4 open\n"));
    // Each entry verifies independently with ssh-keygen under the session namespace.
    let independent = Command::new("/usr/bin/ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(dir.path("signers"))
        .args(["-I", "operator", "-n", NAMESPACE, "-s"])
        .arg(dir.session().join("entries/000001.sig"))
        .stdin(fs::File::open(dir.entry(1)).unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(independent.success());
    let session = dir.session();
    let shown = dir.mira(&["session", "show", session.to_str().unwrap()]);
    let text = stdout(&shown);
    assert!(text.contains("000000 operator header operator=operator agent=agent collector=collector separation=same_user: Why did \"web\" restart? \\ check\n"), "{text}");
    assert!(text.contains("000002 operator directive budget 2: keep it short\n"));
    assert!(text.ends_with("signatures not checked here; run mira session verify\n"));
}

#[test]
fn delegation_expires_and_stop_takes_precedence() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    // Delegation covers entries up to 2 and lapses to assisted at 3.
    assert_eq!(
        dir.write("direct", "operator", &["--delegate-until", "2"])
            .status
            .code(),
        Some(0)
    );
    assert!(
        dir.state()
            .contains("\"autonomy\":\"delegated\",\"budget\":5,\"delegated_until\":2}")
    );
    assert_eq!(
        dir.write("ask", "operator", &["--text", "covered"])
            .status
            .code(),
        Some(0)
    );
    assert!(dir.state().contains("\"autonomy\":\"delegated\""));
    assert_eq!(
        dir.write("ask", "operator", &["--text", "lapsed"])
            .status
            .code(),
        Some(0)
    );
    assert!(
        dir.state()
            .contains("\"autonomy\":\"assisted\",\"budget\":5,\"delegated_until\":null}")
    );
    assert_eq!(
        dir.write("direct", "operator", &["--delegate-until", "9"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        dir.write("direct", "operator", &["--stop"]).status.code(),
        Some(0)
    );
    assert!(
        dir.state()
            .contains("\"autonomy\":\"manual\",\"budget\":5,\"delegated_until\":null}")
    );
    // A delegation that would end at or before its own entry is refused.
    let refused = dir.write("direct", "operator", &["--delegate-until", "6"]);
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert_eq!(
        stdout(&refused),
        "MIRA session: refused (directive contradicts the session state)\n"
    );
    assert_eq!(dir.verify(None).status.code(), Some(0));
}

#[test]
fn a_closed_session_refuses_appends_and_its_receipt_detects_truncation() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    assert_eq!(
        dir.write("ask", "operator", &["--text", "q"]).status.code(),
        Some(0)
    );
    let receipt = dir.path("receipt.json");
    let closed = dir.write(
        "close",
        "operator",
        &[
            "--conclusion",
            "OOM kill of web",
            "--receipt",
            receipt.to_str().unwrap(),
        ],
    );
    assert_eq!(closed.status.code(), Some(0), "{closed:?}");
    assert_eq!(stdout(&closed), "MIRA session: closed at 000002\n");
    assert_eq!(fs::read(&receipt).unwrap(), fs::read(dir.entry(2)).unwrap());
    assert!(dir.verify(Some(&receipt)).status.success());
    for (sub, extra) in [
        ("ask", vec!["--text", "late"]),
        ("direct", vec!["--stop"]),
        ("close", vec!["--conclusion", "again"]),
    ] {
        let refused = dir.write(sub, "operator", &extra);
        assert_eq!(refused.status.code(), Some(1), "{sub}");
        assert_eq!(
            stdout(&refused),
            "MIRA session: refused (session is closed)\n"
        );
    }
    // Removing the close entry leaves a valid-looking open session...
    fs::remove_file(dir.entry(2)).unwrap();
    fs::remove_file(dir.session().join("entries/000002.sig")).unwrap();
    assert!(dir.verify(None).status.success());
    // ...which only the external receipt exposes.
    not_verified(
        &dir.verify(Some(&receipt)),
        "close receipt does not match the session",
    );
    // An existing receipt path is refused before anything is written.
    let other = Dir::new();
    assert_eq!(other.start().status.code(), Some(0));
    let taken = other.path("taken.json");
    fs::write(&taken, "x").unwrap();
    let refused = other.write(
        "close",
        "operator",
        &["--conclusion", "c", "--receipt", taken.to_str().unwrap()],
    );
    assert_eq!(refused.status.code(), Some(2));
    assert!(other.state().contains("\"closed\":false"));
    // A receipt from another session never matches.
    not_verified(
        &other.verify(Some(&receipt)),
        "close receipt does not match the session",
    );
}

#[test]
fn tampering_gaps_foreign_entries_and_wrong_roles_are_not_verified() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    for text in ["one", "two", "three"] {
        assert_eq!(
            dir.write("ask", "operator", &["--text", text])
                .status
                .code(),
            Some(0)
        );
    }
    let entries = dir.session().join("entries");
    // One changed byte in a note.
    let original = fs::read_to_string(dir.entry(2)).unwrap();
    fs::write(dir.entry(2), original.replace("\"two\"", "\"tw0\"")).unwrap();
    not_verified(&dir.verify(None), "signature of entry 2 not verified");
    fs::write(dir.entry(2), &original).unwrap();
    assert!(dir.verify(None).status.success());
    // An entry signed by a key not listed for its principal.
    let saved = fs::read(entries.join("000002.sig")).unwrap();
    dir.raw_sign(original.as_bytes(), "stranger", &entries.join("000002.sig"));
    not_verified(&dir.verify(None), "signature of entry 2 not verified");
    fs::write(entries.join("000002.sig"), &saved).unwrap();
    // An operator-kind entry written and validly signed by the agent.
    let directive = original
        .replace(
            "\"kind\":\"question\",\"principal\":\"operator\"",
            "\"kind\":\"directive\",\"principal\":\"agent\"",
        )
        .replace(
            "\"note\":",
            "\"directive\":\"stop\",\"level\":null,\"budget\":null,\"until_seq\":null,\"note\":",
        );
    fs::write(dir.entry(2), &directive).unwrap();
    dir.raw_sign(directive.as_bytes(), "agent", &entries.join("000002.sig"));
    not_verified(
        &dir.verify(None),
        "entry 2 written by a principal without that role",
    );
    fs::write(dir.entry(2), &original).unwrap();
    fs::write(entries.join("000002.sig"), &saved).unwrap();
    // A missing middle entry.
    fs::rename(dir.entry(2), dir.path("held.json")).unwrap();
    not_verified(&dir.verify(None), "gap at entry 2");
    fs::rename(dir.path("held.json"), dir.entry(2)).unwrap();
    // A missing signature.
    fs::rename(entries.join("000003.sig"), dir.path("held.sig")).unwrap();
    not_verified(&dir.verify(None), "gap at entry 3");
    fs::rename(dir.path("held.sig"), entries.join("000003.sig")).unwrap();
    // A file renamed to another position.
    fs::rename(dir.entry(3), dir.entry(4)).unwrap();
    fs::rename(entries.join("000003.sig"), entries.join("000004.sig")).unwrap();
    not_verified(&dir.verify(None), "gap at entry 3");
    fs::rename(dir.entry(4), dir.entry(3)).unwrap();
    fs::rename(entries.join("000004.sig"), entries.join("000003.sig")).unwrap();
    // An unexpected file.
    fs::write(entries.join("notes.txt"), "x").unwrap();
    not_verified(&dir.verify(None), "unexpected file in the session log");
    fs::remove_file(entries.join("notes.txt")).unwrap();
    // A validly signed entry copied in from another session.
    let other = Dir::new();
    // Same operator key pair in both sessions; ssh-keygen reads KEY.pub too.
    fs::copy(dir.path("operator"), other.path("operator")).unwrap();
    fs::copy(dir.path("operator.pub"), other.path("operator.pub")).unwrap();
    fs::copy(dir.path("signers"), other.path("signers")).unwrap();
    assert_eq!(other.start().status.code(), Some(0));
    assert_eq!(
        other
            .write("ask", "operator", &["--text", "elsewhere"])
            .status
            .code(),
        Some(0)
    );
    fs::copy(other.entry(1), dir.entry(4)).unwrap();
    fs::copy(
        other.session().join("entries/000001.sig"),
        entries.join("000004.sig"),
    )
    .unwrap();
    let replayed = dir.verify(None);
    assert_eq!(replayed.status.code(), Some(1));
    assert!(stdout(&replayed).contains("entry 4"), "{replayed:?}");
    fs::remove_file(dir.entry(4)).unwrap();
    fs::remove_file(entries.join("000004.sig")).unwrap();
    assert!(dir.verify(None).status.success());
}

#[test]
fn concurrent_writers_take_distinct_sequence_numbers() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    let session = dir.session();
    let signers = dir.path("signers");
    let key = dir.path("operator");
    let children: Vec<_> = (0..6)
        .map(|index| {
            Command::new(env!("CARGO_BIN_EXE_mira"))
                .args(["session", "ask"])
                .arg(&session)
                .arg("--allowed-signers")
                .arg(&signers)
                .arg("--key")
                .arg(&key)
                .args(["--text", &format!("writer {index}")])
                .stdout(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let verified = dir.verify(None);
    assert!(verified.status.success(), "{verified:?}");
    assert!(stdout(&verified).ends_with(" entries 7 open\n"));
    let leftovers: Vec<_> = fs::read_dir(session.join("entries"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(".pending-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn wrong_keys_and_bad_invocations_write_nothing() {
    let dir = Dir::new();
    // A key not listed for the operator cannot start a session.
    let refused = dir.write(
        "start",
        "stranger",
        &[
            "--operator",
            "operator",
            "--agent",
            "agent",
            "--collector",
            "collector",
            "--question",
            "q",
        ],
    );
    assert_eq!(refused.status.code(), Some(4), "{refused:?}");
    assert!(
        !dir.session().exists(),
        "a failed start leaves nothing behind"
    );
    assert_eq!(dir.start().status.code(), Some(0));
    // An existing directory is never reused or removed.
    let existing = dir.start();
    assert_eq!(existing.status.code(), Some(4));
    assert!(dir.session().join("entries/000000.json").is_file());
    // The agent's key cannot write as the operator.
    assert_eq!(
        dir.write("ask", "agent", &["--text", "q"]).status.code(),
        Some(4)
    );
    assert!(dir.state().contains("\"entries\":1,"));
    for (sub, extra) in [
        ("ask", vec![]),
        ("ask", vec!["--text", "a", "--text", "b"]),
        ("ask", vec!["--text", "line\nbreak"]),
        ("ask", vec!["--text", "esc\u{1b}[2J"]),
        ("ask", vec!["--text", "bidi\u{202e}"]),
        ("direct", vec![]),
        ("direct", vec!["--stop", "--level", "manual"]),
        ("direct", vec!["--level", "delegated"]),
        ("direct", vec!["--budget", "-1"]),
        ("direct", vec!["--budget", "01"]),
        ("direct", vec!["--unknown"]),
        ("close", vec![]),
        ("frobnicate", vec![]),
    ] {
        let output = dir.write(sub, "operator", &extra);
        assert_eq!(output.status.code(), Some(2), "{sub} {extra:?}");
        assert!(output.stdout.is_empty(), "{sub} {extra:?}");
    }
    let long = "a".repeat(1025);
    assert_eq!(
        dir.write("ask", "operator", &["--text", &long])
            .status
            .code(),
        Some(2)
    );
    assert!(dir.state().contains("\"entries\":1,"));
    let other = Dir::new();
    for extra in [
        vec![
            "--operator",
            "operator",
            "--agent",
            "operator",
            "--collector",
            "collector",
            "--question",
            "q",
        ],
        vec![
            "--operator",
            "-bad",
            "--agent",
            "agent",
            "--collector",
            "collector",
            "--question",
            "q",
        ],
        vec![
            "--operator",
            "operator",
            "--agent",
            "agent",
            "--collector",
            "collector",
            "--autonomy",
            "delegated",
            "--question",
            "q",
        ],
    ] {
        assert_eq!(
            other.write("start", "operator", &extra).status.code(),
            Some(2),
            "{extra:?}"
        );
        assert!(!other.session().exists());
    }
    // A directory that is not a session is invalid, not a crash.
    let session = other.session();
    fs::create_dir(&session).unwrap();
    let shown = other.mira(&["session", "show", session.to_str().unwrap()]);
    assert_eq!(shown.status.code(), Some(1));
}
