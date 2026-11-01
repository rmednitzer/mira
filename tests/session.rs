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

    fn entries(&self) -> PathBuf {
        self.session().join("entries")
    }

    fn entry(&self, seq: u64) -> PathBuf {
        self.entries().join(format!("{seq:06}.entry"))
    }

    /// The entry line and the signature of one record.
    fn split(&self, seq: u64) -> (String, Vec<u8>) {
        let record = fs::read(self.entry(seq)).unwrap();
        let end = record.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        (
            String::from_utf8(record[..end].to_vec()).unwrap(),
            record[end..].to_vec(),
        )
    }

    fn write_record(&self, seq: u64, line: &str, signature: &[u8]) {
        let mut record = line.as_bytes().to_vec();
        record.extend_from_slice(signature);
        fs::write(self.entry(seq), record).unwrap();
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
        self.verify_as("operator", receipt)
    }

    /// Verify with the verifier's own expectation of who the operator is.
    fn verify_as(&self, operator: &str, receipt: Option<&Path>) -> Output {
        let session = self.session();
        let signers = self.path("signers");
        let mut args = vec![
            "session",
            "verify",
            session.to_str().unwrap(),
            "--allowed-signers",
            signers.to_str().unwrap(),
            "--operator",
            operator,
        ];
        if let Some(receipt) = receipt {
            args.extend(["--expect-close", receipt.to_str().unwrap()]);
        }
        self.mira(&args)
    }

    fn show(&self, json: bool) -> Output {
        let session = self.session();
        let mut args = vec!["session", "show", session.to_str().unwrap()];
        if json {
            args.push("--json");
        }
        self.mira(&args)
    }

    fn state(&self) -> String {
        let output = self.show(true);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        stdout(&output)
    }

    fn raw_sign(&self, bytes: &[u8], key: &str) -> Vec<u8> {
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
        output.stdout
    }

    fn session_id(&self) -> String {
        let (line, _) = self.split(0);
        line.split("\"session_id\":\"").nth(1).unwrap()[..64].to_owned()
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
    assert_eq!(
        stdout(&started),
        format!("MIRA session: started at {}\n", dir.session().display())
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(dir.session()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let (header, signature) = dir.split(0);
    assert!(header.starts_with("{\"session_version\":1,\"session_id\":\""));
    assert!(header.contains("\"kind\":\"header\",\"principal\":\"operator\",\"based_on\":null,\"operator\":\"operator\",\"agent\":\"agent\",\"collector\":\"collector\",\"separation\":\"same_user\",\"autonomy\":\"assisted\",\"budget\":5,"));
    assert!(header.ends_with("\"note\":\"Why did \\\"web\\\" restart? \\\\ check\"}\n"));
    assert!(signature.starts_with(b"-----BEGIN SSH SIGNATURE-----\n"));
    for (sub, extra) in [
        ("ask", vec!["--text", "Is the journal visible?"]),
        ("direct", vec!["--budget", "2", "--text", "keep it short"]),
        ("direct", vec!["--level", "advisory"]),
    ] {
        let output = dir.write(sub, "operator", &extra);
        assert_eq!(output.status.code(), Some(0), "{sub} {output:?}");
    }
    assert_eq!(
        dir.state(),
        "{\"session_version\":1,\"entries\":4,\"closed\":false,\"autonomy\":\"advisory\",\"budget\":2,\"delegated_until\":null}\n"
    );
    let verified = dir.verify(None);
    assert_eq!(
        stdout(&verified),
        "MIRA session: verified entries 4 open\n",
        "{verified:?}"
    );
    // Each record's entry line verifies independently with ssh-keygen.
    let (line, signature) = dir.split(1);
    let signature_file = dir.path("one.sig");
    fs::write(&signature_file, signature).unwrap();
    let independent = Command::new("/usr/bin/ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(dir.path("signers"))
        .args(["-I", "operator", "-n", NAMESPACE, "-s"])
        .arg(&signature_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(line.as_bytes())?;
            child.wait()
        })
        .unwrap();
    assert!(independent.success());
    let text = stdout(&dir.show(false));
    assert!(text.starts_with("MIRA session\nautonomy advisory budget 2 entries 4 open\n"));
    assert!(text.contains("000000 operator header operator=operator agent=agent collector=collector separation=same_user: Why did \"web\" restart? \\ check\n"), "{text}");
    assert!(text.contains("000002 operator directive budget 2: keep it short\n"));
    assert!(text.ends_with("signatures not checked here; run mira session verify\n"));
}

#[test]
fn the_session_id_is_never_printed() {
    let dir = Dir::new();
    let started = dir.start();
    let id = dir.session_id();
    let receipt = dir.path("receipt");
    let outputs = [
        started,
        dir.write("ask", "operator", &["--text", "q"]),
        dir.show(false),
        dir.show(true),
        dir.write(
            "close",
            "operator",
            &["--conclusion", "c", "--receipt", receipt.to_str().unwrap()],
        ),
        dir.verify(Some(&receipt)),
    ];
    for output in outputs {
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(!stdout(&output).contains(&id), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&id));
    }
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
    let receipt = dir.path("receipt.entry");
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
    // Removing the close record leaves a valid-looking open session...
    fs::remove_file(dir.entry(2)).unwrap();
    assert!(dir.verify(None).status.success());
    // ...which only the external receipt exposes.
    not_verified(
        &dir.verify(Some(&receipt)),
        "close receipt does not match the session",
    );
    // A receipt from another session never matches.
    let other = Dir::new();
    assert_eq!(other.start().status.code(), Some(0));
    not_verified(
        &other.verify(Some(&receipt)),
        "close receipt does not match the session",
    );
}

#[test]
fn receipts_are_refused_inside_the_session_or_over_existing_files() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    let session = dir.session();
    // A symbolic link outside the session that resolves into it.
    std::os::unix::fs::symlink(&session, dir.path("alias")).unwrap();
    let taken = dir.path("taken");
    fs::write(&taken, "x").unwrap();
    for receipt in [
        session.join("receipt"),
        session.join("entries").join("receipt"),
        dir.path("alias").join("entries").join("receipt"),
        taken.clone(),
        dir.path("missing-directory").join("receipt"),
    ] {
        let refused = dir.write(
            "close",
            "operator",
            &["--conclusion", "c", "--receipt", receipt.to_str().unwrap()],
        );
        assert_eq!(refused.status.code(), Some(2), "{receipt:?} {refused:?}");
        assert!(refused.stdout.is_empty());
        assert!(dir.state().contains("\"closed\":false"), "{receipt:?}");
    }
    assert!(dir.verify(None).status.success());
    assert!(dir.show(false).status.success());
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
    let entries = dir.entries();
    let (line, signature) = dir.split(2);
    // One changed byte in a note.
    dir.write_record(2, &line.replace("\"two\"", "\"tw0\""), &signature);
    not_verified(&dir.verify(None), "signature of entry 2 not verified");
    // An entry re-signed by a key not listed for its principal.
    dir.write_record(2, &line, &dir.raw_sign(line.as_bytes(), "stranger"));
    not_verified(&dir.verify(None), "signature of entry 2 not verified");
    // An operator-kind entry written and validly signed by the agent.
    let directive = line
        .replace(
            "\"kind\":\"question\",\"principal\":\"operator\"",
            "\"kind\":\"directive\",\"principal\":\"agent\"",
        )
        .replace(
            "\"request_id\":null,\"note\":",
            "\"directive\":\"stop\",\"level\":null,\"budget\":null,\"until_seq\":null,\"note\":",
        );
    dir.write_record(2, &directive, &dir.raw_sign(directive.as_bytes(), "agent"));
    not_verified(
        &dir.verify(None),
        "entry 2 written by a principal without that role",
    );
    dir.write_record(2, &line, &signature);
    assert!(dir.verify(None).status.success());
    // A record without its signature.
    dir.write_record(2, &line, b"");
    not_verified(&dir.verify(None), "malformed entry 2");
    dir.write_record(2, &line, &signature);
    // A missing middle record.
    fs::rename(dir.entry(2), dir.path("held")).unwrap();
    not_verified(&dir.verify(None), "gap at entry 2");
    // A record renamed to another position.
    fs::rename(dir.path("held"), dir.entry(5)).unwrap();
    not_verified(&dir.verify(None), "gap at entry 2");
    fs::rename(dir.entry(5), dir.entry(2)).unwrap();
    // An unexpected file.
    fs::write(entries.join("notes.txt"), "x").unwrap();
    not_verified(&dir.verify(None), "unexpected file in the session log");
    fs::remove_file(entries.join("notes.txt")).unwrap();
    // A validly signed record copied in from another session.
    let other = Dir::new();
    // Same operator key pair in both sessions; ssh-keygen reads KEY.pub too.
    for name in ["operator", "operator.pub", "signers"] {
        fs::copy(dir.path(name), other.path(name)).unwrap();
    }
    assert_eq!(other.start().status.code(), Some(0));
    assert_eq!(
        other
            .write("ask", "operator", &["--text", "elsewhere"])
            .status
            .code(),
        Some(0)
    );
    fs::copy(other.entry(1), dir.entry(4)).unwrap();
    not_verified(
        &dir.verify(None),
        "entry 4 belongs to another session or position",
    );
    fs::remove_file(dir.entry(4)).unwrap();
    assert!(dir.verify(None).status.success());
}

#[test]
fn a_listed_agent_cannot_forge_a_session_as_operator() {
    let dir = Dir::new();
    // The agent writes a complete session naming itself operator, signing
    // every record with its own listed key; no operator key is involved.
    let id = "ab".repeat(32);
    let forged = [
        format!(
            "{{\"session_version\":1,\"session_id\":\"{id}\",\"seq\":0,\"kind\":\"header\",\"principal\":\"agent\",\"based_on\":null,\"operator\":\"agent\",\"agent\":\"helper\",\"collector\":\"collector\",\"separation\":\"same_user\",\"autonomy\":\"assisted\",\"budget\":5,\"note\":\"forged\"}}\n"
        ),
        format!(
            "{{\"session_version\":1,\"session_id\":\"{id}\",\"seq\":1,\"kind\":\"directive\",\"principal\":\"agent\",\"based_on\":0,\"directive\":\"delegate\",\"level\":null,\"budget\":null,\"until_seq\":99,\"note\":\"self-granted\"}}\n"
        ),
    ];
    fs::create_dir_all(dir.entries()).unwrap();
    for (seq, line) in forged.iter().enumerate() {
        dir.write_record(seq as u64, line, &dir.raw_sign(line.as_bytes(), "agent"));
    }
    // Trusting the header's own claim would accept it as signed by "agent".
    assert!(dir.verify_as("agent", None).status.success());
    // The verifier names the operator it trusts; the forgery fails.
    not_verified(
        &dir.verify(None),
        "session operator is not the expected principal",
    );
    // The real operator's key cannot append to it either: it never verifies
    // as the forged header's "operator".
    assert_eq!(
        dir.write("ask", "operator", &["--text", "q"]).status.code(),
        Some(4)
    );
}

#[test]
fn readers_never_see_partial_entries_while_writers_append() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    let session = dir.session();
    let signers = dir.path("signers");
    let key = dir.path("operator");
    let mut writers: Vec<_> = (0..6)
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
    // Readers run throughout; every one must see a complete, valid log.
    let mut reads = 0;
    while !writers.is_empty() {
        let shown = dir.show(true);
        assert_eq!(shown.status.code(), Some(0), "{shown:?}");
        reads += 1;
        writers.retain_mut(|child| match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success());
                false
            }
            None => true,
        });
    }
    assert!(reads > 0);
    assert_eq!(
        stdout(&dir.verify(None)),
        "MIRA session: verified entries 7 open\n"
    );
    let leftovers: Vec<_> = fs::read_dir(dir.entries())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(".pending-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn files_left_by_an_interrupted_writer_never_block_the_session() {
    let dir = Dir::new();
    assert_eq!(dir.start().status.code(), Some(0));
    // A writer killed before publishing leaves only pending files.
    fs::write(dir.entries().join(".pending-1-0-0.entry"), "partial").unwrap();
    fs::write(dir.entries().join(".pending-1-0-0.sig"), "partial").unwrap();
    assert!(dir.show(true).status.success());
    assert_eq!(
        dir.write("ask", "operator", &["--text", "after"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        stdout(&dir.verify(None)),
        "MIRA session: verified entries 2 open\n"
    );
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
    assert_eq!(dir.start().status.code(), Some(4));
    assert!(dir.entry(0).is_file());
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
    assert_eq!(other.show(false).status.code(), Some(1));
}
