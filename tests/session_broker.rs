//! The session broker (ADR 0015 stage 1b) end to end, against the real
//! /usr/bin/ssh-keygen with throwaway keys: agent requests, admission,
//! refusals, execution as MIRA itself, collector-signed results and verify.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SESSION: &str = "mira-session-v1@rmednitzer.github.io";
const DOCUMENTS: &str =
    "mira-capture-v1@rmednitzer.github.io,mira-investigation-v1@rmednitzer.github.io";

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mira-broker-{}-{}",
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
            let public = fs::read_to_string(key.with_extension("pub")).unwrap();
            let public: Vec<_> = public.split_whitespace().take(2).collect();
            // The collector signs result documents as well as entries.
            let namespaces = match name {
                "collector" => format!("{SESSION},{DOCUMENTS}"),
                // The agent is listed for documents too, so a document it
                // re-signs verifies as the agent's but never as the collector's.
                "agent" => format!("{SESSION},{DOCUMENTS}"),
                _ => SESSION.to_owned(),
            };
            if name != "stranger" {
                signers.push_str(&format!(
                    "{name} namespaces=\"{namespaces}\" {}\n",
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

    fn command(&self, sub: &str, key: &str, extra: &[&str]) -> Output {
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

    fn start(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "--operator",
            "operator",
            "--agent",
            "agent",
            "--collector",
            "collector",
            "--question",
            "Is memory the problem?",
        ];
        args.extend(extra);
        self.command("start", "operator", &args)
    }

    fn request(&self, extra: &[&str]) -> Output {
        self.command("request", "agent", extra)
    }

    fn broker(&self) -> Output {
        self.command("run", "collector", &["--once"])
    }

    fn verify(&self) -> Output {
        let session = self.session();
        let signers = self.path("signers");
        self.mira(&[
            "session",
            "verify",
            session.to_str().unwrap(),
            "--allowed-signers",
            signers.to_str().unwrap(),
            "--operator",
            "operator",
        ])
    }

    fn state(&self) -> String {
        let session = self.session();
        stdout(&self.mira(&["session", "show", session.to_str().unwrap(), "--json"]))
    }

    fn line(&self, seq: u64) -> String {
        let record = fs::read(self.session().join(format!("entries/{seq:06}.entry"))).unwrap();
        let end = record.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        String::from_utf8(record[..end].to_vec()).unwrap()
    }

    fn sign(&self, bytes: &[u8], key: &str, namespace: &str) -> Vec<u8> {
        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(self.path(key))
            .args(["-n", namespace])
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
        self.line(0).split("\"session_id\":\"").nth(1).unwrap()[..64].to_owned()
    }

    /// Drop a hand-made request record, signed by `key`, into the inbox.
    fn plant(&self, id: &str, key: &str, capability: &str, arguments: &str) {
        let line = format!(
            "{{\"session_version\":1,\"session_id\":\"{}\",\"kind\":\"request\",\"request_id\":\"{id}\",\"principal\":\"agent\",\"based_on\":0,\"request\":\"action\",\"capability\":\"{capability}\",\"arguments\":\"{arguments}\",\"note\":\"planted\"}}\n",
            self.session_id()
        );
        let mut record = line.as_bytes().to_vec();
        record.extend(self.sign(line.as_bytes(), key, SESSION));
        fs::write(self.session().join(format!("inbox/{id}.request")), record).unwrap();
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
fn an_admitted_request_runs_once_and_yields_a_collector_signed_result() {
    let dir = Dir::new();
    assert!(dir.start(&["--budget", "2"]).status.success());
    let submitted = dir.request(&[
        "--capability",
        "memory-headroom",
        "--arguments",
        "1",
        "--text",
        "check headroom first",
    ]);
    assert_eq!(
        stdout(&submitted),
        "MIRA session: request submitted\n",
        "{submitted:?}"
    );
    let inbox: Vec<_> = fs::read_dir(dir.session().join("inbox")).unwrap().collect();
    assert_eq!(inbox.len(), 1);
    let ran = dir.broker();
    assert_eq!(
        stdout(&ran),
        "MIRA session: admitted request as 000001\n",
        "{ran:?}"
    );
    assert_eq!(
        fs::read_dir(dir.session().join("inbox")).unwrap().count(),
        0
    );
    let action = dir.line(1);
    assert!(
        action.contains(
            "\"kind\":\"action\",\"principal\":\"collector\",\"based_on\":0,\"request_id\":\""
        ),
        "{action}"
    );
    assert!(action.ends_with("\"capability\":\"memory-headroom\",\"arguments\":\"1\",\"note\":\"check headroom first\"}\n"));
    let result = dir.line(2);
    assert!(result.contains("\"kind\":\"result\",\"principal\":\"collector\",\"based_on\":1,\"action_seq\":1,\"exit_status\":"), "{result}");
    // The real memory evidence decides; a minimum of 1 KiB is met when observed.
    assert!(
        result.contains("\"exit_status\":0,\"outcome\":\"satisfied\"")
            || result.contains("\"exit_status\":3,\"outcome\":\"indeterminate\""),
        "{result}"
    );
    assert!(
        dir.state()
            .contains("\"entries\":3,\"closed\":false,\"autonomy\":\"assisted\",\"budget\":1,")
    );
    // The document verifies as the collector's with plain mira verify.
    let document = dir.session().join("documents/000001.json");
    let signature = dir.session().join("documents/000001.json.sig");
    let signers = dir.path("signers");
    let verified = dir.mira(&[
        "verify",
        document.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--allowed-signers",
        signers.to_str().unwrap(),
        "--principal",
        "collector",
    ]);
    assert!(verified.status.success(), "{verified:?}");
    assert!(
        fs::read_to_string(&document)
            .unwrap()
            .contains("\"template\":\"memory-headroom/v1\"")
    );
    assert_eq!(
        stdout(&dir.verify()),
        "MIRA session: verified entries 3 open\n"
    );
    let shown = stdout(&dir.mira(&["session", "show", dir.session().to_str().unwrap()]));
    assert!(
        shown.contains(
            "000001 collector action memory-headroom 1 (agent request): check headroom first\n"
        ),
        "{shown}"
    );
}

#[test]
fn refusals_follow_autonomy_budget_capability_and_precedence() {
    let dir = Dir::new();
    assert!(dir.start(&["--budget", "2"]).status.success());
    let ask = |capability: &str, arguments: &str| {
        let output = dir.request(&[
            "--capability",
            capability,
            "--arguments",
            arguments,
            "--text",
            "go",
        ]);
        assert!(output.status.success(), "{output:?}");
        stdout(&dir.broker())
    };
    // The boot ID is operator-only below delegation.
    assert_eq!(
        ask("capture", "host bind-boot"),
        "MIRA session: refused request (operator_only)\n"
    );
    // That refusal cost one unit; one admitted action uses the rest.
    assert!(ask("uptime-minimum", "1").starts_with("MIRA session: admitted request as "));
    // With no budget left the request is dropped without an entry.
    let before = dir.state();
    assert_eq!(
        ask("uptime-minimum", "1"),
        "MIRA session: discarded request (no budget left, or only the operator's reserve)\n"
    );
    assert_eq!(dir.state(), before);
    // A request written before a stop is superseded by it.
    assert!(
        dir.command("direct", "operator", &["--budget", "5"])
            .status
            .success()
    );
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "late"
        ])
        .status
        .success()
    );
    assert!(
        dir.command("direct", "operator", &["--stop"])
            .status
            .success()
    );
    assert_eq!(
        stdout(&dir.broker()),
        "MIRA session: refused request (superseded_by_directive)\n"
    );
    // Without an intervening directive, manual or advisory is plain autonomy.
    assert_eq!(
        ask("uptime-minimum", "1"),
        "MIRA session: refused request (autonomy)\n"
    );
    assert!(
        dir.command("direct", "operator", &["--level", "advisory"])
            .status
            .success()
    );
    assert!(
        dir.request(&["--question", "--text", "is swap enabled?"])
            .status
            .success()
    );
    let admitted = stdout(&dir.broker());
    let seq: u64 = admitted
        .strip_prefix("MIRA session: admitted request as ")
        .and_then(|rest| rest.trim_end().parse().ok())
        .unwrap_or_else(|| panic!("{admitted}"));
    assert!(
        dir.line(seq)
            .contains("\"kind\":\"question\",\"principal\":\"collector\"")
    );
    // Delegation admits the operator-only capture.
    assert!(
        dir.command("direct", "operator", &["--delegate-until", "40"])
            .status
            .success()
    );
    assert!(ask("capture", "host bind-boot").starts_with("MIRA session: admitted request as "));
    assert!(stdout(&dir.verify()).starts_with("MIRA session: verified entries "));
}

#[test]
fn forged_malformed_and_replayed_requests_never_run() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    let ids = ["11", "22", "33", "44"].map(|byte| byte.repeat(32));
    // Signed by a key not listed for the agent.
    dir.plant(&ids[0], "stranger", "uptime-minimum", "1");
    // Validly signed, but outside the closed capability set or option-shaped.
    dir.plant(&ids[1], "agent", "inspect", "");
    dir.plant(&ids[2], "agent", "memory-headroom", "--json");
    // Not a request at all.
    fs::write(
        dir.session().join(format!("inbox/{}.request", ids[3])),
        "garbage",
    )
    .unwrap();
    // Names that are not request IDs are never processed.
    fs::write(dir.session().join("inbox/notes.txt"), "x").unwrap();
    let ran = stdout(&dir.broker());
    let mut lines: Vec<_> = ran.lines().collect();
    lines.sort();
    assert_eq!(
        lines,
        [
            "MIRA session: refused request (capability)",
            "MIRA session: refused request (capability)",
            "MIRA session: refused request (malformed)",
            "MIRA session: refused request (signature)",
        ],
        "{ran}"
    );
    // Anything in the inbox that is not a request is purged.
    assert!(!dir.session().join("inbox/notes.txt").exists());
    // A request admitted once and dropped into the inbox again is discarded.
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "once"
        ])
        .status
        .success()
    );
    let stored: Vec<_> = fs::read_dir(dir.session().join("inbox"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "request"))
        .collect();
    let copy = fs::read(&stored[0]).unwrap();
    assert!(stdout(&dir.broker()).starts_with("MIRA session: admitted request as "));
    fs::write(&stored[0], copy).unwrap();
    assert_eq!(
        stdout(&dir.broker()),
        "MIRA session: discarded replayed request\n"
    );
    let entries = dir.state();
    assert!(
        stdout(&dir.verify()).starts_with("MIRA session: verified entries "),
        "{entries}"
    );
}

#[test]
fn the_operator_acts_directly_and_the_agent_cannot_sign_results() {
    let dir = Dir::new();
    assert!(dir.start(&["--budget", "0"]).status.success());
    let collector = dir.path("collector");
    let acted = dir.command(
        "act",
        "operator",
        &[
            "--collector-key",
            collector.to_str().unwrap(),
            "--capability",
            "capture",
            "--arguments",
            "host",
            "--text",
            "baseline",
        ],
    );
    assert!(
        stdout(&acted).starts_with("MIRA session: action 000001 result 000002 complete_"),
        "{acted:?}"
    );
    assert!(dir.line(1).contains("\"kind\":\"action\",\"principal\":\"operator\",\"based_on\":0,\"request_id\":null,\"capability\":\"capture\",\"arguments\":\"host\""));
    assert!(
        fs::read_to_string(dir.session().join("documents/000001.json"))
            .unwrap()
            .starts_with("{\"capture_version\":2,")
    );
    // Operator actions need no budget, and child refusals are recorded.
    let refused = dir.command(
        "act",
        "operator",
        &[
            "--collector-key",
            collector.to_str().unwrap(),
            "--capability",
            "memory-headroom",
            "--arguments",
            "abc",
        ],
    );
    assert_eq!(
        stdout(&refused),
        "MIRA session: action 000003 result 000004 refused_arguments\n",
        "{refused:?}"
    );
    assert!(!dir.session().join("documents/000003.json").exists());
    // The agent's key cannot stand in for the collector's.
    let agent = dir.path("agent");
    let forged = dir.command(
        "act",
        "operator",
        &[
            "--collector-key",
            agent.to_str().unwrap(),
            "--capability",
            "capture",
            "--arguments",
            "host",
        ],
    );
    assert_eq!(forged.status.code(), Some(4), "{forged:?}");
    assert_eq!(
        dir.command("run", "agent", &["--once"]).status.code(),
        Some(4)
    );
    assert!(stdout(&dir.verify()).starts_with("MIRA session: verified entries "));
}

#[test]
fn verify_rejects_altered_requests_and_documents() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "how long up?"
        ])
        .status
        .success()
    );
    assert!(stdout(&dir.broker()).starts_with("MIRA session: admitted request as 000001"));
    assert!(dir.verify().status.success());
    // The stored agent request, edited after the fact.
    let requests: Vec<_> = fs::read_dir(dir.session().join("requests"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    let original = fs::read(&requests[0]).unwrap();
    let edited = String::from_utf8_lossy(&original).replace("how long up?", "how long up!");
    fs::write(&requests[0], edited.as_bytes()).unwrap();
    not_verified(
        &dir.verify(),
        "agent request relayed by entry 1 missing or altered",
    );
    // A validly signed agent request whose fields differ from the entry.
    let line = String::from_utf8_lossy(
        &original[..original.iter().position(|b| *b == b'\n').unwrap() + 1],
    )
    .replace("how long up?", "how long up!");
    let mut resigned = line.as_bytes().to_vec();
    resigned.extend(dir.sign(line.as_bytes(), "agent", SESSION));
    fs::write(&requests[0], &resigned).unwrap();
    not_verified(
        &dir.verify(),
        "agent request relayed by entry 1 missing or altered",
    );
    fs::write(&requests[0], &original).unwrap();
    assert!(dir.verify().status.success());
    // The result document, edited, re-signed by the agent, or removed.
    let document = dir.session().join("documents/000001.json");
    let signature = dir.session().join("documents/000001.json.sig");
    let bytes = fs::read(&document).unwrap();
    let saved = fs::read(&signature).unwrap();
    fs::write(
        &document,
        String::from_utf8_lossy(&bytes)
            .replacen("\"outcome\":", "\"outcome\" :", 1)
            .as_bytes(),
    )
    .unwrap();
    not_verified(
        &dir.verify(),
        "document of result 2 missing or not signed by the collector",
    );
    fs::write(&document, &bytes).unwrap();
    fs::write(
        &signature,
        dir.sign(
            &bytes,
            "agent",
            "mira-investigation-v1@rmednitzer.github.io",
        ),
    )
    .unwrap();
    not_verified(
        &dir.verify(),
        "document of result 2 missing or not signed by the collector",
    );
    fs::write(&signature, &saved).unwrap();
    fs::remove_file(&document).unwrap();
    not_verified(
        &dir.verify(),
        "document of result 2 missing or not signed by the collector",
    );
}

#[test]
fn a_closed_session_stops_the_broker_and_refuses_requests() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    assert!(
        dir.command("close", "operator", &["--conclusion", "done"])
            .status
            .success()
    );
    let ran = dir.command("run", "collector", &[]);
    assert_eq!(stdout(&ran), "MIRA session: closed; broker stopped\n");
    assert_eq!(ran.status.code(), Some(0));
    let refused = dir.request(&["--question", "--text", "late"]);
    assert_eq!(
        stdout(&refused),
        "MIRA session: refused (session is closed)\n"
    );
}

#[test]
fn invalid_requests_are_usage_errors_before_anything_is_signed() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    for extra in [
        vec!["--text", "nothing asked"],
        vec!["--question", "--capability", "capture", "--text", "both"],
        vec![
            "--question",
            "--arguments",
            "x",
            "--text",
            "arguments without capability",
        ],
        vec!["--capability", "inspect", "--text", "outside the set"],
        vec![
            "--capability",
            "memory-headroom",
            "--arguments",
            "--json",
            "--text",
            "option-shaped",
        ],
        vec![
            "--capability",
            "capture",
            "--arguments",
            "host  bind-boot",
            "--text",
            "double space",
        ],
        vec!["--question", "--text", "bidi\u{202e}"],
    ] {
        let output = dir.request(&extra);
        assert_eq!(output.status.code(), Some(2), "{extra:?} {output:?}");
    }
    assert_eq!(
        fs::read_dir(dir.session().join("inbox")).unwrap().count(),
        0
    );
    // A key that is not the agent's never reaches the inbox.
    assert_eq!(
        dir.command("request", "stranger", &["--question", "--text", "q"])
            .status
            .code(),
        Some(4)
    );
    assert_eq!(
        dir.command("request", "operator", &["--question", "--text", "q"])
            .status
            .code(),
        Some(4)
    );
    assert_eq!(
        fs::read_dir(dir.session().join("inbox")).unwrap().count(),
        0
    );
}

#[test]
fn separate_user_sessions_are_group_shared_and_refuse_own_inbox_files() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = Dir::new();
    let group = String::from_utf8(Command::new("id").arg("-gn").output().unwrap().stdout).unwrap();
    let group = group.trim();
    let started = dir.start(&["--separation", "separate_user", "--agent-group", group]);
    assert!(started.status.success(), "{started:?}");
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    let session = dir.session();
    assert_eq!(mode(&session), 0o750);
    for name in ["entries", "documents", "requests"] {
        assert_eq!(mode(&session.join(name)), 0o2750, "{name}");
    }
    assert_eq!(mode(&session.join("inbox")), 0o2770);
    assert!(dir.line(0).contains("\"separation\":\"separate_user\""));
    let entry = session.join("entries/000000.entry");
    assert_eq!(
        mode(&entry) & 0o077,
        0o040,
        "group-readable, nothing for others"
    );
    assert_eq!(
        fs::metadata(&entry).unwrap().gid(),
        fs::metadata(&session).unwrap().gid()
    );
    // In this test the "agent" runs as the operator's own user, which a
    // separate_user session must never accept.
    assert!(
        dir.request(&["--question", "--text", "same account"])
            .status
            .success()
    );
    assert_eq!(
        stdout(&dir.broker()),
        "MIRA session: refused request (owner)\n"
    );
    for extra in [
        vec!["--separation", "separate_user"],
        vec!["--agent-group", group],
        vec![
            "--separation",
            "separate_user",
            "--agent-group",
            "no-such-group-mira",
        ],
        vec!["--separation", "shared"],
    ] {
        let other = Dir::new();
        assert_eq!(other.start(&extra).status.code(), Some(2), "{extra:?}");
        assert!(!other.session().exists());
    }
}

fn admitted_seq(output: &str) -> u64 {
    output
        .strip_prefix("MIRA session: admitted request as ")
        .and_then(|rest| rest.trim_end().parse().ok())
        .unwrap_or_else(|| panic!("{output}"))
}

#[test]
fn a_result_document_cannot_be_swapped_for_another_collector_signed_one() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    for minimum in ["1", "2"] {
        assert!(
            dir.request(&[
                "--capability",
                "uptime-minimum",
                "--arguments",
                minimum,
                "--text",
                "up?"
            ])
            .status
            .success()
        );
        admitted_seq(&stdout(&dir.broker()));
    }
    assert!(dir.verify().status.success());
    // Both documents are genuine, same family, signed by the same collector.
    let documents = dir.session().join("documents");
    let (first, second) = (documents.join("000001.json"), documents.join("000003.json"));
    let first_signature = documents.join("000001.json.sig");
    let second_signature = documents.join("000003.json.sig");
    fs::copy(&second, &first).unwrap();
    fs::copy(&second_signature, &first_signature).unwrap();
    not_verified(
        &dir.verify(),
        "document of result 2 missing or not signed by the collector",
    );
}

#[test]
fn shared_files_stay_group_readable_under_a_restrictive_umask() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    let group = String::from_utf8(Command::new("id").arg("-gn").output().unwrap().stdout).unwrap();
    let session = dir.session();
    let signers = dir.path("signers");
    // `sh -c 'umask 077 && exec "$0" "$@"' mira ARGS` runs mira under umask 077.
    let masked = |args: &[&str]| {
        Command::new("/bin/sh")
            .args([
                "-c",
                "umask 077 && exec \"$0\" \"$@\"",
                env!("CARGO_BIN_EXE_mira"),
            ])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let operator = dir.path("operator");
    let started = masked(&[
        "session",
        "start",
        session.to_str().unwrap(),
        "--allowed-signers",
        signers.to_str().unwrap(),
        "--key",
        operator.to_str().unwrap(),
        "--operator",
        "operator",
        "--agent",
        "agent",
        "--collector",
        "collector",
        "--separation",
        "separate_user",
        "--agent-group",
        group.trim(),
        "--question",
        "q",
    ]);
    assert!(started.status.success(), "{started:?}");
    let agent = dir.path("agent");
    let requested = masked(&[
        "session",
        "request",
        session.to_str().unwrap(),
        "--allowed-signers",
        signers.to_str().unwrap(),
        "--key",
        agent.to_str().unwrap(),
        "--question",
        "--text",
        "q",
    ]);
    assert!(requested.status.success(), "{requested:?}");
    let mut files = vec![session.join("entries/000000.entry")];
    files.extend(
        fs::read_dir(session.join("inbox"))
            .unwrap()
            .map(|item| item.unwrap().path()),
    );
    for file in files {
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "{file:?}");
    }
}

#[test]
fn a_stored_request_without_a_log_entry_is_resumed_not_discarded() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "resume me"
        ])
        .status
        .success()
    );
    // A previous broker stored the request, then stopped before recording it.
    let inbox: Vec<_> = fs::read_dir(dir.session().join("inbox"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    let name = inbox[0].file_name().unwrap().to_owned();
    fs::copy(&inbox[0], dir.session().join("requests").join(&name)).unwrap();
    let seq = admitted_seq(&stdout(&dir.broker()));
    assert!(dir.line(seq).contains("\"note\":\"resume me\""));
    assert!(dir.verify().status.success());
    // A stored copy that differs from the inbox request is not trusted.
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "original"
        ])
        .status
        .success()
    );
    let inbox: Vec<_> = fs::read_dir(dir.session().join("inbox"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    fs::write(
        dir.session()
            .join("requests")
            .join(inbox[0].file_name().unwrap()),
        "something else",
    )
    .unwrap();
    assert_eq!(
        stdout(&dir.broker()),
        "MIRA session: refused request (malformed)\n"
    );
}

#[test]
fn escaped_unit_names_are_admitted_and_schema_valid() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    // systemd escapes '-' inside instance names as \x2d.
    assert!(
        dir.request(&[
            "--capability",
            "service-active",
            "--arguments",
            "mira-test@a\\x2db.service",
            "--text",
            "escaped",
        ])
        .status
        .success()
    );
    let seq = admitted_seq(&stdout(&dir.broker()));
    assert!(
        dir.line(seq)
            .contains("\"arguments\":\"mira-test@a\\\\x2db.service\"")
    );
    assert!(dir.verify().status.success());
}

#[test]
fn close_waits_for_pending_actions_and_can_abandon_them() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    // An operator action whose result never arrived, as after an interrupted
    // run: written and signed by hand with the operator's key.
    let line = format!(
        "{{\"session_version\":1,\"session_id\":\"{}\",\"seq\":1,\"kind\":\"action\",\"principal\":\"operator\",\"based_on\":0,\"request_id\":null,\"capability\":\"uptime-minimum\",\"arguments\":\"1\",\"note\":\"interrupted\"}}\n",
        dir.session_id()
    );
    let mut record = line.as_bytes().to_vec();
    record.extend(dir.sign(line.as_bytes(), "operator", SESSION));
    fs::write(dir.session().join("entries/000001.entry"), record).unwrap();
    assert!(dir.verify().status.success());
    let refused = dir.command("close", "operator", &["--conclusion", "done"]);
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert_eq!(
        stdout(&refused),
        "MIRA session: refused (actions are still pending; wait for their results or close with --abandon-pending)\n"
    );
    let closed = dir.command(
        "close",
        "operator",
        &["--conclusion", "done", "--abandon-pending"],
    );
    assert_eq!(
        stdout(&closed),
        "MIRA session: abandoned 000001 at 000002\nMIRA session: closed at 000003\n",
        "{closed:?}"
    );
    assert!(dir.line(2).contains(
        "\"kind\":\"abandon\",\"principal\":\"operator\",\"based_on\":1,\"action_seq\":1,"
    ));
    assert!(stdout(&dir.verify()).starts_with("MIRA session: verified entries 4 closed"));
}

#[test]
fn an_agent_cannot_fill_the_log_with_questions_or_refused_requests() {
    let dir = Dir::new();
    assert!(
        dir.start(&["--budget", "2", "--autonomy", "advisory"])
            .status
            .success()
    );
    // One question and one refused action spend the whole budget.
    assert!(
        dir.request(&["--question", "--text", "first"])
            .status
            .success()
    );
    assert!(stdout(&dir.broker()).starts_with("MIRA session: admitted request as "));
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "advisory"
        ])
        .status
        .success()
    );
    assert_eq!(
        stdout(&dir.broker()),
        "MIRA session: refused request (autonomy)\n"
    );
    assert!(dir.state().contains("\"budget\":0,"));
    // Everything after that is dropped unrecorded, however many arrive.
    let before = dir.state();
    for index in 0..5 {
        assert!(
            dir.request(&["--question", "--text", &format!("flood {index}")])
                .status
                .success()
        );
    }
    let ran = stdout(&dir.broker());
    assert_eq!(ran.lines().count(), 5);
    assert!(ran.lines().all(|line| line
        == "MIRA session: discarded request (no budget left, or only the operator's reserve)"));
    assert_eq!(dir.state(), before);
    assert_eq!(
        fs::read_dir(dir.session().join("inbox")).unwrap().count(),
        0
    );
    // The operator can always stop and close.
    assert!(
        dir.command("direct", "operator", &["--stop"])
            .status
            .success()
    );
    assert!(
        dir.command("close", "operator", &["--conclusion", "done"])
            .status
            .success()
    );
    assert!(stdout(&dir.verify()).ends_with(" closed\n"));
}

#[test]
fn signature_files_are_never_group_writable_whatever_the_umask() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    let signature = dir.path("capture.sig");
    let key = dir.path("collector");
    // umask 002 would leave a default-mode file group-writable.
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            "umask 002 && exec \"$0\" \"$@\"",
            env!("CARGO_BIN_EXE_mira"),
        ])
        .args([
            "capture",
            "x",
            "--signature",
            signature.to_str().unwrap(),
            "--sign-with",
            key.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
    let mode = fs::metadata(&signature).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & 0o022, 0, "mode {mode:o}");
}

#[test]
fn an_inbox_flood_is_handled_in_bounded_passes_and_purged() {
    let dir = Dir::new();
    assert!(dir.start(&["--budget", "3"]).status.success());
    let inbox = dir.session().join("inbox");
    // Junk of every kind the agent's group could create.
    for index in 0..300 {
        fs::write(inbox.join(format!("junk-{index}")), "x").unwrap();
    }
    fs::create_dir(inbox.join("empty-dir")).unwrap();
    fs::create_dir(inbox.join("full-dir")).unwrap();
    fs::write(inbox.join("full-dir/file"), "x").unwrap();
    fs::write(inbox.join(".pending-stale"), "x").unwrap();
    assert!(
        Command::new("touch")
            .args(["-d", "2 minutes ago"])
            .arg(inbox.join(".pending-stale"))
            .status()
            .unwrap()
            .success()
    );
    fs::write(inbox.join(".pending-fresh"), "x").unwrap();
    // 70 request-shaped files, more than one pass handles.
    for index in 0..70u32 {
        fs::write(inbox.join(format!("{:064x}.request", index + 1)), "garbage").unwrap();
    }
    let first = stdout(&dir.broker());
    assert_eq!(first.lines().count(), 64, "{first}");
    // Three refusals spend the budget; the rest are dropped unrecorded.
    assert_eq!(first.matches("refused request (malformed)").count(), 3);
    let second = stdout(&dir.broker());
    assert_eq!(second.lines().count(), 6, "{second}");
    let left: Vec<String> = fs::read_dir(&inbox)
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut left = left;
    left.sort();
    // Only the agent's fresh pending write and its non-empty directory remain.
    assert_eq!(left, [".pending-fresh", "full-dir"]);
    assert!(stdout(&dir.verify()).starts_with("MIRA session: verified entries 4 "));
}

#[test]
fn relay_and_document_checks_use_the_authenticated_snapshot() {
    let dir = Dir::new();
    assert!(dir.start(&[]).status.success());
    assert!(
        dir.request(&[
            "--capability",
            "uptime-minimum",
            "--arguments",
            "1",
            "--text",
            "up?"
        ])
        .status
        .success()
    );
    assert!(stdout(&dir.broker()).starts_with("MIRA session: admitted request as 000001"));
    let signers = dir.path("signers");
    // Authenticate the log once.
    let (log, state) = mira::session::verify(&dir.session(), &signers, "operator", None).unwrap();
    // Then replace the result on disk with an unsigned abandon and remove its
    // document, as a concurrent writer could between two reads.
    let abandon = format!(
        "{{\"session_version\":1,\"session_id\":\"{}\",\"seq\":2,\"kind\":\"abandon\",\"principal\":\"operator\",\"based_on\":1,\"action_seq\":1,\"note\":\"\"}}\n-----BEGIN SSH SIGNATURE-----\nAA==\n-----END SSH SIGNATURE-----\n",
        dir.session_id()
    );
    fs::write(dir.session().join("entries/000002.entry"), abandon).unwrap();
    fs::remove_file(dir.session().join("documents/000001.json")).unwrap();
    // The checks run on the snapshot, whose result still needs its document.
    assert_eq!(
        mira::session_broker::verify_relays(&dir.session(), &log, &state, &signers),
        Err(mira::session::Problem::Document(2))
    );
}

#[test]
fn close_receipts_are_owner_only_whatever_the_umask() {
    use std::os::unix::fs::PermissionsExt;
    for umask in ["022", "077"] {
        let dir = Dir::new();
        assert!(dir.start(&[]).status.success());
        let receipt = dir.path("receipt");
        let session = dir.session();
        let signers = dir.path("signers");
        let key = dir.path("operator");
        let closed = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("umask {umask} && exec \"$0\" \"$@\""),
                env!("CARGO_BIN_EXE_mira"),
            ])
            .args([
                "session",
                "close",
                session.to_str().unwrap(),
                "--allowed-signers",
                signers.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "--conclusion",
                "private conclusion",
                "--receipt",
                receipt.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(closed.status.success(), "{closed:?}");
        let mode = fs::metadata(&receipt).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "umask {umask}");
    }
}
