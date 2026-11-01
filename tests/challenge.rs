//! Consumer-challenge freshness (ADR 0014) end to end, against the real
//! /usr/bin/ssh-keygen with throwaway keys.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mira-challenge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn key(&self) -> PathBuf {
        let key = self.path("host-a");
        let status = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "host-a", "-f"])
            .arg(&key)
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        let public: Vec<_> = public.split_whitespace().take(2).collect();
        fs::write(
            self.path("signers"),
            format!(
                "host-a namespaces=\"mira-capture-v1@rmednitzer.github.io\" {}\n",
                public.join(" ")
            ),
        )
        .unwrap();
        key
    }

    /// A signed capture with the given extra options; returns (document, signature).
    fn capture(&self, key: &Path, name: &str, options: &[&str]) -> (PathBuf, PathBuf) {
        let signature = self.path(&format!("{name}.sig"));
        let mut args = vec!["capture", "signed"];
        args.extend(options);
        args.extend([
            "--signature",
            signature.to_str().unwrap(),
            "--sign-with",
            key.to_str().unwrap(),
        ]);
        let output = mira(&args);
        assert!(matches!(output.status.code(), Some(0 | 1)), "{args:?}");
        let document = self.path(&format!("{name}.json"));
        fs::write(&document, &output.stdout).unwrap();
        (document, signature)
    }

    fn issued(&self, name: &str, challenge: &str, at: u64) -> PathBuf {
        let path = self.path(name);
        fs::write(
            &path,
            format!("{{\"challenge_version\":1,\"challenge\":\"{challenge}\",\"issued_unix_ms\":{at}}}\n"),
        )
        .unwrap();
        path
    }

    fn verify(
        &self,
        document: &Path,
        signature: &Path,
        freshness: Option<(&Path, &str)>,
    ) -> Output {
        let mut args = vec![
            "verify".to_owned(),
            document.to_str().unwrap().to_owned(),
            "--signature".to_owned(),
            signature.to_str().unwrap().to_owned(),
            "--allowed-signers".to_owned(),
            self.path("signers").to_str().unwrap().to_owned(),
            "--principal".to_owned(),
            "host-a".to_owned(),
        ];
        if let Some((file, maximum)) = freshness {
            args.extend([
                "--challenge-file".to_owned(),
                file.to_str().unwrap().to_owned(),
                "--max-age-ms".to_owned(),
                maximum.to_owned(),
            ]);
        }
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
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

fn mira(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mira"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn issued_challenges_have_the_fixed_layout_and_differ() {
    let first = mira(&["challenge"]);
    let second = mira(&["challenge"]);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    for output in [&first, &second] {
        let text = stdout(output);
        let rest = text
            .strip_prefix("{\"challenge_version\":1,\"challenge\":\"")
            .unwrap();
        let (hex, rest) = rest.split_at(64);
        assert!(hex.bytes().all(|byte| b"0123456789abcdef".contains(&byte)));
        let digits = rest
            .strip_prefix("\",\"issued_unix_ms\":")
            .unwrap()
            .strip_suffix("}\n")
            .unwrap();
        let issued: u64 = digits.parse().unwrap();
        assert!(issued.abs_diff(now_ms()) < 60_000);
    }
    assert_ne!(first.stdout, second.stdout);
    assert_ne!(stdout(&first)[36..100], stdout(&second)[36..100]);
    assert_eq!(mira(&["challenge", "extra"]).status.code(), Some(2));
}

#[test]
fn a_challenged_capture_verifies_with_an_age_bound() {
    let dir = Dir::new();
    let key = dir.key();
    let issued = mira(&["challenge"]);
    let file = dir.path("challenge.json");
    fs::write(&file, &issued.stdout).unwrap();
    let hex = stdout(&issued)[36..100].to_owned();
    for (index, options) in [
        vec![],
        vec!["--pressure"],
        vec!["--bind-boot"],
        vec!["--pressure", "--timeline", "--bind-boot"],
    ]
    .into_iter()
    .enumerate()
    {
        let mut options = options;
        options.extend(["--challenge", &hex]);
        let (document, signature) = dir.capture(&key, &index.to_string(), &options);
        let bytes = fs::read(&document).unwrap();
        let prefix = format!(
            "{{\"capture_version\":3,\"challenge\":\"{hex}\",\"capture_scope\":\"signed\","
        );
        assert!(bytes.starts_with(prefix.as_bytes()), "{options:?}");
        assert!(bytes.windows(13).any(|window| window == b"\"timeline\":[{"));
        assert_eq!(
            options.contains(&"--bind-boot"),
            bytes
                .windows(19)
                .any(|window| window == b"\"binding\":\"observed"),
            "{options:?}"
        );
        let checked = dir.verify(&document, &signature, Some((&file, "600000")));
        assert_eq!(checked.status.code(), Some(0), "{options:?}");
        let line = stdout(&checked);
        let age: u64 = line
            .strip_prefix("MIRA verify: verified namespace=mira-capture-v1@rmednitzer.github.io principal=host-a age_bound_ms=")
            .unwrap()
            .trim_end()
            .parse()
            .unwrap();
        assert!(age < 600_000);
        // Without the freshness options capture-v3 verifies as a signed document.
        let plain = dir.verify(&document, &signature, None);
        assert_eq!(
            stdout(&plain),
            "MIRA verify: verified namespace=mira-capture-v1@rmednitzer.github.io principal=host-a\n"
        );
    }
}

#[test]
fn every_freshness_failure_has_its_fixed_reason() {
    let dir = Dir::new();
    let key = dir.key();
    let current = dir.issued("current.json", HEX, now_ms());
    let (v3, v3_sig) = dir.capture(&key, "v3", &["--challenge", HEX]);
    let (v2, v2_sig) = dir.capture(&key, "v2", &["--timeline"]);
    let (v1, v1_sig) = dir.capture(&key, "v1", &[]);
    let other = dir.issued("other.json", &HEX.replace("ff", "fe"), now_ms());
    let future = dir.issued("future.json", HEX, now_ms() + 3_600_000);
    let old = dir.issued("old.json", HEX, 1);
    let tampered = dir.path("tampered.json");
    let mut bytes = fs::read(&v3).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 1;
    fs::write(&tampered, bytes).unwrap();
    for (document, signature, file, reason) in [
        (&v3, &v3_sig, &other, "challenge_mismatch"),
        (&v2, &v2_sig, &current, "not_challenged"),
        (&v1, &v1_sig, &current, "not_challenged"),
        (&v3, &v3_sig, &future, "issued_in_future"),
        (&v3, &v3_sig, &old, "older_than_policy"),
        (&tampered, &v3_sig, &current, "signature"),
        (&v3, &v2_sig, &current, "signature"),
    ] {
        let output = dir.verify(document, signature, Some((file, "600000")));
        assert_eq!(output.status.code(), Some(1), "{reason}");
        assert_eq!(
            stdout(&output),
            format!("MIRA verify: not verified ({reason})\n")
        );
    }
    // A zero policy is legal; a challenge issued this millisecond can pass it.
    let zero = dir.verify(&v3, &v3_sig, Some((&current, "0")));
    assert!(matches!(zero.status.code(), Some(0 | 1)));
    // A signature refusal wins even when the challenge file is malformed.
    let malformed = dir.path("malformed.json");
    fs::write(&malformed, "{}\n").unwrap();
    let output = dir.verify(&tampered, &v3_sig, Some((&malformed, "1")));
    assert_eq!(stdout(&output), "MIRA verify: not verified (signature)\n");
}

#[test]
fn malformed_challenges_are_refused_before_collection() {
    let dir = Dir::new();
    let key = dir.key();
    let signature = dir.path("refused.sig");
    let newline = format!("{HEX}\n");
    let upper = HEX.to_uppercase();
    let nonhex = format!("{}g", &HEX[..63]);
    for challenge in [
        &HEX[..63],
        &format!("{HEX}0"),
        &upper,
        &nonhex,
        &newline,
        "",
    ] {
        let output = mira(&[
            "capture",
            "x",
            "--challenge",
            challenge,
            "--signature",
            signature.to_str().unwrap(),
            "--sign-with",
            key.to_str().unwrap(),
        ]);
        assert_eq!(output.status.code(), Some(2), "{challenge:?}");
        assert!(output.stdout.is_empty(), "{challenge:?}");
        assert!(!signature.exists(), "{challenge:?}");
    }
    // Unsigned challenges are refused; so are misplaced or repeated options.
    for args in [
        vec!["capture", "x", "--challenge", HEX],
        vec!["capture", "x", "--challenge"],
        vec!["capture", "x", "--challenge", HEX, "--pressure"],
        vec!["capture", "x", "--challenge", HEX, "--challenge", HEX],
    ] {
        let output = mira(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn freshness_options_are_validated_as_usage() {
    let dir = Dir::new();
    let key = dir.key();
    let (v3, v3_sig) = dir.capture(&key, "v3", &["--challenge", HEX]);
    let current = dir.issued("current.json", HEX, now_ms());
    let oversized = dir.path("oversized.json");
    fs::write(&oversized, vec![b' '; 4097]).unwrap();
    let trailing = dir.path("trailing.json");
    fs::write(
        &trailing,
        format!("{{\"challenge_version\":1,\"challenge\":\"{HEX}\",\"issued_unix_ms\":1}}"),
    )
    .unwrap();
    for (file, maximum) in [
        (&oversized, "1000"),
        (&trailing, "1000"),
        (&dir.0, "1000"),
        (&current, "-1"),
        (&current, "01"),
        (&current, "1.5"),
        (&current, "10000000000000000"),
    ] {
        let output = dir.verify(&v3, &v3_sig, Some((file, maximum)));
        assert_eq!(output.status.code(), Some(2), "{file:?} {maximum}");
        assert!(output.stdout.is_empty(), "{file:?} {maximum}");
    }
    let missing = dir.verify(&v3, &v3_sig, Some((&dir.path("missing.json"), "1000")));
    assert_eq!(missing.status.code(), Some(4));
    assert!(missing.stdout.is_empty());
    let base = [
        "verify",
        v3.to_str().unwrap(),
        "--signature",
        v3_sig.to_str().unwrap(),
        "--allowed-signers",
        "signers",
        "--principal",
        "host-a",
    ];
    let file = current.to_str().unwrap();
    for tail in [
        vec!["--challenge-file", file],
        vec!["--max-age-ms", "1000"],
        vec!["--max-age-ms", "1000", "--challenge-file", file],
        vec![
            "--challenge-file",
            file,
            "--max-age-ms",
            "1000",
            "--revocations",
            "krl",
        ],
        vec!["--challenge-file", file, "--max-age-ms"],
    ] {
        let mut args = base.to_vec();
        args.extend(&tail);
        assert_eq!(mira(&args).status.code(), Some(2), "{tail:?}");
    }
}

#[test]
fn challenge_files_that_are_fifos_never_block() {
    let dir = Dir::new();
    let key = dir.key();
    let (v3, v3_sig) = dir.capture(&key, "v3", &["--challenge", HEX]);
    let fifo = dir.path("challenge.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_mira"))
        .args(["verify"])
        .arg(&v3)
        .arg("--signature")
        .arg(&v3_sig)
        .arg("--allowed-signers")
        .arg(dir.path("signers"))
        .args(["--principal", "host-a", "--challenge-file"])
        .arg(&fifo)
        .args(["--max-age-ms", "1000"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > std::time::Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("verify blocked on a challenge FIFO");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(2));
}

#[cfg(feature = "test-support")]
#[test]
fn an_unreadable_random_source_issues_nothing() {
    let dir = Dir::new();
    let short = dir.path("short");
    fs::write(&short, [0u8; 31]).unwrap();
    for source in [short, dir.path("missing")] {
        let output = Command::new(env!("CARGO_BIN_EXE_mira"))
            .arg("challenge")
            .env("MIRA_TEST_RANDOM_SOURCE", &source)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4), "{source:?}");
        assert!(output.stdout.is_empty(), "{source:?}");
    }
}
