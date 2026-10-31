//! Fixed-argv and failure handling of the ssh-keygen boundary, using the native
//! fixture through the test-support-only tool override.
#![cfg(feature = "test-support")]

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mira-signature-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn mira(&self, mode: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(args)
            .env(
                "MIRA_TEST_SSH_KEYGEN",
                env!("CARGO_BIN_EXE_mira-process-fixture"),
            )
            .env("MIRA_PROCESS_FIXTURE_MODE", mode)
            .output()
            .unwrap()
    }

    fn sign(&self, mode: &str, kind: &str) -> (Output, PathBuf) {
        let signature = self.0.join(format!("{mode}-{kind}.sig"));
        let path = signature.to_str().unwrap().to_owned();
        let args: Vec<&str> = match kind {
            "capture" => vec![
                "capture",
                "fixture",
                "--signature",
                &path,
                "--sign-with",
                "key",
            ],
            _ => vec![
                "investigate",
                "uptime-minimum",
                "--min-uptime-seconds",
                "1",
                "--json",
                "--signature",
                &path,
                "--sign-with",
                "key",
            ],
        };
        (self.mira(mode, &args), signature)
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

#[test]
fn signing_uses_the_exact_argv_and_emits_after_the_signature() {
    let dir = Dir::new();
    for kind in ["capture", "investigation"] {
        let (output, signature) = dir.sign("keygen-ok", kind);
        assert!(matches!(output.status.code(), Some(0 | 1 | 3)), "{kind}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let prefix = if kind == "capture" {
            "{\"capture_version\":"
        } else {
            "{\"investigation_version\":"
        };
        assert!(stdout.starts_with(prefix), "{kind}");
        assert!(
            fs::read(&signature)
                .unwrap()
                .starts_with(b"-----BEGIN SSH SIGNATURE-----\n")
        );
    }
}

#[test]
fn every_signing_failure_emits_nothing_and_leaves_no_signature() {
    let dir = Dir::new();
    for mode in [
        "keygen-refuses",
        "keygen-unarmored",
        "keygen-oversized",
        "keygen-check-fails",
        "keygen-wrong-mode",
    ] {
        for kind in ["capture", "investigation"] {
            let (output, signature) = dir.sign(mode, kind);
            assert_eq!(output.status.code(), Some(4), "{mode} {kind}");
            assert!(output.stdout.is_empty(), "{mode} {kind}");
            assert!(!signature.exists(), "{mode} {kind}: signature left behind");
        }
    }
    // A missing tool is the same fail-closed path.
    let signature = dir.0.join("missing.sig");
    let output = Command::new(env!("CARGO_BIN_EXE_mira"))
        .args([
            "capture",
            "fixture",
            "--signature",
            signature.to_str().unwrap(),
            "--sign-with",
            "key",
        ])
        .env("MIRA_TEST_SSH_KEYGEN", dir.0.join("no-such-ssh-keygen"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(!signature.exists());
}

#[test]
fn verification_trusts_only_the_exit_status() {
    let dir = Dir::new();
    let document = dir.0.join("capture.json");
    let output = dir.mira("", &["capture", "fixture"]);
    fs::write(&document, output.stdout).unwrap();
    fs::write(dir.0.join("capture.sig"), "-----BEGIN SSH SIGNATURE-----\n").unwrap();
    let verify = |mode: &str, extra: &[&str]| {
        let mut args = vec![
            "verify",
            document.to_str().unwrap(),
            "--signature",
            "capture.sig",
            "--allowed-signers",
            "signers",
            "--principal",
            "host-a",
        ];
        args.extend_from_slice(extra);
        dir.mira(mode, &args)
    };
    assert_eq!(verify("keygen-ok", &[]).status.code(), Some(0));
    assert_eq!(
        verify("keygen-ok", &["--revocations", "krl"]).status.code(),
        Some(0)
    );
    assert_eq!(verify("keygen-refuses", &[]).status.code(), Some(1));
    let missing = Command::new(env!("CARGO_BIN_EXE_mira"))
        .args([
            "verify",
            document.to_str().unwrap(),
            "--signature",
            "capture.sig",
            "--allowed-signers",
            "signers",
            "--principal",
            "host-a",
        ])
        .env("MIRA_TEST_SSH_KEYGEN", dir.0.join("no-such-ssh-keygen"))
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(4));
}
