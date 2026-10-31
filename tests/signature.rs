//! Signing and verification against the real /usr/bin/ssh-keygen with throwaway
//! keys (ADR 0011). Native CI runners and Ubuntu installs ship openssh-client.
use mira::signature::{self, Failure, Kind, Trust};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const BOTH: &str =
    "mira-capture-v1@rmednitzer.github.io,mira-investigation-v1@rmednitzer.github.io";

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mira-signature-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn key(&self, name: &str, passphrase: &str) -> PathBuf {
        let key = self.path(name);
        let status = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", name, "-f"])
            .arg(&key)
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        key
    }

    /// One allowed_signers line per (principal, key, extra options).
    fn signers(&self, entries: &[(&str, &Path, &str)]) -> PathBuf {
        let mut text = String::new();
        for (principal, key, options) in entries {
            let public = fs::read_to_string(key.with_extension("pub")).unwrap();
            let public: Vec<_> = public.split_whitespace().take(2).collect();
            text.push_str(&format!(
                "{principal} namespaces=\"{BOTH}\"{options} {}\n",
                public.join(" ")
            ));
        }
        let path = self.path(&format!("signers-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::write(&path, text).unwrap();
        path
    }

    fn raw_sign(&self, document: &[u8], key: &Path, namespace: &str, name: &str) -> PathBuf {
        let signature = self.path(name);
        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(key)
            .args(["-n", namespace])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(document)?;
                child.wait_with_output()
            })
            .unwrap();
        assert!(output.status.success());
        fs::write(&signature, output.stdout).unwrap();
        signature
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

fn trust<'a>(signers: &'a Path, principal: &'a str) -> Trust<'a> {
    Trust {
        allowed_signers: signers,
        principal,
        revocations: None,
    }
}

#[test]
fn every_signable_document_verifies_with_mira_and_ssh_keygen() {
    let dir = Dir::new();
    let key = dir.key("host-a", "");
    let signers = dir.signers(&[("host-a", &key, "")]);
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|release| release.trim().to_owned())
        .unwrap_or_else(|_| "6.17.0".to_owned());
    let invocations: Vec<Vec<&str>> = vec![
        vec!["capture", "signed"],
        vec!["capture", "signed", "--pressure", "--timeline"],
        vec!["capture", "signed", "--bind-boot"],
        vec!["investigate", "service-active", "ssh.service", "--json"],
        vec!["investigate", "service-active/v2", "ssh.service", "--json"],
        vec![
            "investigate",
            "memory-headroom",
            "--min-available-kib",
            "1",
            "--json",
        ],
        vec![
            "investigate",
            "pressure-ceiling",
            "--resource",
            "io",
            "--max-some-avg10-basis-points",
            "10000",
            "--json",
        ],
        vec!["investigate", "package-installed", "dpkg", "--json"],
        vec![
            "investigate",
            "uptime-minimum",
            "--min-uptime-seconds",
            "1",
            "--json",
        ],
        vec![
            "investigate",
            "kernel-release",
            "--expect",
            &release,
            "--json",
        ],
    ];
    for (index, invocation) in invocations.iter().enumerate() {
        let signature = dir.path(&format!("{index}.sig"));
        let mut args = invocation.clone();
        args.extend([
            "--signature",
            signature.to_str().unwrap(),
            "--sign-with",
            key.to_str().unwrap(),
        ]);
        let output = mira(&args);
        assert!(
            matches!(output.status.code(), Some(0 | 1 | 3)),
            "{invocation:?}"
        );
        let document = dir.path(&format!("{index}.json"));
        fs::write(&document, &output.stdout).unwrap();
        let kind = Kind::of(&output.stdout).unwrap();
        assert_eq!(
            kind == Kind::Capture,
            invocation[0] == "capture",
            "{invocation:?}"
        );
        let verified = mira(&[
            "verify",
            document.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--allowed-signers",
            signers.to_str().unwrap(),
            "--principal",
            "host-a",
        ]);
        assert_eq!(verified.status.code(), Some(0), "{invocation:?}");
        assert_eq!(
            String::from_utf8(verified.stdout).unwrap(),
            format!(
                "MIRA verify: verified namespace={} principal=host-a\n",
                kind.namespace()
            )
        );
        // Independent check with ssh-keygen itself over the bytes MIRA printed.
        let independent = Command::new("/usr/bin/ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&signers)
            .args(["-I", "host-a", "-n", kind.namespace(), "-s"])
            .arg(&signature)
            .stdin(fs::File::open(&document).unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(independent.success(), "{invocation:?}");
    }
}

#[test]
fn verification_refuses_every_mismatch() {
    let dir = Dir::new();
    let key = dir.key("host-a", "");
    let other = dir.key("host-b", "");
    let document = mira(&["capture", "refusals"]).stdout;
    let signature = dir.path("capture.sig");
    signature::sign(&document, &key, &signature).unwrap();
    let signers = dir.signers(&[("host-a", &key, "")]);
    assert_eq!(
        signature::verify(&document, &signature, &trust(&signers, "host-a")),
        Ok(Kind::Capture)
    );

    let mut modified = document.clone();
    let last = modified.len() - 2;
    modified[last] ^= 1;
    let foreign = dir.raw_sign(
        &document,
        &key,
        Kind::Investigation.namespace(),
        "foreign.sig",
    );
    let other_file = dir.raw_sign(
        b"{\"capture_version\":1}\n",
        &key,
        Kind::Capture.namespace(),
        "other.sig",
    );
    let only_b = dir.signers(&[("host-b", &key, "")]);
    let unknown = dir.signers(&[("host-a", &other, "")]);
    let expired = dir.signers(&[("host-a", &key, ",valid-before=\"20200101\"")]);
    let garbage = dir.path("garbage.sig");
    fs::write(
        &garbage,
        "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n",
    )
    .unwrap();
    for (case, bytes, sig, signers, principal) in [
        (
            "one modified byte",
            &modified,
            &signature,
            &signers,
            "host-a",
        ),
        (
            "other kind's namespace",
            &document,
            &foreign,
            &signers,
            "host-a",
        ),
        (
            "signature for another file",
            &document,
            &other_file,
            &signers,
            "host-a",
        ),
        ("unknown key", &document, &signature, &unknown, "host-a"),
        (
            "key listed for another principal",
            &document,
            &signature,
            &only_b,
            "host-a",
        ),
        (
            "expired valid-before",
            &document,
            &signature,
            &expired,
            "host-a",
        ),
        ("garbage signature", &document, &garbage, &signers, "host-a"),
        (
            "principal syntax",
            &document,
            &signature,
            &signers,
            "-host-a",
        ),
    ] {
        assert_eq!(
            signature::verify(bytes, sig, &trust(signers, principal)),
            Err(Failure::Refused),
            "{case}"
        );
    }
    assert_eq!(
        signature::verify(
            b"{\"schema_version\":1}\n",
            &signature,
            &trust(&signers, "host-a")
        ),
        Err(Failure::Document)
    );

    // A revoked key fails even when allowed_signers still lists it.
    let revocations = dir.path("revoked.krl");
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-k", "-f"])
        .arg(&revocations)
        .arg(key.with_extension("pub"))
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let revoked = Trust {
        allowed_signers: &signers,
        principal: "host-a",
        revocations: Some(&revocations),
    };
    assert_eq!(
        signature::verify(&document, &signature, &revoked),
        Err(Failure::Refused)
    );

    // Two keys for one principal both verify (rotation is the signers file's decision).
    let rotated = dir.signers(&[("host-a", &key, ""), ("host-a", &other, "")]);
    let second = dir.path("second.sig");
    signature::sign(&document, &other, &second).unwrap();
    for sig in [&signature, &second] {
        assert_eq!(
            signature::verify(&document, sig, &trust(&rotated, "host-a")),
            Ok(Kind::Capture)
        );
    }
}

#[test]
fn signing_failures_leave_no_document_or_signature() {
    let dir = Dir::new();
    let encrypted = dir.key("encrypted", "correct horse");
    let plain = dir.key("plain", "");
    let existing = dir.path("existing.sig");
    fs::write(&existing, "keep").unwrap();
    for (case, key, signature, exit) in [
        (
            "encrypted key without terminal or agent",
            encrypted,
            dir.path("enc.sig"),
            4,
        ),
        ("missing key", dir.path("absent"), dir.path("absent.sig"), 4),
        (
            "existing signature path",
            plain.clone(),
            existing.clone(),
            4,
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mira"))
            .args([
                "capture",
                "unsigned",
                "--signature",
                signature.to_str().unwrap(),
                "--sign-with",
                key.to_str().unwrap(),
            ])
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_ASKPASS")
            .env_remove("DISPLAY")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit), "{case}");
        assert!(output.stdout.is_empty(), "{case}");
        if signature != existing {
            assert!(!signature.exists(), "{case}: signature left behind");
        }
    }
    assert_eq!(
        fs::read_to_string(&existing).unwrap(),
        "keep",
        "existing file overwritten"
    );
    assert_eq!(
        signature::sign(b"{\"schema_version\":1}\n", &plain, &dir.path("jsonl.sig")),
        Err(Failure::Document)
    );
}

#[test]
fn signing_is_opt_in_json_only_and_verify_usage_is_fixed() {
    let dir = Dir::new();
    let plain = mira(&["capture", "unsigned"]);
    assert!(plain.stdout.starts_with(b"{\"capture_version\":1,"));
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    let key = dir.key("host-a", "");
    let signature = dir.path("human.sig");
    for args in [
        vec!["investigate", "memory-headroom", "--min-available-kib", "1"],
        vec!["inspect", "--json"],
        vec!["service", "ssh.service", "--json"],
        vec!["demo"],
    ] {
        let mut args = args;
        args.extend([
            "--signature",
            signature.to_str().unwrap(),
            "--sign-with",
            key.to_str().unwrap(),
        ]);
        let output = mira(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!signature.exists(), "{args:?}");
    }
    for args in [
        vec!["capture", "x", "--signature", "a.sig"],
        vec!["capture", "x", "--sign-with", "key", "--signature", "a.sig"],
        vec!["verify", "file"],
        vec![
            "verify",
            "file",
            "--signature",
            "s",
            "--allowed-signers",
            "a",
        ],
        vec![
            "verify",
            "file",
            "--signature",
            "s",
            "--allowed-signers",
            "a",
            "--principal",
            "p",
            "--revocations",
        ],
        vec![
            "verify",
            "file",
            "--allowed-signers",
            "a",
            "--signature",
            "s",
            "--principal",
            "p",
        ],
    ] {
        assert_eq!(mira(&args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn verify_refuses_fifos_and_devices_without_blocking() {
    let dir = Dir::new();
    let fifo = dir.path("capture.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let signers = dir.path("signers");
    fs::write(&signers, "").unwrap();
    for document in [fifo.as_path(), Path::new("/dev/zero")] {
        // A blocking open of a FIFO with no writer would never return.
        let mut child = Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(["verify"])
            .arg(document)
            .args(["--signature", "none.sig", "--allowed-signers"])
            .arg(&signers)
            .args(["--principal", "host-a"])
            .stdout(Stdio::piped())
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
                panic!("verify blocked on {}", document.display());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(1), "{}", document.display());
    }
    assert!(signature::read_document(&fifo).is_err());
    assert!(signature::read_document(Path::new("/dev/zero")).is_err());
}
