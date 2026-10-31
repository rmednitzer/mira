//! Detached OpenSSH SSHSIG signatures for MIRA documents (ADR 0011).
//! All cryptography stays in `ssh-keygen`; MIRA trusts only its exit status
//! and bounded signature bytes. A signature proves key possession, not truth.
use crate::process::{Stderr, run_bounded};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    process::Command,
    time::Duration,
};

/// Fixed tool path; no PATH lookup in production builds.
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
/// Documents MIRA signs or verifies are small; this matches the comparator bound.
pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
/// Signing may wait for a passphrase or a FIDO2 touch; checks never prompt.
const SIGN_TIMEOUT: Duration = Duration::from_secs(120);
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const ARMOR: &[u8] = b"-----BEGIN SSH SIGNATURE-----\n";

/// One namespace per document kind, so a signature never crosses kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Capture,
    Investigation,
}

impl Kind {
    pub fn namespace(self) -> &'static str {
        match self {
            Self::Capture => "mira-capture-v1@rmednitzer.github.io",
            Self::Investigation => "mira-investigation-v1@rmednitzer.github.io",
        }
    }

    /// Select the kind from the document's leading bytes, exactly as MIRA writes them.
    pub fn of(document: &[u8]) -> Option<Self> {
        if document.starts_with(b"{\"capture_version\":") {
            Some(Self::Capture)
        } else if document.starts_with(b"{\"investigation_version\":") {
            Some(Self::Investigation)
        } else {
            None
        }
    }
}

/// Conservative principal syntax for an argument to `ssh-keygen -I`.
pub fn validate_principal(principal: &str) -> io::Result<()> {
    let leading = principal
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric);
    if !leading
        || principal.len() > 128
        || !principal
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid principal",
        ));
    }
    Ok(())
}

fn ssh_keygen() -> Command {
    // Test-support builds may redirect the tool to the native fixture. Release
    // builds compile this branch out, so the fixed path cannot be overridden.
    #[cfg(feature = "test-support")]
    if let Some(path) = std::env::var_os("MIRA_TEST_SSH_KEYGEN") {
        return Command::new(path);
    }
    Command::new(SSH_KEYGEN)
}

/// Why an integrity operation could not complete. Every variant fails closed.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The tool is missing, timed out or produced unusable output.
    Tool,
    /// ssh-keygen ran and refused (bad key, passphrase, signature or principal).
    Refused,
    /// The signature path already exists or could not be created.
    Output,
    /// The document is not a MIRA capture or investigation report, or too large.
    Document,
}

/// Sign `document` (the exact bytes about to be printed), self-check the
/// signature on a private staged copy, and only then create `signature_path`
/// exclusively. The output path is never unlinked or reopened by name, so a
/// directory swapped underneath it cannot redirect cleanup to another file.
pub fn sign(document: &[u8], key: &Path, signature_path: &Path) -> Result<(), Failure> {
    let kind = Kind::of(document).ok_or(Failure::Document)?;
    // Fail fast before any passphrase prompt; create_new below is authoritative.
    if fs::symlink_metadata(signature_path).is_ok() {
        return Err(Failure::Output);
    }
    let mut command = ssh_keygen();
    command.args([
        OsString::from("-Y"),
        "sign".into(),
        "-f".into(),
        key.into(),
        "-n".into(),
        kind.namespace().into(),
    ]);
    let (status, signature) = run_bounded(
        &mut command,
        Some(document),
        Stderr::Inherit,
        SIGN_TIMEOUT,
        MAX_SIGNATURE_BYTES,
    )
    .map_err(|_| Failure::Tool)?;
    if !status.success() {
        return Err(Failure::Refused);
    }
    if !signature.starts_with(ARMOR) {
        return Err(Failure::Tool);
    }
    check_staged(document, kind, &signature)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(signature_path)
        .map_err(|_| Failure::Output)?;
    if file
        .write_all(&signature)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        // Empty the file through its own descriptor rather than unlinking a
        // name that may no longer refer to it. An empty file never verifies.
        let _ = file.set_len(0);
        return Err(Failure::Output);
    }
    Ok(())
}

/// Self-check the signature from a fresh directory only this process can
/// write to (mode 0700, created exclusively), then remove the staged copy.
fn check_staged(document: &[u8], kind: Kind, signature: &[u8]) -> Result<(), Failure> {
    use std::os::unix::fs::DirBuilderExt;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let base = std::env::temp_dir();
    let mut staging = None;
    for _ in 0..16 {
        let unique = format!(
            "mira-signature-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |time| time.as_nanos())
        );
        let candidate = base.join(unique);
        // create, not create_all: an existing entry is never reused.
        if fs::DirBuilder::new().mode(0o700).create(&candidate).is_ok() {
            staging = Some(candidate);
            break;
        }
    }
    let staging = staging.ok_or(Failure::Tool)?;
    let staged = staging.join("signature");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .and_then(|mut file| file.write_all(signature))
        .map_err(|_| Failure::Tool)
        .and_then(|()| check(document, kind, &staged));
    let _ = fs::remove_file(&staged);
    let _ = fs::remove_dir(&staging);
    result
}

/// `-Y check-novalidate`: the signature is well formed, covers these bytes and
/// uses this namespace. It does not consult any trust list.
fn check(document: &[u8], kind: Kind, signature_path: &Path) -> Result<(), Failure> {
    let mut command = ssh_keygen();
    command.args([
        OsString::from("-Y"),
        "check-novalidate".into(),
        "-n".into(),
        kind.namespace().into(),
        "-s".into(),
        signature_path.into(),
    ]);
    let (status, _) = run_bounded(
        &mut command,
        Some(document),
        Stderr::Discard,
        CHECK_TIMEOUT,
        MAX_SIGNATURE_BYTES,
    )
    .map_err(|_| Failure::Tool)?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::Tool)
    }
}

/// O_NONBLOCK on Linux x86_64 and aarch64, MIRA's only supported targets.
/// std exposes no portable constant and `unsafe`/libc are not admitted.
#[cfg(target_os = "linux")]
pub(crate) const O_NONBLOCK: i32 = 0o4000;

/// Read a document once, bounded, without requiring UTF-8. The open is
/// nonblocking and the opened descriptor must be a regular file, so a FIFO or
/// device substituted for the path is refused instead of blocking forever.
/// Symlinks to regular files remain admitted, as in the offline comparator.
pub fn read_document(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "document must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(crate::collector::limit_exceeded());
    }
    Ok(bytes)
}

/// The operator's trust inputs for verification.
pub struct Trust<'a> {
    pub allowed_signers: &'a Path,
    pub principal: &'a str,
    pub revocations: Option<&'a Path>,
}

/// Verify `document` against `signature_path` for `trust.principal` under the
/// namespace its leading bytes select. Only the exit status is trusted.
pub fn verify(document: &[u8], signature_path: &Path, trust: &Trust) -> Result<Kind, Failure> {
    let kind = Kind::of(document).ok_or(Failure::Document)?;
    validate_principal(trust.principal).map_err(|_| Failure::Refused)?;
    let mut command = ssh_keygen();
    command.args([
        OsString::from("-Y"),
        "verify".into(),
        "-f".into(),
        trust.allowed_signers.into(),
        "-I".into(),
        trust.principal.into(),
        "-n".into(),
        kind.namespace().into(),
        "-s".into(),
        signature_path.into(),
    ]);
    if let Some(revocations) = trust.revocations {
        command.args([OsString::from("-r"), revocations.into()]);
    }
    let (status, _) = run_bounded(
        &mut command,
        Some(document),
        Stderr::Discard,
        CHECK_TIMEOUT,
        MAX_SIGNATURE_BYTES,
    )
    .map_err(|_| Failure::Tool)?;
    if status.success() {
        Ok(kind)
    } else {
        Err(Failure::Refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_follow_leading_bytes_and_have_distinct_namespaces() {
        assert_eq!(Kind::of(b"{\"capture_version\":2,"), Some(Kind::Capture));
        assert_eq!(
            Kind::of(b"{\"investigation_version\":1,"),
            Some(Kind::Investigation)
        );
        for other in [
            &b""[..],
            b" {\"capture_version\":1",
            b"{\"schema_version\":1",
            b"{\"capture_version\" :1",
            b"[{\"capture_version\":1}]",
        ] {
            assert_eq!(Kind::of(other), None, "{other:?}");
        }
        assert_ne!(Kind::Capture.namespace(), Kind::Investigation.namespace());
        assert_eq!(
            Kind::Capture.namespace(),
            "mira-capture-v1@rmednitzer.github.io"
        );
    }

    #[test]
    fn principals_are_conservative_single_arguments() {
        for valid in [
            "host-a",
            "ops@example.org",
            "a",
            "A.b_c+d-1",
            &"x".repeat(128),
        ] {
            assert!(validate_principal(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "-I",
            "-host",
            ".host",
            "@host",
            "host a",
            "host;id",
            "host\n",
            "host*",
            "host,other",
            "hôst",
            &"x".repeat(129),
        ] {
            assert!(validate_principal(invalid).is_err(), "{invalid:?}");
        }
    }
}
