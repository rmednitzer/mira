//! Exercise the public CLI and its fixed-argv collector with native fixtures.
#![cfg(feature = "test-support")]

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mira-process-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        // Never reuse or delete a pre-existing directory belonging to another run.
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        std::os::unix::fs::symlink(
            env!("CARGO_BIN_EXE_mira-process-fixture"),
            fixture.0.join("systemctl"),
        )
        .unwrap();
        fixture
    }

    fn collect(&self, mode: &str) -> Output {
        // Environment changes affect only this child, not parallel Rust tests.
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(["service", "ssh.service", "--json"])
            .env("PATH", &self.0)
            .env("MIRA_PROCESS_FIXTURE_MODE", mode)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn large_valid_response_uses_fixed_arguments_without_python() {
    let output = Fixture::new().collect("valid");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"status\":\"observed\""));
    assert!(stdout.contains("\"id\":\"ssh.service\""));
}

#[test]
fn oversized_malformed_and_failed_children_are_unavailable() {
    let fixture = Fixture::new();
    for (mode, kind) in [
        ("oversized", "InvalidData"),
        ("malformed", "InvalidData"),
        ("invalid-utf8", "InvalidData"),
        ("failure", "Other"),
    ] {
        let output = fixture.collect(mode);
        assert_eq!(output.status.code(), Some(1), "{mode}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("\"status\":\"unavailable\""), "{mode}");
        assert!(
            stdout.contains(&format!("\"error_kind\":\"{kind}\"")),
            "{mode}"
        );
    }
}

#[test]
fn deadline_covers_running_child_and_inherited_stdout() {
    let fixture = Fixture::new();
    for mode in ["timeout", "inherited-stdout"] {
        let start = Instant::now();
        let output = fixture.collect(mode);
        assert_eq!(output.status.code(), Some(1), "{mode}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("\"error_kind\":\"TimedOut\"")
        );
        assert!(start.elapsed() < Duration::from_secs(6), "{mode}");
    }
}
