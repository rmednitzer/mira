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
        self.invoke(&["service", "ssh.service", "--json"], mode)
    }

    fn invoke(&self, args: &[&str], mode: &str) -> Output {
        // Environment changes affect only this child, not parallel Rust tests.
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(args)
            .env("PATH", &self.0)
            .env("MIRA_PROCESS_FIXTURE_MODE", mode)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Cleanup failure still fails a passing test, but a second panic while
        // unwinding would abort the binary and hide the original assertion.
        if let Err(error) = fs::remove_dir_all(&self.0)
            && !std::thread::panicking()
        {
            panic!("fixture cleanup failed: {error}");
        }
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

#[test]
fn investigation_dispositions_preserve_reported_state_and_scope() {
    let fixture = Fixture::new();
    for (mode, code, outcome, reason) in [
        ("valid", 0, "satisfied", "reported_active"),
        ("reloading", 0, "satisfied", "reported_active"),
        ("refreshing", 0, "satisfied", "reported_active"),
        ("masked-active", 0, "satisfied", "reported_active"),
        ("alias-active", 0, "satisfied", "reported_active"),
        ("reported-failed", 1, "not_satisfied", "reported_not_active"),
        (
            "reported-inactive",
            1,
            "not_satisfied",
            "reported_not_active",
        ),
        ("maintenance", 1, "not_satisfied", "reported_not_active"),
        ("activating", 3, "indeterminate", "transition_in_progress"),
        ("deactivating", 3, "indeterminate", "transition_in_progress"),
        (
            "future-state",
            3,
            "indeterminate",
            "unrecognized_active_state",
        ),
    ] {
        let output = fixture.invoke(
            &["investigate", "service-active", "ssh.service", "--json"],
            mode,
        );
        assert_eq!(output.status.code(), Some(code), "{mode}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains(&format!("\"outcome\":\"{outcome}\"")),
            "{mode}"
        );
        assert!(text.contains(&format!("\"reason\":\"{reason}\"")), "{mode}");
        assert!(text.contains("\"scope\":\"ssh.service\""));
        assert!(text.contains("\"application_health\":\"not_assessed\""));
        assert!(text.contains("\"clock_trust\":\"unverified\""));
        if mode == "alias-active" {
            assert!(text.contains("canonical.service"));
        }
        if mode == "masked-active" {
            assert!(text.contains("\"load_state\":\"masked\""));
        }
    }
}

#[test]
fn investigation_does_not_turn_collection_failure_into_failed_service() {
    let fixture = Fixture::new();
    for mode in ["failure", "malformed", "invalid-utf8", "oversized"] {
        let output = fixture.invoke(
            &["investigate", "service-active", "ssh.service", "--json"],
            mode,
        );
        assert_eq!(output.status.code(), Some(3), "{mode}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("\"outcome\":\"indeterminate\""));
        assert!(text.contains("\"reason\":\"evidence_unavailable\""));
        assert!(text.contains("\"status\":\"unavailable\""));
    }
}

#[test]
fn investigation_rejects_unregistered_template_and_invalid_scope() {
    let fixture = Fixture::new();
    for args in [
        ["investigate", "restart", "ssh.service", "--json"],
        ["investigate", "service-active;id", "ssh.service", "--json"],
        ["investigate", "service-active", "--user.service", "--json"],
    ] {
        let output = fixture.invoke(&args, "valid");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn human_service_output_cannot_emit_raw_terminal_controls() {
    let fixture = Fixture::new();
    for args in [
        vec!["service", "ssh.service"],
        vec!["investigate", "service-active", "ssh.service"],
    ] {
        let output = fixture.invoke(&args, "control-state");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("future-"));
    }
}

#[test]
fn versioned_service_templates_distinguish_only_not_found_inactive_units() {
    let fixture = Fixture::new();
    for (mode, v1_reason, v2_code, v2_outcome, v2_reason) in [
        (
            "not-found",
            "reported_not_active",
            1,
            "not_satisfied",
            "unit_not_found",
        ),
        (
            "not-found-active",
            "reported_active",
            0,
            "satisfied",
            "reported_active",
        ),
        (
            "not-found-failed",
            "reported_not_active",
            1,
            "not_satisfied",
            "reported_not_active",
        ),
        (
            "reported-inactive",
            "reported_not_active",
            1,
            "not_satisfied",
            "reported_not_active",
        ),
        (
            "valid",
            "reported_active",
            0,
            "satisfied",
            "reported_active",
        ),
        (
            "activating",
            "transition_in_progress",
            3,
            "indeterminate",
            "transition_in_progress",
        ),
        (
            "failure",
            "evidence_unavailable",
            3,
            "indeterminate",
            "evidence_unavailable",
        ),
    ] {
        // The unversioned name and the explicit v1 name are the same v1 report.
        let unversioned = fixture.invoke(
            &["investigate", "service-active", "ssh.service", "--json"],
            mode,
        );
        let explicit = fixture.invoke(
            &["investigate", "service-active/v1", "ssh.service", "--json"],
            mode,
        );
        for output in [&unversioned, &explicit] {
            let text = String::from_utf8(output.stdout.clone()).unwrap();
            assert!(
                text.contains("\"investigation_version\":1,\"template\":\"service-active/v1\"")
            );
            assert!(
                text.contains(&format!("\"reason\":\"{v1_reason}\"")),
                "{mode}"
            );
        }
        assert_eq!(unversioned.status.code(), explicit.status.code(), "{mode}");

        let v2 = fixture.invoke(
            &["investigate", "service-active/v2", "ssh.service", "--json"],
            mode,
        );
        assert_eq!(v2.status.code(), Some(v2_code), "{mode}");
        let text = String::from_utf8(v2.stdout).unwrap();
        assert!(text.contains("\"investigation_version\":2,\"template\":\"service-active/v2\""));
        assert!(
            text.contains(&format!("\"outcome\":\"{v2_outcome}\"")),
            "{mode}"
        );
        assert!(
            text.contains(&format!("\"reason\":\"{v2_reason}\"")),
            "{mode}"
        );
        assert!(text.contains("\"scope\":\"ssh.service\""));
        assert!(text.contains("\"application_health\":\"not_assessed\""));
    }
}

#[test]
fn unregistered_template_versions_are_usage_errors() {
    let fixture = Fixture::new();
    for template in ["service-active/v3", "service-active/", "service-active/V2"] {
        let output = fixture.invoke(&["investigate", template, "ssh.service", "--json"], "valid");
        assert_eq!(output.status.code(), Some(2), "{template}");
        assert!(output.stdout.is_empty(), "{template}");
    }
    let human = fixture.invoke(
        &["investigate", "service-active/v2", "ssh.service"],
        "not-found",
    );
    assert_eq!(human.status.code(), Some(1));
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("MIRA service-active/v2"));
    assert!(text.contains("outcome=not_satisfied reason=unit_not_found"));
}
