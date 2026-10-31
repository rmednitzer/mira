//! journal-events/v1 through the real CLI with the native journalctl fixture,
//! a fixture journal directory and a fixture procfs root (test-support only).
#![cfg(feature = "test-support")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const MACHINE: &str = "2647eb65b1ed4abe8c03300b925dd8fe";
const ALL: &str = "oom-kill,unit-failure,coredump";

struct Host(PathBuf);

impl Host {
    /// A complete, readable journal and systemd-coredump as the crash handler.
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "mira-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let host = Self(root);
        fs::create_dir_all(host.machine()).unwrap();
        fs::write(host.machine().join("system.journal"), "").unwrap();
        fs::write(host.machine().join("system@0006-01.journal~"), "").unwrap();
        fs::write(host.machine().join("user-1000.journal"), "").unwrap();
        fs::create_dir_all(host.0.join("proc/sys/kernel")).unwrap();
        host.core_pattern("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n");
        host
    }

    fn machine(&self) -> PathBuf {
        self.0.join("var").join(MACHINE)
    }

    fn core_pattern(&self, pattern: &str) {
        fs::write(self.0.join("proc/sys/kernel/core_pattern"), pattern).unwrap();
    }

    fn run(&self, mode: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(["investigate", "journal-events"])
            .args(args)
            .env(
                "MIRA_TEST_JOURNALCTL",
                env!("CARGO_BIN_EXE_mira-process-fixture"),
            )
            .env("MIRA_PROCESS_FIXTURE_MODE", mode)
            .env("MIRA_TEST_JOURNAL_DIRS", self.0.join("var"))
            .env("MIRA_TEST_PROC_ROOT", self.0.join("proc"))
            .env("MIRA_FIXTURE_RECORD", self.0.join("calls"))
            .output()
            .unwrap()
    }

    fn report(&self, mode: &str, classes: &str, boot: &str) -> (i32, String) {
        let output = self.run(mode, &["--absent", classes, "--boot", boot, "--json"]);
        (
            output.status.code().unwrap(),
            String::from_utf8(output.stdout).unwrap(),
        )
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.0.join("calls")).unwrap_or_default()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // Restore permissions changed by the mixed-ACL case before cleanup.
        for entry in fs::read_dir(self.machine()).into_iter().flatten().flatten() {
            let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644));
        }
        if let Err(error) = fs::remove_dir_all(&self.0)
            && !std::thread::panicking()
        {
            panic!("fixture cleanup failed: {error}");
        }
    }
}

fn reason(json: &str) -> &str {
    let start = json.find("\"reason\":\"").unwrap() + 10;
    &json[start..start + json[start..].find('"').unwrap()]
}

#[test]
fn every_outcome_row_is_reachable_and_exit_codes_match() {
    let host = Host::new();
    for (mode, classes, boot, code, expected) in [
        ("journal-quiet", ALL, "current", 0, "none_recorded"),
        ("journal-events", ALL, "current", 1, "events_recorded"),
        (
            "journal-no-current",
            ALL,
            "current",
            3,
            "journal_not_visible",
        ),
        (
            "journal-no-previous",
            "unit-failure",
            "previous-retained",
            3,
            "journal_not_visible",
        ),
        (
            "journal-quiet",
            "unit-failure",
            "previous-retained",
            0,
            "none_recorded",
        ),
        (
            "journal-quiet",
            ALL,
            "previous-retained",
            3,
            "crash_handler_unknown_for_boot",
        ),
        (
            "journal-events",
            ALL,
            "previous-retained",
            1,
            "events_recorded",
        ),
        (
            "journal-fail",
            "unit-failure",
            "current",
            3,
            "evidence_unavailable",
        ),
    ] {
        let (status, json) = host.report(mode, classes, boot);
        assert_eq!(
            (status, reason(&json)),
            (code, expected),
            "{mode} {classes} {boot}"
        );
        assert!(json.contains("\"template\":\"journal-events/v1\""));
    }
    host.core_pattern("|/usr/share/apport/apport -p%p -s%s -c%c\n");
    let (status, json) = host.report("journal-quiet", ALL, "current");
    assert_eq!(
        (status, reason(&json)),
        (3, "crash_handler_not_systemd_coredump")
    );
    // Without the coredump class the crash handler does not matter.
    let (status, json) = host.report("journal-quiet", "oom-kill,unit-failure", "current");
    assert_eq!((status, reason(&json)), (0, "none_recorded"));
    assert!(json.contains("\"crash_handler\":null"));
}

#[test]
fn recorded_events_export_units_and_times_but_no_text_or_ids() {
    let host = Host::new();
    let (_, json) = host.report("journal-events", ALL, "current");
    for expected in [
        "\"units\":[\"db.service\",\"home.mount\"]",
        r#""units":["session-3.scope","systemd-fsck@dev-disk-by\\x2duuid-1.service"]"#,
        "\"units\":[\"nginx.service\"]",
        "\"first_monotonic_us\":10,\"last_monotonic_us\":20",
        "\"crash_handler\":\"systemd-coredump\"",
    ] {
        assert!(json.contains(expected), "{expected} in {json}");
    }
    for forbidden in [
        "MESSAGE",
        "_EXE",
        "_UID",
        "__CURSOR",
        "_BOOT_ID",
        "e7",
        "init.scope",
        "systemd-coredump@0-77",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} leaked");
    }
}

#[test]
fn boot_selection_never_borrows_an_older_boot() {
    let host = Host::new();
    // The running boot left no entries: previous-retained must not run at all.
    let (_, json) = host.report("journal-no-current", "unit-failure", "previous-retained");
    assert_eq!(reason(&json), "journal_not_visible");
    assert!(!host.calls().contains("-b -1"), "{}", host.calls());
    assert!(host.calls().lines().all(|call| call.contains("--boot")));
    let host = Host::new();
    host.report("journal-quiet", "unit-failure", "previous-retained");
    let calls = host.calls();
    let order: Vec<_> = calls.lines().collect();
    assert!(order[0].contains("--boot") && order[0].ends_with("_PID=1"));
    assert!(order[1].contains("-b -1") && order[1].ends_with("_PID=1"));
    assert!(order[2].contains("-b -1") && order[2].contains("MESSAGE_ID=d9b373ed"));
}

#[test]
fn incomplete_access_is_never_none_recorded() {
    let host = Host::new();
    let archive = host.machine().join("system@0006-01.journal~");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&archive).is_ok() {
        // Running as root: permissions cannot be withheld, so this case cannot be staged.
        return;
    }
    let (status, json) = host.report("journal-quiet", "unit-failure", "current");
    assert_eq!((status, reason(&json)), (3, "journal_access_incomplete"));
    assert!(json.contains("\"journal_access_complete\":false"));
    // Recorded events stay conclusive despite incomplete access.
    let (status, json) = host.report("journal-events", "unit-failure", "current");
    assert_eq!((status, reason(&json)), (1, "events_recorded"));
    // No system journal files at all is not complete access either.
    let empty = Host::new();
    for name in ["system.journal", "system@0006-01.journal~"] {
        fs::remove_file(empty.machine().join(name)).unwrap();
    }
    assert_eq!(
        reason(&empty.report("journal-quiet", "unit-failure", "current").1),
        "journal_access_incomplete"
    );
}

#[test]
fn decoys_defects_and_tool_failures_fail_closed() {
    let host = Host::new();
    for (mode, classes, expected) in [
        (
            "journal-decoys-full",
            "unit-failure",
            "evidence_unavailable",
        ),
        (
            "journal-decoys-one-valid",
            "unit-failure",
            "events_recorded",
        ),
        ("journal-wrong-origin", "unit-failure", "none_recorded"),
        ("journal-backtrace", "coredump", "none_recorded"),
        (
            "journal-missing-field",
            "unit-failure",
            "evidence_unavailable",
        ),
        ("journal-binary", "unit-failure", "evidence_unavailable"),
        ("journal-bad-unit", "unit-failure", "evidence_unavailable"),
        ("journal-oversized", "unit-failure", "evidence_unavailable"),
    ] {
        let (_, json) = host.report(mode, classes, "current");
        assert_eq!(reason(&json), expected, "{mode}");
    }
    let (_, json) = host.report("journal-decoys-one-valid", "unit-failure", "current");
    assert!(json.contains("\"count\":1,\"truncated\":true"));
    assert!(json.contains("\"first_monotonic_us\":null"));
    let missing = Command::new(env!("CARGO_BIN_EXE_mira"))
        .args([
            "investigate",
            "journal-events",
            "--absent",
            "unit-failure",
            "--json",
        ])
        .env("MIRA_TEST_JOURNALCTL", host.0.join("no-such-journalctl"))
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3));
    assert_eq!(
        reason(&String::from_utf8(missing.stdout).unwrap()),
        "evidence_unavailable"
    );
}

#[test]
fn invalid_invocations_emit_no_report() {
    let host = Host::new();
    for args in [
        vec![],
        vec!["--absent"],
        vec!["--absent", "watchdog"],
        vec!["--absent", "oom-kill,oom-kill"],
        vec!["--absent", ""],
        vec!["--absent", "oom-kill", "--boot", "previous"],
        vec!["--absent", "oom-kill", "--boot", "-1"],
        vec!["--absent", "oom-kill", "--boot"],
        vec!["--absent", "oom-kill", "--json", "--boot", "current"],
        vec!["--absent", "oom-kill", "--boot", "current", "--json", "x"],
        vec!["--boot", "current", "--absent", "oom-kill"],
    ] {
        let output = host.run("journal-quiet", &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(
        host.calls().is_empty(),
        "journalctl ran for a refused invocation"
    );
}
