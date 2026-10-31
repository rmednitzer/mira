//! Authored uptime and kernel-release cases use the real procfs readers and no other source.
use mira::{host_investigation, investigation::Outcome};
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mira-host-investigation-{}-{name}",
            std::process::id()
        ));
        // Own only a newly created directory; never reuse another run's files.
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(root.join("sys/kernel")).unwrap();
        Self(root)
    }

    fn uptime(&self, text: &str, minimum: u64) -> host_investigation::UptimeReport {
        fs::write(self.0.join("uptime"), text).unwrap();
        host_investigation::collect_uptime(minimum, &self.0).unwrap()
    }

    fn kernel(&self, text: &str, expected: &str) -> host_investigation::KernelReport {
        fs::write(self.0.join("sys/kernel/osrelease"), text).unwrap();
        host_investigation::collect_kernel(expected, &self.0).unwrap()
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
fn uptime_minimum_is_exact_at_whole_second_boundaries() {
    let fixture = Fixture::new("uptime");
    for (text, minimum, expected, reason) in [
        ("59.99 0.00\n", 60, Outcome::NotSatisfied, "below_minimum"),
        ("60.00 0.00\n", 60, Outcome::Satisfied, "minimum_met"),
        ("60.01 9999.00\n", 60, Outcome::Satisfied, "minimum_met"),
        ("0.50 0.00\n", 1, Outcome::NotSatisfied, "below_minimum"),
        ("1 0\n", 1, Outcome::Satisfied, "minimum_met"),
        (
            "18446744073709551615.99 0.00\n",
            u64::MAX,
            Outcome::Satisfied,
            "minimum_met",
        ),
        (
            "18446744073709551614.99 0.00\n",
            u64::MAX,
            Outcome::NotSatisfied,
            "below_minimum",
        ),
    ] {
        let report = fixture.uptime(text, minimum);
        assert_eq!(report.outcome(), expected, "{text:?} >= {minimum}");
        assert_eq!(report.reason(), reason);
        let json = report.to_json();
        assert!(json.contains(&format!("\"minimum_uptime_seconds\":{minimum}")));
        assert!(json.contains("\"source\":\"/proc/uptime\""));
        assert!(json.contains("\"schema_version\":2"));
    }
}

#[test]
fn unavailable_uptime_stays_indeterminate() {
    let fixture = Fixture::new("uptime-unavailable");
    for (text, failure) in [
        ("garbage\n".to_owned(), "malformed_data"),
        ("42.50\n".to_owned(), "malformed_data"),
        ("42.50 -1.00\n".to_owned(), "malformed_data"),
        ("1e9 0.00\n".to_owned(), "malformed_data"),
        ("42.50\u{00a0}0.00\n".to_owned(), "malformed_data"),
        (
            "18446744073709551616.00 0.00\n".to_owned(),
            "malformed_data",
        ),
        (
            format!("42.50 0.00{}", " ".repeat(64 * 1024)),
            "limit_exceeded",
        ),
    ] {
        // The smallest minimum must still not turn bad evidence into success.
        let report = fixture.uptime(&text, 1);
        assert_eq!(report.outcome(), Outcome::Indeterminate, "{text:.40?}");
        assert_eq!(report.reason(), "evidence_unavailable");
        assert!(
            report
                .to_json()
                .contains(&format!("\"failure_reason\":\"{failure}\""))
        );
    }
    fs::remove_file(fixture.0.join("uptime")).unwrap();
    let report = host_investigation::collect_uptime(1, &fixture.0).unwrap();
    assert_eq!(report.outcome(), Outcome::Indeterminate);
    assert!(
        report
            .to_json()
            .contains("\"failure_reason\":\"not_found\"")
    );
    assert!(!report.to_json().contains("mira-host-investigation-"));
}

#[test]
fn kernel_release_matches_exactly() {
    let fixture = Fixture::new("kernel");
    for (text, expected, outcome, reason) in [
        (
            "6.17.0-5-generic\n",
            "6.17.0-5-generic",
            Outcome::Satisfied,
            "release_matches",
        ),
        (
            "6.17.0-5-generic",
            "6.17.0-5-generic",
            Outcome::Satisfied,
            "release_matches",
        ),
        (
            "6.17.0-5-generic\n",
            "6.17.0-5-Generic",
            Outcome::NotSatisfied,
            "release_differs",
        ),
        (
            "6.17.0-5-generic\n",
            "6.17.0-5",
            Outcome::NotSatisfied,
            "release_differs",
        ),
        (
            "6.17.0-5-generic\n",
            "6.17.0-5-generic+1",
            Outcome::NotSatisfied,
            "release_differs",
        ),
        (
            "6.17.0-50-generic\n",
            "6.17.0-5-generic",
            Outcome::NotSatisfied,
            "release_differs",
        ),
        (
            "6.6.1+rpt-rpi-v8\n",
            "6.6.1+rpt-rpi-v8",
            Outcome::Satisfied,
            "release_matches",
        ),
    ] {
        let report = fixture.kernel(text, expected);
        assert_eq!(report.outcome(), outcome, "{text:?} vs {expected}");
        assert_eq!(report.reason(), reason);
        assert!(
            report
                .to_json()
                .contains(&format!("\"release\":\"{expected}\""))
        );
    }
    for (text, failure) in [
        ("6.17.0 generic\n".to_owned(), "malformed_data"),
        ("6.17.0\u{00a0}\n".to_owned(), "malformed_data"),
        ("\n".to_owned(), "malformed_data"),
        (format!("{}\n", "6".repeat(257)), "malformed_data"),
        ("6".repeat(16 * 1024 + 1), "limit_exceeded"),
    ] {
        let report = fixture.kernel(&text, "6.17.0");
        assert_eq!(report.outcome(), Outcome::Indeterminate, "{text:.40?}");
        assert!(
            report
                .to_json()
                .contains(&format!("\"failure_reason\":\"{failure}\""))
        );
    }
}

fn mira(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mira"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn invalid_criteria_emit_no_report() {
    for minimum in [
        "",
        "0",
        "-1",
        "+1",
        "1.0",
        "1e3",
        " 1",
        "18446744073709551616",
        "000000000000000000001",
    ] {
        let output = mira(&[
            "investigate",
            "uptime-minimum",
            "--min-uptime-seconds",
            minimum,
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(2), "{minimum:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"MIRA: uptime minimum must be a positive integer number of seconds\n"
        );
    }
    for release in [
        "", " 6.17.0", "6.17.0 ", "6.17.0\n", "6.17/0", "--json", "-x", ".6", "é",
    ] {
        let output = mira(&["investigate", "kernel-release", "--expect", release]);
        assert_eq!(output.status.code(), Some(2), "{release:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"MIRA: expected kernel release must be 1-256 characters from A-Za-z0-9._+- starting with a letter or digit\n"
        );
    }
}

#[test]
fn malformed_invocations_report_template_usage() {
    let uptime = b"Usage: mira investigate uptime-minimum --min-uptime-seconds N [--json]\n";
    let kernel = b"Usage: mira investigate kernel-release --expect RELEASE [--json]\n";
    for (arguments, usage) in [
        (vec!["investigate", "uptime-minimum"], &uptime[..]),
        (vec!["investigate", "uptime-minimum", "60"], uptime),
        (
            vec![
                "investigate",
                "uptime-minimum",
                "--json",
                "--min-uptime-seconds",
                "60",
            ],
            uptime,
        ),
        (
            vec![
                "investigate",
                "uptime-minimum",
                "--min-uptime-seconds",
                "60",
                "--json",
                "x",
            ],
            uptime,
        ),
        (vec!["investigate", "kernel-release"], kernel),
        (vec!["investigate", "kernel-release", "6.17.0"], kernel),
        (vec!["investigate", "kernel-release", "--expect"], kernel),
        (
            vec![
                "investigate",
                "kernel-release",
                "--expect",
                "6.17.0",
                "--pressure",
            ],
            kernel,
        ),
    ] {
        let output = mira(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert_eq!(output.stderr, usage, "{arguments:?}");
    }
}
