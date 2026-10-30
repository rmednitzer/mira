//! Authored expectation cases use the real memory reader and no other sources.
use mira::{investigation::Outcome, memory_investigation};
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn memory_criteria_bind_to_bounded_evidence_and_preserve_unknowns() {
    let root =
        std::env::temp_dir().join(format!("mira-memory-investigation-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root);
    for (total, available, minimum, expected) in [
        (100, 50, 49, Outcome::Satisfied),
        (100, 50, 50, Outcome::Satisfied),
        (100, 50, 51, Outcome::NotSatisfied),
        (100, 0, 1, Outcome::NotSatisfied),
        (100, 50, 101, Outcome::NotSatisfied),
        (u64::MAX, u64::MAX, u64::MAX, Outcome::Satisfied),
    ] {
        fs::write(
            fixture.0.join("meminfo"),
            format!("MemTotal: {total} kB\nMemAvailable: {available} kB\n"),
        )
        .unwrap();
        let report = memory_investigation::collect(minimum, &fixture.0).unwrap();
        assert_eq!(report.outcome(), expected);
        assert_eq!(report.minimum(), minimum);
        assert!(report.to_json().contains("\"source\":\"/proc/meminfo\""));
        assert!(
            report
                .to_json()
                .contains("\"application_health\":\"not_assessed\"")
        );
    }
    fs::write(
        fixture.0.join("meminfo"),
        "MemTotal: 1 kB\nMemAvailable: 2 kB\n",
    )
    .unwrap();
    assert_eq!(
        memory_investigation::collect(1, &fixture.0)
            .unwrap()
            .outcome(),
        Outcome::Indeterminate
    );
    // Malformed source text cannot satisfy an otherwise valid minimum.
    for invalid in ["+50", "-50", "50.0", "5e1", "５０", "50\u{00a0}"] {
        for field in ["MemTotal", "MemAvailable"] {
            let text = if field == "MemTotal" {
                format!("MemTotal: {invalid} kB\nMemAvailable: 50 kB\n")
            } else {
                format!("MemTotal: 100 kB\nMemAvailable: {invalid} kB\n")
            };
            fs::write(fixture.0.join("meminfo"), text).unwrap();
            let report = memory_investigation::collect(1, &fixture.0).unwrap();
            assert_eq!(
                report.outcome(),
                Outcome::Indeterminate,
                "{field}: {invalid}"
            );
            assert_eq!(report.reason(), "evidence_unavailable");
            assert!(report.to_json().contains("\"error_kind\":\"InvalidData\""));
        }
    }
    fs::remove_file(fixture.0.join("meminfo")).unwrap();
    let report = memory_investigation::collect(1, &fixture.0).unwrap();
    assert_eq!(report.outcome(), Outcome::Indeterminate);
    assert_eq!(report.reason(), "evidence_unavailable");
    assert!(!report.to_json().contains("mira-memory-investigation-"));
    assert!(memory_investigation::collect(0, &fixture.0).is_err());
}

#[test]
fn invalid_memory_invocations_emit_no_report() {
    for minimum in [
        "",
        "0",
        "-1",
        "+1",
        "1.0",
        "1e3",
        "18446744073709551616",
        "000000000000000000001",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mira"))
            .args([
                "investigate",
                "memory-headroom",
                "--min-available-kib",
                minimum,
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
