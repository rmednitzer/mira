//! Authored PSI ceiling cases use the real pressure reader and no other sources.
use mira::{host_extra::PressureResource, investigation::Outcome, pressure_investigation};
use std::{fs, path::PathBuf, process::Command};

const RESOURCES: [PressureResource; 3] = [
    PressureResource::Cpu,
    PressureResource::Memory,
    PressureResource::Io,
];

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mira-pressure-investigation-{}-{name}",
            std::process::id()
        ));
        // Own only a newly created directory; never reuse another run's files.
        fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        fs::create_dir(fixture.0.join("pressure")).unwrap();
        fixture
    }

    fn write(&self, resource: PressureResource, text: &str) {
        fs::write(self.0.join("pressure").join(resource.name()), text).unwrap();
    }

    fn assess(&self, resource: PressureResource, maximum: u32) -> pressure_investigation::Report {
        pressure_investigation::collect(resource, maximum, &self.0).unwrap()
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

fn psi(some: &str, full: &str) -> String {
    format!(
        "some avg10={some} avg60=0.00 avg300=0.00 total=1\nfull avg10={full} avg60=0.00 avg300=0.00 total=1\n"
    )
}

#[test]
fn ceilings_bind_to_the_selected_resource_and_some_avg10() {
    let fixture = Fixture::new("table");
    for resource in RESOURCES {
        for (some, full, maximum, expected, reason) in [
            ("0.00", "0.00", 0, Outcome::Satisfied, "within_ceiling"),
            ("0.01", "0.00", 0, Outcome::NotSatisfied, "above_ceiling"),
            ("0.25", "90.00", 25, Outcome::Satisfied, "within_ceiling"),
            ("0.26", "0.00", 25, Outcome::NotSatisfied, "above_ceiling"),
            ("12.5", "0.00", 1250, Outcome::Satisfied, "within_ceiling"),
            (
                "100.00",
                "100.00",
                10_000,
                Outcome::Satisfied,
                "within_ceiling",
            ),
            (
                "100.00",
                "0.00",
                9_999,
                Outcome::NotSatisfied,
                "above_ceiling",
            ),
        ] {
            fixture.write(resource, &psi(some, full));
            let report = fixture.assess(resource, maximum);
            let case = format!("{resource:?} some={some} full={full} max={maximum}");
            assert_eq!(report.outcome(), expected, "{case}");
            assert_eq!(report.reason(), reason, "{case}");
            assert_eq!(report.evidence().source, resource.source(), "{case}");
            let json = report.to_json();
            assert!(json.contains(&format!("\"resource\":\"{}\"", resource.name())));
            assert!(json.contains(&format!("\"max_some_avg10_basis_points\":{maximum}")));
            assert!(json.contains("\"application_health\":\"not_assessed\""));
            assert!(json.contains("\"schema_version\":2"));
        }
    }
}

#[test]
fn other_resources_cannot_influence_the_selected_one() {
    let fixture = Fixture::new("isolation");
    fixture.write(PressureResource::Cpu, "garbage\n");
    fixture.write(PressureResource::Io, &psi("100.00", "100.00"));
    fixture.write(PressureResource::Memory, &psi("0.00", "0.00"));
    assert_eq!(
        fixture.assess(PressureResource::Memory, 0).outcome(),
        Outcome::Satisfied
    );
    assert_eq!(
        fixture.assess(PressureResource::Cpu, 10_000).outcome(),
        Outcome::Indeterminate
    );
    assert_eq!(
        fixture.assess(PressureResource::Io, 9_999).outcome(),
        Outcome::NotSatisfied
    );
}

#[test]
fn unavailable_or_malformed_pressure_stays_indeterminate() {
    let fixture = Fixture::new("unavailable");
    let resource = PressureResource::Io;
    for (text, failure) in [
        ("some avg10=101.00\n".to_owned(), "malformed_data"),
        ("full avg10=0.00\n".to_owned(), "malformed_data"),
        ("some\u{00a0}avg10=0.00\n".to_owned(), "malformed_data"),
        (
            "some avg10=0.00 avg60=0.00\u{2003}avg10=99.00\n".to_owned(),
            "malformed_data",
        ),
        ("some avg10=0.00\n".repeat(2), "malformed_data"),
        (
            format!("some avg10=0.00\n{}", " ".repeat(16 * 1024)),
            "limit_exceeded",
        ),
    ] {
        fixture.write(resource, &text);
        // The widest ceiling must still not turn bad evidence into success.
        let report = fixture.assess(resource, 10_000);
        assert_eq!(report.outcome(), Outcome::Indeterminate, "{text:?}");
        assert_eq!(report.reason(), "evidence_unavailable");
        assert!(
            report
                .to_json()
                .contains(&format!("\"failure_reason\":\"{failure}\"")),
            "{text:?}"
        );
    }
    fs::remove_file(fixture.0.join("pressure/io")).unwrap();
    let report = fixture.assess(resource, 10_000);
    assert_eq!(report.outcome(), Outcome::Indeterminate);
    assert!(
        report
            .to_json()
            .contains("\"failure_reason\":\"not_found\"")
    );
    assert!(!report.to_json().contains("mira-pressure-investigation-"));
}

fn mira(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mira"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn invalid_criteria_and_resources_emit_no_report() {
    for maximum in [
        "", "-1", "+1", "1.5", "1e3", "10001", "000000", " 1", "1 ", "0x10", "١",
    ] {
        let output = mira(&[
            "investigate",
            "pressure-ceiling",
            "--resource",
            "cpu",
            "--max-some-avg10-basis-points",
            maximum,
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(2), "{maximum:?}");
        assert!(output.stdout.is_empty(), "{maximum:?}");
        assert_eq!(
            output.stderr,
            b"MIRA: pressure ceiling must be an integer from 0 to 10000 basis points\n"
        );
    }
    for resource in ["", "CPU", "irq", "cpu ", "../io", "pressure/memory"] {
        let output = mira(&[
            "investigate",
            "pressure-ceiling",
            "--resource",
            resource,
            "--max-some-avg10-basis-points",
            "1",
        ]);
        assert_eq!(output.status.code(), Some(2), "{resource:?}");
        assert!(output.stdout.is_empty(), "{resource:?}");
        assert_eq!(
            output.stderr,
            b"MIRA: pressure resource must be cpu, memory or io\n"
        );
    }
}

#[test]
fn malformed_pressure_invocations_report_template_usage() {
    for arguments in [
        vec!["investigate", "pressure-ceiling"],
        vec!["investigate", "pressure-ceiling", "--resource", "cpu"],
        vec!["investigate", "pressure-ceiling", "cpu", "25"],
        vec!["investigate", "pressure-ceiling", "ssh.service"],
        vec!["investigate", "pressure-ceiling", "ssh.service", "--json"],
        vec![
            "investigate",
            "pressure-ceiling",
            "--max-some-avg10-basis-points",
            "25",
            "--resource",
            "cpu",
        ],
        vec![
            "investigate",
            "pressure-ceiling",
            "--resource",
            "cpu",
            "--max-some-avg10-basis-points",
            "25",
            "--json",
            "x",
        ],
        vec![
            "investigate",
            "pressure-ceiling",
            "--resource",
            "cpu",
            "--max-some-avg10-basis-points",
            "25",
            "--pressure",
        ],
    ] {
        let output = mira(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert_eq!(
            output.stderr,
            b"Usage: mira investigate pressure-ceiling --resource cpu|memory|io --max-some-avg10-basis-points N [--json]\n",
            "{arguments:?}"
        );
    }
}
