//! Exercise acquisition bounds through complete captures, not parser-only inputs.
use mira::capture::{self, Profile};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mira-source-bounds-{}-{name}", std::process::id()));
        // Own only a newly created directory; never reuse another run's files.
        fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        fs::create_dir_all(fixture.0.join("sys/kernel")).unwrap();
        fs::create_dir(fixture.0.join("pressure")).unwrap();
        for (path, _, content) in SOURCES {
            fs::write(fixture.0.join(path), content).unwrap();
        }
        fixture
    }

    fn capture(&self) -> capture::Capture {
        capture::collect(
            "source-boundary-fixture",
            Profile::HostPressure,
            &self.0,
            &self.0.join("status"),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// Freeze the documented acquisition budgets independently of collector constants.
const SOURCES: [(&str, usize, &str); 7] = [
    ("meminfo", 65_536, "MemTotal: 100 kB\nMemAvailable: 50 kB\n"),
    ("uptime", 65_536, "42.50 123.00\n"),
    ("sys/kernel/osrelease", 16_384, "6.17.0-fixture\n"),
    ("pressure/cpu", 16_384, "some avg10=0.25\n"),
    ("pressure/memory", 16_384, "some avg10=0.25\n"),
    ("pressure/io", 16_384, "some avg10=0.25\n"),
    (
        "status",
        33_554_432,
        "Package: boundary-fixture\nStatus: install ok installed\nArchitecture: all\nVersion: 1\nDescription: fixture\n",
    ),
];

fn assert_failure(capture: &capture::Capture, path: &str, reason: &str) {
    assert!(!capture.all_available(), "{path}");
    let json = capture.to_json();
    let source = if path == "status" {
        "/var/lib/dpkg/status".to_owned()
    } else {
        format!("/proc/{path}")
    };
    // The failed record has a null value, so its closing brace bounds this check.
    let start = json.find(&format!("\"source\":\"{source}\"")).unwrap();
    let record = json[start..].split('}').next().unwrap();
    assert!(record.contains("\"status\":\"unavailable\""), "{path}");
    assert!(
        record.contains(&format!("\"failure_reason\":\"{reason}\"")),
        "{path}"
    );
    assert_eq!(json.matches("\"status\":\"observed\"").count(), 6, "{path}");
    assert!(json.contains("\"collection_complete\":true"));
    assert!(!json.contains("mira-source-bounds-"));
}

#[test]
fn exact_limits_overflow_and_invalid_utf8_preserve_independent_evidence() {
    let fixture = Fixture::new("byte-budgets");
    assert!(fixture.capture().all_available());
    for (path, limit, content) in SOURCES {
        let file = fixture.0.join(path);
        // Pad the final valid line; an extra empty PSI line is not valid input.
        let mut exact = content.trim_end_matches('\n').as_bytes().to_vec();
        exact.resize(limit - 1, b' ');
        exact.push(b'\n');
        fs::write(&file, &exact).unwrap();
        assert!(fixture.capture().all_available(), "exact limit: {path}");

        OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(b" ")
            .unwrap();
        let capture = fixture.capture();
        assert_failure(&capture, path, "limit_exceeded");

        let mut invalid = content.as_bytes().to_vec();
        invalid.push(0xff);
        fs::write(&file, invalid).unwrap();
        let capture = fixture.capture();
        assert_failure(&capture, path, "malformed_data");
        fs::write(file, content).unwrap();
    }
    assert!(fixture.capture().all_available());
}

#[test]
fn malformed_memory_tokens_preserve_other_capture_sources() {
    let fixture = Fixture::new("memory-tokens");
    for invalid in ["+50", "50\u{00a0}", "\u{00a0}50"] {
        fs::write(
            fixture.0.join("meminfo"),
            format!("MemTotal: 100 kB\nMemAvailable: {invalid} kB\n"),
        )
        .unwrap();
        assert_failure(&fixture.capture(), "meminfo", "malformed_data");
    }
}
