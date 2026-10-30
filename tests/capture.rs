//! Frozen authored source/availability matrix. No model-generated verdict oracle.
use mira::{capture::{self, Profile}, evidence::{self, EvidenceStatus}, host_extra::{self, PressureResource}};
use std::{fs, path::{Path, PathBuf}};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mira-capture-{}-{name}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let source = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/proc"));
        fs::create_dir_all(fixture.0.join("sys/kernel")).unwrap();
        fs::create_dir(fixture.0.join("pressure")).unwrap();
        for file in ["meminfo", "uptime", "sys/kernel/osrelease", "pressure/cpu"] {
            fs::copy(source.join(file), fixture.0.join(file)).unwrap();
        }
        fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dpkg/status"), fixture.0.join("status")).unwrap();
        for file in ["pressure/memory", "pressure/io"] {
            fs::write(fixture.0.join(file), "some avg10=1.25 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.50 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        }
        fixture
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

#[test]
fn source_availability_matrix_preserves_completion_and_independence() {
    for (name, changed, contents, profile, expected_available, count) in [
        ("host", "", Some(""), Profile::Host, true, 5),
        ("pressure", "", Some(""), Profile::HostPressure, true, 7),
        ("bad-memory", "meminfo", Some("malformed"), Profile::Host, false, 5),
        ("bad-uptime", "uptime", Some("42.50 garbage"), Profile::Host, false, 5),
        ("missing-cpu", "pressure/cpu", None, Profile::Host, false, 5),
        ("missing-memory-pressure", "pressure/memory", None, Profile::HostPressure, false, 7),
        ("bad-io-pressure", "pressure/io", Some("some avg10=101.00\n"), Profile::HostPressure, false, 7),
        ("optional-pressure", "pressure/io", None, Profile::Host, true, 5),
    ] {
        let fixture = Fixture::new(name);
        if !changed.is_empty() {
            if let Some(value) = contents { fs::write(fixture.0.join(changed), value).unwrap(); }
            else { fs::remove_file(fixture.0.join(changed)).unwrap(); }
        }
        let capture = capture::collect("synthetic", profile, &fixture.0, &fixture.0.join("status")).unwrap();
        assert_eq!(capture.all_available(), expected_available, "{name}");
        let json = capture.to_json();
        assert!(json.contains("\"collection_complete\":true"));
        assert_eq!(json.matches("\"schema_version\":2").count(), count);
        assert_eq!(json.matches("\"elapsed_ms\":").count(), count);
        let host = evidence::collect(&fixture.0);
        assert!(host.kernel_release.is_available());
    }
}

#[test]
fn resource_sources_and_basis_points_are_preserved() {
    let fixture = Fixture::new("resources");
    for resource in [PressureResource::Memory, PressureResource::Io] {
        let value = host_extra::pressure(&fixture.0, resource).unwrap();
        assert_eq!(value.some_avg10_basis_points, 125);
        assert_eq!(value.full_avg10_basis_points, Some(50));
        let observation = evidence::observe(resource.source(), || Ok(value));
        assert!(matches!(observation.status, EvidenceStatus::Observed(_)));
        assert!(observation.elapsed_ms.is_some());
    }
}
