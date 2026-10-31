//! Frozen authored source/availability matrix. No model-generated verdict oracle.
use mira::{
    capture::{self, Profile},
    evidence::{self, EvidenceStatus},
    host_extra::{self, PressureResource},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
        fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dpkg/status"),
            fixture.0.join("status"),
        )
        .unwrap();
        for file in ["pressure/memory", "pressure/io"] {
            fs::write(fixture.0.join(file), "some avg10=1.25 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.50 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        }
        fixture
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn source_availability_matrix_preserves_completion_and_independence() {
    for (name, changed, contents, profile, expected_available, count) in [
        ("host", "", Some(""), Profile::Host, true, 5),
        ("pressure", "", Some(""), Profile::HostPressure, true, 7),
        (
            "bad-memory",
            "meminfo",
            Some("malformed"),
            Profile::Host,
            false,
            5,
        ),
        (
            "bad-uptime",
            "uptime",
            Some("42.50 garbage"),
            Profile::Host,
            false,
            5,
        ),
        ("missing-cpu", "pressure/cpu", None, Profile::Host, false, 5),
        (
            "missing-memory-pressure",
            "pressure/memory",
            None,
            Profile::HostPressure,
            false,
            7,
        ),
        (
            "bad-io-pressure",
            "pressure/io",
            Some("some avg10=101.00\n"),
            Profile::HostPressure,
            false,
            7,
        ),
        (
            "optional-pressure",
            "pressure/io",
            None,
            Profile::Host,
            true,
            5,
        ),
    ] {
        let fixture = Fixture::new(name);
        if !changed.is_empty() {
            if let Some(value) = contents {
                fs::write(fixture.0.join(changed), value).unwrap();
            } else {
                fs::remove_file(fixture.0.join(changed)).unwrap();
            }
        }
        let capture =
            capture::collect("synthetic", profile, &fixture.0, &fixture.0.join("status")).unwrap();
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

#[test]
fn timeline_covers_every_source_in_profile_order_within_one_window() {
    let fixture = Fixture::new("timeline");
    for profile in [Profile::Host, Profile::HostPressure] {
        let capture = capture::collect(
            "timeline-fixture",
            profile,
            &fixture.0,
            &fixture.0.join("status"),
        )
        .unwrap();
        let timeline = capture.timeline();
        let sources: Vec<_> = timeline.entries.iter().map(|entry| entry.source).collect();
        assert_eq!(sources, profile.sources());
        let mut previous = 0;
        for entry in &timeline.entries {
            let elapsed = entry.elapsed_ms.expect("monotonic elapsed time");
            assert!(entry.offset_ms >= previous, "{entry:?}");
            assert!(
                entry.offset_ms + elapsed <= timeline.monotonic_window_ms,
                "{entry:?}"
            );
            previous = entry.offset_ms;
        }
        assert!(timeline.started_unix_ms <= timeline.ended_unix_ms);
        assert_ne!(timeline.wall_clock(), "unknown");

        // capture-v2 is capture-v1 with a new version and the timing members
        // inserted before records; every record byte is unchanged.
        let v1 = capture.to_json();
        let v2 = capture.to_timeline_json();
        let split = v1.find("\"records\":").unwrap();
        let head = v1[..split].replacen("\"capture_version\":1", "\"capture_version\":2", 1);
        assert!(v2.starts_with(&head), "{v2}");
        assert!(v2.ends_with(&v1[split..]), "{v2}");
        let timing = &v2[head.len()..v2.len() - (v1.len() - split)];
        assert!(timing.starts_with("\"collection\":{\"monotonic_window_ms\":"));
        assert!(timing.contains("\"boot\":{\"binding\":\"not_requested\"}"));
        assert!(timing.contains(&format!(
            "\"timeline\":[{{\"source\":\"/proc/meminfo\",\"offset_ms\":{},",
            timeline.entries[0].offset_ms
        )));
        assert_eq!(
            timing.matches("\"source\":").count(),
            profile.sources().len()
        );
    }
}

#[test]
fn boot_binding_is_opt_in_and_unavailable_without_partial_values() {
    const ID: &str = "e740207d-b13a-48dd-8e9d-595a950d6930";
    let fixture = Fixture::new("boot");
    let status = fixture.0.join("status");
    let collect = |bind: bool| {
        let collect = if bind {
            capture::collect_with_boot
        } else {
            capture::collect
        };
        collect("boot-fixture", Profile::Host, &fixture.0, &status).unwrap()
    };
    // Without a request the boot ID file is never needed.
    assert_eq!(collect(false).boot(), &capture::BootBinding::NotRequested);
    assert_eq!(
        collect(true).boot(),
        &capture::BootBinding::Unavailable(mira::collector::FailureReason::NotFound)
    );
    fs::create_dir_all(fixture.0.join("sys/kernel/random")).unwrap();
    let boot_id = fixture.0.join("sys/kernel/random/boot_id");
    fs::write(&boot_id, format!("{ID}\n")).unwrap();
    let uptime = fs::read_to_string(fixture.0.join("uptime")).unwrap();
    let centiseconds = mira::linux::parse_uptime_centiseconds(&uptime).unwrap();
    let bound = collect(true);
    assert_eq!(
        bound.boot(),
        &capture::BootBinding::Observed {
            boot_id: ID.to_owned(),
            started_uptime_cs: centiseconds,
            ended_uptime_cs: centiseconds,
        }
    );
    assert!(bound.all_available());
    let json = bound.to_timeline_json();
    assert!(json.contains(&format!("\"boot_id\":\"{ID}\"")));
    assert!(
        !bound.to_json().contains(ID),
        "capture-v1 must not carry the boot ID"
    );
    for (contents, reason) in [
        (ID.to_uppercase() + "\n", "malformed_data"),
        (ID.to_owned(), "malformed_data"),
        (format!("{ID}\n{ID}\n"), "limit_exceeded"),
    ] {
        fs::write(&boot_id, contents).unwrap();
        let capture = collect(true);
        let json = capture.to_timeline_json();
        assert!(
            json.contains(&format!(
                "\"boot\":{{\"binding\":\"unavailable\",\"failure_reason\":\"{reason}\"}}"
            )),
            "{json}"
        );
        assert!(!json.contains(ID));
        // Boot binding failure never changes record availability.
        assert!(capture.all_available());
    }
    // Malformed uptime makes both the uptime record and the binding unavailable.
    fs::write(&boot_id, format!("{ID}\n")).unwrap();
    fs::write(fixture.0.join("uptime"), "garbage\n").unwrap();
    let capture = collect(true);
    assert!(!capture.all_available());
    assert_eq!(
        capture.boot(),
        &capture::BootBinding::Unavailable(mira::collector::FailureReason::MalformedData)
    );
}
