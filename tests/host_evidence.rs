use mira::{
    evidence::{self, EvidenceStatus},
    host_extra, linux,
};
use std::path::Path;

#[test]
fn fixture_parses_into_complete_host_evidence() {
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/proc"));
    let snapshot = evidence::collect(root);
    assert!(snapshot.complete(), "{snapshot:?}");
    assert_eq!(snapshot.memory.source, "/proc/meminfo");
    assert!(snapshot.memory.collected_unix_ms.is_some());
    assert!(matches!(
        snapshot.memory.status,
        EvidenceStatus::Observed(linux::MemoryEvidence {
            total_kib: 16_384_000,
            available_kib: 8_192_000
        })
    ));
    assert!(matches!(
        snapshot.uptime.status,
        EvidenceStatus::Observed(123456)
    ));
    assert!(
        matches!(snapshot.kernel_release.status, EvidenceStatus::Observed(ref v) if v == "6.17.0-5-generic")
    );
    assert!(matches!(
        snapshot.cpu_pressure.status,
        EvidenceStatus::Observed(host_extra::CpuPressure {
            some_avg10_basis_points: 250,
            full_avg10_basis_points: Some(0)
        })
    ));
}

#[test]
fn malformed_idle_time_is_unavailable_without_hiding_memory() {
    // Exercise the same source-report and evidence projection used by inspect.
    // A unique directory owns only these fixture files; no environment changes.
    let root = std::env::temp_dir().join(format!("mira-uptime-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::fs::write(root.join("meminfo"), "MemTotal: 100 kB\nMemAvailable: 50 kB\n").unwrap();
    std::fs::write(root.join("uptime"), "42.50 garbage\n").unwrap();
    let snapshot = evidence::collect(&root);
    assert!(snapshot.memory.is_available());
    assert!(matches!(
        snapshot.uptime.status,
        EvidenceStatus::Unavailable {
            kind: std::io::ErrorKind::InvalidData,
            ..
        }
    ));
    let json = mira::evidence_json::record(&snapshot.uptime, None, |value| value.to_string());
    assert!(json.contains("\"status\":\"unavailable\""));
    assert!(json.contains("\"value\":null"));
    assert!(json.contains("\"error_kind\":\"InvalidData\""));
    assert!(!json.contains("garbage"));
}
