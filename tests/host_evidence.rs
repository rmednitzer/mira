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
