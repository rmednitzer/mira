use mira::evidence::{self, EvidenceStatus};
use std::path::Path;

#[test]
fn package_fixture_has_source_and_timestamp() {
    let fixture = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dpkg/status"
    ));
    let result = evidence::collect_packages(fixture);
    assert_eq!(result.source, "/var/lib/dpkg/status");
    assert!(result.collected_unix_ms.is_some());
    match result.status {
        EvidenceStatus::Observed(packages) => assert_eq!(packages.len(), 1),
        EvidenceStatus::Unavailable { message, .. } => panic!("fixture failed: {message}"),
    }
}

#[test]
fn missing_package_database_remains_unknown() {
    let result = evidence::collect_packages(Path::new("/nonexistent-mira-dpkg-fixture"));
    assert!(!result.is_available());
    assert!(matches!(result.status, EvidenceStatus::Unavailable { .. }));
}

#[test]
fn invalid_service_name_cannot_execute() {
    let result = evidence::collect_service("--user.service");
    assert!(!result.is_available());
    assert_eq!(result.source, "systemd/system");
}
