//! A typed, read-only evidence snapshot with explicit source status and timing.
//!
//! A snapshot is a sequence of file observations, not an atomic host state.
//! Wall-clock values are informational and do not establish trusted provenance.
use crate::{collector::FailureReason, host_extra, linux, packages, systemd};
use std::{
    io,
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceStatus<T> {
    Observed(T),
    Unavailable {
        kind: io::ErrorKind,
        message: String,
        reason: FailureReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence<T> {
    pub source: &'static str,
    pub collected_unix_ms: Option<u128>,
    pub elapsed_ms: Option<u128>,
    pub status: EvidenceStatus<T>,
}

impl<T> Evidence<T> {
    pub fn from_result(source: &'static str, result: io::Result<T>, at: Option<u128>) -> Self {
        let status = match result {
            Ok(value) => EvidenceStatus::Observed(value),
            Err(error) => EvidenceStatus::Unavailable {
                reason: FailureReason::from_error(&error),
                kind: error.kind(),
                message: error.to_string(),
            },
        };
        Self {
            source,
            collected_unix_ms: at,
            elapsed_ms: None,
            status,
        }
    }
    pub fn is_available(&self) -> bool {
        matches!(self.status, EvidenceStatus::Observed(_))
    }
}

#[derive(Debug)]
pub struct Snapshot {
    pub memory: Evidence<linux::MemoryEvidence>,
    pub uptime: Evidence<u64>,
    pub kernel_release: Evidence<String>,
    pub cpu_pressure: Evidence<host_extra::CpuPressure>,
}

impl Snapshot {
    pub fn complete(&self) -> bool {
        self.memory.is_available()
            && self.uptime.is_available()
            && self.kernel_release.is_available()
            && self.cpu_pressure.is_available()
    }
}

fn timestamp() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|t| t.as_millis())
}

/// Reads only the four registered procfs sources, without executing commands.
/// An injectable root supports isolated fixture tests. The root is not a security boundary.
pub fn collect(proc_root: &Path) -> Snapshot {
    Snapshot {
        memory: observe("/proc/meminfo", || linux::memory(proc_root)),
        uptime: observe("/proc/uptime", || linux::uptime(proc_root)),
        kernel_release: observe("/proc/sys/kernel/osrelease", || host_extra::kernel_release(proc_root)),
        cpu_pressure: observe("/proc/pressure/cpu", || host_extra::pressure(proc_root, host_extra::PressureResource::Cpu)),
    }
}

/// Read-only observations from a single, explicitly selected operational scope.
/// A package database is not a vulnerability verdict; a service state is not health assurance.
#[derive(Debug)]
pub struct OperationalSnapshot {
    pub packages: Evidence<Vec<packages::Package>>,
    pub service: Option<Evidence<systemd::ServiceState>>,
}

impl OperationalSnapshot {
    pub fn complete(&self) -> bool {
        self.packages.is_available() && self.service.as_ref().is_none_or(Evidence::is_available)
    }
}

/// Capture package database provenance without requiring a service query.
pub fn collect_packages(status_path: &Path) -> Evidence<Vec<packages::Package>> {
    observe("/var/lib/dpkg/status", || packages::collect(status_path))
}

/// Capture one selected system service without requiring package database access.
pub fn collect_service(unit: &str) -> Evidence<systemd::ServiceState> {
    observe("systemd/system", || systemd::inspect(unit))
}

/// The status path is injectable for offline tests. Service queries are optional,
/// explicit and bounded by the systemd collector; no automatic unit discovery.
pub fn collect_operations(status_path: &Path, unit: Option<&str>) -> OperationalSnapshot {
    let packages = collect_packages(status_path);
    let service = unit.map(collect_service);
    OperationalSnapshot { packages, service }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_sources_remain_unknown() {
        let result = collect(Path::new("/nonexistent-mira-evidence-fixtures"));
        assert!(!result.complete());
        assert!(matches!(
            result.memory.status,
            EvidenceStatus::Unavailable { .. }
        ));
        assert_eq!(result.memory.source, "/proc/meminfo");
    }
    #[test]
    fn success_and_failure_stay_distinct() {
        let good = Evidence::from_result("/proc/uptime", Ok(7_u64), Some(1));
        assert!(good.is_available());
        assert_eq!(good.collected_unix_ms, Some(1));
        let bad = Evidence::<u64>::from_result(
            "/proc/uptime",
            Err(io::Error::new(io::ErrorKind::InvalidData, "bad")),
            None,
        );
        assert!(!bad.is_available());
        assert_eq!(bad.collected_unix_ms, None);
    }
}

/// The wall-clock completion and monotonic duration surround only this acquisition.
/// Duration is informational, not a deadline or a trusted freshness assertion.
pub fn observe<T>(source: &'static str, collect: impl FnOnce() -> io::Result<T>) -> Evidence<T> {
    let start = Instant::now();
    let result = collect();
    let at = timestamp();
    let elapsed_ms = start.elapsed().as_millis();
    let mut observation = Evidence::from_result(source, result, at);
    observation.elapsed_ms = Some(elapsed_ms);
    observation
}

#[cfg(test)]
mod acquisition_tests {
    use super::*;
    #[test]
    fn measured_success_and_typed_failures_preserve_metadata() {
        let observation = observe("fixture", || Ok(7));
        assert_eq!(observation.status, EvidenceStatus::Observed(7));
        assert!(observation.elapsed_ms.is_some());
        assert!(observation.collected_unix_ms.is_some());
        for (error, expected) in [
            (crate::collector::limit_exceeded(), FailureReason::LimitExceeded),
            (crate::collector::backend_failed(), FailureReason::BackendFailed),
            (io::Error::new(io::ErrorKind::TimedOut, "private"), FailureReason::Timeout),
            (io::Error::new(io::ErrorKind::PermissionDenied, "private"), FailureReason::PermissionDenied),
            (io::Error::new(io::ErrorKind::NotFound, "private"), FailureReason::NotFound),
            (io::Error::new(io::ErrorKind::InvalidData, "private"), FailureReason::MalformedData),
            (io::Error::other("private"), FailureReason::IoFailure),
        ] {
            let observation = observe::<u64>("fixture", || Err(error));
            assert!(observation.elapsed_ms.is_some());
            assert!(matches!(observation.status, EvidenceStatus::Unavailable { reason, .. } if reason == expected));
        }
    }
}
