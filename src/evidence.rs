//! A typed, read-only evidence snapshot with explicit source status and timing.
//!
//! A snapshot is a sequence of file observations, not an atomic host state.
//! Wall-clock values are informational and do not establish trusted provenance.
use crate::{host_extra, linux};
use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceStatus<T> {
    Observed(T),
    Unavailable {
        kind: io::ErrorKind,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence<T> {
    pub source: &'static str,
    pub collected_unix_ms: Option<u128>,
    pub status: EvidenceStatus<T>,
}

impl<T> Evidence<T> {
    fn from_result(source: &'static str, result: io::Result<T>, at: Option<u128>) -> Self {
        let status = match result {
            Ok(value) => EvidenceStatus::Observed(value),
            Err(error) => EvidenceStatus::Unavailable {
                kind: error.kind(),
                message: error.to_string(),
            },
        };
        Self {
            source,
            collected_unix_ms: at,
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
    let base = linux::report(proc_root);
    let extra = host_extra::inspect(proc_root);
    Snapshot {
        memory: Evidence::from_result(base.memory.source, base.memory.result, timestamp()),
        uptime: Evidence::from_result(base.uptime.source, base.uptime.result, timestamp()),
        kernel_release: Evidence::from_result(
            extra.kernel_release.source,
            extra.kernel_release.result,
            timestamp(),
        ),
        cpu_pressure: Evidence::from_result(
            extra.cpu_pressure.source,
            extra.cpu_pressure.result,
            timestamp(),
        ),
    }
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
