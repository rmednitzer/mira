//! Versioned, bounded JSON Lines evidence projection. No external dependencies.
//! Times are untrusted recording timestamps; freshness is unknown without a trusted clock.
use crate::evidence::{Evidence, EvidenceStatus, Snapshot};
use crate::{host_extra, linux, packages, systemd};

pub const SCHEMA_VERSION: u32 = 1;

pub(crate) fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{001f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Shared value encodings keep inspect, capture and investigation records identical.
pub(crate) fn memory_value(memory: &linux::MemoryEvidence) -> String {
    format!(
        "{{\"total_kib\":{},\"available_kib\":{}}}",
        memory.total_kib, memory.available_kib
    )
}

pub(crate) fn pressure_value(pressure: &host_extra::CpuPressure) -> String {
    format!(
        "{{\"some_avg10_basis_points\":{},\"full_avg10_basis_points\":{}}}",
        pressure.some_avg10_basis_points,
        pressure
            .full_avg10_basis_points
            .map_or_else(|| "null".to_owned(), |n| n.to_string())
    )
}

pub(crate) fn packages_value(installed: &[packages::Package]) -> String {
    format!("{{\"installed_count\":{}}}", installed.len())
}

pub(crate) fn timestamp(time: Option<u128>) -> String {
    time.map_or_else(|| "null".to_owned(), |t| t.to_string())
}

/// Errors are reported by stable kind only. Never embed arbitrary OS error messages.
pub fn record<T>(
    e: &Evidence<T>,
    scope: Option<&str>,
    encode: impl FnOnce(&T) -> String,
) -> String {
    project(e, scope, encode, false)
}

/// Capture-only v2 metadata; the public v1 projection remains unchanged.
pub fn record_v2<T>(
    e: &Evidence<T>,
    scope: Option<&str>,
    encode: impl FnOnce(&T) -> String,
) -> String {
    project(e, scope, encode, true)
}

fn project<T>(
    e: &Evidence<T>,
    scope: Option<&str>,
    encode: impl FnOnce(&T) -> String,
    v2: bool,
) -> String {
    let scope = scope.map_or_else(|| "null".to_owned(), quoted);
    let (status, value, error) = match &e.status {
        EvidenceStatus::Observed(value) => ("observed", encode(value), "null".to_owned()),
        EvidenceStatus::Unavailable { kind, .. } => (
            "unavailable",
            "null".to_owned(),
            quoted(&format!("{kind:?}")),
        ),
    };
    let version = if v2 { 2 } else { SCHEMA_VERSION };
    let metadata = if v2 {
        let reason = match &e.status {
            EvidenceStatus::Observed(_) => "null".to_owned(),
            EvidenceStatus::Unavailable { reason, .. } => quoted(reason.as_str()),
        };
        format!(
            ",\"elapsed_ms\":{},\"failure_reason\":{reason}",
            timestamp(e.elapsed_ms)
        )
    } else {
        String::new()
    };
    format!(
        "{{\"schema_version\":{version},\"source\":{},\"scope\":{scope},\"recorded_unix_ms\":{},\"clock_trust\":\"unverified\",\"freshness\":\"unknown\",\"status\":{},\"value\":{value},\"error_kind\":{error}{metadata}}}",
        quoted(e.source),
        timestamp(e.collected_unix_ms),
        quoted(status)
    )
}

pub fn host_records(
    snapshot: &Snapshot,
    packages: &Evidence<Vec<packages::Package>>,
) -> Vec<String> {
    vec![
        record(&snapshot.memory, None, memory_value),
        record(&snapshot.uptime, None, |v| v.to_string()),
        record(&snapshot.kernel_release, None, |v| quoted(v)),
        record(&snapshot.cpu_pressure, None, pressure_value),
        record(packages, None, |list| packages_value(list)),
    ]
}

pub fn service_record(unit: &str, observation: &Evidence<systemd::ServiceState>) -> String {
    record(observation, Some(unit), |s| {
        format!(
            "{{\"id\":{},\"load_state\":{},\"active_state\":{},\"sub_state\":{}}}",
            quoted(&s.id),
            quoted(&s.load_state),
            quoted(&s.active_state),
            quoted(&s.sub_state)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    #[test]
    fn error_message_never_leaks_into_json() {
        let e: Evidence<u64> = Evidence::from_result(
            "test",
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private /home/secret",
            )),
            None,
        );
        let json = record(&e, None, |v| v.to_string());
        assert!(json.contains("\"error_kind\":\"PermissionDenied\""));
        assert!(!json.contains("private"));
        assert!(json.contains("\"freshness\":\"unknown\""));
    }
    #[test]
    fn quotes_controls_and_untrusted_text() {
        let e = Evidence::from_result("test", Ok(String::from("x\"\\\n\u{0001}")), Some(7));
        let json = record(&e, Some("a\"b"), |v| quoted(v));
        assert!(json.contains("\\u0001"));
        assert!(json.contains("\"recorded_unix_ms\":7"));
        assert!(json.contains("\"scope\":\"a\\\"b\""));
    }
}
