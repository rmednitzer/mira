//! Complete, explicitly scoped captures. Labels are operator assertions, not identity.
use crate::{evidence, evidence_json, host_extra};
use std::{io, path::Path};

#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Host,
    HostPressure,
}

impl Profile {
    pub fn id(self) -> &'static str {
        match self {
            Self::Host => "host/v1",
            Self::HostPressure => "host-pressure/v1",
        }
    }
    pub fn sources(self) -> &'static [&'static str] {
        match self {
            Self::Host => &[
                "/proc/meminfo",
                "/proc/uptime",
                "/proc/sys/kernel/osrelease",
                "/proc/pressure/cpu",
                "/var/lib/dpkg/status",
            ],
            Self::HostPressure => &[
                "/proc/meminfo",
                "/proc/uptime",
                "/proc/sys/kernel/osrelease",
                "/proc/pressure/cpu",
                "/var/lib/dpkg/status",
                "/proc/pressure/memory",
                "/proc/pressure/io",
            ],
        }
    }
}

/// Conservative printable labels avoid accidentally publishing host identifiers.
/// Syntax cannot prevent an operator from placing sensitive text in a label.
pub fn validate_label(label: &str) -> io::Result<()> {
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid capture label",
        ));
    }
    Ok(())
}

pub struct Capture {
    label: String,
    profile: Profile,
    records: Vec<String>,
    all_available: bool,
}
impl Capture {
    pub fn all_available(&self) -> bool {
        self.all_available
    }
    pub fn to_json(&self) -> String {
        let sources = self
            .profile
            .sources()
            .iter()
            .map(|s| evidence_json::quoted(s))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"capture_version\":1,\"capture_scope\":{},\"scope_trust\":\"operator_asserted\",\"profile\":{},\"expected_sources\":[{sources}],\"collection_complete\":true,\"all_available\":{},\"records\":[{}]}}",
            evidence_json::quoted(&self.label),
            evidence_json::quoted(self.profile.id()),
            self.all_available,
            self.records.join(",")
        )
    }
}

/// Fixed profiles only. Injectable paths support offline fixtures, not confinement.
pub fn collect(
    label: &str,
    profile: Profile,
    proc_root: &Path,
    status: &Path,
) -> io::Result<Capture> {
    validate_label(label)?;
    let host = evidence::collect(proc_root);
    let packages = evidence::collect_packages(status);
    let mut records = vec![
        evidence_json::record_v2(&host.memory, None, |m| {
            format!(
                "{{\"total_kib\":{},\"available_kib\":{}}}",
                m.total_kib, m.available_kib
            )
        }),
        evidence_json::record_v2(&host.uptime, None, |v| v.to_string()),
        evidence_json::record_v2(&host.kernel_release, None, |v| evidence_json::quoted(v)),
        pressure_record(&host.cpu_pressure),
        evidence_json::record_v2(&packages, None, |p| {
            format!("{{\"installed_count\":{}}}", p.len())
        }),
    ];
    let mut all_available = host.complete() && packages.is_available();
    if matches!(profile, Profile::HostPressure) {
        for resource in [
            host_extra::PressureResource::Memory,
            host_extra::PressureResource::Io,
        ] {
            let observation = evidence::observe(resource.source(), || {
                host_extra::pressure(proc_root, resource)
            });
            all_available &= observation.is_available();
            records.push(pressure_record(&observation));
        }
    }
    Ok(Capture {
        label: label.to_owned(),
        profile,
        records,
        all_available,
    })
}

fn pressure_record(observation: &evidence::Evidence<host_extra::CpuPressure>) -> String {
    evidence_json::record_v2(observation, None, |p| {
        format!(
            "{{\"some_avg10_basis_points\":{},\"full_avg10_basis_points\":{}}}",
            p.some_avg10_basis_points,
            p.full_avg10_basis_points
                .map_or_else(|| "null".to_owned(), |v| v.to_string())
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_labels_are_rejected_before_collection() {
        for label in ["", "private name", "x\u{001b}", "a/b", &"a".repeat(65)] {
            assert!(
                collect(
                    label,
                    Profile::Host,
                    Path::new("/missing"),
                    Path::new("/missing")
                )
                .is_err()
            );
        }
    }
    #[test]
    fn missing_sources_still_produce_a_complete_capture() {
        let capture = collect(
            "fixture",
            Profile::HostPressure,
            Path::new("/nonexistent-mira-capture"),
            Path::new("/nonexistent-mira-status"),
        )
        .unwrap();
        assert!(!capture.all_available());
        let json = capture.to_json();
        assert!(json.contains("\"collection_complete\":true"));
        assert_eq!(json.matches("\"status\":\"unavailable\"").count(), 7);
        assert_eq!(json.matches("\"failure_reason\":\"not_found\"").count(), 7);
        assert!(!json.contains("nonexistent"));
    }
}
