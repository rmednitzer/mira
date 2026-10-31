//! Explicit PSI ceiling expectation; never workload health, latency or root cause.
use crate::{
    evidence::{self, Evidence, EvidenceStatus},
    evidence_json,
    host_extra::{self, CpuPressure, PressureResource},
    investigation::Outcome,
};
use std::{fmt, io, path::Path};

/// Inclusive upper bound of a PSI ratio in basis points (100.00%).
pub const MAX_BASIS_POINTS: u32 = 10_000;

/// Parse only ASCII integer basis points in 0..=10000, without rounding or defaults.
pub fn parse_maximum(text: &str) -> io::Result<u32> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_criterion());
    }
    text.parse::<u32>()
        .ok()
        .filter(|value| *value <= MAX_BASIS_POINTS)
        .ok_or_else(invalid_criterion)
}

/// Parse the closed resource selection before any acquisition.
pub fn parse_resource(text: &str) -> io::Result<PressureResource> {
    PressureResource::from_name(text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pressure resource"))
}

fn invalid_criterion() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid pressure ceiling")
}

/// Private fields bind the resource, criterion, observation and derived disposition.
pub struct Report {
    resource: PressureResource,
    maximum: u32,
    evidence: Evidence<CpuPressure>,
    outcome: Outcome,
}

impl fmt::Debug for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PressureReport")
            .field("resource", &self.resource)
            .field("maximum", &self.maximum)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl Report {
    pub fn resource(&self) -> PressureResource {
        self.resource
    }

    pub fn maximum(&self) -> u32 {
        self.maximum
    }

    pub fn evidence(&self) -> &Evidence<CpuPressure> {
        &self.evidence
    }

    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub fn reason(&self) -> &'static str {
        match self.outcome {
            Outcome::Satisfied => "within_ceiling",
            Outcome::NotSatisfied => "above_ceiling",
            Outcome::Indeterminate => "evidence_unavailable",
        }
    }

    pub fn to_json(&self) -> String {
        let evidence =
            evidence_json::record_v2(&self.evidence, None, evidence_json::pressure_value);
        format!(
            "{{\"investigation_version\":1,\"template\":\"pressure-ceiling/v1\",\"scope\":\"local/procfs\",\"expectation\":{{\"resource\":{},\"max_some_avg10_basis_points\":{}}},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{evidence}}}",
            evidence_json::quoted(self.resource.name()),
            self.maximum,
            evidence_json::quoted(self.outcome.as_str()),
            evidence_json::quoted(self.reason()),
        )
    }
}

/// Only `some avg10` is assessed; `full` stays literal evidence.
fn assess(evidence: &Evidence<CpuPressure>, maximum: u32) -> Outcome {
    match &evidence.status {
        EvidenceStatus::Observed(pressure) if pressure.some_avg10_basis_points <= maximum => {
            Outcome::Satisfied
        }
        EvidenceStatus::Observed(_) => Outcome::NotSatisfied,
        EvidenceStatus::Unavailable { .. } => Outcome::Indeterminate,
    }
}

/// Acquire only the selected PSI file. The injectable root is for fixtures, not confinement.
pub fn collect(resource: PressureResource, maximum: u32, proc_root: &Path) -> io::Result<Report> {
    if maximum > MAX_BASIS_POINTS {
        return Err(invalid_criterion());
    }
    let evidence = evidence::observe(resource.source(), || {
        host_extra::pressure(proc_root, resource)
    });
    let outcome = assess(&evidence, maximum);
    Ok(Report {
        resource,
        maximum,
        evidence,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(some: u32, full: Option<u32>) -> Evidence<CpuPressure> {
        let mut evidence = Evidence::from_result(
            PressureResource::Memory.source(),
            Ok(CpuPressure {
                some_avg10_basis_points: some,
                full_avg10_basis_points: full,
            }),
            Some(7),
        );
        evidence.elapsed_ms = Some(1);
        evidence
    }

    #[test]
    fn criteria_are_exact_ascii_basis_points() {
        for invalid in [
            "", "-1", "+1", "1.0", "1e3", " 1", "1 ", "10001", "99999", "000000", "١", "0x10",
        ] {
            assert!(parse_maximum(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(parse_maximum("0").unwrap(), 0);
        assert_eq!(parse_maximum("00025").unwrap(), 25);
        assert_eq!(parse_maximum("10000").unwrap(), MAX_BASIS_POINTS);
    }

    #[test]
    fn resources_are_a_closed_lowercase_set() {
        for name in ["cpu", "memory", "io"] {
            assert_eq!(parse_resource(name).unwrap().name(), name);
        }
        for invalid in ["", "CPU", "Memory", "irq", "cpu ", "pressure/cpu", "../io"] {
            assert_eq!(
                parse_resource(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn some_avg10_alone_decides_and_equality_is_within() {
        for (some, full, maximum, expected) in [
            (0, Some(0), 0, Outcome::Satisfied),
            (1, None, 0, Outcome::NotSatisfied),
            (25, Some(9_000), 25, Outcome::Satisfied),
            (26, Some(0), 25, Outcome::NotSatisfied),
            (10_000, Some(10_000), 10_000, Outcome::Satisfied),
        ] {
            assert_eq!(assess(&observed(some, full), maximum), expected);
        }
        let missing = Evidence::from_result(
            PressureResource::Io.source(),
            Err(io::Error::other("private /home/secret")),
            None,
        );
        assert_eq!(assess(&missing, MAX_BASIS_POINTS), Outcome::Indeterminate);
    }

    #[test]
    fn report_json_is_frozen_and_redacts_backend_text() {
        let report = Report {
            resource: PressureResource::Memory,
            maximum: 25,
            outcome: assess(&observed(26, None), 25),
            evidence: observed(26, None),
        };
        assert_eq!(
            report.to_json(),
            r##"{"investigation_version":1,"template":"pressure-ceiling/v1","scope":"local/procfs","expectation":{"resource":"memory","max_some_avg10_basis_points":25},"assessment":{"outcome":"not_satisfied","reason":"above_ceiling","evidence_ref":"#/evidence"},"application_health":"not_assessed","root_cause":"not_assessed","evidence":{"schema_version":2,"source":"/proc/pressure/memory","scope":null,"recorded_unix_ms":7,"clock_trust":"unverified","freshness":"unknown","status":"observed","value":{"some_avg10_basis_points":26,"full_avg10_basis_points":null},"error_kind":null,"elapsed_ms":1,"failure_reason":null}}"##
        );
        let hidden = Report {
            resource: PressureResource::Io,
            maximum: 0,
            outcome: Outcome::Indeterminate,
            evidence: Evidence::from_result(
                PressureResource::Io.source(),
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private /home/secret",
                )),
                None,
            ),
        };
        let json = hidden.to_json();
        assert!(!json.contains("secret"));
        assert!(!format!("{hidden:?}").contains("secret"));
        assert!(json.contains("\"reason\":\"evidence_unavailable\""));
        assert!(json.contains("\"failure_reason\":\"permission_denied\""));
    }

    #[test]
    fn out_of_range_ceiling_is_refused_before_acquisition() {
        let root = Path::new("/nonexistent-mira-pressure-investigation");
        assert!(collect(PressureResource::Cpu, MAX_BASIS_POINTS + 1, root).is_err());
        let report = collect(PressureResource::Cpu, MAX_BASIS_POINTS, root).unwrap();
        assert_eq!(report.outcome(), Outcome::Indeterminate);
        assert_eq!(report.evidence().source, "/proc/pressure/cpu");
    }
}
