//! Explicit procfs memory expectation; never workload health or allocation assurance.
use crate::{
    evidence::{self, Evidence, EvidenceStatus},
    evidence_json,
    investigation::Outcome,
    linux::{self, MemoryEvidence},
};
use std::{fmt, io, path::Path};

/// Parse only positive ASCII integer KiB criteria, without rounding or defaults.
pub fn parse_minimum(text: &str) -> io::Result<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_minimum());
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(invalid_minimum)
}

fn invalid_minimum() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid memory minimum")
}

/// Private fields bind the criterion, observation and derived disposition.
pub struct Report {
    minimum: u64,
    evidence: Evidence<MemoryEvidence>,
    outcome: Outcome,
}

impl fmt::Debug for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryReport")
            .field("minimum", &self.minimum)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl Report {
    pub fn minimum(&self) -> u64 {
        self.minimum
    }

    pub fn evidence(&self) -> &Evidence<MemoryEvidence> {
        &self.evidence
    }

    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub fn reason(&self) -> &'static str {
        match self.outcome {
            Outcome::Satisfied => "minimum_met",
            Outcome::NotSatisfied => "below_minimum",
            Outcome::Indeterminate => "evidence_unavailable",
        }
    }

    pub fn to_json(&self) -> String {
        let evidence = evidence_json::record(&self.evidence, None, |memory| {
            format!(
                "{{\"total_kib\":{},\"available_kib\":{}}}",
                memory.total_kib, memory.available_kib
            )
        });
        format!(
            "{{\"investigation_version\":1,\"template\":\"memory-headroom/v1\",\"scope\":\"local/procfs\",\"expectation\":{{\"minimum_available_kib\":{}}},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{evidence}}}",
            self.minimum,
            evidence_json::quoted(self.outcome.as_str()),
            evidence_json::quoted(self.reason()),
        )
    }
}

/// Acquire only meminfo. The injectable root is for fixtures, not confinement.
pub fn collect(minimum: u64, proc_root: &Path) -> io::Result<Report> {
    if minimum == 0 {
        return Err(invalid_minimum());
    }
    let evidence = evidence::observe("/proc/meminfo", || linux::memory(proc_root));
    let outcome = match &evidence.status {
        EvidenceStatus::Observed(memory) if memory.available_kib >= minimum => Outcome::Satisfied,
        EvidenceStatus::Observed(_) => Outcome::NotSatisfied,
        EvidenceStatus::Unavailable { .. } => Outcome::Indeterminate,
    };
    Ok(Report {
        minimum,
        evidence,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn criteria_are_exact_positive_ascii_integers() {
        for invalid in [
            "",
            "0",
            "-1",
            "+1",
            "1.0",
            "1e3",
            " 1",
            "1 ",
            "١",
            "18446744073709551616",
            "000000000000000000001",
        ] {
            assert!(parse_minimum(invalid).is_err(), "{invalid}");
        }
        assert_eq!(parse_minimum("0001").unwrap(), 1);
        assert_eq!(parse_minimum("18446744073709551615").unwrap(), u64::MAX);
    }
}
