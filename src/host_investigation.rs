//! Explicit uptime-minimum and kernel-release expectations over existing procfs evidence.
//! Neither is a reboot cause, patch-compliance, vulnerability or health verdict.
use crate::{
    evidence::{self, Evidence, EvidenceStatus},
    evidence_json::{self, quoted},
    host_extra,
    investigation::Outcome,
    linux,
};
use std::{fmt, io, path::Path};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Parse only positive ASCII integer seconds, without rounding or defaults.
pub fn parse_minimum_uptime(text: &str) -> io::Result<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("invalid uptime minimum"));
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("invalid uptime minimum"))
}

/// Accept the collector's kernel-release syntax, never trimmed. A leading letter
/// or digit keeps a forgotten value such as `--json` from becoming the criterion.
pub fn parse_expected_release(text: &str) -> io::Result<String> {
    let leading = text
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric);
    match host_extra::parse_kernel_release(text) {
        Ok(release) if leading && release == text => Ok(release),
        _ => Err(invalid("invalid expected kernel release")),
    }
}

fn reason(outcome: Outcome, met: &'static str, unmet: &'static str) -> &'static str {
    match outcome {
        Outcome::Satisfied => met,
        Outcome::NotSatisfied => unmet,
        Outcome::Indeterminate => "evidence_unavailable",
    }
}

fn outcome<T>(evidence: &Evidence<T>, satisfied: impl FnOnce(&T) -> bool) -> Outcome {
    match &evidence.status {
        EvidenceStatus::Observed(value) if satisfied(value) => Outcome::Satisfied,
        EvidenceStatus::Observed(_) => Outcome::NotSatisfied,
        EvidenceStatus::Unavailable { .. } => Outcome::Indeterminate,
    }
}

fn report_json(
    template: &str,
    expectation: String,
    outcome: Outcome,
    reason: &str,
    evidence: String,
) -> String {
    format!(
        "{{\"investigation_version\":1,\"template\":{},\"scope\":\"local/procfs\",\"expectation\":{expectation},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{evidence}}}",
        quoted(template),
        quoted(outcome.as_str()),
        quoted(reason),
    )
}

/// Private fields bind the minimum, the uptime observation and the derived outcome.
pub struct UptimeReport {
    minimum: u64,
    evidence: Evidence<u64>,
    outcome: Outcome,
}

impl fmt::Debug for UptimeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UptimeReport")
            .field("minimum", &self.minimum)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl UptimeReport {
    pub fn minimum(&self) -> u64 {
        self.minimum
    }
    pub fn evidence(&self) -> &Evidence<u64> {
        &self.evidence
    }
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    pub fn reason(&self) -> &'static str {
        reason(self.outcome, "minimum_met", "below_minimum")
    }
    pub fn to_json(&self) -> String {
        report_json(
            "uptime-minimum/v1",
            format!("{{\"minimum_uptime_seconds\":{}}}", self.minimum),
            self.outcome,
            self.reason(),
            evidence_json::record_v2(&self.evidence, None, |seconds| seconds.to_string()),
        )
    }
}

/// Acquire only /proc/uptime. Whole-second truncation is exact for an integer minimum.
pub fn collect_uptime(minimum: u64, proc_root: &Path) -> io::Result<UptimeReport> {
    if minimum == 0 {
        return Err(invalid("invalid uptime minimum"));
    }
    let evidence = evidence::observe("/proc/uptime", || linux::uptime(proc_root));
    let outcome = outcome(&evidence, |seconds| *seconds >= minimum);
    Ok(UptimeReport {
        minimum,
        evidence,
        outcome,
    })
}

/// Private fields bind the expected release, the observation and the derived outcome.
pub struct KernelReport {
    expected: String,
    evidence: Evidence<String>,
    outcome: Outcome,
}

impl fmt::Debug for KernelReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelReport")
            .field("expected", &self.expected)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl KernelReport {
    pub fn expected(&self) -> &str {
        &self.expected
    }
    pub fn evidence(&self) -> &Evidence<String> {
        &self.evidence
    }
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    pub fn reason(&self) -> &'static str {
        reason(self.outcome, "release_matches", "release_differs")
    }
    pub fn to_json(&self) -> String {
        report_json(
            "kernel-release/v1",
            format!("{{\"release\":{}}}", quoted(&self.expected)),
            self.outcome,
            self.reason(),
            evidence_json::record_v2(&self.evidence, None, |release| quoted(release)),
        )
    }
}

/// Acquire only /proc/sys/kernel/osrelease and compare bytes exactly; no ordering or prefixes.
pub fn collect_kernel(expected: &str, proc_root: &Path) -> io::Result<KernelReport> {
    let expected = parse_expected_release(expected)?;
    let evidence = evidence::observe("/proc/sys/kernel/osrelease", || {
        host_extra::kernel_release(proc_root)
    });
    let outcome = outcome(&evidence, |release| *release == expected);
    Ok(KernelReport {
        expected,
        evidence,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed<T>(source: &'static str, value: T) -> Evidence<T> {
        let mut evidence = Evidence::from_result(source, Ok(value), Some(7));
        evidence.elapsed_ms = Some(1);
        evidence
    }

    #[test]
    fn uptime_criteria_are_exact_positive_ascii_integers() {
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
            assert!(parse_minimum_uptime(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(parse_minimum_uptime("0060").unwrap(), 60);
        assert_eq!(
            parse_minimum_uptime("18446744073709551615").unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn release_criteria_match_collector_syntax_without_trimming() {
        for valid in [
            "6.17.0-5-generic",
            "6.6.1+rpt-rpi-v8",
            "a",
            &"9".repeat(256),
        ] {
            assert_eq!(parse_expected_release(valid).unwrap(), valid);
        }
        for invalid in [
            "",
            " 6.17.0",
            "6.17.0 ",
            "6.17.0\n",
            "6.17 .0",
            "6.17/0",
            "--json",
            "-6.17.0",
            ".6",
            "_6",
            "+6",
            "6.17.0\u{00a0}",
            "é",
            &"9".repeat(257),
        ] {
            assert!(parse_expected_release(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn both_reports_are_frozen_and_redact_backend_text() {
        let uptime = UptimeReport {
            minimum: 60,
            evidence: observed("/proc/uptime", 59),
            outcome: Outcome::NotSatisfied,
        };
        assert_eq!(
            uptime.to_json(),
            r##"{"investigation_version":1,"template":"uptime-minimum/v1","scope":"local/procfs","expectation":{"minimum_uptime_seconds":60},"assessment":{"outcome":"not_satisfied","reason":"below_minimum","evidence_ref":"#/evidence"},"application_health":"not_assessed","root_cause":"not_assessed","evidence":{"schema_version":2,"source":"/proc/uptime","scope":null,"recorded_unix_ms":7,"clock_trust":"unverified","freshness":"unknown","status":"observed","value":59,"error_kind":null,"elapsed_ms":1,"failure_reason":null}}"##
        );
        let kernel = KernelReport {
            expected: "6.17.0-5-generic".to_owned(),
            evidence: observed("/proc/sys/kernel/osrelease", "6.17.0-5-generic".to_owned()),
            outcome: Outcome::Satisfied,
        };
        assert_eq!(
            kernel.to_json(),
            r##"{"investigation_version":1,"template":"kernel-release/v1","scope":"local/procfs","expectation":{"release":"6.17.0-5-generic"},"assessment":{"outcome":"satisfied","reason":"release_matches","evidence_ref":"#/evidence"},"application_health":"not_assessed","root_cause":"not_assessed","evidence":{"schema_version":2,"source":"/proc/sys/kernel/osrelease","scope":null,"recorded_unix_ms":7,"clock_trust":"unverified","freshness":"unknown","status":"observed","value":"6.17.0-5-generic","error_kind":null,"elapsed_ms":1,"failure_reason":null}}"##
        );
        let hidden = KernelReport {
            expected: "x".to_owned(),
            evidence: Evidence::from_result(
                "/proc/sys/kernel/osrelease",
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private /home/secret",
                )),
                None,
            ),
            outcome: Outcome::Indeterminate,
        };
        assert!(!hidden.to_json().contains("secret"));
        assert!(!format!("{hidden:?}").contains("secret"));
        assert!(
            hidden
                .to_json()
                .contains("\"reason\":\"evidence_unavailable\"")
        );
    }

    #[test]
    fn invalid_criteria_are_refused_before_acquisition() {
        let root = Path::new("/nonexistent-mira-host-investigation");
        assert!(collect_uptime(0, root).is_err());
        assert!(collect_kernel(" 6.17.0", root).is_err());
        assert_eq!(
            collect_uptime(1, root).unwrap().outcome(),
            Outcome::Indeterminate
        );
        assert_eq!(
            collect_kernel("6.17.0", root).unwrap().outcome(),
            Outcome::Indeterminate
        );
    }
}
