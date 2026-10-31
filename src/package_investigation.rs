//! Explicit dpkg presence expectation for one named package.
//! Never vulnerability exposure, file integrity, service health or root cause.
use crate::{
    evidence::{self, Evidence, EvidenceStatus},
    evidence_json::{quoted, timestamp},
    investigation::Outcome,
    packages::{self, Record},
};
use std::{fmt, io, path::Path};

const STATUS_SOURCE: &str = "/var/lib/dpkg/status";

/// An operator-selected package name with an optional exact architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    package: String,
    architecture: Option<String>,
}

impl Selector {
    /// Parse `PACKAGE[:ARCH]` using Debian policy name syntax before acquisition.
    pub fn parse(text: &str) -> io::Result<Self> {
        let (package, architecture) = match text.split_once(':') {
            Some((package, architecture)) => (package, Some(architecture)),
            None => (text, None),
        };
        let leading = |value: &str| {
            value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        };
        let package_ok = (2..=128).contains(&package.len())
            && leading(package)
            && package.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
            });
        let architecture_ok = architecture.is_none_or(|architecture| {
            (1..=32).contains(&architecture.len())
                && leading(architecture)
                && architecture
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
        if !package_ok || !architecture_ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid package selector",
            ));
        }
        Ok(Self {
            package: package.to_owned(),
            architecture: architecture.map(str::to_owned),
        })
    }

    pub fn package(&self) -> &str {
        &self.package
    }

    pub fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }
}

/// One enum fixes both disposition and reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    ReportedInstalled,
    ReportedNotInstalled,
    IncompleteInstallationState,
    EvidenceUnavailable,
}

impl Assessment {
    pub fn outcome(self) -> Outcome {
        match self {
            Self::ReportedInstalled => Outcome::Satisfied,
            Self::ReportedNotInstalled => Outcome::NotSatisfied,
            Self::IncompleteInstallationState | Self::EvidenceUnavailable => Outcome::Indeterminate,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::ReportedInstalled => "reported_installed",
            Self::ReportedNotInstalled => "reported_not_installed",
            Self::IncompleteInstallationState => "incomplete_installation_state",
            Self::EvidenceUnavailable => "evidence_unavailable",
        }
    }
}

/// Only `installed` with flag `ok` counts as installed. Selection never decides.
pub fn assess(evidence: &Evidence<Vec<Record>>) -> Assessment {
    let records = match &evidence.status {
        EvidenceStatus::Observed(records) => records,
        EvidenceStatus::Unavailable { .. } => return Assessment::EvidenceUnavailable,
    };
    if records
        .iter()
        .any(|record| record.state == "installed" && record.flag == "ok")
    {
        Assessment::ReportedInstalled
    } else if records.iter().any(|record| {
        record.flag == "reinstreq" || !matches!(record.state, "not-installed" | "config-files")
    }) {
        Assessment::IncompleteInstallationState
    } else {
        Assessment::ReportedNotInstalled
    }
}

/// Private fields bind the selector, observation and derived assessment.
pub struct Report {
    selector: Selector,
    evidence: Evidence<Vec<Record>>,
    assessment: Assessment,
}

impl fmt::Debug for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageReport")
            .field("selector", &self.selector)
            .field("evidence_available", &self.evidence.is_available())
            .field("assessment", &self.assessment)
            .finish_non_exhaustive()
    }
}

fn optional(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), quoted)
}

impl Report {
    pub fn selector(&self) -> &Selector {
        &self.selector
    }

    pub fn evidence(&self) -> &Evidence<Vec<Record>> {
        &self.evidence
    }

    pub fn assessment(&self) -> Assessment {
        self.assessment
    }

    /// Report-local dpkg record projection; errors are fixed kinds, never OS text.
    fn evidence_json(&self) -> String {
        let selector = format!(
            "{{\"package\":{},\"architecture\":{}}}",
            quoted(&self.selector.package),
            optional(self.selector.architecture())
        );
        let (status, value, error_kind, failure_reason) = match &self.evidence.status {
            EvidenceStatus::Observed(records) => {
                let records = records
                    .iter()
                    .map(|record| {
                        format!(
                            "{{\"package\":{},\"architecture\":{},\"version\":{},\"selection\":{},\"flag\":{},\"state\":{}}}",
                            quoted(&record.name),
                            optional(record.architecture.as_deref()),
                            optional(record.version.as_deref()),
                            quoted(record.selection),
                            quoted(record.flag),
                            quoted(record.state)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                (
                    "observed",
                    format!("{{\"records\":[{records}]}}"),
                    "null".to_owned(),
                    "null".to_owned(),
                )
            }
            EvidenceStatus::Unavailable { kind, reason, .. } => (
                "unavailable",
                "null".to_owned(),
                quoted(&format!("{kind:?}")),
                quoted(reason.as_str()),
            ),
        };
        format!(
            "{{\"source\":{},\"selector\":{selector},\"recorded_unix_ms\":{},\"clock_trust\":\"unverified\",\"freshness\":\"unknown\",\"elapsed_ms\":{},\"status\":\"{status}\",\"value\":{value},\"error_kind\":{error_kind},\"failure_reason\":{failure_reason}}}",
            quoted(self.evidence.source),
            timestamp(self.evidence.collected_unix_ms),
            timestamp(self.evidence.elapsed_ms),
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"investigation_version\":1,\"template\":\"package-installed/v1\",\"scope\":\"local/dpkg\",\"expectation\":{{\"package\":{},\"architecture\":{}}},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"vulnerability_exposure\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{}}}",
            quoted(&self.selector.package),
            optional(self.selector.architecture()),
            quoted(self.assessment.outcome().as_str()),
            quoted(self.assessment.reason()),
            self.evidence_json()
        )
    }
}

/// Acquire only the dpkg status database. The path is injectable for fixtures, not confinement.
pub fn collect(selector: Selector, status_path: &Path) -> Report {
    let evidence = evidence::observe(STATUS_SOURCE, || {
        packages::select(status_path, selector.package(), selector.architecture())
    });
    let assessment = assess(&evidence);
    Report {
        selector,
        evidence,
        assessment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: &'static str, flag: &'static str) -> Record {
        Record {
            name: "alpha".to_owned(),
            version: Some("1.0-1".to_owned()),
            architecture: Some("amd64".to_owned()),
            selection: "install",
            flag,
            state,
        }
    }

    fn observed(records: Vec<Record>) -> Evidence<Vec<Record>> {
        let mut evidence = Evidence::from_result(STATUS_SOURCE, Ok(records), Some(7));
        evidence.elapsed_ms = Some(1);
        evidence
    }

    #[test]
    fn selectors_follow_debian_name_syntax() {
        for valid in [
            "ab",
            "openssh-server",
            "libc6",
            "g++",
            "lib32z1:i386",
            "a.b-c+d:arm64",
            "x0:all",
        ] {
            assert!(Selector::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "a",
            "A1",
            "Openssh",
            "-ab",
            ".ab",
            "+ab",
            "ab cd",
            "ab\tcd",
            "ab_cd",
            "ab/cd",
            "../ab",
            "ab:",
            ":amd64",
            "ab:AMD64",
            "ab:-x",
            "ab:x_y",
            "ab:x:y",
            "ab:x86.64",
            "äb",
            "ab\u{00a0}",
        ] {
            assert_eq!(
                Selector::parse(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{invalid:?}"
            );
        }
        assert!(Selector::parse(&"a".repeat(128)).is_ok());
        assert!(Selector::parse(&"a".repeat(129)).is_err());
        assert!(Selector::parse(&format!("ab:{}", "a".repeat(32))).is_ok());
        assert!(Selector::parse(&format!("ab:{}", "a".repeat(33))).is_err());
    }

    #[test]
    fn every_state_and_flag_maps_to_one_documented_reason() {
        use Assessment::*;
        for (state, ok, reinstreq) in [
            ("installed", ReportedInstalled, IncompleteInstallationState),
            (
                "not-installed",
                ReportedNotInstalled,
                IncompleteInstallationState,
            ),
            (
                "config-files",
                ReportedNotInstalled,
                IncompleteInstallationState,
            ),
            (
                "half-installed",
                IncompleteInstallationState,
                IncompleteInstallationState,
            ),
            (
                "unpacked",
                IncompleteInstallationState,
                IncompleteInstallationState,
            ),
            (
                "half-configured",
                IncompleteInstallationState,
                IncompleteInstallationState,
            ),
            (
                "triggers-awaited",
                IncompleteInstallationState,
                IncompleteInstallationState,
            ),
            (
                "triggers-pending",
                IncompleteInstallationState,
                IncompleteInstallationState,
            ),
        ] {
            assert_eq!(assess(&observed(vec![record(state, "ok")])), ok, "{state}");
            assert_eq!(
                assess(&observed(vec![record(state, "reinstreq")])),
                reinstreq,
                "{state}"
            );
        }
        assert_eq!(assess(&observed(Vec::new())), ReportedNotInstalled);
        // One installed architecture satisfies an unqualified multiarch selector.
        assert_eq!(
            assess(&observed(vec![
                record("half-installed", "ok"),
                record("installed", "ok")
            ])),
            ReportedInstalled
        );
        let missing = Evidence::from_result(
            STATUS_SOURCE,
            Err(io::Error::other("private /home/secret")),
            None,
        );
        assert_eq!(assess(&missing), EvidenceUnavailable);
        for assessment in [
            ReportedInstalled,
            ReportedNotInstalled,
            IncompleteInstallationState,
            EvidenceUnavailable,
        ] {
            let expected = match assessment {
                ReportedInstalled => Outcome::Satisfied,
                ReportedNotInstalled => Outcome::NotSatisfied,
                _ => Outcome::Indeterminate,
            };
            assert_eq!(assessment.outcome(), expected);
        }
    }

    #[test]
    fn report_json_is_frozen_and_redacts_backend_text() {
        let mut sparse = record("config-files", "ok");
        sparse.version = None;
        sparse.architecture = None;
        sparse.selection = "deinstall";
        let report = Report {
            selector: Selector::parse("alpha").unwrap(),
            assessment: Assessment::ReportedNotInstalled,
            evidence: observed(vec![sparse]),
        };
        assert_eq!(
            report.to_json(),
            r##"{"investigation_version":1,"template":"package-installed/v1","scope":"local/dpkg","expectation":{"package":"alpha","architecture":null},"assessment":{"outcome":"not_satisfied","reason":"reported_not_installed","evidence_ref":"#/evidence"},"application_health":"not_assessed","vulnerability_exposure":"not_assessed","root_cause":"not_assessed","evidence":{"source":"/var/lib/dpkg/status","selector":{"package":"alpha","architecture":null},"recorded_unix_ms":7,"clock_trust":"unverified","freshness":"unknown","elapsed_ms":1,"status":"observed","value":{"records":[{"package":"alpha","architecture":null,"version":null,"selection":"deinstall","flag":"ok","state":"config-files"}]},"error_kind":null,"failure_reason":null}}"##
        );
        let hidden = Report {
            selector: Selector::parse("alpha:arm64").unwrap(),
            assessment: Assessment::EvidenceUnavailable,
            evidence: Evidence::from_result(
                STATUS_SOURCE,
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
        assert!(json.contains("\"architecture\":\"arm64\""));
        assert!(json.contains("\"failure_reason\":\"permission_denied\""));
        assert!(json.contains("\"error_kind\":\"PermissionDenied\""));
    }

    #[test]
    fn untrusted_database_text_is_escaped() {
        let mut odd = record("installed", "ok");
        odd.version = Some("1\u{001b}[2J\"\\".to_owned());
        let report = Report {
            selector: Selector::parse("alpha").unwrap(),
            assessment: Assessment::ReportedInstalled,
            evidence: observed(vec![odd]),
        };
        let json = report.to_json();
        assert!(!json.contains('\u{001b}'));
        assert!(json.contains(r#""version":"1\u001b[2J\"\\""#));
    }
}
