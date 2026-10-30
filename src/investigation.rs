//! Closed, read-only investigations keep operator expectations separate from evidence.
//! An assessment is not application health, source authentication or action authority.
use crate::{
    evidence::{self, Evidence, EvidenceStatus},
    evidence_json, systemd,
};
use std::{fmt, io};

pub const REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    ServiceActive,
}

impl Template {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "service-active" => Some(Self::ServiceActive),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::ServiceActive => "service-active/v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Satisfied,
    NotSatisfied,
    Indeterminate,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::NotSatisfied => "not_satisfied",
            Self::Indeterminate => "indeterminate",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Self::Satisfied => 0,
            Self::NotSatisfied => 1,
            Self::Indeterminate => 3,
        }
    }
}

/// One enum determines both disposition and reason; callers cannot combine
/// an unavailable reason with a satisfied outcome. Reasons contain no OS text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    ReportedActive,
    ReportedNotActive,
    TransitionInProgress,
    UnrecognizedActiveState,
    EvidenceUnavailable,
    UnexpectedSource,
    InvalidServiceIdentity,
}

impl Assessment {
    pub fn outcome(self) -> Outcome {
        match self {
            Self::ReportedActive => Outcome::Satisfied,
            Self::ReportedNotActive => Outcome::NotSatisfied,
            _ => Outcome::Indeterminate,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::ReportedActive => "reported_active",
            Self::ReportedNotActive => "reported_not_active",
            Self::TransitionInProgress => "transition_in_progress",
            Self::UnrecognizedActiveState => "unrecognized_active_state",
            Self::EvidenceUnavailable => "evidence_unavailable",
            Self::UnexpectedSource => "unexpected_source",
            Self::InvalidServiceIdentity => "invalid_service_identity",
        }
    }
}

/// Pure assessment of reported activation. LoadState is orthogonal; SubState
/// stays literal evidence. Constructed Evidence values are not authenticated.
pub fn assess_service_active(observation: &Evidence<systemd::ServiceState>) -> Assessment {
    if observation.source != "systemd/system" {
        return Assessment::UnexpectedSource;
    }
    let state = match &observation.status {
        EvidenceStatus::Observed(state) => state,
        EvidenceStatus::Unavailable { .. } => return Assessment::EvidenceUnavailable,
    };
    if systemd::validate_unit(&state.id).is_err() {
        return Assessment::InvalidServiceIdentity;
    }
    match state.active_state.as_str() {
        "active" | "reloading" | "refreshing" => Assessment::ReportedActive,
        "inactive" | "failed" | "maintenance" => Assessment::ReportedNotActive,
        "activating" | "deactivating" => Assessment::TransitionInProgress,
        _ => Assessment::UnrecognizedActiveState,
    }
}

/// Scope and evidence are bound by collection, not assembled from caller JSON.
/// Only read-only getters are exposed; the report is export-only.
pub struct Report {
    template: Template,
    scope: String,
    observation: Evidence<systemd::ServiceState>,
    assessment: Assessment,
}

impl fmt::Debug for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Report")
            .field("template", &self.template)
            .field("scope", &self.scope)
            .field("source", &self.observation.source)
            .field("evidence_available", &self.observation.is_available())
            .field("assessment", &self.assessment)
            .finish_non_exhaustive()
    }
}

impl Report {
    pub fn template(&self) -> Template {
        self.template
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn evidence(&self) -> &Evidence<systemd::ServiceState> {
        &self.observation
    }
    pub fn assessment(&self) -> Assessment {
        self.assessment
    }

    pub fn to_json(&self) -> String {
        let observation = evidence_json::service_record(&self.scope, &self.observation);
        format!(
            "{{\"investigation_version\":{REPORT_VERSION},\"template\":{},\"scope\":{},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{observation}}}",
            evidence_json::quoted(self.template.id()),
            evidence_json::quoted(&self.scope),
            evidence_json::quoted(self.assessment.outcome().as_str()),
            evidence_json::quoted(self.assessment.reason()),
        )
    }
}

/// Admit one known template and a bounded service scope before any dispatch.
/// Collector failures become indeterminate reports; rejected scope is usage error.
pub fn run(template: Template, unit: &str) -> io::Result<Report> {
    systemd::validate_unit(unit)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid investigation scope"))?;
    let observation = match template {
        Template::ServiceActive => evidence::collect_service(unit),
    };
    let assessment = match template {
        Template::ServiceActive => assess_service_active(&observation),
    };
    Ok(Report {
        template,
        scope: unit.to_owned(),
        observation,
        assessment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(active: &str, load: &str) -> Evidence<systemd::ServiceState> {
        Evidence::from_result(
            "systemd/system",
            Ok(systemd::ServiceState {
                id: "canonical.service".to_owned(),
                load_state: load.to_owned(),
                active_state: active.to_owned(),
                sub_state: "literal-future-substate".to_owned(),
            }),
            Some(7),
        )
    }

    #[test]
    fn documented_state_table_preserves_unknowns() {
        for (state, expected) in [
            ("active", Assessment::ReportedActive),
            ("reloading", Assessment::ReportedActive),
            ("refreshing", Assessment::ReportedActive),
            ("inactive", Assessment::ReportedNotActive),
            ("failed", Assessment::ReportedNotActive),
            ("maintenance", Assessment::ReportedNotActive),
            ("activating", Assessment::TransitionInProgress),
            ("deactivating", Assessment::TransitionInProgress),
            ("future-state", Assessment::UnrecognizedActiveState),
            ("", Assessment::UnrecognizedActiveState),
        ] {
            assert_eq!(assess_service_active(&observed(state, "loaded")), expected);
        }
    }

    #[test]
    fn active_state_is_independent_of_load_and_sub_state() {
        for load in ["loaded", "masked", "error", "future-load"] {
            assert_eq!(
                assess_service_active(&observed("active", load)),
                Assessment::ReportedActive
            );
        }
    }

    #[test]
    fn unavailable_wrong_source_and_invalid_identity_cannot_satisfy() {
        let missing = Evidence::from_result(
            "systemd/system",
            Err(io::Error::other("private secret")),
            None,
        );
        assert_eq!(
            assess_service_active(&missing),
            Assessment::EvidenceUnavailable
        );
        let mut wrong = observed("active", "loaded");
        wrong.source = "/proc/uptime";
        assert_eq!(assess_service_active(&wrong), Assessment::UnexpectedSource);
        let mut invalid = observed("active", "loaded");
        if let EvidenceStatus::Observed(state) = &mut invalid.status {
            state.id = "--user.service".to_owned();
        }
        assert_eq!(
            assess_service_active(&invalid),
            Assessment::InvalidServiceIdentity
        );
    }

    #[test]
    fn report_preserves_alias_scope_evidence_and_uncertainty() {
        let observation = observed("active", "masked");
        let original = evidence_json::service_record("alias.service", &observation);
        let report = Report {
            template: Template::ServiceActive,
            scope: "alias.service".to_owned(),
            assessment: assess_service_active(&observation),
            observation,
        };
        let json = report.to_json();
        assert!(json.contains(&format!("\"evidence\":{original}")));
        assert!(json.contains("\"application_health\":\"not_assessed\""));
        assert!(json.contains("\"evidence_ref\":\"#/evidence\""));
        assert!(json.contains("\"freshness\":\"unknown\""));
    }

    #[test]
    fn report_never_exports_raw_error_text() {
        let observation = Evidence::from_result(
            "systemd/system",
            Err(io::Error::other("private secret")),
            None,
        );
        let report = Report {
            template: Template::ServiceActive,
            scope: "ssh.service".to_owned(),
            assessment: assess_service_active(&observation),
            observation,
        };
        let json = report.to_json();
        assert!(!json.contains("secret"));
        assert!(!format!("{report:?}").contains("secret"));
        assert!(json.contains("\"outcome\":\"indeterminate\""));
        assert!(json.contains("\"recorded_unix_ms\":null"));
    }

    #[test]
    fn unknown_templates_and_invalid_scope_are_not_admitted() {
        for name in ["", "restart", "SERVICE-ACTIVE", "service-active;id"] {
            assert!(Template::from_name(name).is_none());
        }
        assert_eq!(
            Template::from_name("service-active"),
            Some(Template::ServiceActive)
        );
        for unit in ["", "../ssh.service", "--user.service", "ssh.service;id"] {
            assert_eq!(
                run(Template::ServiceActive, unit).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
