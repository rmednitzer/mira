//! Closed, read-only investigations keep operator expectations separate from evidence.
//! An assessment is not application health, source authentication or action authority.
use crate::{
    evidence::{self, Evidence, EvidenceStatus},
    evidence_json, systemd,
};
use std::{fmt, io};

/// Report version of `service-active/v1`; see [`Template::report_version`].
pub const REPORT_VERSION: u32 = 1;

/// Closed, versioned template selection. The unversioned name stays pinned to
/// v1 so existing invocations keep byte-identical output (ADR 0006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    ServiceActive,
    ServiceActiveV2,
}

impl Template {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "service-active" | "service-active/v1" => Some(Self::ServiceActive),
            "service-active/v2" => Some(Self::ServiceActiveV2),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::ServiceActive => "service-active/v1",
            Self::ServiceActiveV2 => "service-active/v2",
        }
    }

    pub fn report_version(self) -> u32 {
        match self {
            Self::ServiceActive => REPORT_VERSION,
            Self::ServiceActiveV2 => 2,
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
    /// v2 only: no loadable unit definition and not active.
    UnitNotFound,
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
            Self::ReportedNotActive | Self::UnitNotFound => Outcome::NotSatisfied,
            _ => Outcome::Indeterminate,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::ReportedActive => "reported_active",
            Self::ReportedNotActive => "reported_not_active",
            Self::UnitNotFound => "unit_not_found",
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

/// Pure v2 assessment: the v1 table plus one rule. A `not-found` definition
/// that is also `inactive` is the stub systemd reports for an undefined name.
/// Every other `not-found` combination keeps its v1 reason; for example, a
/// running unit whose file was removed is still reported active.
pub fn assess_service_active_v2(observation: &Evidence<systemd::ServiceState>) -> Assessment {
    let assessment = assess_service_active(observation);
    match &observation.status {
        EvidenceStatus::Observed(state)
            if assessment == Assessment::ReportedNotActive
                && state.load_state == "not-found"
                && state.active_state == "inactive" =>
        {
            Assessment::UnitNotFound
        }
        _ => assessment,
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
            "{{\"investigation_version\":{},\"template\":{},\"scope\":{},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{observation}}}",
            self.template.report_version(),
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
    let observation = evidence::collect_service(unit);
    let assessment = match template {
        Template::ServiceActive => assess_service_active(&observation),
        Template::ServiceActiveV2 => assess_service_active_v2(&observation),
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
        for name in [
            "",
            "restart",
            "SERVICE-ACTIVE",
            "service-active;id",
            "service-active/",
            "service-active/v0",
            "service-active/v3",
            "service-active/V2",
            "service-active/v2 ",
            "service-active-v2",
        ] {
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

    const ACTIVE_STATES: [&str; 10] = [
        "active",
        "reloading",
        "refreshing",
        "inactive",
        "failed",
        "maintenance",
        "activating",
        "deactivating",
        "future-state",
        "",
    ];

    #[test]
    fn versioned_names_select_closed_templates() {
        for (name, template, id, version) in [
            (
                "service-active",
                Template::ServiceActive,
                "service-active/v1",
                1,
            ),
            (
                "service-active/v1",
                Template::ServiceActive,
                "service-active/v1",
                1,
            ),
            (
                "service-active/v2",
                Template::ServiceActiveV2,
                "service-active/v2",
                2,
            ),
        ] {
            assert_eq!(Template::from_name(name), Some(template), "{name}");
            assert_eq!((template.id(), template.report_version()), (id, version));
        }
    }

    #[test]
    fn v2_adds_only_the_not_found_inactive_rule() {
        for load in [
            "loaded",
            "not-found",
            "masked",
            "error",
            "bad-setting",
            "future-load",
        ] {
            for active in ACTIVE_STATES {
                let observation = observed(active, load);
                let v1 = assess_service_active(&observation);
                let v2 = assess_service_active_v2(&observation);
                if load == "not-found" && active == "inactive" {
                    assert_eq!(v1, Assessment::ReportedNotActive);
                    assert_eq!(v2, Assessment::UnitNotFound);
                    assert_eq!(v2.outcome(), Outcome::NotSatisfied);
                    assert_eq!(v2.outcome().exit_code(), v1.outcome().exit_code());
                } else {
                    assert_eq!(v2, v1, "{load}/{active}");
                }
            }
        }
    }

    #[test]
    fn not_found_units_that_run_or_failed_keep_their_reported_state() {
        // A running unit whose unit file was removed still reports not-found.
        for (active, expected) in [
            ("active", Assessment::ReportedActive),
            ("reloading", Assessment::ReportedActive),
            ("failed", Assessment::ReportedNotActive),
            ("maintenance", Assessment::ReportedNotActive),
            ("activating", Assessment::TransitionInProgress),
            ("future-state", Assessment::UnrecognizedActiveState),
        ] {
            assert_eq!(
                assess_service_active_v2(&observed(active, "not-found")),
                expected
            );
        }
    }

    #[test]
    fn v1_never_reports_unit_not_found() {
        for load in ["loaded", "not-found", "masked"] {
            for active in ACTIVE_STATES {
                assert_ne!(
                    assess_service_active(&observed(active, load)),
                    Assessment::UnitNotFound
                );
            }
        }
    }

    #[test]
    fn v2_preserves_unavailable_source_and_identity_rejections() {
        let missing =
            Evidence::from_result("systemd/system", Err(io::Error::other("private")), None);
        assert_eq!(
            assess_service_active_v2(&missing),
            Assessment::EvidenceUnavailable
        );
        let mut wrong = observed("inactive", "not-found");
        wrong.source = "/proc/uptime";
        assert_eq!(
            assess_service_active_v2(&wrong),
            Assessment::UnexpectedSource
        );
        let mut invalid = observed("inactive", "not-found");
        if let EvidenceStatus::Observed(state) = &mut invalid.status {
            state.id = "--user.service".to_owned();
        }
        assert_eq!(
            assess_service_active_v2(&invalid),
            Assessment::InvalidServiceIdentity
        );
    }

    fn report(template: Template, observation: Evidence<systemd::ServiceState>) -> Report {
        let assessment = match template {
            Template::ServiceActive => assess_service_active(&observation),
            Template::ServiceActiveV2 => assess_service_active_v2(&observation),
        };
        Report {
            template,
            scope: "missing.service".to_owned(),
            observation,
            assessment,
        }
    }

    #[test]
    fn frozen_v1_and_v2_reports_for_a_not_found_unit() {
        let evidence = r#"{"schema_version":1,"source":"systemd/system","scope":"missing.service","recorded_unix_ms":7,"clock_trust":"unverified","freshness":"unknown","status":"observed","value":{"id":"canonical.service","load_state":"not-found","active_state":"inactive","sub_state":"literal-future-substate"},"error_kind":null}"#;
        // v1 output is frozen byte for byte; v2 must not alter it.
        assert_eq!(
            report(Template::ServiceActive, observed("inactive", "not-found")).to_json(),
            format!(
                r##"{{"investigation_version":1,"template":"service-active/v1","scope":"missing.service","assessment":{{"outcome":"not_satisfied","reason":"reported_not_active","evidence_ref":"#/evidence"}},"application_health":"not_assessed","root_cause":"not_assessed","evidence":{evidence}}}"##
            )
        );
        assert_eq!(
            report(Template::ServiceActiveV2, observed("inactive", "not-found")).to_json(),
            format!(
                r##"{{"investigation_version":2,"template":"service-active/v2","scope":"missing.service","assessment":{{"outcome":"not_satisfied","reason":"unit_not_found","evidence_ref":"#/evidence"}},"application_health":"not_assessed","root_cause":"not_assessed","evidence":{evidence}}}"##
            )
        );
    }
}
