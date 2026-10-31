//! Authored dpkg presence cases use the real bounded status reader and no other source.
use mira::{
    investigation::Outcome,
    package_investigation::{self, Assessment, Selector},
    packages::MAX_SELECTED_RECORDS,
};
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mira-package-investigation-{}-{name}",
            std::process::id()
        ));
        // Own only a newly created directory; never reuse another run's files.
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn status(&self) -> PathBuf {
        self.0.join("status")
    }

    fn assess(&self, database: &str, selector: &str) -> package_investigation::Report {
        fs::write(self.status(), database).unwrap();
        package_investigation::collect(Selector::parse(selector).unwrap(), &self.status())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Cleanup failure still fails a passing test, but a second panic while
        // unwinding would abort the binary and hide the original assertion.
        if let Err(error) = fs::remove_dir_all(&self.0)
            && !std::thread::panicking()
        {
            panic!("fixture cleanup failed: {error}");
        }
    }
}

fn stanza(name: &str, architecture: &str, status: &str) -> String {
    format!(
        "Package: {name}\nStatus: {status}\nArchitecture: {architecture}\nVersion: 1.0-1\nDescription: fixture\n long description\n\n"
    )
}

#[test]
fn each_dpkg_state_and_flag_has_one_outcome() {
    let fixture = Fixture::new("states");
    for (status, expected) in [
        ("install ok installed", Assessment::ReportedInstalled),
        ("hold ok installed", Assessment::ReportedInstalled),
        ("deinstall ok installed", Assessment::ReportedInstalled),
        ("purge ok installed", Assessment::ReportedInstalled),
        (
            "install reinstreq installed",
            Assessment::IncompleteInstallationState,
        ),
        (
            "install ok half-installed",
            Assessment::IncompleteInstallationState,
        ),
        (
            "install ok unpacked",
            Assessment::IncompleteInstallationState,
        ),
        (
            "install ok half-configured",
            Assessment::IncompleteInstallationState,
        ),
        (
            "install ok triggers-awaited",
            Assessment::IncompleteInstallationState,
        ),
        (
            "install ok triggers-pending",
            Assessment::IncompleteInstallationState,
        ),
        (
            "deinstall reinstreq config-files",
            Assessment::IncompleteInstallationState,
        ),
        (
            "deinstall ok config-files",
            Assessment::ReportedNotInstalled,
        ),
        ("purge ok not-installed", Assessment::ReportedNotInstalled),
        ("unknown ok not-installed", Assessment::ReportedNotInstalled),
    ] {
        let database = format!(
            "{}{}",
            stanza("other", "all", "install ok installed"),
            stanza("alpha", "amd64", status)
        );
        let report = fixture.assess(&database, "alpha");
        assert_eq!(report.assessment(), expected, "{status}");
        let json = report.to_json();
        assert!(json.contains("\"vulnerability_exposure\":\"not_assessed\""));
        // Only the selected package is exported, never the rest of the inventory.
        assert!(!json.contains("\"other\""), "{status}");
        assert_eq!(json.matches("\"package\":\"alpha\"").count(), 3, "{status}");
    }
}

#[test]
fn names_and_architectures_match_exactly() {
    let fixture = Fixture::new("matching");
    let database = [
        stanza("alpha", "amd64", "install ok installed"),
        stanza("alpha", "i386", "deinstall ok config-files"),
        stanza("alpha2", "arm64", "install ok installed"),
        stanza("alph", "arm64", "install ok installed"),
        stanza("Alpha", "arm64", "install ok installed"),
        stanza("beta", "all", "install ok installed"),
        "Package: gamma\nStatus: purge ok not-installed\n\n".to_owned(),
    ]
    .concat();
    for (selector, outcome, records) in [
        ("alpha", Outcome::Satisfied, 2),
        ("alpha:amd64", Outcome::Satisfied, 1),
        ("alpha:i386", Outcome::NotSatisfied, 1),
        ("alpha:arm64", Outcome::NotSatisfied, 0),
        ("alpha:all", Outcome::NotSatisfied, 0),
        ("beta:all", Outcome::Satisfied, 1),
        ("beta:amd64", Outcome::NotSatisfied, 0),
        ("alp", Outcome::NotSatisfied, 0),
        ("alpha2", Outcome::Satisfied, 1),
        // A sparse stanza has no architecture, so a qualifier cannot match it.
        ("gamma", Outcome::NotSatisfied, 1),
        ("gamma:amd64", Outcome::NotSatisfied, 0),
        ("missing", Outcome::NotSatisfied, 0),
    ] {
        let report = fixture.assess(&database, selector);
        assert_eq!(report.assessment().outcome(), outcome, "{selector}");
        let mira::evidence::EvidenceStatus::Observed(found) = &report.evidence().status else {
            panic!("{selector}: evidence unavailable");
        };
        assert_eq!(found.len(), records, "{selector}");
        assert!(
            found
                .iter()
                .all(|record| record.name == selector.split(':').next().unwrap())
        );
    }
    let sparse = fixture.assess(&database, "gamma").to_json();
    assert!(sparse.contains("\"architecture\":null,\"version\":null,\"selection\":\"purge\""));
}

#[test]
fn a_malformed_database_or_too_many_matches_stays_indeterminate() {
    let fixture = Fixture::new("unavailable");
    let good = stanza("alpha", "amd64", "install ok installed");
    for (database, failure) in [
        (
            format!("{good}Package: beta\nStatus: install bogus installed\n"),
            "malformed_data",
        ),
        (format!("{good}{good}"), "malformed_data"),
        (
            format!("{good}Package: beta\nStatus: install ok installed\nVersion: 1\n"),
            "malformed_data",
        ),
        (format!("{good}not a field\n"), "malformed_data"),
        (
            format!("{good}Package: beta\nStatus: install\u{00a0}ok installed\n"),
            "malformed_data",
        ),
        (
            "Package: alpha\nStatus: purge ok not-installed\n\n".repeat(MAX_SELECTED_RECORDS + 1),
            "limit_exceeded",
        ),
    ] {
        let report = fixture.assess(&database, "alpha");
        assert_eq!(
            report.assessment(),
            Assessment::EvidenceUnavailable,
            "{database:?}"
        );
        assert_eq!(report.assessment().outcome(), Outcome::Indeterminate);
        assert!(
            report
                .to_json()
                .contains(&format!("\"failure_reason\":\"{failure}\"")),
            "{database:?}"
        );
    }
    // Exactly the record limit is still admitted.
    let at_limit =
        "Package: alpha\nStatus: purge ok not-installed\n\n".repeat(MAX_SELECTED_RECORDS);
    assert_eq!(
        fixture.assess(&at_limit, "alpha").assessment(),
        Assessment::ReportedNotInstalled
    );
    fs::remove_file(fixture.status()).unwrap();
    let report =
        package_investigation::collect(Selector::parse("alpha").unwrap(), &fixture.status());
    assert_eq!(report.assessment(), Assessment::EvidenceUnavailable);
    assert!(
        report
            .to_json()
            .contains("\"failure_reason\":\"not_found\"")
    );
    assert!(!report.to_json().contains("mira-package-investigation-"));
}

fn mira(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mira"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn invalid_selectors_emit_no_report() {
    for selector in [
        "",
        "a",
        "Dpkg",
        "-dpkg",
        "dpkg:",
        ":amd64",
        "dpkg:AMD64",
        "dpkg:x:y",
        "dpkg/x",
        "../dpkg",
        "dpkg_x",
        "dpkg\u{00a0}",
        "--json",
    ] {
        let output = mira(&["investigate", "package-installed", selector, "--json"]);
        assert_eq!(output.status.code(), Some(2), "{selector:?}");
        assert!(output.stdout.is_empty(), "{selector:?}");
        assert_eq!(
            output.stderr, b"MIRA: package must be a Debian package name, optionally :ARCH\n",
            "{selector:?}"
        );
    }
}

#[test]
fn malformed_package_invocations_report_template_usage() {
    for arguments in [
        vec!["investigate", "package-installed"],
        vec!["investigate", "package-installed", "dpkg", "extra"],
        vec!["investigate", "package-installed", "dpkg", "--json", "x"],
        vec!["investigate", "package-installed", "dpkg", "libc6"],
        vec!["investigate", "package-installed", "--json", "dpkg", "x"],
    ] {
        let output = mira(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert_eq!(
            output.stderr, b"Usage: mira investigate package-installed PACKAGE[:ARCH] [--json]\n",
            "{arguments:?}"
        );
    }
}
