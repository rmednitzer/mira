//! Read-only Debian package database observations.
//! Installed package metadata is not vulnerability applicability evidence.
use crate::collector::read_bounded;
use std::{collections::BTreeSet, io, path::Path};

pub const MAX_STATUS_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

/// One validated status stanza. Sparse non-installed stanzas may omit version
/// and architecture. Status words are drawn from dpkg's closed vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub selection: &'static str,
    pub flag: &'static str,
    pub state: &'static str,
}

const SELECTIONS: [&str; 5] = ["unknown", "install", "hold", "deinstall", "purge"];
const FLAGS: [&str; 2] = ["ok", "reinstreq"];
const STATES: [&str; 8] = [
    "not-installed",
    "config-files",
    "half-installed",
    "unpacked",
    "half-configured",
    "triggers-awaited",
    "triggers-pending",
    "installed",
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn word(words: &[&'static str], value: &str) -> Option<&'static str> {
    words.iter().copied().find(|candidate| *candidate == value)
}

type Fields = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn finish_entry(
    fields: &mut Fields,
    identities: &mut BTreeSet<(String, String)>,
    visit: &mut impl FnMut(Record) -> io::Result<()>,
) -> io::Result<()> {
    let (name, version, architecture, status) = std::mem::take(fields);
    if name.is_none() && version.is_none() && architecture.is_none() && status.is_none() {
        return Ok(());
    }
    let name = name.ok_or_else(|| invalid("missing package name"))?;
    let status = status.ok_or_else(|| invalid("missing package status"))?;
    // dpkg writes ASCII-space-separated words; Unicode separators are invalid data.
    let status_fields: Vec<_> = status.split_ascii_whitespace().collect();
    let [selection, flag, state] = status_fields[..] else {
        return Err(invalid("invalid package status"));
    };
    let (Some(selection), Some(flag), Some(state)) = (
        word(&SELECTIONS, selection),
        word(&FLAGS, flag),
        word(&STATES, state),
    ) else {
        return Err(invalid("invalid package status"));
    };
    // Selection and error flags must not hide installed package provenance.
    if state == "installed" {
        let architecture = architecture
            .as_ref()
            .ok_or_else(|| invalid("missing installed architecture"))?;
        if version.is_none() {
            return Err(invalid("missing installed version"));
        }
        if !identities.insert((name.clone(), architecture.clone())) {
            return Err(invalid("duplicate installed package identity"));
        }
    }
    visit(Record {
        name,
        version,
        architecture,
        selection,
        flag,
        state,
    })
}

/// Validate the whole database and visit every stanza in order. Any malformed
/// stanza fails the whole source, so a partial database cannot become evidence.
fn parse_records(input: &str, mut visit: impl FnMut(Record) -> io::Result<()>) -> io::Result<()> {
    let mut identities = BTreeSet::new();
    let mut fields: Fields = (None, None, None, None);
    for line in input.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            finish_entry(&mut fields, &mut identities, &mut visit)?;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, raw)) = line.split_once(':') else {
            return Err(invalid("invalid package field"));
        };
        let value = raw.strip_prefix(' ').unwrap_or(raw);
        let target = match key {
            "Package" => Some(&mut fields.0),
            "Version" => Some(&mut fields.1),
            "Architecture" => Some(&mut fields.2),
            "Status" => Some(&mut fields.3),
            _ => None,
        };
        if let Some(target) = target {
            if value.is_empty() || value.len() > 512 || value.contains('\0') {
                return Err(invalid("invalid package value"));
            }
            if target.replace(value.to_owned()).is_some() {
                return Err(invalid("duplicate package field"));
            }
        }
    }
    Ok(())
}

pub fn parse_status(input: &str) -> io::Result<Vec<Package>> {
    let mut entries = Vec::new();
    parse_records(input, |record| {
        if record.state == "installed"
            && let (Some(version), Some(architecture)) = (record.version, record.architecture)
        {
            entries.push(Package {
                name: record.name,
                version,
                architecture,
            });
        }
        Ok(())
    })?;
    Ok(entries)
}

/// Upper bound on records returned for one selector; more is a limit failure.
pub const MAX_SELECTED_RECORDS: usize = 16;

/// Validate the whole database, then keep only stanzas whose Package equals
/// `name` exactly and, when given, whose Architecture equals `architecture`.
pub fn parse_selected(
    input: &str,
    name: &str,
    architecture: Option<&str>,
) -> io::Result<Vec<Record>> {
    let mut selected = Vec::new();
    parse_records(input, |record| {
        if record.name == name
            && architecture.is_none_or(|wanted| record.architecture.as_deref() == Some(wanted))
        {
            if selected.len() == MAX_SELECTED_RECORDS {
                return Err(crate::collector::limit_exceeded());
            }
            selected.push(record);
        }
        Ok(())
    })?;
    Ok(selected)
}

/// Read a bounded status database. The root is injectable for fixtures, not a sandbox.
pub fn collect(status_path: &Path) -> io::Result<Vec<Package>> {
    parse_status(&read_bounded(status_path, MAX_STATUS_BYTES)?)
}

/// Read a bounded status database and select one package's records.
pub fn select(
    status_path: &Path,
    name: &str,
    architecture: Option<&str>,
) -> io::Result<Vec<Record>> {
    parse_selected(
        &read_bounded(status_path, MAX_STATUS_BYTES)?,
        name,
        architecture,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_installed_packages_are_collected() {
        let status = "Package: alpha\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.2-3ubuntu1\nDescription: Example\n longer description\n\nPackage: beta\nStatus: deinstall ok config-files\nArchitecture: all\nVersion: 2\n";
        let packages = parse_status(status).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "alpha");
        assert_eq!(packages[0].version, "1.2-3ubuntu1");
    }

    #[test]
    fn selection_does_not_hide_currently_installed_packages() {
        for selection in ["install", "hold", "deinstall", "purge"] {
            let input = format!(
                "Package: alpha\nVersion: 1\nArchitecture: all\nStatus: {selection} ok installed\n"
            );
            assert_eq!(parse_status(&input).unwrap().len(), 1);
        }
        let input =
            "Package: alpha\nVersion: 1\nArchitecture: all\nStatus: hold reinstreq installed\n";
        assert_eq!(parse_status(input).unwrap().len(), 1);
    }

    #[test]
    fn malformed_status_cannot_become_installed_evidence() {
        for status in [
            "bogus ok installed",
            "hold bogus installed",
            "install ok bogus",
        ] {
            let input =
                format!("Package: alpha\nVersion: 1\nArchitecture: all\nStatus: {status}\n");
            assert!(parse_status(&input).is_err());
        }
    }

    #[test]
    fn sparse_noninstalled_records_do_not_hide_installed_packages() {
        let input = "Package: removed\nStatus: purge ok not-installed\n\nPackage: alpha\nStatus: hold ok installed\nArchitecture: all\nVersion: 1\n";
        let packages = parse_status(input).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "alpha");
    }

    #[test]
    fn incomplete_or_duplicate_records_fail() {
        assert!(parse_status("Package: alpha\nStatus: install ok installed\n").is_err());
        assert!(parse_status("Package: a\nPackage: b\n").is_err());
    }

    #[test]
    fn status_words_require_ascii_separators() {
        for separator in ['\u{00a0}', '\u{2003}', '\u{0085}'] {
            let input = format!(
                "Package: alpha\nVersion: 1\nArchitecture: all\nStatus: install{separator}ok installed\n"
            );
            assert_eq!(
                parse_status(&input).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{separator:?}"
            );
        }
    }

    #[test]
    fn non_installed_entries_do_not_claim_exposure() {
        let result = parse_status(
            "Package: alpha\nVersion: 1\nArchitecture: all\nStatus: deinstall ok config-files\n",
        )
        .unwrap();
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn duplicate_identity_is_rejected_but_multiarch_is_preserved() {
        let entry =
            "Package: alpha\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 1\n\n";
        assert!(parse_status(&format!("{entry}{entry}")).is_err());
        assert!(
            parse_status(&format!(
                "{entry}{}",
                entry.replace("Version: 1", "Version: 2")
            ))
            .is_err()
        );
        let multiarch = format!("{entry}{}", entry.replace("amd64", "arm64"));
        assert_eq!(parse_status(&multiarch).unwrap().len(), 2);
    }
}
