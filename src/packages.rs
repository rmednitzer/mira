//! Read-only Debian package database observations.
//! Installed package metadata is not vulnerability applicability evidence.
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    path::Path,
};

pub const MAX_STATUS_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn finish_entry(
    fields: &mut (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ),
    output: &mut Vec<Package>,
    identities: &mut BTreeSet<(String, String)>,
) -> io::Result<()> {
    let (name, version, architecture, status) = std::mem::take(fields);
    if name.is_none() && version.is_none() && architecture.is_none() && status.is_none() {
        return Ok(());
    }
    let name = name.ok_or_else(|| invalid("missing package name"))?;
    let status = status.ok_or_else(|| invalid("missing package status"))?;
    let status_fields: Vec<_> = status.split_whitespace().collect();
    if status_fields.len() != 3
        || !["unknown", "install", "hold", "deinstall", "purge"].contains(&status_fields[0])
        || !["ok", "reinstreq"].contains(&status_fields[1])
        || ![
            "not-installed",
            "config-files",
            "half-installed",
            "unpacked",
            "half-configured",
            "triggers-awaited",
            "triggers-pending",
            "installed",
        ]
        .contains(&status_fields[2])
    {
        return Err(invalid("invalid package status"));
    }
    // Selection and error flags must not hide installed package provenance.
    if status_fields[2] == "installed" {
        let architecture = architecture.ok_or_else(|| invalid("missing installed architecture"))?;
        if !identities.insert((name.clone(), architecture.clone())) {
            return Err(invalid("duplicate installed package identity"));
        }
        output.push(Package {
            name,
            version: version.ok_or_else(|| invalid("missing installed version"))?,
            architecture,
        });
    }
    Ok(())
}

pub fn parse_status(input: &str) -> io::Result<Vec<Package>> {
    let mut entries = Vec::new();
    let mut identities = BTreeSet::new();
    let mut fields = (None, None, None, None);
    for line in input.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            finish_entry(&mut fields, &mut entries, &mut identities)?;
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
    Ok(entries)
}

/// Read a bounded status database. The root is injectable for fixtures, not a sandbox.
pub fn collect(status_path: &Path) -> io::Result<Vec<Package>> {
    let mut content = Vec::new();
    File::open(status_path)?
        .take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut content)?;
    if content.len() as u64 > MAX_STATUS_BYTES {
        return Err(crate::collector::limit_exceeded());
    }
    let content = String::from_utf8(content).map_err(|_| invalid("invalid UTF-8"))?;
    parse_status(&content)
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
        let entry = "Package: alpha\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 1\n\n";
        assert!(parse_status(&format!("{entry}{entry}")).is_err());
        assert!(parse_status(&format!("{entry}{}", entry.replace("Version: 1", "Version: 2"))).is_err());
        let multiarch = format!("{entry}{}", entry.replace("amd64", "arm64"));
        assert_eq!(parse_status(&multiarch).unwrap().len(), 2);
    }
}
