//! Read-only Debian package database observations.
//! Installed package metadata is not vulnerability applicability evidence.
use std::{fs::File, io::{self, Read}, path::Path};

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
    fields: &mut (Option<String>, Option<String>, Option<String>, Option<String>),
    output: &mut Vec<Package>,
) -> io::Result<()> {
    let (name, version, architecture, status) = std::mem::take(fields);
    match (name, version, architecture, status) {
        (None, None, None, None) => Ok(()),
        (Some(name), Some(version), Some(architecture), Some(status)) => {
            if status == "install ok installed" {
                output.push(Package {
                    name,
                    version,
                    architecture,
                });
            }
            Ok(())
        }
        _ => Err(invalid("incomplete package record")),
    }
}

pub fn parse_status(input: &str) -> io::Result<Vec<Package>> {
    let mut entries = Vec::new();
    let mut fields = (None, None, None, None);
    for line in input.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            finish_entry(&mut fields, &mut entries)?;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, value)) = line.split_once(": ") else {
            return Err(invalid("invalid package field"));
        };
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
        return Err(invalid("package database exceeds limit"));
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
    fn incomplete_or_duplicate_records_fail() {
        assert!(parse_status("Package: alpha\nStatus: install ok installed\n").is_err());
        assert!(parse_status("Package: a\nPackage: b\n").is_err());
    }

    #[test]
    fn non_installed_entries_do_not_claim_exposure() {
        let result = parse_status("Package: alpha\nVersion: 1\nArchitecture: all\nStatus: deinstall ok config-files\n").unwrap();
        assert!(result.is_empty());
    }
}
