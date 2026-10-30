//! Bounded, read-only Linux host evidence collection.
//!
//! No command execution, privilege escalation, network calls or mutation.
//! The root is injectable so tests never inspect the runner's actual /proc.
use std::fs;
use std::io;
use std::path::Path;

pub const MAX_SOURCE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEvidence {
    pub total_kib: u64,
    pub available_kib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEvidence {
    pub memory: MemoryEvidence,
    pub uptime_seconds: u64,
}

fn read_bounded(path: &Path) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut contents = Vec::new();
    use std::io::Read;
    file.take(MAX_SOURCE_BYTES + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_SOURCE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "source too large"));
    }
    String::from_utf8(contents)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8"))
}

pub fn parse_meminfo(text: &str) -> io::Result<MemoryEvidence> {
    fn value(text: &str, name: &str) -> io::Result<u64> {
        let mut found = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(name).and_then(|s| s.strip_prefix(':')) {
                if found.is_some() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "duplicate field"));
                }
                let mut fields = rest.split_whitespace();
                let number = fields.next().and_then(|n| n.parse::<u64>().ok());
                if fields.next() != Some("kB") || fields.next().is_some() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid unit"));
                }
                found = number;
                if found.is_none() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid number"));
                }
            }
        }
        found.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing field"))
    }
    let total_kib = value(text, "MemTotal")?;
    let available_kib = value(text, "MemAvailable")?;
    if total_kib == 0 || available_kib > total_kib {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid memory values"));
    }
    Ok(MemoryEvidence { total_kib, available_kib })
}

pub fn parse_uptime(text: &str) -> io::Result<u64> {
    let mut fields = text.split_whitespace();
    let seconds = fields.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing uptime"))?;
    let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid uptime"));
    }
    if fields.next().is_none() || fields.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid uptime fields"));
    }
    whole.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "uptime overflow"))
}

/// Read a narrow allowlist of procfs sources. Caller selects the procfs root.
pub fn collect(proc_root: &Path) -> io::Result<HostEvidence> {
    let memory = parse_meminfo(&read_bounded(&proc_root.join("meminfo"))?)?;
    let uptime_seconds = parse_uptime(&read_bounded(&proc_root.join("uptime"))?)?;
    Ok(HostEvidence { memory, uptime_seconds })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_memory() {
        let m = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 750 kB\n").unwrap();
        assert_eq!(m.available_kib, 750);
    }
    #[test]
    fn rejects_inconsistent_memory() {
        assert!(parse_meminfo("MemTotal: 100 kB\nMemAvailable: 101 kB\n").is_err());
    }
    #[test]
    fn rejects_duplicate_fields() {
        assert!(parse_meminfo("MemTotal: 100 kB\nMemTotal: 200 kB\nMemAvailable: 80 kB\n").is_err());
    }
    #[test]
    fn parses_uptime() {
        assert_eq!(parse_uptime("123.45 678.90\n").unwrap(), 123);
    }
    #[test]
    fn rejects_uptime_overflow() {
        assert!(parse_uptime("18446744073709551616.5 0.0").is_err());
    }
    #[test]
    fn rejects_missing_uptime() {
        assert!(parse_uptime("").is_err());
    }
}
