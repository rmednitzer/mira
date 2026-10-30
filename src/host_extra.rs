//! Additional bounded Linux evidence. All fields are observations, not diagnoses.
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

const LIMIT: u64 = 16 * 1024;

fn bounded(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(crate::collector::limit_exceeded());
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 source"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuPressure {
    /// PSI avg10 in basis points; 10000 represents 100.00%.
    pub some_avg10_basis_points: u32,
    pub full_avg10_basis_points: Option<u32>,
}

fn decimal_basis_points(input: &str) -> io::Result<u32> {
    let (whole, fraction) = input.split_once('.').unwrap_or((input, ""));
    if input.ends_with('.')
        || whole.is_empty()
        || !whole.bytes().all(|c| c.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PSI decimal",
        ));
    }
    let major: u32 = whole
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PSI overflow"))?;
    let minor: u32 = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PSI fraction"))?
            * if fraction.len() == 1 { 10 } else { 1 }
    };
    let result = major
        .checked_mul(100)
        .and_then(|v| v.checked_add(minor))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PSI overflow"))?;
    if result > 10_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PSI out of range",
        ));
    }
    Ok(result)
}

pub fn parse_cpu_pressure(input: &str) -> io::Result<CpuPressure> {
    let mut some = None;
    let mut full = None;
    for line in input.lines() {
        let mut tokens = line.split_whitespace();
        let kind = tokens
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty PSI line"))?;
        if kind != "some" && kind != "full" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown PSI type",
            ));
        }
        let mut avg10 = None;
        for field in tokens {
            if let Some(v) = field.strip_prefix("avg10=") {
                if avg10.replace(decimal_basis_points(v)?).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate avg10",
                    ));
                }
            }
        }
        let avg10 =
            avg10.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing avg10"))?;
        match kind {
            "some" if some.replace(avg10).is_some() => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "duplicate some"));
            }
            "full" if full.replace(avg10).is_some() => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "duplicate full"));
            }
            _ => {}
        }
    }
    Ok(CpuPressure {
        some_avg10_basis_points: some
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing some"))?,
        full_avg10_basis_points: full,
    })
}

pub fn parse_kernel_release(input: &str) -> io::Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.len() > 256
        || !trimmed
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid kernel release",
        ));
    }
    Ok(trimmed.to_owned())
}

#[derive(Debug)]
pub struct Observation<T> {
    pub source: &'static str,
    pub result: io::Result<T>,
}

pub struct ExtendedReport {
    pub kernel_release: Observation<String>,
    pub cpu_pressure: Observation<CpuPressure>,
}

/// Only the two fixed files below are requested. The roots are injectable for fixtures.
/// Callers must never treat a supplied root as a privilege boundary.
pub fn inspect(proc_root: &Path) -> ExtendedReport {
    ExtendedReport {
        kernel_release: Observation {
            source: "/proc/sys/kernel/osrelease",
            result: bounded(&proc_root.join("sys/kernel/osrelease"))
                .and_then(|v| parse_kernel_release(&v)),
        },
        cpu_pressure: Observation {
            source: "/proc/pressure/cpu",
            result: bounded(&proc_root.join("pressure/cpu")).and_then(|v| parse_cpu_pressure(&v)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_cpu_psi() {
        let p = parse_cpu_pressure("some avg10=0.25 avg60=1.00 avg300=2.00 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        assert_eq!(p.some_avg10_basis_points, 25);
        assert_eq!(p.full_avg10_basis_points, Some(0));
    }
    #[test]
    fn rejects_invalid_psi() {
        assert!(parse_cpu_pressure("some avg10=101.00\n").is_err());
        assert!(parse_cpu_pressure("some avg10=1.\n").is_err());
        assert!(parse_cpu_pressure("some avg10=1.00\nsome avg10=2.00\n").is_err());
        assert!(parse_cpu_pressure("full avg10=0.00\n").is_err());
    }
    #[test]
    fn validates_kernel_identity() {
        assert_eq!(
            parse_kernel_release("6.17.0-5-generic\n").unwrap(),
            "6.17.0-5-generic"
        );
        assert!(parse_kernel_release("kernel\nother\n").is_err());
    }
    #[test]
    fn reports_missing_sources_independently() {
        let r = inspect(Path::new("/nonexistent-mira-extended-fixture"));
        assert!(r.cpu_pressure.result.is_err());
        assert!(r.kernel_release.result.is_err());
    }
}

/// Closed resource selection; no caller-supplied path or trigger writes.
#[derive(Debug, Clone, Copy)]
pub enum PressureResource { Cpu, Memory, Io }
impl PressureResource {
    pub fn source(self) -> &'static str {
        match self {
            Self::Cpu => "/proc/pressure/cpu",
            Self::Memory => "/proc/pressure/memory",
            Self::Io => "/proc/pressure/io",
        }
    }
    fn relative(self) -> &'static str {
        match self {
            Self::Cpu => "pressure/cpu",
            Self::Memory => "pressure/memory",
            Self::Io => "pressure/io",
        }
    }
}
pub fn pressure(proc_root: &Path, resource: PressureResource) -> io::Result<CpuPressure> {
    bounded(&proc_root.join(resource.relative())).and_then(|value| parse_cpu_pressure(&value))
}
pub fn kernel_release(proc_root: &Path) -> io::Result<String> {
    bounded(&proc_root.join("sys/kernel/osrelease")).and_then(|value| parse_kernel_release(&value))
}
