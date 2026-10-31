//! Additional bounded Linux evidence. All fields are observations, not diagnoses.
use crate::collector::read_bounded;
use std::{io, path::Path};

const LIMIT: u64 = 16 * 1024;

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
        // The kernel separates PSI fields with ASCII spaces; Unicode separators
        // would otherwise split into tokens the producer never emits.
        let mut tokens = line.split_ascii_whitespace();
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
    // Only the producer's ASCII newline is framing; Unicode whitespace is data.
    let trimmed = input.trim_ascii();
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

/// Closed resource selection; no caller-supplied path or trigger writes.
#[derive(Debug, Clone, Copy)]
pub enum PressureResource {
    Cpu,
    Memory,
    Io,
}
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

/// Only the fixed files below are requested. The roots are injectable for fixtures;
/// callers must never treat a supplied root as a privilege boundary.
pub fn pressure(proc_root: &Path, resource: PressureResource) -> io::Result<CpuPressure> {
    read_bounded(&proc_root.join(resource.relative()), LIMIT)
        .and_then(|value| parse_cpu_pressure(&value))
}
pub fn kernel_release(proc_root: &Path) -> io::Result<String> {
    read_bounded(&proc_root.join("sys/kernel/osrelease"), LIMIT)
        .and_then(|value| parse_kernel_release(&value))
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
    fn psi_requires_ascii_separators() {
        assert!(parse_cpu_pressure("some\tavg10=0.25  avg60=1.00\n").is_ok());
        for separator in ['\u{00a0}', '\u{2003}', '\u{3000}', '\u{0085}'] {
            let input = format!("some{separator}avg10=0.25 avg60=1.00\n");
            assert_eq!(
                parse_cpu_pressure(&input).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{separator:?}"
            );
        }
        // A Unicode separator before avg10 must not hide a malformed value.
        assert!(parse_cpu_pressure("some avg60=1.00\u{2003}avg10=0.25\n").is_err());
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
    fn kernel_release_trims_only_ascii_whitespace() {
        assert_eq!(parse_kernel_release(" 6.17.0\t\n").unwrap(), "6.17.0");
        for invalid in ["6.17.0\u{00a0}\n", "\u{2003}6.17.0\n", "6.17.0\u{0085}"] {
            assert!(parse_kernel_release(invalid).is_err(), "{invalid:?}");
        }
    }
    #[test]
    fn reports_missing_sources_independently() {
        let root = Path::new("/nonexistent-mira-extended-fixture");
        assert!(pressure(root, PressureResource::Cpu).is_err());
        assert!(kernel_release(root).is_err());
    }
}
