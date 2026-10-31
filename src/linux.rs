//! Bounded, read-only Linux host evidence collection.
//!
//! No command execution, privilege escalation, network calls or mutation.
//! Injectable roots support deterministic fixtures; CLI integration checks may
//! inspect the runner's actual /proc.
use crate::collector::read_bounded;
use std::io;
use std::path::Path;

pub const MAX_SOURCE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEvidence {
    pub total_kib: u64,
    pub available_kib: u64,
}

pub fn parse_meminfo(text: &str) -> io::Result<MemoryEvidence> {
    fn value(text: &str, name: &str) -> io::Result<u64> {
        let mut found = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(name).and_then(|s| s.strip_prefix(':')) {
                if found.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate field",
                    ));
                }
                // procfs emits unsigned ASCII decimal values with ASCII separators.
                let mut fields = rest.split_ascii_whitespace();
                let number = fields
                    .next()
                    .filter(|n| n.bytes().all(|byte| byte.is_ascii_digit()))
                    .and_then(|n| n.parse::<u64>().ok());
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid memory values",
        ));
    }
    Ok(MemoryEvidence {
        total_kib,
        available_kib,
    })
}

/// Validate both nonnegative decimal-second fields and return the uptime field's
/// whole seconds and fraction digits. Idle is summed across CPUs, so it may
/// exceed uptime. No floating point is used.
fn uptime_field(text: &str) -> io::Result<(u64, &str)> {
    fn seconds(field: &str) -> io::Result<(u64, &str)> {
        let (whole, fraction) = match field.split_once('.') {
            Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
            Some(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "empty fraction"));
            }
            None => (field, ""),
        };
        if whole.is_empty()
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid seconds",
            ));
        }
        let whole = whole
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "seconds overflow"))?;
        Ok((whole, fraction))
    }

    let mut fields = text.split_ascii_whitespace();
    let uptime = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing uptime"))?;
    let idle = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing idle time"))?;
    if fields.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extra uptime field",
        ));
    }
    let uptime = seconds(uptime)?;
    seconds(idle)?;
    Ok(uptime)
}

/// Whole uptime seconds; the fraction is validated and discarded.
pub fn parse_uptime(text: &str) -> io::Result<u64> {
    uptime_field(text).map(|(whole, _)| whole)
}

/// Uptime in centiseconds, the kernel's printed resolution. Extra fraction
/// digits are truncated, never rounded up; overflow is invalid data.
pub fn parse_uptime_centiseconds(text: &str) -> io::Result<u64> {
    let (whole, fraction) = uptime_field(text)?;
    let digits = fraction.as_bytes();
    let tenths = digits.first().map_or(0, |digit| u64::from(digit - b'0'));
    let hundredths = digits.get(1).map_or(0, |digit| u64::from(digit - b'0'));
    whole
        .checked_mul(100)
        .and_then(|value| value.checked_add(tenths * 10 + hundredths))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "uptime overflow"))
}

/// Read one source so callers can timestamp it before starting the next.
/// The procfs root is caller-selected for fixtures, not a confinement boundary.
pub fn memory(proc_root: &Path) -> io::Result<MemoryEvidence> {
    read_bounded(&proc_root.join("meminfo"), MAX_SOURCE_BYTES)
        .and_then(|value| parse_meminfo(&value))
}
pub fn uptime(proc_root: &Path) -> io::Result<u64> {
    read_bounded(&proc_root.join("uptime"), MAX_SOURCE_BYTES).and_then(|value| parse_uptime(&value))
}
pub fn uptime_centiseconds(proc_root: &Path) -> io::Result<u64> {
    read_bounded(&proc_root.join("uptime"), MAX_SOURCE_BYTES)
        .and_then(|value| parse_uptime_centiseconds(&value))
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
    fn accepts_ascii_memory_layout_and_zero_available() {
        let memory = parse_meminfo("MemTotal:\t00100 kB\nMemAvailable: 0\tkB \n").unwrap();
        assert_eq!(memory.total_kib, 100);
        assert_eq!(memory.available_kib, 0);
    }
    #[test]
    fn rejects_inconsistent_memory() {
        assert!(parse_meminfo("MemTotal: 100 kB\nMemAvailable: 101 kB\n").is_err());
    }
    #[test]
    fn rejects_duplicate_fields() {
        assert!(
            parse_meminfo("MemTotal: 100 kB\nMemTotal: 200 kB\nMemAvailable: 80 kB\n").is_err()
        );
    }
    #[test]
    fn parses_uptime() {
        assert_eq!(parse_uptime("123.45 678.90\n").unwrap(), 123);
    }
    #[test]
    fn validates_both_uptime_fields() {
        for invalid in [
            "garbage",
            "NaN",
            "inf",
            "-1.00",
            "+1.00",
            ".25",
            "1.",
            "1.2.3",
            "1e3",
            "18446744073709551616.00",
            "0.00\\n",
            "1\u{001b}",
        ] {
            for input in [format!("{invalid} 0.00"), format!("42.50 {invalid}")] {
                assert_eq!(
                    parse_uptime(&input).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
        for input in ["42.50", "42.50 0.00 extra", "42.50\u{00a0}0.00"] {
            assert!(parse_uptime(input).is_err());
        }
    }
    #[test]
    fn accepts_multicore_idle_and_exact_integer_limits() {
        assert_eq!(parse_uptime("42.99 1234.56\n").unwrap(), 42);
        assert_eq!(parse_uptime("0 0").unwrap(), 0);
        assert_eq!(
            parse_uptime("18446744073709551615.99 18446744073709551615.00").unwrap(),
            u64::MAX
        );
    }
    #[test]
    fn rejects_uptime_overflow() {
        assert!(parse_uptime("18446744073709551616.5 0.0").is_err());
    }
    #[test]
    fn centiseconds_keep_kernel_resolution_and_truncate() {
        for (text, expected) in [
            ("42.50 0.00\n", 4_250),
            ("42.5 0.00\n", 4_250),
            ("42 0", 4_200),
            ("42.509 0.00", 4_250),
            ("0.01 0.00", 1),
            ("0 0", 0),
            ("184467440737095516.15 0.00", u64::MAX),
        ] {
            assert_eq!(parse_uptime_centiseconds(text).unwrap(), expected, "{text}");
        }
        for invalid in [
            "184467440737095516.16 0.00",
            "184467440737095517 0.00",
            "42.50",
            "42.50 x",
            "-1.00 0.00",
            "1e3 0.00",
            "42.50\u{00a0}0.00",
        ] {
            assert_eq!(
                parse_uptime_centiseconds(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{invalid:?}"
            );
        }
        // Whole-second parsing is unaffected by the centisecond limit.
        assert_eq!(
            parse_uptime("184467440737095517 0.00").unwrap(),
            184_467_440_737_095_517
        );
    }
    #[test]
    fn rejects_missing_uptime() {
        assert!(parse_uptime("").is_err());
    }
    #[test]
    fn missing_sources_are_independent_errors() {
        let root = Path::new("/nonexistent-mira-proc-test-fixtures");
        assert_eq!(memory(root).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(uptime(root).unwrap_err().kind(), io::ErrorKind::NotFound);
    }
}
