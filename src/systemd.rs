//! Read-only systemd unit observations via a fixed systemctl invocation.
//! No shell, privilege escalation, unit discovery or state-changing verb.
use std::{
    io::{self, Read},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    pub id: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Restrict callers to an explicitly selected system service unit.
/// This checks syntax, not the caller's authority to inspect a service.
pub fn validate_unit(unit: &str) -> io::Result<()> {
    if unit.len() < 9 || unit.len() > 200 || !unit.ends_with(".service") || unit.starts_with('-') {
        return Err(invalid("invalid systemd service name"));
    }
    let bytes = unit.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || bytes[index + 1] != b'x'
                || !bytes[index + 2].is_ascii_hexdigit()
                || !bytes[index + 3].is_ascii_hexdigit()
            {
                return Err(invalid("invalid systemd escape"));
            }
            index += 4;
        } else if bytes[index].is_ascii_alphanumeric() || b"._@:-".contains(&bytes[index]) {
            index += 1;
        } else {
            return Err(invalid("invalid systemd service name"));
        }
    }
    Ok(())
}

/// Parse precisely the properties requested by the collector.
/// Unknown state values remain literal evidence, not inferred health.
pub fn parse_show(output: &str, requested: &str) -> io::Result<ServiceState> {
    validate_unit(requested)?;
    if output.len() > 8192 {
        return Err(invalid("systemctl output too large"));
    }
    let mut id = None;
    let mut load = None;
    let mut active = None;
    let mut sub = None;
    let mut names = None;
    for line in output.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("malformed property"))?;
        if value.is_empty() || value.len() > 256 || !value.is_ascii() {
            return Err(invalid("invalid property value"));
        }
        let slot = match key {
            "Id" => &mut id,
            "LoadState" => &mut load,
            "ActiveState" => &mut active,
            "SubState" => &mut sub,
            "Names" => &mut names,
            _ => return Err(invalid("unexpected property")),
        };
        if slot.replace(value.to_owned()).is_some() {
            return Err(invalid("duplicate property"));
        }
    }
    let result = ServiceState {
        id: id.ok_or_else(|| invalid("missing Id"))?,
        load_state: load.ok_or_else(|| invalid("missing LoadState"))?,
        active_state: active.ok_or_else(|| invalid("missing ActiveState"))?,
        sub_state: sub.ok_or_else(|| invalid("missing SubState"))?,
    };
    validate_unit(&result.id)?;
    let names = names.ok_or_else(|| invalid("missing Names"))?;
    if !names.split_whitespace().any(|name| name == requested)
        || !names.split_whitespace().any(|name| name == result.id)
    {
        return Err(invalid("service identity mismatch"));
    }
    Ok(result)
}

/// Queries one named system service. Fixed argv, no shell, no interactive auth.
/// Timeout is enforced even when systemd is unresponsive.
pub fn inspect(unit: &str) -> io::Result<ServiceState> {
    validate_unit(unit)?;
    let mut child = Command::new("systemctl")
        .args([
            "--system",
            "--no-pager",
            "--no-ask-password",
            "show",
            "--property=Id,Names,LoadState,ActiveState,SubState",
            "--",
            unit,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "systemd query timeout",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(io::Error::other("systemd query unavailable or failed"));
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing stdout"))?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(invalid("systemd response exceeds limit"));
    }
    let text = String::from_utf8(bytes).map_err(|_| invalid("non-UTF8 systemd response"))?;
    parse_show(&text, unit)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &str = "Id=ssh.service\nNames=ssh.service\nLoadState=loaded\nActiveState=active\nSubState=running\n";

    #[test]
    fn parses_service_state() {
        let service = parse_show(SAMPLE, "ssh.service").unwrap();
        assert_eq!(service.active_state, "active");
        assert_eq!(service.sub_state, "running");
    }

    #[test]
    fn rejects_forged_or_incomplete_output() {
        assert!(parse_show(SAMPLE, "other.service").is_err());
        assert!(parse_show("Id=ssh.service\nActiveState=active\n", "ssh.service").is_err());
        assert!(parse_show(&format!("{SAMPLE}ActiveState=failed\n"), "ssh.service").is_err());
    }

    #[test]
    fn accepts_canonical_service_alias() {
        let output = "Id=systemd-sysctl.service\nNames=systemd-sysctl.service procps.service\nLoadState=loaded\nActiveState=active\nSubState=exited\n";
        assert_eq!(
            parse_show(output, "procps.service").unwrap().id,
            "systemd-sysctl.service"
        );
    }

    #[test]
    fn accepts_valid_escaped_instances() {
        let unit = r"systemd-fsck@dev-disk-by\x2duuid-1234\x2d5678.service";
        assert!(validate_unit(unit).is_ok());
        let output = format!(
            "Id={unit}\nNames={unit}\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        );
        assert!(parse_show(&output, unit).is_ok());
    }

    #[test]
    fn rejects_invalid_escapes_or_unlisted_aliases() {
        assert!(validate_unit(r"foo@bar\x2G.service").is_err());
        assert!(validate_unit(r"foo@bar\x2.service").is_err());
        let output = "Id=ssh.service\nNames=ssh.service other.service\nLoadState=loaded\nActiveState=active\nSubState=running\n";
        assert!(parse_show(output, "wrong.service").is_err());
    }

    #[test]
    fn rejects_unit_argument_injection() {
        for name in [
            "--user.service",
            "../ssh.service",
            "ssh.service;id",
            "ssh.socket",
            "",
        ] {
            assert!(validate_unit(name).is_err(), "{name}");
        }
    }
}
