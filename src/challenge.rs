//! Consumer-challenge freshness for signed captures (ADR 0014). The consumer
//! issues a random challenge and keeps its issue time; a capture embeds the
//! challenge before collection; the verifier bounds the capture's age on its
//! own clock. The host's clock is never trusted.
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

/// Fixed source in production builds.
const RANDOM_SOURCE: &str = "/dev/urandom";
const CHALLENGE_BYTES: usize = 32;
const CHALLENGE_HEX: usize = 2 * CHALLENGE_BYTES;
/// challenge-v1 documents are about 120 bytes.
pub const MAX_CHALLENGE_FILE_BYTES: u64 = 4096;
/// Up to 16 decimal digits for times and policies: enough for any wall clock
/// until the year 2286 and well inside JSON's exact-integer range.
const MAX_DIGITS: usize = 16;
const ISSUED_PREFIX: &[u8] = b"{\"challenge_version\":1,\"challenge\":\"";
const ISSUED_MIDDLE: &[u8] = b"\",\"issued_unix_ms\":";
const CAPTURE_PREFIX: &[u8] = b"{\"capture_version\":3,\"challenge\":\"";

/// 64 lowercase hex characters, the only accepted syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge(String);

impl Challenge {
    pub fn parse(text: &str) -> Option<Self> {
        is_challenge(text.as_bytes()).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_challenge(bytes: &[u8]) -> bool {
    bytes.len() == CHALLENGE_HEX && bytes.iter().all(|byte| b"0123456789abcdef".contains(byte))
}

/// Strict decimal: 1-16 digits, no sign and no leading zero except "0".
pub fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty()
        || bytes.len() > MAX_DIGITS
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn random_source() -> PathBuf {
    // Test-support builds may redirect the source to exercise read failures.
    // Release builds compile this branch out, so the fixed path cannot be overridden.
    #[cfg(feature = "test-support")]
    if let Some(path) = std::env::var_os("MIRA_TEST_RANDOM_SOURCE") {
        return path.into();
    }
    RANDOM_SOURCE.into()
}

/// Issue a challenge-v1 document (without the trailing newline). Any short
/// read or missing wall clock is an error, never a weaker challenge.
pub fn issue() -> io::Result<String> {
    let mut bytes = [0u8; CHALLENGE_BYTES];
    File::open(random_source())?.read_exact(&mut bytes)?;
    let issued = crate::evidence::timestamp()
        .ok_or_else(|| io::Error::other("wall clock before the Unix epoch"))?;
    Ok(render(&bytes, issued))
}

/// 32 bytes from the kernel CSPRNG as 64 lowercase hex characters, for other
/// fixed-width random identifiers (ADR 0015 session IDs).
pub(crate) fn random_hex() -> io::Result<String> {
    let mut bytes = [0u8; CHALLENGE_BYTES];
    File::open(random_source())?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn render(bytes: &[u8; CHALLENGE_BYTES], issued_unix_ms: u128) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{{\"challenge_version\":1,\"challenge\":\"{hex}\",\"issued_unix_ms\":{issued_unix_ms}}}"
    )
}

/// A challenge-v1 document as the consumer kept it.
#[derive(Debug, PartialEq, Eq)]
pub struct Issued {
    pub challenge: Challenge,
    pub issued_unix_ms: u64,
}

/// Accept exactly the byte layout `mira challenge` prints, with its newline.
pub fn parse_issued(document: &[u8]) -> Option<Issued> {
    let rest = document.strip_prefix(ISSUED_PREFIX)?;
    let (challenge, rest) = rest.split_at_checked(CHALLENGE_HEX)?;
    let digits = rest.strip_prefix(ISSUED_MIDDLE)?.strip_suffix(b"}\n")?;
    let challenge = Challenge::parse(std::str::from_utf8(challenge).ok()?)?;
    Some(Issued {
        challenge,
        issued_unix_ms: parse_decimal(digits)?,
    })
}

/// Why a signed capture does not answer the consumer's challenge in time.
#[derive(Debug, PartialEq, Eq)]
pub enum Stale {
    /// Not a capture-v3 document.
    NotChallenged,
    /// A capture-v3 document answering a different challenge.
    Mismatch,
    /// The verifier clock is earlier than the issue time.
    IssuedInFuture,
    /// The age bound exceeds the consumer's policy.
    OlderThanPolicy,
}

impl Stale {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotChallenged => "not_challenged",
            Self::Mismatch => "challenge_mismatch",
            Self::IssuedInFuture => "issued_in_future",
            Self::OlderThanPolicy => "older_than_policy",
        }
    }
}

/// Check the fixed capture-v3 prefix against the issued challenge and bound the
/// age on the verifier's clock. Call only after the signature verified: the
/// prefix is trusted because the signed bytes are.
pub fn check(
    document: &[u8],
    issued: &Issued,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<u64, Stale> {
    let rest = document
        .strip_prefix(CAPTURE_PREFIX)
        .ok_or(Stale::NotChallenged)?;
    match rest.split_at_checked(CHALLENGE_HEX) {
        Some((answered, tail))
            if answered == issued.challenge.as_str().as_bytes() && tail.starts_with(b"\",") => {}
        _ => return Err(Stale::Mismatch),
    }
    let age = now_unix_ms
        .checked_sub(issued.issued_unix_ms)
        .ok_or(Stale::IssuedInFuture)?;
    if age > max_age_ms {
        return Err(Stale::OlderThanPolicy);
    }
    Ok(age)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn issued(at: u64) -> Issued {
        Issued {
            challenge: Challenge::parse(HEX).unwrap(),
            issued_unix_ms: at,
        }
    }

    fn capture(challenge: &str) -> Vec<u8> {
        format!("{{\"capture_version\":3,\"challenge\":\"{challenge}\",\"capture_scope\":\"x\"}}\n")
            .into_bytes()
    }

    #[test]
    fn challenge_syntax_is_exactly_64_lowercase_hex() {
        assert!(Challenge::parse(HEX).is_some());
        for bad in [
            "",
            &HEX[..63],
            &format!("{HEX}0"),
            &HEX.to_uppercase(),
            &format!("{}g", &HEX[..63]),
            &format!("{HEX}\n"),
            &format!(" {}", &HEX[..63]),
        ] {
            assert_eq!(Challenge::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn decimals_are_strict() {
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"1793520000000"), Some(1_793_520_000_000));
        assert_eq!(
            parse_decimal(b"9999999999999999"),
            Some(9_999_999_999_999_999)
        );
        for bad in [
            &b""[..],
            b"01",
            b"-1",
            b"+1",
            b"1.0",
            b"1e3",
            b" 1",
            b"10000000000000000",
        ] {
            assert_eq!(parse_decimal(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn issued_documents_round_trip_and_reject_any_other_layout() {
        let text = render(&[0xab; CHALLENGE_BYTES], 1_793_520_000_000);
        assert_eq!(
            text,
            format!(
                "{{\"challenge_version\":1,\"challenge\":\"{}\",\"issued_unix_ms\":1793520000000}}",
                "ab".repeat(32)
            )
        );
        let parsed = parse_issued(format!("{text}\n").as_bytes()).unwrap();
        assert_eq!(parsed.challenge.as_str(), "ab".repeat(32));
        assert_eq!(parsed.issued_unix_ms, 1_793_520_000_000);
        for bad in [
            text.clone(),
            format!("{text}\n\n"),
            format!(" {text}\n"),
            text.replace("\"challenge_version\":1", "\"challenge_version\":2") + "\n",
            text.replace("ab", "AB") + "\n",
            text.replace(":1793520000000", ":01793520000000") + "\n",
            text.replace(":1793520000000", ":-1") + "\n",
            text.replace(",\"issued", ", \"issued") + "\n",
            format!("{}\n", text.replace('}', ",\"x\":1}")),
        ] {
            assert_eq!(parse_issued(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn every_outcome_of_the_freshness_check() {
        let at = 1_000_000;
        assert_eq!(check(&capture(HEX), &issued(at), at, 0), Ok(0));
        assert_eq!(check(&capture(HEX), &issued(at), at + 500, 500), Ok(500));
        assert_eq!(
            check(&capture(HEX), &issued(at), at + 501, 500),
            Err(Stale::OlderThanPolicy)
        );
        assert_eq!(
            check(&capture(HEX), &issued(at), at - 1, 500),
            Err(Stale::IssuedInFuture)
        );
        let other = HEX.replace("ff", "fe");
        assert_eq!(
            check(&capture(&other), &issued(at), at, 500),
            Err(Stale::Mismatch)
        );
        assert_eq!(
            check(&capture(&HEX[..62]), &issued(at), at, 500),
            Err(Stale::Mismatch)
        );
        let unterminated = format!("{{\"capture_version\":3,\"challenge\":\"{HEX}0\",");
        assert_eq!(
            check(unterminated.as_bytes(), &issued(at), at, 500),
            Err(Stale::Mismatch)
        );
        for other in [
            &b"{\"capture_version\":2,\"capture_scope\":\"x\"}\n"[..],
            b"{\"capture_version\":1,\"capture_scope\":\"x\"}\n",
            b"{\"investigation_version\":1}\n",
            b" {\"capture_version\":3,\"challenge\":\"",
        ] {
            assert_eq!(
                check(other, &issued(at), at, 500),
                Err(Stale::NotChallenged),
                "{other:?}"
            );
        }
    }
}
