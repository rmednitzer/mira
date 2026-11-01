//! The closed set of actions a session can run (ADR 0015): exactly the
//! existing signable, read-only captures and investigation templates. Each
//! maps to a fixed `mira` argument vector; nothing else can be expressed.
//!
//! Arguments are space-separated tokens, each from a small charset and never
//! starting with `-`, so no request can inject an option such as
//! `--signature`. The templates' own validators still check semantics.

/// The fixed label for every session capture; labels are operator assertions.
const CAPTURE_LABEL: &str = "mira-session";
const MAX_TOKEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Capture,
    Investigation,
}

/// A validated action: the argument vector after the `mira` binary, and
/// whether it is reserved for the operator or a delegated agent.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub argv: Vec<String>,
    pub family: Family,
    pub operator_only: bool,
}

fn token_ok(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN
        && !token.starts_with('-')
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:+@,/=\\-".contains(&byte))
}

/// Tokens of a canonical argument string: single spaces, no empty tokens.
fn tokens(arguments: &str) -> Option<Vec<&str>> {
    if arguments.is_empty() {
        return Some(Vec::new());
    }
    let tokens: Vec<&str> = arguments.split(' ').collect();
    tokens.iter().all(|token| token_ok(token)).then_some(tokens)
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// Map one capability and its arguments to a plan, or refuse it.
pub fn plan(capability: &str, arguments: &str) -> Option<Plan> {
    let tokens = tokens(arguments)?;
    let investigation = |argv: Vec<String>| Plan {
        argv,
        family: Family::Investigation,
        operator_only: false,
    };
    // Captures always print JSON; only investigations take --json.
    let mut argv = match (capability, tokens.as_slice()) {
        ("capture", [profile, rest @ ..]) => {
            let pressure = match *profile {
                "host" => false,
                "host-pressure" => true,
                _ => return None,
            };
            let bind = match rest {
                [] => false,
                ["bind-boot"] => true,
                _ => return None,
            };
            let mut argv = strings(&["capture", CAPTURE_LABEL]);
            if pressure {
                argv.push("--pressure".to_owned());
            }
            argv.push("--timeline".to_owned());
            if bind {
                argv.push("--bind-boot".to_owned());
            }
            // The boot ID is a linkable identifier: operator or delegation only.
            return Some(Plan {
                argv,
                family: Family::Capture,
                operator_only: bind,
            });
        }
        ("service-active" | "service-active/v1" | "service-active/v2", [unit]) => {
            investigation(strings(&["investigate", capability, unit]))
        }
        ("memory-headroom", [minimum]) => investigation(strings(&[
            "investigate",
            "memory-headroom",
            "--min-available-kib",
            minimum,
        ])),
        ("pressure-ceiling", [resource, maximum]) => investigation(strings(&[
            "investigate",
            "pressure-ceiling",
            "--resource",
            resource,
            "--max-some-avg10-basis-points",
            maximum,
        ])),
        ("package-installed", [package]) => {
            investigation(strings(&["investigate", "package-installed", package]))
        }
        ("uptime-minimum", [minimum]) => investigation(strings(&[
            "investigate",
            "uptime-minimum",
            "--min-uptime-seconds",
            minimum,
        ])),
        ("kernel-release", [release]) => investigation(strings(&[
            "investigate",
            "kernel-release",
            "--expect",
            release,
        ])),
        ("journal-events", [classes]) => investigation(strings(&[
            "investigate",
            "journal-events",
            "--absent",
            classes,
        ])),
        ("journal-events", [classes, boot]) => investigation(strings(&[
            "investigate",
            "journal-events",
            "--absent",
            classes,
            "--boot",
            boot,
        ])),
        _ => return None,
    };
    argv.argv.push("--json".to_owned());
    Some(argv)
}

/// The fixed outcome of an executed action, from its exit status alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Satisfied,
    NotSatisfied,
    Indeterminate,
    CompleteAvailable,
    CompleteUnavailable,
    RefusedArguments,
    SigningFailed,
    RunnerError,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::NotSatisfied => "not_satisfied",
            Self::Indeterminate => "indeterminate",
            Self::CompleteAvailable => "complete_available",
            Self::CompleteUnavailable => "complete_unavailable",
            Self::RefusedArguments => "refused_arguments",
            Self::SigningFailed => "signing_failed",
            Self::RunnerError => "runner_error",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Satisfied,
            Self::NotSatisfied,
            Self::Indeterminate,
            Self::CompleteAvailable,
            Self::CompleteUnavailable,
            Self::RefusedArguments,
            Self::SigningFailed,
            Self::RunnerError,
        ]
        .into_iter()
        .find(|outcome| outcome.as_str() == text)
    }

    /// Whether a signed document was produced and stored.
    pub fn has_document(self) -> bool {
        !matches!(
            self,
            Self::RefusedArguments | Self::SigningFailed | Self::RunnerError
        )
    }

    /// The documented exit statuses of captures and investigations. `None`
    /// is a timeout or a child that could not run.
    pub fn of(family: Family, status: Option<i32>) -> Self {
        match (family, status) {
            (_, Some(2)) => Self::RefusedArguments,
            (_, Some(4)) => Self::SigningFailed,
            (Family::Investigation, Some(0)) => Self::Satisfied,
            (Family::Investigation, Some(1)) => Self::NotSatisfied,
            (Family::Investigation, Some(3)) => Self::Indeterminate,
            (Family::Capture, Some(0)) => Self::CompleteAvailable,
            (Family::Capture, Some(1)) => Self::CompleteUnavailable,
            _ => Self::RunnerError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_maps_to_its_fixed_argv() {
        let cases = [
            ("capture", "host", "capture mira-session --timeline", false),
            (
                "capture",
                "host-pressure",
                "capture mira-session --pressure --timeline",
                false,
            ),
            (
                "capture",
                "host bind-boot",
                "capture mira-session --timeline --bind-boot",
                true,
            ),
            (
                "service-active",
                "ssh.service",
                "investigate service-active ssh.service --json",
                false,
            ),
            (
                "service-active/v2",
                "a@b.service",
                "investigate service-active/v2 a@b.service --json",
                false,
            ),
            (
                "memory-headroom",
                "1024",
                "investigate memory-headroom --min-available-kib 1024 --json",
                false,
            ),
            (
                "pressure-ceiling",
                "io 500",
                "investigate pressure-ceiling --resource io --max-some-avg10-basis-points 500 --json",
                false,
            ),
            (
                "package-installed",
                "libc6:arm64",
                "investigate package-installed libc6:arm64 --json",
                false,
            ),
            (
                "uptime-minimum",
                "60",
                "investigate uptime-minimum --min-uptime-seconds 60 --json",
                false,
            ),
            (
                "kernel-release",
                "6.17.0-5-generic",
                "investigate kernel-release --expect 6.17.0-5-generic --json",
                false,
            ),
            (
                "journal-events",
                "oom-kill,coredump",
                "investigate journal-events --absent oom-kill,coredump --json",
                false,
            ),
            (
                "journal-events",
                "oom-kill previous-retained",
                "investigate journal-events --absent oom-kill --boot previous-retained --json",
                false,
            ),
        ];
        for (capability, arguments, argv, operator_only) in cases {
            let plan = plan(capability, arguments).unwrap();
            assert_eq!(plan.argv.join(" "), argv, "{capability} {arguments}");
            assert_eq!(plan.operator_only, operator_only);
        }
    }

    #[test]
    fn nothing_outside_the_closed_set_or_shaped_like_an_option_is_planned() {
        for (capability, arguments) in [
            ("inspect", ""),
            ("verify", "x"),
            ("session", "run"),
            ("challenge", ""),
            ("demo", ""),
            ("capture", ""),
            ("capture", "host --signature"),
            ("capture", "host bind-boot extra"),
            ("capture", "everything"),
            ("memory-headroom", "--json"),
            ("memory-headroom", "1 2"),
            ("memory-headroom", ""),
            ("memory-headroom", " 1"),
            ("memory-headroom", "1 "),
            ("memory-headroom", "1  2"),
            ("package-installed", "-rf"),
            ("package-installed", "a;b"),
            ("package-installed", "a\tb"),
            ("kernel-release", "6.17 --signature"),
            ("journal-events", "oom-kill current extra"),
            ("service-active/v3", "ssh.service"),
            ("SERVICE-ACTIVE", "ssh.service"),
        ] {
            assert_eq!(
                plan(capability, arguments),
                None,
                "{capability} {arguments:?}"
            );
        }
        assert!(plan("package-installed", &"a".repeat(257)).is_none());
    }

    #[test]
    fn outcomes_follow_documented_exit_statuses() {
        use Family::*;
        assert_eq!(Outcome::of(Investigation, Some(0)), Outcome::Satisfied);
        assert_eq!(Outcome::of(Investigation, Some(1)), Outcome::NotSatisfied);
        assert_eq!(Outcome::of(Investigation, Some(3)), Outcome::Indeterminate);
        assert_eq!(Outcome::of(Capture, Some(0)), Outcome::CompleteAvailable);
        assert_eq!(Outcome::of(Capture, Some(1)), Outcome::CompleteUnavailable);
        assert_eq!(Outcome::of(Capture, Some(3)), Outcome::RunnerError);
        for family in [Capture, Investigation] {
            assert_eq!(Outcome::of(family, Some(2)), Outcome::RefusedArguments);
            assert_eq!(Outcome::of(family, Some(4)), Outcome::SigningFailed);
            assert_eq!(Outcome::of(family, None), Outcome::RunnerError);
            assert_eq!(Outcome::of(family, Some(137)), Outcome::RunnerError);
        }
        for outcome in ["satisfied", "complete_unavailable", "runner_error"] {
            assert_eq!(Outcome::parse(outcome).unwrap().as_str(), outcome);
        }
        assert!(!Outcome::RefusedArguments.has_document());
        assert!(Outcome::Indeterminate.has_document());
    }
}
