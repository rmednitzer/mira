//! Complete, explicitly scoped captures. Labels are operator assertions, not identity.
use crate::{
    challenge::Challenge,
    collector::FailureReason,
    evidence, evidence_json,
    host_extra::{self, PressureResource},
    linux, packages,
};
use std::{io, path::Path, time::Instant};

#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Host,
    HostPressure,
}

impl Profile {
    pub fn id(self) -> &'static str {
        match self {
            Self::Host => "host/v1",
            Self::HostPressure => "host-pressure/v1",
        }
    }
    pub fn sources(self) -> &'static [&'static str] {
        match self {
            Self::Host => &[
                "/proc/meminfo",
                "/proc/uptime",
                "/proc/sys/kernel/osrelease",
                "/proc/pressure/cpu",
                "/var/lib/dpkg/status",
            ],
            Self::HostPressure => &[
                "/proc/meminfo",
                "/proc/uptime",
                "/proc/sys/kernel/osrelease",
                "/proc/pressure/cpu",
                "/var/lib/dpkg/status",
                "/proc/pressure/memory",
                "/proc/pressure/io",
            ],
        }
    }
}

/// Conservative printable labels avoid accidentally publishing host identifiers.
/// Syntax cannot prevent an operator from placing sensitive text in a label.
/// A leading letter or digit keeps an option such as `--pressure` from being
/// admitted as the label of a different profile. Capture-v1 admission of
/// previously produced documents is unchanged; only the producer is stricter.
pub fn validate_label(label: &str) -> io::Result<()> {
    if label.len() > 64
        || !label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid capture label",
        ));
    }
    Ok(())
}

/// One source's acquisition on the capture's monotonic reference (ADR 0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub source: &'static str,
    /// Milliseconds from the capture's reference to this acquisition's start.
    pub offset_ms: u128,
    pub elapsed_ms: Option<u128>,
}

/// Collection window measured by MIRA's own monotonic clock. Wall-clock edges
/// are unverified readings; none of this establishes freshness or chronology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeline {
    pub monotonic_window_ms: u128,
    pub started_unix_ms: Option<u128>,
    pub ended_unix_ms: Option<u128>,
    pub entries: Vec<TimelineEntry>,
}

impl Timeline {
    pub fn wall_clock(&self) -> &'static str {
        wall_clock_consistency(
            self.started_unix_ms,
            self.ended_unix_ms,
            self.monotonic_window_ms,
        )
    }
}

/// Whether the unverified wall clock advanced like the monotonic window, within
/// max(50 ms, 1% of the window rounded down). Steps and suspend both diverge,
/// because the monotonic clock excludes suspended time.
pub fn wall_clock_consistency(
    started: Option<u128>,
    ended: Option<u128>,
    window_ms: u128,
) -> &'static str {
    let (Some(started), Some(ended)) = (started, ended) else {
        return "unknown";
    };
    let tolerance = (window_ms / 100).max(50);
    if ended >= started && (ended - started).abs_diff(window_ms) <= tolerance {
        "consistent"
    } else {
        "stepped_or_suspended"
    }
}

struct Recorder {
    start: Instant,
    entries: Vec<TimelineEntry>,
}

impl Recorder {
    fn observe<T>(
        &mut self,
        source: &'static str,
        collect: impl FnOnce() -> io::Result<T>,
    ) -> evidence::Evidence<T> {
        let offset_ms = self.start.elapsed().as_millis();
        let observation = evidence::observe(source, collect);
        self.entries.push(TimelineEntry {
            source,
            offset_ms,
            elapsed_ms: observation.elapsed_ms,
        });
        observation
    }
}

/// Opt-in boot binding (ADR 0010 stage 2). Only `NotRequested` reads nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootBinding {
    NotRequested,
    Observed {
        boot_id: String,
        started_uptime_cs: u64,
        ended_uptime_cs: u64,
    },
    Unavailable(FailureReason),
}

impl BootBinding {
    fn to_json(&self) -> String {
        match self {
            Self::NotRequested => "{\"binding\":\"not_requested\"}".to_owned(),
            Self::Observed {
                boot_id,
                started_uptime_cs,
                ended_uptime_cs,
            } => format!(
                "{{\"binding\":\"observed\",\"boot_id\":{},\"started_uptime_cs\":{started_uptime_cs},\"ended_uptime_cs\":{ended_uptime_cs}}}",
                evidence_json::quoted(boot_id)
            ),
            Self::Unavailable(reason) => format!(
                "{{\"binding\":\"unavailable\",\"failure_reason\":{}}}",
                evidence_json::quoted(reason.as_str())
            ),
        }
    }
}

/// One edge sample: the boot ID and boot-relative uptime in centiseconds.
pub type BootSample = io::Result<(String, u64)>;

/// Combine the two window-edge samples. Any failure, a changed boot ID or a
/// reversed uptime window is unavailable; partial values are never exported.
pub fn bind_boot(started: BootSample, ended: BootSample) -> BootBinding {
    let unavailable =
        |error: &io::Error| BootBinding::Unavailable(FailureReason::from_error(error));
    let (started_id, started_uptime_cs) = match started {
        Ok(sample) => sample,
        Err(error) => return unavailable(&error),
    };
    let (ended_id, ended_uptime_cs) = match ended {
        Ok(sample) => sample,
        Err(error) => return unavailable(&error),
    };
    if started_id != ended_id || ended_uptime_cs < started_uptime_cs {
        return BootBinding::Unavailable(FailureReason::MalformedData);
    }
    BootBinding::Observed {
        boot_id: started_id,
        started_uptime_cs,
        ended_uptime_cs,
    }
}

fn boot_sample(proc_root: &Path) -> BootSample {
    let boot_id = host_extra::boot_id(proc_root)?;
    let uptime = linux::uptime_centiseconds(proc_root)?;
    Ok((boot_id, uptime))
}

pub struct Capture {
    label: String,
    profile: Profile,
    records: Vec<String>,
    all_available: bool,
    timeline: Timeline,
    boot: BootBinding,
}
impl Capture {
    pub fn all_available(&self) -> bool {
        self.all_available
    }
    pub fn timeline(&self) -> &Timeline {
        &self.timeline
    }
    pub fn boot(&self) -> &BootBinding {
        &self.boot
    }
    /// capture-v1, unchanged; the timeline is not exported.
    pub fn to_json(&self) -> String {
        self.render(1, "", "")
    }
    /// capture-v2: the same records plus the collection window and timeline.
    pub fn to_timeline_json(&self) -> String {
        self.render(2, "", &self.timing_json())
    }
    /// capture-v3: capture-v2 with the consumer's challenge immediately after
    /// the version, so verifiers can check a fixed prefix (ADR 0014).
    pub fn to_challenge_json(&self, challenge: &Challenge) -> String {
        self.render(
            3,
            &format!("\"challenge\":\"{}\",", challenge.as_str()),
            &self.timing_json(),
        )
    }
    fn timing_json(&self) -> String {
        let timeline = &self.timeline;
        let entries = timeline
            .entries
            .iter()
            .map(|entry| {
                format!(
                    "{{\"source\":{},\"offset_ms\":{},\"elapsed_ms\":{}}}",
                    evidence_json::quoted(entry.source),
                    entry.offset_ms,
                    evidence_json::timestamp(entry.elapsed_ms)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "\"collection\":{{\"monotonic_window_ms\":{},\"started_unix_ms\":{},\"ended_unix_ms\":{},\"wall_clock\":{},\"boot\":{}}},\"timeline\":[{entries}],",
            timeline.monotonic_window_ms,
            evidence_json::timestamp(timeline.started_unix_ms),
            evidence_json::timestamp(timeline.ended_unix_ms),
            evidence_json::quoted(timeline.wall_clock()),
            self.boot.to_json()
        )
    }
    fn render(&self, version: u32, header: &str, timing: &str) -> String {
        let sources = self
            .profile
            .sources()
            .iter()
            .map(|s| evidence_json::quoted(s))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"capture_version\":{version},{header}\"capture_scope\":{},\"scope_trust\":\"operator_asserted\",\"profile\":{},\"expected_sources\":[{sources}],\"collection_complete\":true,\"all_available\":{},{timing}\"records\":[{}]}}",
            evidence_json::quoted(&self.label),
            evidence_json::quoted(self.profile.id()),
            self.all_available,
            self.records.join(",")
        )
    }
}

/// Fixed profiles only. Injectable paths support offline fixtures, not confinement.
/// Sources are read in profile order against one monotonic reference.
pub fn collect(
    label: &str,
    profile: Profile,
    proc_root: &Path,
    status: &Path,
) -> io::Result<Capture> {
    collect_inner(label, profile, false, proc_root, status)
}

/// As [`collect`], plus boot ID and centisecond uptime samples at both window
/// edges. Only this explicit entry point reads the boot ID.
pub fn collect_with_boot(
    label: &str,
    profile: Profile,
    proc_root: &Path,
    status: &Path,
) -> io::Result<Capture> {
    collect_inner(label, profile, true, proc_root, status)
}

fn collect_inner(
    label: &str,
    profile: Profile,
    bind: bool,
    proc_root: &Path,
    status: &Path,
) -> io::Result<Capture> {
    validate_label(label)?;
    let mut recorder = Recorder {
        start: Instant::now(),
        entries: Vec::with_capacity(profile.sources().len()),
    };
    let started_unix_ms = evidence::timestamp();
    let started_boot = bind.then(|| boot_sample(proc_root));
    let memory = recorder.observe("/proc/meminfo", || linux::memory(proc_root));
    let uptime = recorder.observe("/proc/uptime", || linux::uptime(proc_root));
    let kernel = recorder.observe("/proc/sys/kernel/osrelease", || {
        host_extra::kernel_release(proc_root)
    });
    let cpu = recorder.observe(PressureResource::Cpu.source(), || {
        host_extra::pressure(proc_root, PressureResource::Cpu)
    });
    let packages = recorder.observe("/var/lib/dpkg/status", || packages::collect(status));
    let mut all_available = memory.is_available()
        && uptime.is_available()
        && kernel.is_available()
        && cpu.is_available()
        && packages.is_available();
    let mut records = vec![
        evidence_json::record_v2(&memory, None, evidence_json::memory_value),
        evidence_json::record_v2(&uptime, None, |v| v.to_string()),
        evidence_json::record_v2(&kernel, None, |v| evidence_json::quoted(v)),
        pressure_record(&cpu),
        evidence_json::record_v2(&packages, None, |p| evidence_json::packages_value(p)),
    ];
    if matches!(profile, Profile::HostPressure) {
        for resource in [PressureResource::Memory, PressureResource::Io] {
            let observation = recorder.observe(resource.source(), || {
                host_extra::pressure(proc_root, resource)
            });
            all_available &= observation.is_available();
            records.push(pressure_record(&observation));
        }
    }
    let boot = match started_boot {
        Some(started) => bind_boot(started, boot_sample(proc_root)),
        None => BootBinding::NotRequested,
    };
    let monotonic_window_ms = recorder.start.elapsed().as_millis();
    let ended_unix_ms = evidence::timestamp();
    Ok(Capture {
        label: label.to_owned(),
        profile,
        records,
        all_available,
        timeline: Timeline {
            monotonic_window_ms,
            started_unix_ms,
            ended_unix_ms,
            entries: recorder.entries,
        },
        boot,
    })
}

fn pressure_record(observation: &evidence::Evidence<host_extra::CpuPressure>) -> String {
    evidence_json::record_v2(observation, None, evidence_json::pressure_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_labels_are_rejected_before_collection() {
        for label in [
            "",
            "private name",
            "x\u{001b}",
            "a/b",
            &"a".repeat(65),
            "--pressure",
            "--json",
            "-",
            "-a",
            ".",
            ".hidden",
            "_a",
        ] {
            assert!(
                collect(
                    label,
                    Profile::Host,
                    Path::new("/missing"),
                    Path::new("/missing")
                )
                .is_err()
            );
        }
    }
    #[test]
    fn labels_starting_with_letters_or_digits_remain_admitted() {
        for label in ["a", "0", "incident-a", "Z9._-", &"a".repeat(64)] {
            assert!(validate_label(label).is_ok(), "{label}");
        }
    }
    #[test]
    fn missing_sources_still_produce_a_complete_capture() {
        let capture = collect(
            "fixture",
            Profile::HostPressure,
            Path::new("/nonexistent-mira-capture"),
            Path::new("/nonexistent-mira-status"),
        )
        .unwrap();
        assert!(!capture.all_available());
        let json = capture.to_json();
        assert!(json.contains("\"collection_complete\":true"));
        assert_eq!(json.matches("\"status\":\"unavailable\"").count(), 7);
        assert_eq!(json.matches("\"failure_reason\":\"not_found\"").count(), 7);
        assert!(!json.contains("nonexistent"));
    }

    #[test]
    fn wall_clock_rule_uses_fixed_tolerance_and_detects_steps() {
        for (started, ended, window, expected) in [
            (Some(1_000), Some(1_007), 7, "consistent"),
            (Some(1_000), Some(1_050), 0, "consistent"),
            (Some(1_000), Some(1_051), 0, "stepped_or_suspended"),
            (Some(1_000), Some(1_000), 50, "consistent"),
            (Some(1_000), Some(1_000), 51, "stepped_or_suspended"),
            // 1% of a 10 s window (100 ms) exceeds the 50 ms floor.
            (Some(0), Some(10_100), 10_000, "consistent"),
            (Some(0), Some(10_101), 10_000, "stepped_or_suspended"),
            (Some(0), Some(9_900), 10_000, "consistent"),
            (Some(0), Some(9_899), 10_000, "stepped_or_suspended"),
            // A backwards step is never consistent, even inside the tolerance.
            (Some(1_000), Some(999), 0, "stepped_or_suspended"),
            (None, Some(1_000), 0, "unknown"),
            (Some(1_000), None, 0, "unknown"),
            (None, None, 0, "unknown"),
        ] {
            assert_eq!(
                wall_clock_consistency(started, ended, window),
                expected,
                "{started:?} {ended:?} {window}"
            );
        }
    }

    fn fixed_capture() -> Capture {
        Capture {
            label: "fixture".to_owned(),
            profile: Profile::Host,
            records: vec!["{\"r\":1}".to_owned(), "{\"r\":2}".to_owned()],
            all_available: false,
            timeline: Timeline {
                monotonic_window_ms: 7,
                started_unix_ms: Some(1_000),
                ended_unix_ms: None,
                entries: vec![
                    TimelineEntry {
                        source: "/proc/meminfo",
                        offset_ms: 0,
                        elapsed_ms: Some(1),
                    },
                    TimelineEntry {
                        source: "/proc/uptime",
                        offset_ms: 2,
                        elapsed_ms: None,
                    },
                ],
            },
            boot: BootBinding::NotRequested,
        }
    }

    #[test]
    fn boot_binding_requires_two_agreeing_edge_samples() {
        let id = || "e740207d-b13a-48dd-8e9d-595a950d6930".to_owned();
        let other = || "00000000-0000-0000-0000-000000000000".to_owned();
        let missing = || Err(io::Error::new(io::ErrorKind::NotFound, "private"));
        let denied = || Err(io::Error::new(io::ErrorKind::PermissionDenied, "private"));
        assert_eq!(
            bind_boot(Ok((id(), 10)), Ok((id(), 12))),
            BootBinding::Observed {
                boot_id: id(),
                started_uptime_cs: 10,
                ended_uptime_cs: 12,
            }
        );
        assert!(matches!(
            bind_boot(Ok((id(), 10)), Ok((id(), 10))),
            BootBinding::Observed { .. }
        ));
        for (started, ended, reason) in [
            (
                Ok((id(), 10)),
                Ok((other(), 12)),
                FailureReason::MalformedData,
            ),
            (Ok((id(), 12)), Ok((id(), 10)), FailureReason::MalformedData),
            (missing(), Ok((id(), 12)), FailureReason::NotFound),
            (Ok((id(), 10)), denied(), FailureReason::PermissionDenied),
            // The first failure decides the reason.
            (denied(), missing(), FailureReason::PermissionDenied),
        ] {
            assert_eq!(bind_boot(started, ended), BootBinding::Unavailable(reason));
        }
    }

    #[test]
    fn boot_binding_renders_each_shape_without_partial_values() {
        let mut capture = fixed_capture();
        capture.boot = BootBinding::Observed {
            boot_id: "e740207d-b13a-48dd-8e9d-595a950d6930".to_owned(),
            started_uptime_cs: 1_102_523,
            ended_uptime_cs: 1_102_524,
        };
        assert!(capture.to_timeline_json().contains(r#""boot":{"binding":"observed","boot_id":"e740207d-b13a-48dd-8e9d-595a950d6930","started_uptime_cs":1102523,"ended_uptime_cs":1102524}}"#));
        capture.boot = BootBinding::Unavailable(FailureReason::NotFound);
        let json = capture.to_timeline_json();
        assert!(json.contains(r#""boot":{"binding":"unavailable","failure_reason":"not_found"}}"#));
        assert!(!json.contains("boot_id"));
        // capture-v1 never carries the boot binding.
        assert!(!capture.to_json().contains("boot"));
    }

    #[test]
    fn capture_v1_rendering_is_unchanged_and_v2_only_adds_timing() {
        let capture = fixed_capture();
        let sources = r#"["/proc/meminfo","/proc/uptime","/proc/sys/kernel/osrelease","/proc/pressure/cpu","/var/lib/dpkg/status"]"#;
        assert_eq!(
            capture.to_json(),
            format!(
                r#"{{"capture_version":1,"capture_scope":"fixture","scope_trust":"operator_asserted","profile":"host/v1","expected_sources":{sources},"collection_complete":true,"all_available":false,"records":[{{"r":1}},{{"r":2}}]}}"#
            )
        );
        assert_eq!(
            capture.to_timeline_json(),
            format!(
                r#"{{"capture_version":2,"capture_scope":"fixture","scope_trust":"operator_asserted","profile":"host/v1","expected_sources":{sources},"collection_complete":true,"all_available":false,"collection":{{"monotonic_window_ms":7,"started_unix_ms":1000,"ended_unix_ms":null,"wall_clock":"unknown","boot":{{"binding":"not_requested"}}}},"timeline":[{{"source":"/proc/meminfo","offset_ms":0,"elapsed_ms":1}},{{"source":"/proc/uptime","offset_ms":2,"elapsed_ms":null}}],"records":[{{"r":1}},{{"r":2}}]}}"#
            )
        );
    }

    #[test]
    fn capture_v3_is_capture_v2_with_the_challenge_after_the_version() {
        let capture = fixed_capture();
        let hex = "0123456789abcdef".repeat(4);
        let challenge = Challenge::parse(&hex).unwrap();
        let v2 = capture.to_timeline_json();
        let v3 = capture.to_challenge_json(&challenge);
        let rest = v2.strip_prefix(r#"{"capture_version":2,"#).unwrap();
        assert_eq!(
            v3,
            format!(r#"{{"capture_version":3,"challenge":"{hex}",{rest}"#)
        );
    }
}
