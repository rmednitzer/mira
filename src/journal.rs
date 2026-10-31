//! Bounded, text-free journal event evidence (ADR 0012).
//!
//! Events are selected only by systemd catalog `MESSAGE_ID`s bound to their
//! actual producer's journald-set fields. No message text, PID, command line,
//! executable name of a crashed process, cursor or boot ID is read or exported.
//! Absence is reported only when the journal for the boot is visible and every
//! system journal file is openable; journal evidence is still TB2 input.
use crate::process::{Stderr, run_bounded};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const JOURNALCTL: &str = "/usr/bin/journalctl";
const SYSTEMD: &str = "/usr/lib/systemd/systemd";
const COREDUMP: &str = "/usr/lib/systemd/systemd-coredump";
const COREDUMP_SLICE: &str = r"system-systemd\x2dcoredump.slice";
/// Entries requested per class; reaching it means the window is full.
pub const WINDOW: usize = 1001;
/// Reported counts never exceed this; beyond it `truncated` is set.
pub const MAX_COUNT: usize = 1000;
pub const MAX_UNITS: usize = 16;
const MAX_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_DIR_ENTRIES: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(10);
const OUTPUT_FIELDS: &str = "--output-fields=MESSAGE_ID,UNIT,USER_UNIT,COREDUMP_UNIT,COREDUMP_USER_UNIT,_UID,_EXE,_SYSTEMD_UNIT,_SYSTEMD_SLICE";
/// Fields the parser keeps; everything else journalctl emits is ignored.
const KEPT: [&str; 11] = [
    "MESSAGE_ID",
    "UNIT",
    "USER_UNIT",
    "COREDUMP_UNIT",
    "COREDUMP_USER_UNIT",
    "_UID",
    "_EXE",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_SLICE",
    "_PID",
    "__MONOTONIC_TIMESTAMP",
];

/// Closed event classes, in canonical report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    OomKill,
    UnitFailure,
    Coredump,
}

impl Class {
    pub const ALL: [Class; 3] = [Self::OomKill, Self::UnitFailure, Self::Coredump];

    pub fn name(self) -> &'static str {
        match self {
            Self::OomKill => "oom-kill",
            Self::UnitFailure => "unit-failure",
            Self::Coredump => "coredump",
        }
    }

    pub fn message_ids(self) -> &'static [&'static str] {
        match self {
            // Kernel OOM kill in a unit; systemd-oomd kill (both logged by the manager).
            Self::OomKill => &[
                "fe6faa94e7774663a0da52717891d8ef",
                "d989611b15e44c9dbf31e3c81256e4ed",
            ],
            // Unit failed; start job failed.
            Self::UnitFailure => &[
                "d9b373ed55a64feb8242e02dbe79a49c",
                "be02cf6855d2428ba40df7e9d022f03d",
            ],
            // Core dump processed by socket-activated systemd-coredump only.
            Self::Coredump => &["fc2e22bc6ee647b6b90729ab34a250b1"],
        }
    }

    /// Journal match arguments: each ID bound to its producer, ORed with `+`.
    pub fn matches(self) -> Vec<String> {
        let mut args = Vec::new();
        for (index, id) in self.message_ids().iter().enumerate() {
            if index > 0 {
                args.push("+".to_owned());
            }
            args.push(format!("MESSAGE_ID={id}"));
            match self {
                Self::OomKill | Self::UnitFailure => {
                    args.push("_UID=0".to_owned());
                    args.push(format!("_EXE={SYSTEMD}"));
                }
                Self::Coredump => {
                    args.push(format!("_EXE={COREDUMP}"));
                    args.push(format!("_SYSTEMD_SLICE={COREDUMP_SLICE}"));
                }
            }
        }
        args
    }

    fn unit_fields(self) -> [&'static str; 2] {
        match self {
            Self::OomKill | Self::UnitFailure => ["UNIT", "USER_UNIT"],
            Self::Coredump => ["COREDUMP_UNIT", "COREDUMP_USER_UNIT"],
        }
    }

    /// Trusted fields the re-check needs; a returned entry lacking one is a defect.
    fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::OomKill | Self::UnitFailure => {
                &["MESSAGE_ID", "_UID", "_EXE", "__MONOTONIC_TIMESTAMP"]
            }
            Self::Coredump => &[
                "MESSAGE_ID",
                "_EXE",
                "_SYSTEMD_UNIT",
                "_SYSTEMD_SLICE",
                "__MONOTONIC_TIMESTAMP",
            ],
        }
    }

    /// Present fields that do not match the producer mark a decoy, not a defect.
    fn producer_matches(self, entry: &Entry) -> bool {
        let field = |name: &str| entry.get(name).map(String::as_str);
        if !field("MESSAGE_ID").is_some_and(|id| self.message_ids().contains(&id)) {
            return false;
        }
        match self {
            Self::OomKill | Self::UnitFailure => {
                field("_UID") == Some("0") && field("_EXE") == Some(SYSTEMD)
            }
            Self::Coredump => {
                field("_EXE") == Some(COREDUMP)
                    && field("_SYSTEMD_SLICE") == Some(COREDUMP_SLICE)
                    && field("_SYSTEMD_UNIT").is_some_and(|unit| {
                        unit.starts_with("systemd-coredump@")
                            && unit.ends_with(".service")
                            && validate_unit(unit).is_ok()
                    })
            }
        }
    }
}

/// Parse `CLASS[,CLASS...]`: closed names, no repetition, canonical order.
pub fn parse_classes(text: &str) -> io::Result<Vec<Class>> {
    let mut classes = BTreeSet::new();
    for name in text.split(',') {
        let class = Class::ALL
            .into_iter()
            .find(|class| class.name() == name)
            .ok_or_else(|| invalid_input("unknown journal event class"))?;
        if !classes.insert(class) {
            return Err(invalid_input("repeated journal event class"));
        }
    }
    Ok(classes.into_iter().collect())
}

/// The boot scope, named for what the journal can deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boot {
    /// The running boot, selected by a bare `--boot`, never offset 0.
    Current,
    /// `-b -1`: the most recent earlier boot still retained in the journal.
    PreviousRetained,
}

impl Boot {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "current" => Some(Self::Current),
            "previous-retained" => Some(Self::PreviousRetained),
            _ => None,
        }
    }

    pub fn report_name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::PreviousRetained => "previous_retained",
        }
    }

    fn args(self) -> &'static [&'static str] {
        match self {
            Self::Current => &["--boot"],
            Self::PreviousRetained => &["-b", "-1"],
        }
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Journal-wide unit names: every unit type, escapes allowed. Separate from
/// `systemd::validate_unit`, which stays service-only for service selection.
pub fn validate_unit(unit: &str) -> io::Result<()> {
    const SUFFIXES: [&str; 11] = [
        ".service",
        ".socket",
        ".device",
        ".mount",
        ".automount",
        ".swap",
        ".target",
        ".path",
        ".timer",
        ".slice",
        ".scope",
    ];
    let Some(suffix) = SUFFIXES.iter().find(|suffix| unit.ends_with(**suffix)) else {
        return Err(invalid_data("invalid unit type"));
    };
    if unit.len() > 255 || unit.len() == suffix.len() || unit.starts_with('-') {
        return Err(invalid_data("invalid unit name"));
    }
    let bytes = unit.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                if index + 3 >= bytes.len()
                    || bytes[index + 1] != b'x'
                    || !bytes[index + 2].is_ascii_hexdigit()
                    || !bytes[index + 3].is_ascii_hexdigit()
                {
                    return Err(invalid_data("invalid unit escape"));
                }
                index += 4;
            }
            byte if byte.is_ascii_alphanumeric() || b":_.-@".contains(&byte) => index += 1,
            _ => return Err(invalid_data("invalid unit name")),
        }
    }
    Ok(())
}

/// One export-format entry, holding only the kept fields.
pub type Entry = BTreeMap<String, String>;

/// Parse journalctl `-o export`. Only kept fields are stored; any field may
/// appear in output, but binary-encoded fields (a name line without `=`), an
/// unterminated entry or a repeated kept field make the whole output invalid.
pub fn parse_export(output: &[u8]) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut entry = Entry::new();
    let mut open = false;
    let mut rest = output;
    while !rest.is_empty() {
        let end = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| invalid_data("unterminated export line"))?;
        let line = &rest[..end];
        rest = &rest[end + 1..];
        if line.is_empty() {
            if !open {
                return Err(invalid_data("empty export entry"));
            }
            entries.push(std::mem::take(&mut entry));
            open = false;
            continue;
        }
        open = true;
        let separator = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| invalid_data("binary or malformed export field"))?;
        let (name, value) = (&line[..separator], &line[separator + 1..]);
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(invalid_data("invalid export field name"));
        }
        let name = std::str::from_utf8(name).map_err(|_| invalid_data("invalid field name"))?;
        if !KEPT.contains(&name) {
            continue;
        }
        if value.is_empty()
            || value.len() > 512
            || !value.iter().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid_data("invalid export field value"));
        }
        let value = String::from_utf8(value.to_vec()).map_err(|_| invalid_data("invalid value"))?;
        if entry.insert(name.to_owned(), value).is_some() {
            return Err(invalid_data("repeated export field"));
        }
    }
    if open {
        return Err(invalid_data("unterminated export entry"));
    }
    Ok(entries)
}

/// The evidence for one class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassEvidence {
    /// At least one producer-valid entry.
    Recorded {
        count: usize,
        truncated: bool,
        units: Vec<String>,
        units_truncated: bool,
        first_monotonic_us: Option<u64>,
        last_monotonic_us: u64,
    },
    /// No producer-valid entry, and the window was not full.
    None,
    /// The class cannot be determined.
    Unavailable(crate::collector::FailureReason),
    /// Not queried, because an earlier precondition already decided the report.
    NotQueried,
}

/// Apply producer binding, the window rule and the unit mapping to one
/// class's parsed entries. Pure; see ADR 0012 "Window and decoys".
pub fn evaluate_class(class: Class, entries: &[Entry]) -> ClassEvidence {
    use crate::collector::FailureReason::{LimitExceeded, MalformedData};
    let mut count = 0;
    let mut units = BTreeSet::new();
    let mut first = None;
    let mut last = 0;
    for entry in entries {
        if class
            .required_fields()
            .iter()
            .any(|field| !entry.contains_key(*field))
        {
            return ClassEvidence::Unavailable(MalformedData);
        }
        if !class.producer_matches(entry) {
            continue;
        }
        let Some(time) = entry["__MONOTONIC_TIMESTAMP"].parse::<u64>().ok() else {
            return ClassEvidence::Unavailable(MalformedData);
        };
        if let Some(unit) = class
            .unit_fields()
            .iter()
            .find_map(|field| entry.get(*field))
        {
            if validate_unit(unit).is_err() {
                return ClassEvidence::Unavailable(MalformedData);
            }
            units.insert(unit.clone());
        }
        count += 1;
        first = Some(first.map_or(time, |first: u64| first.min(time)));
        last = last.max(time);
    }
    let full = entries.len() >= WINDOW;
    if count == 0 {
        return if full {
            ClassEvidence::Unavailable(LimitExceeded)
        } else {
            ClassEvidence::None
        };
    }
    let units_truncated = units.len() > MAX_UNITS;
    ClassEvidence::Recorded {
        count: count.min(MAX_COUNT),
        // `-n` returns the latest entries; with a full window the true first was not seen.
        truncated: full,
        units: units.into_iter().take(MAX_UNITS).collect(),
        units_truncated,
        first_monotonic_us: if full { None } else { first },
        last_monotonic_us: last,
    }
}

/// What the running kernel's crash handler is, if `coredump` was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashHandler {
    SystemdCoredump,
    Other,
    /// The selected boot is not the running one; its handler is unknowable.
    UnknownForBoot,
}

impl CrashHandler {
    pub fn report_name(self) -> &'static str {
        match self {
            Self::SystemdCoredump => "systemd-coredump",
            Self::Other => "other",
            Self::UnknownForBoot => "unknown_for_boot",
        }
    }
}

/// Fixed outcome reasons; one enum fixes disposition and reason together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NoneRecorded,
    EventsRecorded,
    JournalNotVisible,
    JournalAccessIncomplete,
    CrashHandlerNotSystemdCoredump,
    CrashHandlerUnknownForBoot,
    EvidenceUnavailable,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoneRecorded => "none_recorded",
            Self::EventsRecorded => "events_recorded",
            Self::JournalNotVisible => "journal_not_visible",
            Self::JournalAccessIncomplete => "journal_access_incomplete",
            Self::CrashHandlerNotSystemdCoredump => "crash_handler_not_systemd_coredump",
            Self::CrashHandlerUnknownForBoot => "crash_handler_unknown_for_boot",
            Self::EvidenceUnavailable => "evidence_unavailable",
        }
    }

    pub fn outcome(self) -> crate::investigation::Outcome {
        use crate::investigation::Outcome;
        match self {
            Self::NoneRecorded => Outcome::Satisfied,
            Self::EventsRecorded => Outcome::NotSatisfied,
            _ => Outcome::Indeterminate,
        }
    }
}

/// Outcome precedence. Producer-valid events are conclusive; every route to
/// `none_recorded` requires visibility, complete access, no unavailable class
/// and, for `coredump`, a crash handler whose absence means something.
pub fn decide(
    visible: Option<bool>,
    access_complete: Option<bool>,
    classes: &[(Class, ClassEvidence)],
    crash_handler: Option<CrashHandler>,
) -> Reason {
    match visible {
        None => return Reason::EvidenceUnavailable,
        Some(false) => return Reason::JournalNotVisible,
        Some(true) => {}
    }
    if classes
        .iter()
        .any(|(_, evidence)| matches!(evidence, ClassEvidence::Recorded { .. }))
    {
        return Reason::EventsRecorded;
    }
    if classes.iter().any(|(_, evidence)| {
        matches!(
            evidence,
            ClassEvidence::Unavailable(_) | ClassEvidence::NotQueried
        )
    }) {
        return Reason::EvidenceUnavailable;
    }
    if classes.iter().any(|(class, _)| *class == Class::Coredump) {
        match crash_handler {
            Some(CrashHandler::SystemdCoredump) => {}
            Some(CrashHandler::UnknownForBoot) => return Reason::CrashHandlerUnknownForBoot,
            Some(CrashHandler::Other) | None => return Reason::CrashHandlerNotSystemdCoredump,
        }
    }
    if access_complete != Some(true) {
        return Reason::JournalAccessIncomplete;
    }
    Reason::NoneRecorded
}

/// Where collection looks. Production uses the fixed defaults.
pub struct Paths {
    pub journal_dirs: Vec<PathBuf>,
    pub proc_root: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            journal_dirs: vec!["/var/log/journal".into(), "/run/log/journal".into()],
            proc_root: "/proc".into(),
        }
    }
}

impl Paths {
    /// The paths the CLI uses. Test-support builds may redirect them to a
    /// fixture; release builds compile the override out.
    pub fn for_cli() -> Self {
        #[allow(unused_mut)]
        let mut paths = Self::default();
        #[cfg(feature = "test-support")]
        {
            if let Some(dirs) = std::env::var_os("MIRA_TEST_JOURNAL_DIRS") {
                paths.journal_dirs = std::env::split_paths(&dirs).collect();
            }
            if let Some(root) = std::env::var_os("MIRA_TEST_PROC_ROOT") {
                paths.proc_root = root.into();
            }
        }
        paths
    }
}

/// Open every system journal file read-only and nonblocking, without reading.
/// `Ok(true)` only when at least one exists and all of them open.
pub fn access_complete(journal_dirs: &[PathBuf]) -> io::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut examined = 0;
    let mut found = 0;
    for root in journal_dirs {
        let machines = match fs::read_dir(root) {
            Ok(machines) => machines,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Ok(false),
        };
        for machine in machines {
            let machine = machine?;
            examined += 1;
            if examined > MAX_DIR_ENTRIES {
                return Ok(false);
            }
            let name = machine.file_name();
            let is_machine_dir = name.len() == 32
                && name
                    .to_str()
                    .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_hexdigit()));
            if !is_machine_dir {
                continue;
            }
            let files = match fs::read_dir(machine.path()) {
                Ok(files) => files,
                Err(_) => return Ok(false),
            };
            for file in files {
                let file = file?;
                examined += 1;
                if examined > MAX_DIR_ENTRIES {
                    return Ok(false);
                }
                let name = file.file_name();
                let Some(name) = name.to_str() else { continue };
                let system = name == "system.journal"
                    || (name.starts_with("system@")
                        && (name.ends_with(".journal") || name.ends_with(".journal~")));
                if !system {
                    continue;
                }
                match OpenOptions::new()
                    .read(true)
                    .custom_flags(crate::signature::O_NONBLOCK)
                    .open(file.path())
                {
                    Ok(_) => found += 1,
                    // Rotated away between listing and opening.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Ok(false),
                }
            }
        }
    }
    Ok(found > 0)
}

/// The running kernel's crash handler, from a bounded procfs read.
pub fn crash_handler(proc_root: &Path) -> io::Result<CrashHandler> {
    let pattern = crate::collector::read_bounded(&proc_root.join("sys/kernel/core_pattern"), 4096)?;
    Ok(if pattern.starts_with(&format!("|{COREDUMP}")) {
        CrashHandler::SystemdCoredump
    } else {
        CrashHandler::Other
    })
}

fn journalctl() -> Command {
    // Test-support builds may redirect the tool to the native fixture; release
    // builds compile this branch out, so the fixed path cannot be overridden.
    #[cfg(feature = "test-support")]
    if let Some(path) = std::env::var_os("MIRA_TEST_JOURNALCTL") {
        return Command::new(path);
    }
    Command::new(JOURNALCTL)
}

fn run(args: &[String]) -> io::Result<(std::process::ExitStatus, Vec<u8>)> {
    let mut command = journalctl();
    command.args(args);
    run_bounded(&mut command, None, Stderr::Discard, TIMEOUT, MAX_OUTPUT)
}

fn base_args(boot: Boot) -> Vec<String> {
    let mut args: Vec<String> = ["--system", "--no-pager", "--quiet"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    args.extend(boot.args().iter().map(|arg| (*arg).to_owned()));
    args
}

/// The exact sentinel argv, text-free like the class queries.
pub fn sentinel_args(boot: Boot) -> Vec<String> {
    let mut args = base_args(boot);
    args.extend(
        ["-n", "1", "-o", "export", "--output-fields=_PID", "_PID=1"]
            .iter()
            .map(|arg| (*arg).to_owned()),
    );
    args
}

/// The exact per-class argv.
pub fn class_args(boot: Boot, class: Class) -> Vec<String> {
    let mut args = base_args(boot);
    args.extend(
        ["-o", "export", OUTPUT_FIELDS, "-n", "1001"]
            .iter()
            .map(|arg| (*arg).to_owned()),
    );
    args.extend(class.matches());
    args
}

/// `Some(true)` when a PID 1 entry is visible; `Some(false)` when journalctl
/// ran and found none (including an unavailable boot); `None` on tool failure.
fn sentinel(boot: Boot) -> Option<bool> {
    let (status, output) = run(&sentinel_args(boot)).ok()?;
    if !status.success() {
        return Some(false);
    }
    let entries = parse_export(&output).ok()?;
    Some(
        entries
            .iter()
            .any(|entry| entry.get("_PID").map(String::as_str) == Some("1")),
    )
}

fn query(boot: Boot, class: Class) -> ClassEvidence {
    use crate::collector::FailureReason;
    let (status, output) = match run(&class_args(boot, class)) {
        Ok(result) => result,
        Err(error) => return ClassEvidence::Unavailable(FailureReason::from_error(&error)),
    };
    if !status.success() {
        return ClassEvidence::Unavailable(FailureReason::BackendFailed);
    }
    match parse_export(&output) {
        Ok(entries) => evaluate_class(class, &entries),
        Err(_) => ClassEvidence::Unavailable(FailureReason::MalformedData),
    }
}

/// Everything one report binds together.
pub struct Collection {
    pub classes: Vec<(Class, ClassEvidence)>,
    pub boot: Boot,
    pub visible: Option<bool>,
    pub access_complete: Option<bool>,
    pub crash_handler: Option<CrashHandler>,
    pub reason: Reason,
}

/// Collect in the ADR's order: visibility first (for `previous-retained` the
/// current boot must be visible too), then access, then each class.
pub fn collect(classes: &[Class], boot: Boot, paths: &Paths) -> Collection {
    let mut visible = sentinel(Boot::Current);
    if boot == Boot::PreviousRetained && visible == Some(true) {
        visible = sentinel(boot);
    }
    let mut evidence: Vec<(Class, ClassEvidence)> = classes
        .iter()
        .map(|class| (*class, ClassEvidence::NotQueried))
        .collect();
    let mut access = None;
    let mut handler = None;
    if visible == Some(true) {
        access = access_complete(&paths.journal_dirs).ok();
        for (class, slot) in &mut evidence {
            *slot = query(boot, *class);
        }
        if classes.contains(&Class::Coredump) {
            handler = Some(match boot {
                Boot::PreviousRetained => CrashHandler::UnknownForBoot,
                Boot::Current => crash_handler(&paths.proc_root).unwrap_or(CrashHandler::Other),
            });
        }
    }
    let reason = decide(visible, access, &evidence, handler);
    Collection {
        classes: evidence,
        boot,
        visible,
        access_complete: access,
        crash_handler: handler,
        reason,
    }
}

/// A journal-events/v1 report. Private fields bind expectation, evidence and reason.
pub struct Report {
    absent: Vec<Class>,
    collection: Collection,
    recorded_unix_ms: Option<u128>,
    elapsed_ms: u128,
}

fn optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn class_json(class: Class, evidence: &ClassEvidence) -> String {
    use crate::evidence_json::quoted;
    let (status, count, truncated, units, units_truncated, first, last, failure) = match evidence {
        ClassEvidence::Recorded {
            count,
            truncated,
            units,
            units_truncated,
            first_monotonic_us,
            last_monotonic_us,
        } => (
            "recorded",
            count.to_string(),
            *truncated,
            units
                .iter()
                .map(|unit| quoted(unit))
                .collect::<Vec<_>>()
                .join(","),
            *units_truncated,
            optional(*first_monotonic_us),
            last_monotonic_us.to_string(),
            "null".to_owned(),
        ),
        ClassEvidence::None => (
            "none",
            "0".to_owned(),
            false,
            String::new(),
            false,
            "null".to_owned(),
            "null".to_owned(),
            "null".to_owned(),
        ),
        ClassEvidence::Unavailable(reason) => (
            "unavailable",
            "null".to_owned(),
            false,
            String::new(),
            false,
            "null".to_owned(),
            "null".to_owned(),
            quoted(reason.as_str()),
        ),
        ClassEvidence::NotQueried => (
            "not_queried",
            "null".to_owned(),
            false,
            String::new(),
            false,
            "null".to_owned(),
            "null".to_owned(),
            "null".to_owned(),
        ),
    };
    format!(
        "{{\"class\":{},\"status\":\"{status}\",\"count\":{count},\"truncated\":{truncated},\"units\":[{units}],\"units_truncated\":{units_truncated},\"first_monotonic_us\":{first},\"last_monotonic_us\":{last},\"failure_reason\":{failure}}}",
        quoted(class.name())
    )
}

impl Report {
    pub fn reason(&self) -> Reason {
        self.collection.reason
    }

    pub fn collection(&self) -> &Collection {
        &self.collection
    }

    pub fn to_json(&self) -> String {
        use crate::evidence_json::{quoted, timestamp};
        let collection = &self.collection;
        let absent = self
            .absent
            .iter()
            .map(|class| quoted(class.name()))
            .collect::<Vec<_>>()
            .join(",");
        let classes = collection
            .classes
            .iter()
            .map(|(class, evidence)| class_json(*class, evidence))
            .collect::<Vec<_>>()
            .join(",");
        let handler = collection.crash_handler.map_or_else(
            || "null".to_owned(),
            |handler| quoted(handler.report_name()),
        );
        format!(
            "{{\"investigation_version\":1,\"template\":\"journal-events/v1\",\"scope\":\"local/journal\",\"expectation\":{{\"absent\":[{absent}],\"boot\":{boot}}},\"assessment\":{{\"outcome\":{},\"reason\":{},\"evidence_ref\":\"#/evidence\"}},\"application_health\":\"not_assessed\",\"root_cause\":\"not_assessed\",\"evidence\":{{\"source\":\"journal/system\",\"boot\":{boot},\"recorded_unix_ms\":{},\"clock_trust\":\"unverified\",\"freshness\":\"unknown\",\"elapsed_ms\":{},\"journal_visible\":{},\"journal_access_complete\":{},\"crash_handler\":{handler},\"classes\":[{classes}]}}}}",
            quoted(self.reason().outcome().as_str()),
            quoted(self.reason().as_str()),
            timestamp(self.recorded_unix_ms),
            self.elapsed_ms,
            optional(collection.visible),
            optional(collection.access_complete),
            boot = quoted(collection.boot.report_name()),
        )
    }
}

/// Run the whole investigation and time it as one acquisition.
pub fn investigate(absent: &[Class], boot: Boot, paths: &Paths) -> Report {
    let start = std::time::Instant::now();
    let collection = collect(absent, boot, paths);
    Report {
        absent: absent.to_vec(),
        collection,
        recorded_unix_ms: crate::evidence::timestamp(),
        elapsed_ms: start.elapsed().as_millis(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::FailureReason;

    fn manager(id: &str, unit: Option<&str>, time: u64) -> Entry {
        let mut entry = Entry::new();
        entry.insert("MESSAGE_ID".into(), id.into());
        entry.insert("_UID".into(), "0".into());
        entry.insert("_EXE".into(), SYSTEMD.into());
        entry.insert("__MONOTONIC_TIMESTAMP".into(), time.to_string());
        if let Some(unit) = unit {
            entry.insert("UNIT".into(), unit.into());
        }
        entry
    }

    fn coredump(unit: &str, time: u64) -> Entry {
        let mut entry = Entry::new();
        entry.insert("MESSAGE_ID".into(), Class::Coredump.message_ids()[0].into());
        entry.insert("_UID".into(), "989".into());
        entry.insert("_EXE".into(), COREDUMP.into());
        entry.insert("_SYSTEMD_SLICE".into(), COREDUMP_SLICE.into());
        entry.insert(
            "_SYSTEMD_UNIT".into(),
            "systemd-coredump@0-1234-0.service".into(),
        );
        entry.insert("COREDUMP_UNIT".into(), unit.into());
        entry.insert("__MONOTONIC_TIMESTAMP".into(), time.to_string());
        entry
    }

    #[test]
    fn classes_are_closed_unrepeated_and_canonical() {
        assert_eq!(
            parse_classes("coredump,oom-kill").unwrap(),
            vec![Class::OomKill, Class::Coredump]
        );
        for invalid in [
            "",
            "oom",
            "OOM-KILL",
            "oom-kill,",
            ",oom-kill",
            "oom-kill,oom-kill",
            "watchdog",
            "oom-kill unit-failure",
        ] {
            assert!(parse_classes(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(Boot::from_name("current"), Some(Boot::Current));
        assert_eq!(
            Boot::from_name("previous-retained"),
            Some(Boot::PreviousRetained)
        );
        for invalid in ["", "previous", "0", "-1", "all"] {
            assert_eq!(Boot::from_name(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn exact_argv_never_uses_offset_zero_and_binds_producers() {
        assert_eq!(
            sentinel_args(Boot::Current),
            [
                "--system",
                "--no-pager",
                "--quiet",
                "--boot",
                "-n",
                "1",
                "-o",
                "export",
                "--output-fields=_PID",
                "_PID=1"
            ]
        );
        let previous = class_args(Boot::PreviousRetained, Class::UnitFailure);
        assert_eq!(&previous[3..5], ["-b", "-1"]);
        assert!(!previous.iter().any(|arg| arg == "0" || arg == "-b0"));
        assert_eq!(
            &previous[previous.len() - 7..],
            [
                "MESSAGE_ID=d9b373ed55a64feb8242e02dbe79a49c",
                "_UID=0",
                "_EXE=/usr/lib/systemd/systemd",
                "+",
                "MESSAGE_ID=be02cf6855d2428ba40df7e9d022f03d",
                "_UID=0",
                "_EXE=/usr/lib/systemd/systemd",
            ]
        );
        assert_eq!(
            Class::Coredump.matches(),
            [
                "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1",
                "_EXE=/usr/lib/systemd/systemd-coredump",
                r"_SYSTEMD_SLICE=system-systemd\x2dcoredump.slice",
            ]
        );
        assert!(class_args(Boot::Current, Class::Coredump).contains(&OUTPUT_FIELDS.to_owned()));
        assert!(OUTPUT_FIELDS.contains("_SYSTEMD_SLICE"));
        // The backtrace ID is never queried.
        assert!(!Class::ALL.iter().any(|class| {
            class
                .message_ids()
                .contains(&"1f4e0a44a88649939aaea34fc6da8c95")
        }));
    }

    #[test]
    fn journal_units_cover_every_type_but_stay_strict() {
        for valid in [
            "ssh.service",
            "home.mount",
            "session-3.scope",
            "dbus.socket",
            r"systemd-fsck@dev-disk-by\x2duuid-1.service",
            "user-1000.slice",
            "apt-daily.timer",
            "a.target",
        ] {
            assert!(validate_unit(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            ".service",
            "-x.service",
            "ssh",
            "ssh.serv",
            "a b.service",
            r"a\x2.service",
            "a/b.mount",
            "ssh.service\n",
            &format!("{}.service", "a".repeat(250)),
        ] {
            assert!(validate_unit(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn export_parsing_keeps_only_allowed_fields_and_rejects_binary_framing() {
        let text = b"__CURSOR=s=1;i=2\n__MONOTONIC_TIMESTAMP=42\nMESSAGE=private text\nMESSAGE_ID=d9b373ed55a64feb8242e02dbe79a49c\nUNIT=home.mount\n_BOOT_ID=e7\n\n";
        let entries = parse_export(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].contains_key("MESSAGE"));
        assert!(!entries[0].contains_key("__CURSOR"));
        assert_eq!(entries[0]["UNIT"], "home.mount");
        assert!(parse_export(b"").unwrap().is_empty());
        for invalid in [
            &b"MESSAGE\n\x05\x00\x00\x00\x00\x00\x00\x00hello\n\n"[..],
            b"UNIT=a.service\n",
            b"UNIT=a.service",
            b"\n",
            b"UNIT=a.service\nUNIT=b.service\n\n",
            b"unit=a.service\n\n",
            b"UNIT=\n\n",
            b"UNIT=a service\n\n",
            b"UNIT=caf\xc3\xa9.service\n\n",
        ] {
            assert!(parse_export(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn producer_binding_window_and_units() {
        let failed = Class::UnitFailure.message_ids()[0];
        assert_eq!(evaluate_class(Class::UnitFailure, &[]), ClassEvidence::None);
        let recorded = evaluate_class(
            Class::UnitFailure,
            &[
                manager(failed, Some("home.mount"), 50),
                manager(failed, Some("a.service"), 10),
            ],
        );
        assert_eq!(
            recorded,
            ClassEvidence::Recorded {
                count: 2,
                truncated: false,
                units: vec!["a.service".into(), "home.mount".into()],
                units_truncated: false,
                first_monotonic_us: Some(10),
                last_monotonic_us: 50,
            }
        );
        // Wrong origin is a decoy: excluded, never counted.
        let mut decoy = manager(failed, Some("forged.service"), 5);
        decoy.insert("_UID".into(), "33".into());
        assert_eq!(
            evaluate_class(Class::UnitFailure, std::slice::from_ref(&decoy)),
            ClassEvidence::None
        );
        // A missing re-check field is a defect, never skipped.
        let mut missing = manager(failed, None, 5);
        missing.remove("_EXE");
        assert_eq!(
            evaluate_class(Class::UnitFailure, &[missing]),
            ClassEvidence::Unavailable(FailureReason::MalformedData)
        );
        // A full window of decoys is "cannot tell"; one valid entry among them is conclusive.
        let decoys = vec![decoy; WINDOW];
        assert_eq!(
            evaluate_class(Class::UnitFailure, &decoys),
            ClassEvidence::Unavailable(FailureReason::LimitExceeded)
        );
        let mut mixed = decoys.clone();
        mixed[0] = manager(failed, Some("db.service"), 7);
        assert!(matches!(
            evaluate_class(Class::UnitFailure, &mixed),
            ClassEvidence::Recorded {
                count: 1,
                truncated: true,
                first_monotonic_us: None,
                ..
            }
        ));
        // Invalid unit from a valid producer is unavailable, not dropped.
        assert_eq!(
            evaluate_class(Class::UnitFailure, &[manager(failed, Some("bad unit"), 1)]),
            ClassEvidence::Unavailable(FailureReason::MalformedData)
        );
        // A full window of valid entries caps the count and drops the first time.
        let many: Vec<_> = (0..WINDOW as u64)
            .map(|time| manager(failed, Some("x.service"), time))
            .collect();
        assert!(matches!(
            evaluate_class(Class::UnitFailure, &many),
            ClassEvidence::Recorded {
                count: MAX_COUNT,
                truncated: true,
                first_monotonic_us: None,
                last_monotonic_us: 1000,
                ..
            }
        ));
        // Unit cap.
        let units: Vec<_> = (0..20)
            .map(|i| manager(failed, Some(&format!("u{i:02}.service")), i))
            .collect();
        assert!(matches!(
            evaluate_class(Class::UnitFailure, &units),
            ClassEvidence::Recorded { units_truncated: true, ref units, .. } if units.len() == MAX_UNITS
        ));
    }

    #[test]
    fn coredump_needs_its_cgroup_and_maps_its_own_unit_fields() {
        let valid = coredump("nginx.service", 9);
        assert!(matches!(
            evaluate_class(Class::Coredump, std::slice::from_ref(&valid)),
            ClassEvidence::Recorded { ref units, .. } if units == &["nginx.service".to_owned()]
        ));
        // A direct --backtrace invocation runs in the reporter's own cgroup.
        let mut backtrace = valid.clone();
        backtrace.insert("_SYSTEMD_UNIT".into(), "attacker.service".into());
        assert_eq!(
            evaluate_class(Class::Coredump, &[backtrace]),
            ClassEvidence::None
        );
        let mut wrong_slice = valid.clone();
        wrong_slice.insert("_SYSTEMD_SLICE".into(), "system.slice".into());
        assert_eq!(
            evaluate_class(Class::Coredump, &[wrong_slice]),
            ClassEvidence::None
        );
        // Manager unit fields are not coredump attribution.
        let mut manager_field = valid.clone();
        manager_field.remove("COREDUMP_UNIT");
        manager_field.insert("UNIT".into(), "other.service".into());
        assert!(matches!(
            evaluate_class(Class::Coredump, &[manager_field]),
            ClassEvidence::Recorded { ref units, .. } if units.is_empty()
        ));
        let mut missing_slice = valid;
        missing_slice.remove("_SYSTEMD_SLICE");
        assert_eq!(
            evaluate_class(Class::Coredump, &[missing_slice]),
            ClassEvidence::Unavailable(FailureReason::MalformedData)
        );
    }

    #[test]
    fn outcome_precedence_never_reaches_none_without_every_precondition() {
        use ClassEvidence::{None as Empty, NotQueried, Recorded, Unavailable};
        let recorded = Recorded {
            count: 1,
            truncated: false,
            units: vec![],
            units_truncated: false,
            first_monotonic_us: Some(1),
            last_monotonic_us: 1,
        };
        let oom = |evidence: ClassEvidence| vec![(Class::OomKill, evidence)];
        let with_core =
            |a: ClassEvidence, b: ClassEvidence| vec![(Class::OomKill, a), (Class::Coredump, b)];
        let sd = Some(CrashHandler::SystemdCoredump);
        for (visible, access, classes, handler, expected) in [
            (
                None,
                None,
                oom(NotQueried),
                None,
                Reason::EvidenceUnavailable,
            ),
            (
                Some(false),
                None,
                oom(NotQueried),
                None,
                Reason::JournalNotVisible,
            ),
            (
                Some(true),
                Some(true),
                oom(Empty),
                None,
                Reason::NoneRecorded,
            ),
            (
                Some(true),
                Some(false),
                oom(Empty),
                None,
                Reason::JournalAccessIncomplete,
            ),
            (
                Some(true),
                None,
                oom(Empty),
                None,
                Reason::JournalAccessIncomplete,
            ),
            // Recorded events stay conclusive even with incomplete access or another unavailable class.
            (
                Some(true),
                Some(false),
                oom(recorded.clone()),
                None,
                Reason::EventsRecorded,
            ),
            (
                Some(true),
                Some(true),
                with_core(recorded.clone(), Unavailable(FailureReason::Timeout)),
                sd,
                Reason::EventsRecorded,
            ),
            (
                Some(true),
                Some(true),
                oom(Unavailable(FailureReason::LimitExceeded)),
                None,
                Reason::EvidenceUnavailable,
            ),
            (
                Some(true),
                Some(true),
                with_core(Empty, Empty),
                sd,
                Reason::NoneRecorded,
            ),
            (
                Some(true),
                Some(true),
                with_core(Empty, Empty),
                Some(CrashHandler::Other),
                Reason::CrashHandlerNotSystemdCoredump,
            ),
            (
                Some(true),
                Some(true),
                with_core(Empty, Empty),
                None,
                Reason::CrashHandlerNotSystemdCoredump,
            ),
            (
                Some(true),
                Some(true),
                with_core(Empty, Empty),
                Some(CrashHandler::UnknownForBoot),
                Reason::CrashHandlerUnknownForBoot,
            ),
            (
                Some(true),
                Some(true),
                with_core(Empty, recorded.clone()),
                Some(CrashHandler::UnknownForBoot),
                Reason::EventsRecorded,
            ),
        ] {
            assert_eq!(
                decide(visible, access, &classes, handler),
                expected,
                "{visible:?} {access:?} {classes:?} {handler:?}"
            );
        }
        assert_eq!(Reason::NoneRecorded.outcome().exit_code(), 0);
        assert_eq!(Reason::EventsRecorded.outcome().exit_code(), 1);
        assert_eq!(Reason::JournalNotVisible.outcome().exit_code(), 3);
    }

    #[test]
    fn crash_handler_reads_only_the_pipe_target() {
        let root = std::env::temp_dir().join(format!("mira-core-pattern-{}", std::process::id()));
        fs::create_dir_all(root.join("sys/kernel")).unwrap();
        for (pattern, expected) in [
            (
                "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h\n",
                CrashHandler::SystemdCoredump,
            ),
            (
                "|/usr/share/apport/apport -p%p -s%s -c%c\n",
                CrashHandler::Other,
            ),
            ("core\n", CrashHandler::Other),
            ("/usr/lib/systemd/systemd-coredump\n", CrashHandler::Other),
        ] {
            fs::write(root.join("sys/kernel/core_pattern"), pattern).unwrap();
            assert_eq!(crash_handler(&root).unwrap(), expected, "{pattern}");
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
