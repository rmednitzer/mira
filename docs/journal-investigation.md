# Journal events investigation

```sh
mira investigate journal-events --absent oom-kill,unit-failure
mira investigate journal-events --absent oom-kill,unit-failure,coredump --boot previous-retained --json
```

The question is: **were none of these events recorded in this boot?** It is the quickest check after an unexpected restart or a wave of failures, and it never reads log message text. See [ADR 0012](adr/0012-bounded-journal-events.md) for the full design and the review findings that shaped it.

## Event classes

| Class | Recorded when |
|---|---|
| `oom-kill` | the systemd manager logged that a unit's process was killed by the kernel OOM killer, or by systemd-oomd |
| `unit-failure` | the systemd manager logged that a unit failed or its start job failed |
| `coredump` | socket-activated systemd-coredump processed a core dump (backtrace reports are excluded) |

Events are selected only by systemd catalog `MESSAGE_ID`s, and each is bound to its actual producer's journald-set fields:
- **Manager messages** must come from `/usr/lib/systemd/systemd` running as UID 0.
- **Core dumps** must come from `/usr/lib/systemd/systemd-coredump` in its own cgroup slice and unit.

An entry carrying the right ID from another process is a decoy and is not counted. Root can still forge entries, so treat the journal as untrusted input.

## Options

- `--absent` takes one or more classes, comma-separated, without repetition.
- `--boot current` (the default) is the running boot itself, selected with a bare `--boot`, never offset 0.
- `--boot previous-retained` is the most recent earlier boot **still retained in the journal**. If the boot just before this one was never persisted, this is an older one; the journal cannot tell the difference. It runs only when the running boot's journal is visible.
- Anything else exits 2 before `journalctl` runs.

## Outcomes

| Reason | Outcome | Exit | Meaning |
|---|---|---|---|
| none_recorded | satisfied | 0 | journal visible, every system journal file openable, and no selected event recorded |
| events_recorded | not_satisfied | 1 | at least one producer-valid event; this is conclusive even if other checks failed |
| journal_not_visible | indeterminate | 3 | no PID 1 entry visible for the boot: no journal access, the boot was not persisted, rotation, or PID 1 is not systemd |
| journal_access_incomplete | indeterminate | 3 | some system journal file cannot be opened, so events could be hidden |
| crash_handler_not_systemd_coredump | indeterminate | 3 | `coredump` selected and empty, but the running crash handler is not systemd-coredump. The pipe's executable must be exactly `/usr/lib/systemd/systemd-coredump`; a wrapper sharing that prefix does not count. Ubuntu uses apport by default |
| crash_handler_unknown_for_boot | indeterminate | 3 | `coredump` selected and empty for `previous-retained`; that boot's handler cannot be established |
| evidence_unavailable | indeterminate | 3 | `journalctl` missing, failing, timing out, oversized or malformed, or a full window of 1001 entries with no producer-valid one |

**No recorded events does not mean no events.** journald rate limits, rotation, storage limits and lost messages all hide events. A unit that is designed to fail still counts. A handler change during the running boot is not detected. Crashes of processes run by ordinary users are stored in their own journals and are outside this check.

## What the report contains

`--json` emits one `journal-events/v1` report. Per class it holds:
- `count`, capped at 1000, plus `truncated`
- up to 16 validated unit names, which may be of any unit type, including the root mount `-.mount` and root slice `-.slice`
- the first and last event times in microseconds since boot; the first is null when the window was full, because `journalctl -n` returns the latest entries

The evidence also records whether the journal was visible, whether every system journal file was openable, and the crash handler when `coredump` was selected.

The report never contains message text, PIDs, UIDs, command lines, crashed executable names, journal cursors or the boot ID. Both `journalctl` calls request only the needed fields (`--output-fields`), and MIRA parses only those.

The [schema](../schemas/journal-events-v1.schema.json) checks structure, vocabularies and unit syntax. Consumers must also re-derive the reason from the evidence, as `scripts/validate_journal_investigation.py` does. The report can be [signed](signatures.md) like any investigation report.

## Access

Members of the `adm` or `systemd-journal` groups can read the system journal. Without that access, `journalctl` returns success with fewer entries; MIRA detects this and reports `journal_not_visible` or `journal_access_incomplete` instead of a false all-clear. MIRA never asks for elevated privileges.
