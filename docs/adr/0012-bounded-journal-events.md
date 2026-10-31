# ADR 0012: bounded journal event evidence

Status: **Proposed**, 2026-10-31. Design only; no code, schema or CLI change is made by this record. Implementation would follow in a separate PR after review.

## Context

The primary use case is investigating host instability. The most direct evidence of what went wrong is usually in the system journal: a process killed by the kernel OOM killer, a unit that failed, a crash dump. MIRA reads none of it today, and the roadmap lists "bounded journal sources where justified" as remaining Phase 1 work. ADR 0001 requires an actual MIRA requirement and a separate decision before another infrastructure mechanism is added; this record is that decision.

The journal is also the riskiest source MIRA could add:

- **Disclosure.** Message text routinely contains paths, user names, host names, addresses, tokens and other application data. A log reader that exports text turns MIRA into an exfiltration tool for anything that was ever logged.
- **Silent partial access.** A user outside the `adm` or `systemd-journal` groups gets exit 0 from `journalctl` and simply sees fewer entries, without the system journal. Zero results then look exactly like "nothing happened".
- **Absence is weak evidence.** journald rate-limits, rotates and can lose messages, and volatile storage loses everything at reboot. No recorded event does not mean no event occurred.
- **Volume.** Journals hold millions of entries; any query must be bounded in time, entries and bytes.

Observed on the development host (systemd 259):
- **Message IDs:** stable catalog `MESSAGE_ID`s exist for the relevant events, for example `fe6faa94e7774663a0da52717891d8ef` (a unit process killed by the kernel OOM killer) and `d9b373ed55a64feb8242e02dbe79a49c` (unit failed).
- **Field limits:** `--output-fields` suppresses `MESSAGE` and other user fields. The cursor, timestamps and boot ID are always included.
- **Export format:** `-o export` prints `KEY=value` lines with a blank line between entries, which can be parsed without a JSON library.
- **Exit codes:** no matches gives exit 0, and an invalid boot gives exit 1.
- **Sentinel:** a PID 1 entry (`-b B -n 1 -o export --output-fields=_PID _PID=1`) was visible for both the current and the previous retained boot. `-n` returns the latest N matching entries in chronological order.
- **Boot selection:** a bare `--boot` (no argument) selected the running boot; its `_BOOT_ID` equalled `/proc/sys/kernel/random/boot_id`. `-b 0`, by contrast, is the last boot *in the journal*, which is a different boot whenever the running boot has no retained entries.
- **Origin:** all 19 genuine unit-failure entries carried trusted, journald-set fields `_EXE=/usr/lib/systemd/systemd` and `_UID=0`, from PID 1 (`_SYSTEMD_UNIT=init.scope`) or root's user manager (`user@0.service`). Match groups can be ORed with `+`, so each `MESSAGE_ID` can be required together with its producer's trusted fields.
- **Forgery probe:** an unprivileged user (UID 1000) logged an entry carrying the unit-failure `MESSAGE_ID` and `UNIT=forged.service`. It appeared in the user's own journal view but **not** under `--system`, because per-UID split storage keeps it out of the system journal. A service running as a system user (UID below 1000) does write to the system journal, so without origin binding it could forge events.
- **Boots:** the current boot had no such events, while earlier boots held 19 unit failures. That is why an earlier boot matters when the question is "why did it restart". `-b -1` means the previous boot *retained in the journal*, counted back from the end of the journal, not necessarily the machine's immediately preceding boot.

## Criteria

- **No message text, ever.** Classify events by structured catalog IDs, never by reading or matching free text.
- **Closed scope.** Fixed event classes, the current boot or the previous boot retained in the journal only, and no caller-supplied match expressions.
- **Absence only when visible.** Report "no events recorded" only when the query demonstrably saw the system journal for that boot; otherwise the result is indeterminate.
- **Bounded.** Bounded in time, entries per class and bytes, reusing the shared subprocess runner (ADR 0011). Use a fixed argv with no shell.
- **Unchanged surface.** No elevation, network, persistence or new crate. Existing outputs stay unchanged.

## Alternatives

| Option | Consequence |
|---|---|
| A. Status quo | No journal evidence; operators read logs by hand, outside MIRA's evidence contract |
| B. Export raw journal entries or `MESSAGE` text | Maximal detail, maximal disclosure; incompatible with the threat model |
| C. Match message text (for example "Out of memory") | Locale- and version-dependent, requires reading text, and invites caller-supplied patterns |
| D. Read journal files directly, or link libsystemd | The binary format is undocumented for consumers and changes; FFI needs `unsafe`, which is forbidden |
| E. `/dev/kmsg` or `dmesg` | Kernel ring buffer only, often restricted by `dmesg_restrict`, text-based and lost at reboot |
| F. **Closed event classes by catalog `MESSAGE_ID`, queried with a fixed `journalctl` argv, exporting counts, unit names and boot-relative times only** | Answers "was there an OOM kill, unit failure or crash in this boot" without any message text |

## Proposed decision (option F)

### Event classes

| Class | Catalog `MESSAGE_ID`s | Meaning |
|---|---|---|
| `oom-kill` | `fe6faa94e7774663a0da52717891d8ef`, `d989611b15e44c9dbf31e3c81256e4ed` | A unit's process was killed by the kernel OOM killer, or systemd-oomd killed processes in a unit |
| `unit-failure` | `d9b373ed55a64feb8242e02dbe79a49c`, `be02cf6855d2428ba40df7e9d022f03d` | A unit entered the failed state, or its start job failed |
| `coredump` | `fc2e22bc6ee647b6b90729ab34a250b1`, `1f4e0a44a88649939aaea34fc6da8c95` | A process dumped core, or terminated abnormally without a stored dump |

The kernel OOM class covers only kills that systemd attributes to a unit; an OOM kill outside any unit's cgroup is not visible without reading kernel message text, and this is documented rather than worked around.

### Command

```sh
mira investigate journal-events --absent CLASS[,CLASS...] [--boot current|previous-retained] [--json]
```

The question is an expectation, like the other templates: **were none of these event classes recorded in this boot?**

- CLASS is from the closed set above, given without repetition. Boot selection never uses offset 0:
  - `--boot current` (the default) passes a bare `--boot`, which journalctl resolves to the running boot itself. If the running boot has no retained entries, the sentinel finds nothing, and the result is indeterminate rather than an older boot labelled `current`.
  - `--boot previous-retained` passes `-b -1`, the most recent earlier boot that the journal still holds. Offsets count back from the end of the journal, so `-1` is the boot before the running one only if the running boot is itself retained. MIRA therefore requires a visible **current-boot** sentinel (bare `--boot`) before it runs any `-b -1` query, and is indeterminate otherwise.
  - If the boot immediately preceding the running one was never persisted, for example on volatile storage or after a journal loss, `-b -1` still selects an older retained boot. A boot that left no entries is indistinguishable from a powered-off interval, so the option and the report name the scope exactly, `previous-retained`, never "previous boot", and the guide states the limitation. Binding to the actual predecessor would need independent evidence and is out of scope.
- **Visibility sentinel.** First run `/usr/bin/journalctl --system --no-pager --quiet BOOT -n 1 -o export --output-fields=_PID _PID=1`, where BOOT is a bare `--boot` or `-b -1` as above, with the same export format and field allowlist discipline as the class queries, so no message text is read even for the sentinel. MIRA only counts the entries returned. systemd as PID 1 always logs during boot, so at least one entry must be visible. If none is, MIRA cannot see the system journal for that boot: the caller lacks journal access, the boot was not persisted, the journal was rotated away, or PID 1 is not systemd. The outcome is then indeterminate (`journal_not_visible`), never satisfied.
- **Per-class query.** Then query, per class, `/usr/bin/journalctl --system --no-pager --quiet BOOT -o export --output-fields=MESSAGE_ID,UNIT,USER_UNIT,COREDUMP_UNIT,COREDUMP_USER_UNIT,_UID,_EXE,_SYSTEMD_UNIT -n 1001`. The matches are that class's `MESSAGE_ID`s, each **bound to its actual producer's journald-set fields** and ORed with `+`. Those fields are set by journald from kernel credentials and the cgroup, not by the client:

  | `MESSAGE_ID` | Actual producer (systemd 259) | Query binding | Parser re-check |
  |---|---|---|---|
  | `fe6faa94…` (kernel OOM in unit), `d989611b…` (systemd-oomd kill), `d9b373ed…` (unit failed), `be02cf68…` (start job failed) | the systemd **manager** (PID 1 or root's user manager), via `log_unit_struct()`. The oomd kill message is also logged by the manager, not by systemd-oomd | `_UID=0 _EXE=/usr/lib/systemd/systemd` | same |
  | `fc2e22bc…`, `1f4e0a44…` (core dump) | the `systemd-coredump@….service` instance, **after it has dropped privileges** to the `systemd-coredump` account or the crashing user | `_EXE=/usr/lib/systemd/systemd-coredump` | `_SYSTEMD_UNIT` is a `systemd-coredump@<instance>.service` unit; entries that fail this are excluded and never counted |

  **Why these fields.** `_EXE` alone is not enough: a lower-privileged service can execute an allowed binary with injected code (for example through the dynamic loader), and `/proc/self/exe` still names the allowed path. The binding therefore pairs `_EXE` with either `_UID=0`, which only root has and root is outside this boundary, or the cgroup-derived `_SYSTEMD_UNIT`. Joining another unit's cgroup requires privilege.

  **Flooding.** A forger who passes `_EXE` but not the parser check can still fill the result window. If a class query returns the full 1001 entries, the class is indeterminate (`evidence_unavailable`, `limit_exceeded`), because genuine entries may have been pushed out. Forgery can therefore cause "cannot tell", never a false `none_recorded` or a false `events_recorded`.

  For example, `unit-failure` is `MESSAGE_ID=d9b3… _UID=0 _EXE=/usr/lib/systemd/systemd + MESSAGE_ID=be02… _UID=0 _EXE=/usr/lib/systemd/systemd`. All argument values are constants except the closed boot selector. The executable paths are Ubuntu 26.04's merged-`/usr` locations, and each producer binding is confirmed against genuine entries during implementation: a manager-origin oomd kill, a system-service crash handled by systemd-coredump, and a manager unit failure. A distribution with other paths needs its own reviewed constants, not a pattern. Root, or anyone who can replace the systemd binaries or journal files, can still forge; that is outside this boundary.
- **Crash-handler precondition for `coredump`.** systemd-coredump records crashes only when it is the kernel's crash handler. Ubuntu installs apport by default, and `systemd-coredump` is not installed on the development host. MIRA therefore reads `/proc/sys/kernel/core_pattern` (bounded, like the other procfs sources), but that file describes only the **running** kernel's handler. The rule is asymmetric:
  - **Recorded crashes always count.** Genuine, producer-bound crash entries are `events_recorded` for any boot, whatever the current handler.
  - **Absence in the current boot** is `none_recorded` only when `core_pattern` pipes to `/usr/lib/systemd/systemd-coredump`; otherwise the class is indeterminate (`crash_handler_not_systemd_coredump`). A handler change during the running boot, for example installing systemd-coredump after some crashes went to apport, is not detected. The guide states this remaining risk.
  - **Absence in a `previous-retained` boot** is always indeterminate (`crash_handler_unknown_for_boot`). The handler that boot used cannot be established from the running system, so zero entries there say nothing. Crashes of processes run by ordinary users are stored in their own per-UID journals and are not part of `--system`; the class covers system-service crashes only, and the guide says so.
- **Parsing.** MIRA reads only `MESSAGE_ID`, `__MONOTONIC_TIMESTAMP`, the trusted `_UID`, `_EXE` and `_SYSTEMD_UNIT` it re-checks, and the class's unit fields, mapped per class:

  | Class | Unit fields, in order of preference |
  |---|---|
  | `oom-kill`, `unit-failure` | `UNIT`, then `USER_UNIT` (manager-generated messages about a unit) |
  | `coredump` | `COREDUMP_UNIT`, then `COREDUMP_USER_UNIT` (the crashed process's unit, per systemd-coredump) |

  A unit field from the other class's mapping is ignored. Unit values are checked by a **separate, journal-wide unit-name validator**: at most 255 bytes, characters `A-Za-z0-9:_.-@` and `\xHH` escapes, and a suffix from the closed set `.service`, `.socket`, `.device`, `.mount`, `.automount`, `.swap`, `.target`, `.path`, `.timer`, `.slice`, `.scope`. The existing `systemd::validate_unit` stays unchanged and service-only, because it guards the `service` and `service-active` scope. With origin binding, an entry with an invalid unit can only come from a trusted producer and should not occur; if it does, the evidence is unavailable rather than silently dropped. The exact field each catalog message carries, including systemd-oomd's, is confirmed against real entries during implementation. Binary-encoded export fields, unknown message IDs among the results, and malformed lines make the evidence unavailable.

| Observation | Outcome | Reason | Exit |
|---|---|---|---|
| Sentinel visible; every selected class has zero entries | satisfied | none_recorded | 0 |
| Sentinel visible; any selected class has at least one entry | not_satisfied | events_recorded | 1 |
| Sentinel not visible | indeterminate | journal_not_visible | 3 |
| journalctl missing, failing, timing out, oversized or malformed | indeterminate | evidence_unavailable | 3 |
| `coredump` selected, no crash entries, and the running crash handler is not systemd-coredump | indeterminate | crash_handler_not_systemd_coredump | 3 |
| `coredump` selected for `previous-retained`, with no crash entries | indeterminate | crash_handler_unknown_for_boot | 3 |
| Unknown class, repetition, bad boot selector, malformed invocation | no report | usage | 2 |

### Evidence exported (and nothing else)

Per selected class:
- `count`, capped at 1000, with `truncated: true` beyond that
- `units`: up to 16 distinct, sorted unit names that pass the journal-wide unit-name validator, with `units_truncated` when more exist
- `first_monotonic_us` / `last_monotonic_us`: boot-relative times of the first and last entry. `-n` returns the *latest* entries, so when a class is truncated the true first entry was not seen, and `first_monotonic_us` is null rather than misleading

Plus:
- `boot`: `current` or `previous_retained`
- `journal_visible`: whether the sentinel was seen
- the evidence-v2 envelope: source `journal/system`, an unverified recording time, unknown freshness, elapsed time and a fixed failure reason

The following are deliberately **not** exported:
- message text
- PIDs, UIDs, command lines and environment
- core dump executable names, paths or signals
- host names
- cursors, sequence numbers and the boot ID (ADR 0010 keeps the boot ID opt-in)

## Semantics and limits

- **No recorded events is not no events.** journald rate limits, storage limits, rotation, volatile storage and lost messages all hide events. The reason is `none_recorded`, never "healthy" or "no failures".
- **Unit failures include intended ones.** A unit that is designed to fail, or was stopped by an administrator in a way that marks it failed, counts; the template does not judge intent.
- **Previous boot depends on persistence.** It needs persistent journal storage and enough retention. Otherwise the sentinel fails and the result is indeterminate.
- **Unauthenticated source.** The journal is TB2 input. Origin binding to journald-set `_UID`, `_EXE` and, for core dumps, the cgroup-derived `_SYSTEMD_UNIT` stops unprivileged users (already excluded from `--system` by per-UID storage) and system services that are not the expected executables from forging these events. Root, or anyone who can replace the systemd binaries or journal files, can still forge or delete entries. Counts are reported observations, not proof.
- **Boot-relative times are reported values.** The monotonic times come from the journal entries themselves.

## Contract, trust and validation

- **Schema:** a separate journal-events-v1 report schema, with the closed classes and units syntax, and binding of reason to outcome and visibility to reason. It also enforces the absence of message, PID and cmdline fields.
- **Validator:** an independent validator re-derives the outcome from counts and visibility. On a host with journal access it compares the CLI's counts with its own direct `journalctl` export query.
- **Fixture:** the test-support fixture gains `journalctl` modes that check the exact argv. They also emit adversarial output: binary-encoded fields, unknown IDs, oversized output, more than 1001 entries, malformed lines, invalid unit names, and missing or present sentinels.
- **Deadline:** each `journalctl` call has a fixed, bounded deadline, through the shared runner.

## Trust, privacy and failure analysis

- **Disclosure** is the main risk. Bounded field selection (`--output-fields`) and a parser that ignores every field but the timestamp, message ID and class unit fields keep text out even if `journalctl` returned more. Unit names can reveal what runs on a host; they are bounded, validated and part of a report the operator explicitly requested.
- **Partial access** is handled by the sentinel. This is more reliable than inspecting group membership, which ACLs, containers and future journald policies can change.
- **Execution boundary.** A third fixed-argv tool (after `systemctl` and `ssh-keygen`) runs under the same runner and test-only override pattern, with the override compiled out of release builds.
- **Resource use.** Each class query returns at most 1001 entries of four short fields. With three classes plus the sentinel, a report costs at most four bounded queries.

## Acceptance for implementation

- **Native fixture tests:** every outcome row, each class alone and combined, current and previous-retained boot, a retention gap (the fixture serves an older boot for `-b -1`, and the report must still say `previous_retained`), a running boot with no retained entries while an older boot exists (`current` must be indeterminate, never satisfied from the older boot, and `previous-retained` must not run), wrong-origin entries: a matching `MESSAGE_ID` with another `_UID` or `_EXE` must be excluded by the query and refused by the parser, and a core-dump entry with the right `_EXE` but another `_SYSTEMD_UNIT` must not be counted. Also: a full 1001-entry window is indeterminate; genuine-shape entries for a manager-origin oomd kill and a privilege-dropped systemd-coredump crash are counted; a non-systemd-coredump `core_pattern` makes an empty current-boot `coredump` indeterminate; a handler change between boots (apport then, systemd-coredump now) keeps an empty `previous-retained` `coredump` indeterminate, while genuine historical crash entries still count; non-service units (`.mount`, `.scope`, `.socket` and an escaped template instance) reported correctly, the 1000/1001 cap, unit cap and syntax, and binary-field, unknown-ID, malformed, oversized, timeout, missing-tool and argv-mismatch cases. The exact argv is checked for the sentinel query as well as the class queries.
- **Parser unit tests** on export framing.
- **Frozen JSON** for one report.
- **Schema fixtures** with semantic-only cases.
- **Live comparison** against direct `journalctl` on both native CI runners, which have systemd and journal access.
- **Packaging:** the guide and schema are packaged, and `Suggests` already includes `systemd`.

## Consequences and rollback

Blast radius: one opt-in investigation template, its schema, guide, tests and validator. Existing commands and formats are unchanged. Revert the template as a unit. No operational state requires rollback.

## Open questions for review

1. **Shape:** an expectation template (`journal-events --absent ...`, proposed), or an observation-only command that just reports counts?
2. **Classes:** are `oom-kill`, `unit-failure` and `coredump` the right first set? Watchdog failures (`375ac151…`, `8739789e…`) are a candidate fourth.
3. **Detail:** export unit names (proposed, bounded and validated) or counts only? Should `coredump` include the crashing executable's short name (`COREDUMP_COMM`), which is useful but more revealing?
4. **Boot scope:** current and previous-retained boot (proposed), or current only? `-b -1` cannot guarantee the immediately preceding boot, so the scope is named for what it is.

## Primary references

- [systemd catalog message IDs](https://github.com/systemd/systemd/blob/main/catalog/systemd.catalog.in)
- [journalctl(1): -b, -o export, --output-fields](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- [Journal export format](https://systemd.io/JOURNAL_EXPORT_FORMATS/)
- [journald.conf(5): Storage, RateLimitBurst](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html)
