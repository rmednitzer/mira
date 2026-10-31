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
- **Sentinel:** a PID 1 entry (`-b B -n 1 _PID=1`) was visible for both the current and the previous boot. `-n` returns the latest N matching entries in chronological order.
- **Boots:** the current boot had no such events, while earlier boots held 19 unit failures. That is why the previous boot matters when the question is "why did it restart".

## Criteria

- **No message text, ever.** Classify events by structured catalog IDs, never by reading or matching free text.
- **Closed scope.** Fixed event classes, the current or the immediately previous boot only, and no caller-supplied match expressions.
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
mira investigate journal-events --absent CLASS[,CLASS...] [--boot current|previous] [--json]
```

The question is an expectation, like the other templates: **were none of these event classes recorded in this boot?**

- CLASS is from the closed set above, given without repetition. `--boot` defaults to `current` (`-b 0`); `previous` is `-b -1`.
- **Visibility sentinel.** First query `-b B -n 1 _PID=1`. systemd as PID 1 always logs during boot, so at least one entry must be visible. If none is, MIRA cannot see the system journal for that boot: the caller lacks journal access, the boot was not persisted, the journal was rotated away, or PID 1 is not systemd. The outcome is then indeterminate (`journal_not_visible`), never satisfied.
- **Per-class query.** Then query, per class, `/usr/bin/journalctl --system --no-pager --quiet -b B -o export --output-fields=MESSAGE_ID,UNIT,USER_UNIT -n 1001` with that class's `MESSAGE_ID=` matches. All argument values are constants except the closed boot selector.
- **Parsing.** MIRA reads only `MESSAGE_ID`, `UNIT`/`USER_UNIT` and `__MONOTONIC_TIMESTAMP`. Binary-encoded export fields, unknown message IDs among the results, and malformed lines make the evidence unavailable.

| Observation | Outcome | Reason | Exit |
|---|---|---|---|
| Sentinel visible; every selected class has zero entries | satisfied | none_recorded | 0 |
| Sentinel visible; any selected class has at least one entry | not_satisfied | events_recorded | 1 |
| Sentinel not visible | indeterminate | journal_not_visible | 3 |
| journalctl missing, failing, timing out, oversized or malformed | indeterminate | evidence_unavailable | 3 |
| Unknown class, repetition, bad boot selector, malformed invocation | no report | usage | 2 |

### Evidence exported (and nothing else)

Per selected class:
- `count`, capped at 1000, with `truncated: true` beyond that
- `units`: up to 16 distinct, sorted unit names that pass the existing unit-name syntax check, with `units_truncated` when more exist
- `first_monotonic_us` / `last_monotonic_us`: boot-relative times of the first and last entry. `-n` returns the *latest* entries, so when a class is truncated the true first entry was not seen, and `first_monotonic_us` is null rather than misleading

Plus:
- `boot`: `current` or `previous`
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
- **Unauthenticated source.** The journal is TB2 input. A privileged party can write forged entries with these message IDs, or delete real ones. Counts are reported observations, not proof.
- **Boot-relative times are reported values.** The monotonic times come from the journal entries themselves.

## Contract, trust and validation

- **Schema:** a separate journal-events-v1 report schema, with the closed classes and units syntax, and binding of reason to outcome and visibility to reason. It also enforces the absence of message, PID and cmdline fields.
- **Validator:** an independent validator re-derives the outcome from counts and visibility. On a host with journal access it compares the CLI's counts with its own direct `journalctl` export query.
- **Fixture:** the test-support fixture gains `journalctl` modes that check the exact argv. They also emit adversarial output: binary-encoded fields, unknown IDs, oversized output, more than 1001 entries, malformed lines, invalid unit names, and missing or present sentinels.
- **Deadline:** each `journalctl` call has a fixed, bounded deadline, through the shared runner.

## Trust, privacy and failure analysis

- **Disclosure** is the main risk. Bounded field selection (`--output-fields`) and a parser that ignores every field but four keep text out even if `journalctl` returned more. Unit names can reveal what runs on a host; they are bounded, validated and part of a report the operator explicitly requested.
- **Partial access** is handled by the sentinel. This is more reliable than inspecting group membership, which ACLs, containers and future journald policies can change.
- **Execution boundary.** A third fixed-argv tool (after `systemctl` and `ssh-keygen`) runs under the same runner and test-only override pattern, with the override compiled out of release builds.
- **Resource use.** Each class query returns at most 1001 entries of four short fields. With three classes plus the sentinel, a report costs at most four bounded queries.

## Acceptance for implementation

- **Native fixture tests:** every outcome row, each class alone and combined, current and previous boot, the 1000/1001 cap, unit cap and syntax, and binary-field, unknown-ID, malformed, oversized, timeout, missing-tool and argv-mismatch cases.
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
4. **Boot scope:** current and previous boot (proposed), or current only?

## Primary references

- [systemd catalog message IDs](https://github.com/systemd/systemd/blob/main/catalog/systemd.catalog.in)
- [journalctl(1): -b, -o export, --output-fields](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- [Journal export format](https://systemd.io/JOURNAL_EXPORT_FORMATS/)
- [journald.conf(5): Storage, RateLimitBurst](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html)
