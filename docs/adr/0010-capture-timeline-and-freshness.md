# ADR 0010: capture timeline, boot binding and freshness vocabulary

Status: **Accepted**, 2026-10-31 (proposed and reviewed the same day). **Implemented in three reviewed stages:** stage 1 timeline (capture-v2), stage 2 opt-in boot binding, stage 3 comparison-v3. The boot samples are taken inside the monotonic window, at its edges, and are not timeline entries. Windows that touch or overlap at centisecond resolution are reported as `overlapping`, never ordered. `--max-window-ms` requires two capture-v2 inputs.

## Context

Every evidence record says `freshness: "unknown"` and `clock_trust: "unverified"`, and the comparator says `clock_order: "unverified"`. That is honest, but it hides three different questions behind one word:

| Question | Example | Answerable locally today? |
|---|---|---|
| Q1. **Intra-capture skew:** how far apart in time were the sources of one capture read? | Was memory read 5 ms or 5 s after PSI? | No. Each record has an unverified wall-clock completion and its own monotonic `elapsed_ms`, but no shared reference |
| Q2. **Inter-capture order and interval:** was capture A taken before capture B, how far apart, and was there a reboot between them? | "before.json" and "after.json" from an incident | No. Labels state intent only, and wall clocks can step |
| Q3. **Age at consumption:** how old is this capture now? | Is this evidence from today? | No, and not without a trusted clock |

What MIRA records now (ADR 0002): per source, the wall-clock time immediately after acquisition, the monotonic duration of that acquisition, and a fixed failure reason. The capture has no start or end, sources have no common monotonic reference, and nothing ties a capture to a boot. `docs/captures.md` promises that no hostname, machine ID or boot ID is collected automatically.

Q1 can be answered within one process from its own monotonic clock. Q2 can be answered for two captures from the **same boot**, using the kernel's per-boot identifier and boot-relative time, and otherwise only by unverified wall clocks. Q3 needs a trusted time source: network time with authentication, or attested hardware time. That is a different trust boundary.

## Criteria

- Answer Q1 and same-boot Q2 with evidence MIRA can actually observe, and say plainly when neither applies.
- Keep evidence-v1/v2 records, capture-v1 and comparison-v1/v2 byte-for-byte unchanged by default.
- No new network path, privileged source, command, daemon, persistence or runtime dependency. `unsafe` stays forbidden.
- Correlatable identifiers (the boot ID) are collected only on explicit operator request, consistent with the existing capture privacy promise.
- Reported times and identifiers remain unauthenticated (TB2); vocabulary must not imply otherwise.

## Alternatives

| Option | Consequence |
|---|---|
| A. Status quo | Honest but uninformative; operators fall back on wall-clock timestamps that the contract tells them not to trust |
| B. Trust wall clocks for ordering | Simple, but NTP steps, manual changes and VM restores silently reorder evidence |
| C. Per-record monotonic offsets in a new evidence-v3 | Changes the shared record contract that inspect, capture and six investigation reports embed; disproportionate |
| D. **Capture-level timeline plus opt-in boot binding (capture-v2), and a comparator that uses them** | Answers Q1 always and Q2 for same-boot captures; additive; records unchanged |
| E. Authenticated network time (NTS, Roughtime) or attested time (TPM) | Answers Q3, but adds network or hardware trust boundaries, credentials and availability dependencies. Separate decision |
| F. Bind to `/etc/machine-id` instead of boot ID | A stable host identifier is far more linkable, does not detect reboots, and is really host identity, which is a separate roadmap item |
| G. Always collect the boot ID in capture-v2 | Contradicts the existing privacy promise; rejected in favour of an explicit flag |

## Decision (option D)

### 1. capture-v2 with a collection timeline (answers Q1)

`mira capture LABEL [--pressure] --timeline` emits **capture-v2**. Without `--timeline`, capture-v1 is emitted exactly as today. The records array is unchanged: the same evidence-v2 records in the same order. Two capture-level members are added:

```json
"collection": {
  "monotonic_window_ms": 7,
  "started_unix_ms": 1793460822111,
  "ended_unix_ms": 1793460822118,
  "wall_clock": "consistent",
  "boot": {"binding": "not_requested"}
},
"timeline": [
  {"source": "/proc/meminfo", "offset_ms": 0, "elapsed_ms": 0},
  {"source": "/proc/uptime", "offset_ms": 1, "elapsed_ms": 0}
]
```

- One monotonic reference (`std::time::Instant`) is taken immediately before the first acquisition. Rust documents `Instant` as CLOCK_MONOTONIC on Linux; an earlier switch to CLOCK_BOOTTIME was reverted. The implementation must confirm the clock for the pinned toolchain, because the suspend semantics below depend on it. `offset_ms` is each source's acquisition start relative to it. `monotonic_window_ms` runs from that reference to the end of the last acquisition, so every source was read within that window, as measured by MIRA's own clock.
- `started_unix_ms` and `ended_unix_ms` are unverified wall-clock readings at the window edges, either of which may be null.
- `wall_clock` is `consistent` when both readings exist, `ended >= started`, and the wall delta differs from the monotonic window by at most max(50 ms, 1% of the window). It is `stepped_or_suspended` otherwise, and `unknown` when a reading is missing. A suspend during capture also triggers it, because CLOCK_MONOTONIC excludes suspend; the name says so. It detects changes only within the capture, not before.
- Timeline entries are in record order and name exactly the record sources. The offsets are milliseconds and non-decreasing.

### 2. Opt-in boot binding (enables same-boot Q2)

`--bind-boot` implies `--timeline` (giving both is equivalent) and additionally reads two existing-class procfs sources at both window edges:

- `/proc/sys/kernel/random/boot_id`: a kernel-generated random UUID that changes on every boot. Bounded to 64 bytes; it must be a lowercase 8-4-4-4-12 hex UUID with a trailing newline. Readable without privilege.
- `/proc/uptime`, retained at centisecond resolution (the kernel prints exactly two decimals). The existing whole-second uptime record is unchanged.

```json
"boot": {
  "binding": "observed",
  "boot_id": "e740207d-b13a-48dd-8e9d-595a950d6930",
  "started_uptime_cs": 1102523,
  "ended_uptime_cs": 1102524
}
```

`binding` is `observed` only when both boot ID reads succeed and are equal, and both uptime reads succeed with `ended >= started`. Otherwise it is `unavailable`, with a fixed `failure_reason` and no partial values. A boot ID change during the window is reported as `unavailable` with `malformed_data`, never as a valid binding. Boot binding failure never fails the capture or changes `all_available`, which keeps its meaning for records.

### 3. Comparator use (comparison-v3 for two capture-v2 inputs)

When both inputs are capture-v2, the comparator emits comparison-v3. Value outcomes are unchanged, and a capture-level `timing` member is added:

| Boot evidence | `boot_relation` | `order` | Interval |
|---|---|---|---|
| Both observed, equal boot IDs | `same_boot_reported` | `before_precedes_after`, `after_precedes_before` or `overlapping`, from the uptime windows | `interval_cs` between the windows, or null when they overlap |
| Both observed, different boot IDs | `different_boot_or_host_reported` | `unverified` | null |
| Either side not bound or unavailable | `unknown` | `unverified` | null |

`different_boot_or_host_reported` is deliberately two-sided: boot IDs differ across hosts as well as across reboots, and labels do not authenticate hosts. Each side's `monotonic_window_ms` and `wall_clock` value are echoed. An optional `--max-window-ms N` policy reports `window_within_policy` per side. It is a consumer criterion, not a freshness guarantee. Mixed v1/v2 capture input continues to compare values as comparison-v2, with timing unknown.

### 4. Vocabulary

Record-level `freshness: "unknown"` stays. MIRA still makes no claim about age relative to a consumer's present (Q3), and no record changes. The new capture-level members are named for what they measure: a monotonic window, wall-clock consistency within the window, and reported same-boot order. They never use the words fresh, current or verified. Q3 remains explicitly unanswered until a separate trusted-time decision (option E).

## Trust, privacy and failure analysis

- **Attacker-influenced sources (TB2).** procfs can be stale, emulated or altered by a privileged party, and container runtimes may virtualize uptime. Every boot claim is "reported". Same-boot order is evidence about what the kernel interface reported, not proof of real-world chronology.
- **Document forgery.** Anyone who can write a capture file can forge timelines and boot bindings consistently. Integrity needs signatures and custody, which are separate work. The comparator must still check that windows and offsets are internally consistent, so that accidental corruption is caught.
- **Disclosure and linkability.** A boot ID links all captures from one boot, and containers on one host usually share the host's boot ID, linking tenants. It is therefore never collected by default, never placed in investigation reports, and documented as an identifier operators must treat like a label. The timeline (offsets, window, wall-edge times) adds no identifier beyond the per-record wall times that already exist.
- **Clock behaviour.** NTP slew stays within tolerance; steps, manual changes and suspend during capture show as `stepped_or_suspended`. A step between two captures is invisible to the wall clock but irrelevant to same-boot ordering, which uses uptime. Uptime includes suspend, so same-boot intervals include suspended time.
- **Resource bounds.** Boot binding adds four bounded reads (two of at most 64 bytes, two of at most 64 KiB) and no retries.

## Acceptance for implementation

Staged PRs, each with its own exact-head review:

1. **Timeline:** capture-v2 producer, schema and fixtures.
   - Native tests: offset ordering, the window covering all sources, wall-clock consistency including synthetic step cases via an injectable clock, unchanged records, and capture-v1 output byte-identical without `--timeline`.
   - Independent validator for the capture-v2 structure and the timeline/record source agreement.
2. **Boot binding:** boot ID and centisecond uptime parsers.
   - Bounds, UUID syntax and case, trailing data and changed-ID cases.
   - `--bind-boot` alone producing the same capture-v2 shape as `--timeline --bind-boot`.
   - A live check that the boot ID equals a direct read and that the uptime window brackets direct samples.
3. **Comparator:** comparison-v3.
   - Every row of the table above, overlapping windows, forged inconsistent windows refused, the `--max-window-ms` policy, mixed-version fallback, and unchanged comparison-v1/v2 outputs.

Packaging, docs and threat model are updated in each stage. CI runs on both native architectures.

## Consequences and rollback

Blast radius: one opt-in capture version, one opt-in flag, one comparator output version. Existing defaults are unchanged. Each stage can be reverted independently, and exported capture-v2 documents keep their version. No operational state requires rollback.

## Review decisions

The four questions raised in review were settled as follows:

1. **Flag names:** `--timeline` and `--bind-boot`, not a single format flag. Each flag names what it collects. The boot ID is a privacy decision and deserves its own visible flag rather than being implied by a format name.
2. **Wall-clock tolerance:** fixed at max(50 ms, 1% of the window), not configurable. A tunable tolerance would let two captures disagree about the same clock behaviour. Consumers can apply a stricter rule to the exported window and edge times themselves.
3. **`--bind-boot` implies `--timeline`.** Boot binding is meaningless without the timeline, so requiring both would add a usage error without any safety benefit.
4. **No timeline for investigation reports.** Each reads a single source, so there is no intra-report skew to bound. Revisit only if a multi-source template is added.

## Primary references

- [Linux procfs: /proc/uptime and boot_id](https://docs.kernel.org/filesystems/proc.html)
- [Linux random driver sysctls (boot_id)](https://docs.kernel.org/admin-guide/sysctl/kernel.html#random)
- [clock_gettime(2): CLOCK_MONOTONIC vs CLOCK_BOOTTIME](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
- [Rust std::time::Instant platform notes](https://doc.rust-lang.org/std/time/struct.Instant.html)
