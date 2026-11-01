# Complete offline captures

```sh
mira capture incident-a > before.json
mira capture incident-a --pressure > pressure.json
```

The command emits one capture-v1 JSON document. `host/v1` requests memory, uptime, kernel release, CPU PSI and installed package count. Explicit `--pressure` selects `host-pressure/v1`, adding memory and IO PSI. The question is whether the kernel reports resource stalls alongside resource availability, not whether an application is healthy or why it failed. Only avg10 is projected in basis points; unprojected PSI fields are not interpreted. CPU full is undefined at system scope and its compatibility value is not an operational CPU-full metric. There are no threshold writes, trigger registration, discovery, model calls or background monitoring.

LABEL must contain 1–64 ASCII letters, digits, dots, underscores or hyphens and must begin with a letter or digit. The leading-character rule rejects option-shaped input such as `mira capture --pressure`, which would otherwise become the label of a `host/v1` capture without pressure sources; such invocations exit 2 without collection. Capture-v1 admission is unchanged, so documents produced earlier with other leading characters remain valid for comparison. It is an operator assertion for comparison scope, never authenticated host identity. Avoid secrets or identifying infrastructure names in public captures. No hostname, machine ID or boot ID is collected automatically. The opt-in [collection timeline](#collection-timeline-capture-v2) adds no identifier. Only an explicit [`--bind-boot`](#boot-binding) collects the boot ID.

## Contract

`capture_version: 1`, `capture_scope`, `scope_trust: operator_asserted`, closed `profile`, ordered `expected_sources`, `collection_complete`, `all_available` and `records` are required. All requested sources appear exactly once in order. Every record is evidence-v2; it adds `elapsed_ms` and `failure_reason` to the existing observation shape. Completion means collection returned a result for every requested source, including failures. It does not mean all evidence is available, atomic, fresh or truthful.

Exit 0 means every requested source was available. Exit 1 still emits a complete document with one or more unavailable sources. Exit 2 rejects the invocation before collection and emits no document. Invalid UTF-8 command-line arguments also produce a fixed usage error without a panic or raw argument bytes. An interrupted or truncated output is not a complete capture; validation must precede comparison or consumption.

Wall-clock recording times are taken immediately after each acquisition. `elapsed_ms` measures that acquisition with a monotonic clock. Neither authenticates time or establishes a file-I/O deadline. Fixed unavailable reasons are `timeout`, `limit_exceeded`, `malformed_data`, `permission_denied`, `not_found`, `backend_failed` and `io_failure`. No backend message is exported. Admission checks failure-reason/error-kind consistency, including the io_failure fallback: specifically mapped timeout, invalid-data/input, permission and not-found kinds cannot use that fallback; Other remains valid for either generic I/O or typed backend failures. Evidence-v1 and investigation-v1 output retain their existing shapes; elapsed/reason metadata appears only in evidence-v2 captures.

The [capture schema](../schemas/capture-v1.schema.json) references [evidence-v2](../schemas/evidence-v2.schema.json). Consumers must also check exact ordered source coverage, scope syntax, availability consistency and memory-value consistency. Repository validators resolve local schemas without retrieving remote references.

## Collection timeline (capture-v2)

```sh
mira capture incident-a --timeline
mira capture incident-a --pressure --timeline
```

Options follow the label in this fixed order; `--timeline --pressure` and repeated options exit 2. Without `--timeline` the output is capture-v1, byte-for-byte as before. With it, the document has `capture_version: 2`, the same ordered evidence-v2 records, and two more members:

- `collection.monotonic_window_ms`: from one monotonic reference taken before the first acquisition to the end of the last one. Every source was read within this window, as measured by MIRA's own clock (CLOCK_MONOTONIC on Linux, which excludes suspend).
- `collection.started_unix_ms` / `ended_unix_ms`: unverified wall-clock readings at the window edges, or null.
- `collection.wall_clock`: `consistent` when both edges exist, the end is not before the start, and the wall delta is within max(50 ms, 1% of the window, rounded down) of the monotonic window. `stepped_or_suspended` otherwise, and `unknown` when an edge is missing. It describes only the capture window, not the clock's accuracy.
- `collection.boot`: `{"binding": "not_requested"}` unless [`--bind-boot`](#boot-binding) is given.
- `timeline`: one entry per record, in record order, with the acquisition's `offset_ms` from the reference and its `elapsed_ms` (equal to the record's). Offsets never decrease, and offset plus elapsed never exceeds the window.

Milliseconds are truncated, so a 0 ms window means everything was read within the same millisecond. Record-level `freshness: "unknown"` stays: the window bounds skew within one capture, not how old the capture is now. The [capture-v2 schema](../schemas/capture-v2.schema.json) checks structure; consumers must also check timeline/record agreement, offset bounds and the wall-clock rule, as `scripts/capture_contract.py` does.

## Boot binding

```sh
mira capture incident-a --bind-boot
mira capture incident-a --pressure --timeline --bind-boot
```

`--bind-boot` implies `--timeline`; the option order stays `[--pressure] [--timeline] [--bind-boot]`. At both edges of the monotonic window, MIRA reads `/proc/sys/kernel/random/boot_id` (at most 64 bytes; exactly a lowercase 8-4-4-4-12 hex UUID and one newline) and `/proc/uptime` at centisecond resolution. These samples are inside the window but are not timeline entries. The uptime record keeps whole seconds, unchanged.

```json
"boot": {"binding": "observed", "boot_id": "e740207d-b13a-48dd-8e9d-595a950d6930",
         "started_uptime_cs": 1341874, "ended_uptime_cs": 1341875}
```

`observed` requires both samples to succeed, equal boot IDs and `ended >= started`. Anything else is `{"binding": "unavailable", "failure_reason": ...}` with no partial values. A missing file gives `not_found`, a malformed or changed ID or reversed uptime gives `malformed_data`, and an oversized file gives `limit_exceeded`. A failed binding never fails the capture or changes `all_available`.

The boot ID is a kernel-generated random identifier that changes on every boot. It links every capture from one boot, and containers on one host usually share it, so it can link tenants. Treat it like a label: keep it out of public captures unless linkability is intended. It is never collected without `--bind-boot`, never appears in capture-v1 or investigation reports, and does not authenticate a host. procfs can be emulated or altered by a privileged party, so the binding is what the kernel interface reported.

## Challenged captures (capture-v3)

```sh
mira capture incident-a --challenge HEX --signature incident-a.json.sig --sign-with KEY > incident-a.json
```

`--challenge HEX` answers a consumer's challenge so the consumer can bound the capture's age on its own clock ([ADR 0014](adr/0014-consumer-challenge-freshness.md), see [signatures](signatures.md#freshness-answer-a-challenge)). It comes last, after `[--pressure] [--timeline] [--bind-boot]`, implies `--timeline` and requires signing. HEX must be exactly 64 lowercase hex characters. A malformed challenge, or a challenge without `--signature`/`--sign-with`, exits 2 before anything is read. The output is capture-v3: capture-v2 with `"challenge": HEX` immediately after `"capture_version": 3`, and otherwise identical. The challenge carries no host data. The comparator accepts capture-v3 wherever it accepts capture-v2, with the same timing and same-boot ordering, and the [capture-v3 schema](../schemas/capture-v3.schema.json) is capture-v2's plus the challenge.

## Compare

Produce two captures with the same label and profile, then run:

```sh
.schema-venv/bin/python scripts/compare_evidence.py before.json after.json
```

Capture comparison emits comparison-v2 with explicit completion and operator-asserted scope. Mixed capture-v1/v2 input of the same scope and profile also compares values as comparison-v2. When **both** inputs are capture-v2, the comparator emits comparison-v3: identical value rows plus a capture-level `timing` member.

```sh
.schema-venv/bin/python scripts/compare_evidence.py before.json after.json --max-window-ms 1000
```

| Boot evidence | `boot_relation` | `order` | `interval_cs` |
|---|---|---|---|
| Both observed, equal boot IDs | `same_boot_reported` | `before_precedes_after` or `after_precedes_before` when the uptime windows are strictly separated; `overlapping` when they touch or overlap | gap in centiseconds, or null when overlapping |
| Both observed, different boot IDs | `different_boot_or_host_reported` | `unverified` | null |
| Either side not requested or unavailable | `unknown` | `unverified` | null |

`different_boot_or_host_reported` is two-sided on purpose: boot IDs differ between hosts as well as between boots, and labels do not authenticate hosts. Order comes from boot-relative uptime, so wall-clock steps between captures cannot reorder them; it includes suspended time. `timing.before` and `timing.after` echo each window and wall-clock label. The optional `--max-window-ms N` adds `window_within_policy` per side. That is a consumer criterion, not a freshness guarantee, and it is refused unless both inputs are capture-v2. Row-level `freshness: unknown` and `clock_order: unverified` and `overall_freshness: unknown` are unchanged: the comparator still makes no claim about age relative to the present.

Input is limited to 1 MiB, 128 legacy records and JSON nesting depth 32. Strict UTF-8 and unique object keys are required. Numeric values must use integer JSON tokens; decimal and exponent forms are refused before conversion, even when mathematically integral. This preserves exact integer comparisons and leaves numeric-looking strings unchanged. Nonfinite numbers, invalid Unicode, empty input and incomplete/contradictory capture sets are refused. Nonblocking open and descriptor validation reject FIFOs/devices, including path replacement before open. Symlinks remain supported; parent paths are caller-trusted and mutable regular files are not immutable snapshots. Use a trusted private directory for capture custody. There is no general application deadline for regular filesystem reads.

See [ADR 0002](adr/0002-complete-captures-and-admission.md), [validation](testing.md) and [host evidence](host-evidence.md). There is no managed persistent store, signature, authenticated host binding or automatic retention policy. Captures can be [signed and verified](signatures.md) by `mira` itself through detached OpenSSH signatures ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)). The comparator verifies signed captures itself with `--allowed-signers FILE --principal NAME`, checking exactly the bytes it compares.
