# Complete offline captures

```sh
mira capture incident-a > before.json
mira capture incident-a --pressure > pressure.json
```

The command emits one capture-v1 JSON document. `host/v1` requests memory, uptime, kernel release, CPU PSI and installed package count. Explicit `--pressure` selects `host-pressure/v1`, adding memory and IO PSI. The question is whether the kernel reports resource stalls alongside resource availability, not whether an application is healthy or why it failed. Only avg10 is projected in basis points; unprojected PSI fields are not interpreted. CPU full is undefined at system scope and its compatibility value is not an operational CPU-full metric. There are no threshold writes, trigger registration, discovery, model calls or background monitoring.

LABEL must contain 1–64 ASCII letters, digits, dots, underscores or hyphens and must begin with a letter or digit. The leading-character rule rejects option-shaped input such as `mira capture --pressure`, which would otherwise become the label of a `host/v1` capture without pressure sources; such invocations exit 2 without collection. Capture-v1 admission is unchanged, so documents produced earlier with other leading characters remain valid for comparison. It is an operator assertion for comparison scope, never authenticated host identity. Avoid secrets or identifying infrastructure names in public captures. No hostname, machine ID or boot ID is collected automatically.

## Contract

`capture_version: 1`, `capture_scope`, `scope_trust: operator_asserted`, closed `profile`, ordered `expected_sources`, `collection_complete`, `all_available` and `records` are required. All requested sources appear exactly once in order. Every record is evidence-v2; it adds `elapsed_ms` and `failure_reason` to the existing observation shape. Completion means collection returned a result for every requested source, including failures. It does not mean all evidence is available, atomic, fresh or truthful.

Exit 0 means every requested source was available. Exit 1 still emits a complete document with one or more unavailable sources. Exit 2 rejects the invocation before collection and emits no document. Invalid UTF-8 command-line arguments also produce a fixed usage error without a panic or raw argument bytes. An interrupted or truncated output is not a complete capture; validation must precede comparison or consumption.

Wall-clock recording times are taken immediately after each acquisition. `elapsed_ms` measures that acquisition with a monotonic clock. Neither authenticates time or establishes a file-I/O deadline. Fixed unavailable reasons are `timeout`, `limit_exceeded`, `malformed_data`, `permission_denied`, `not_found`, `backend_failed` and `io_failure`. No backend message is exported. Admission checks failure-reason/error-kind consistency, including the io_failure fallback: specifically mapped timeout, invalid-data/input, permission and not-found kinds cannot use that fallback; Other remains valid for either generic I/O or typed backend failures. Evidence-v1 and investigation-v1 output retain their existing shapes; elapsed/reason metadata appears only in evidence-v2 captures.

The [capture schema](../schemas/capture-v1.schema.json) references [evidence-v2](../schemas/evidence-v2.schema.json). Consumers must also check exact ordered source coverage, scope syntax, availability consistency and memory-value consistency. Repository validators resolve local schemas without retrieving remote references.

## Compare

Produce two captures with the same label and profile, then run:

```sh
.schema-venv/bin/python scripts/compare_evidence.py before.json after.json
```

Capture comparison emits comparison-v2 with explicit completion and operator-asserted scope. Different scopes/profiles and mixed capture/legacy input are refused. Equal labels do not prove that two captures came from the same host. Changes compare values, not timing, and unavailable evidence remains indeterminate. Freshness and clock order remain unknown/unverified. Legacy evidence-v1 JSONL remains supported as comparison-v1, without completion claims.

Input is limited to 1 MiB, 128 legacy records and JSON nesting depth 32. Strict UTF-8 and unique object keys are required. Numeric values must use integer JSON tokens; decimal and exponent forms are refused before conversion, even when mathematically integral. This preserves exact integer comparisons and leaves numeric-looking strings unchanged. Nonfinite numbers, invalid Unicode, empty input and incomplete/contradictory capture sets are refused. Nonblocking open and descriptor validation reject FIFOs/devices, including path replacement before open. Symlinks remain supported; parent paths are caller-trusted and mutable regular files are not immutable snapshots. Use a trusted private directory for capture custody. There is no general application deadline for regular filesystem reads.

See [ADR 0002](adr/0002-complete-captures-and-admission.md), [validation](testing.md) and [host evidence](host-evidence.md). There is no managed persistent store, signature, authenticated host binding or automatic retention policy.
