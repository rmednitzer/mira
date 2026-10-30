# Offline evidence comparison (experimental)

Capture `mira inspect --json > before.jsonl` and repeat later as `after.jsonl`. Compare with `.schema-venv/bin/python scripts/compare_evidence.py before.jsonl after.jsonl` after installing the pinned CI validator dependency. The command performs no host inspection, system mutation, network requests, persistence, or inference. It validates each input against the v1 JSON Schema.

Limits: 1 MiB per capture and at most 128 unique source/scope records. Duplicated source/scope pairs, malformed JSON, unsupported schema versions and oversized inputs fail closed with exit code 2. Output is deterministic JSON with sorted sources and no raw evidence values.

Outcomes: `changed` and `unchanged` apply only to two observed values for the same source and scope. `indeterminate` means at least one record is unavailable. `added` and `missing` indicate absence from one capture, **not** that a condition began or ended on the host.

All outcomes carry `freshness: unknown` and `clock_order: unverified`. Recorded wall-clock values are deliberately not used to assert chronology, freshness or trust, and collections are not atomic. Capture names (`before` and `after`) express caller intent, not a proven ordering. No authorization or remediation follows from a comparison.

The comparison is a small offline research utility rather than a persistent history store or a normalized diagnostic model. Package count changes are not package advisories or vulnerability determinations.
