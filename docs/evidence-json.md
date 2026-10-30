# Evidence JSON Lines v1

Use `mira inspect --json` or `mira service UNIT.service --json`. Standard output is one JSON object per line; unrelated failures are represented as unavailable records, and the process exits with status 1 for incomplete evidence. Existing human-readable commands remain available.

Every record includes `schema_version: 1`, `source`, `scope` (null for host-wide records; requested unit for systemd), `recorded_unix_ms` (number or null), `clock_trust: "unverified"`, `freshness: "unknown"`, `status` (`observed` or `unavailable`), `value` and `error_kind`. Unavailable records carry null values and a stable Rust I/O error-kind label, not raw OS error messages.

Known values: memory has `total_kib` and `available_kib`; uptime is seconds; kernel release is a string; CPU pressure has basis-point fields; dpkg has `installed_count` only; a systemd result contains unit ID and literal load/active/sub states. The output deliberately does not include installed package inventories or arbitrary stderr. Source data are not authenticated, timestamps are non-atomic and cannot prove freshness, and output is not a signed attestation or a vulnerability finding.

Consumers must validate schema version, source and scope and must not infer host health, permission or remediation authorization from these records. An optional offline [history comparison](evidence-history.md) validates captures against the schema and distinguishes changes, missing observations and indeterminate evidence. There is no managed persistent evidence store. Independent schema checks use separate Python tooling; the Rust serializer and CLI have no Python runtime dependency.

The opt-in [investigation report](investigations.md) has a separate version/schema and embeds one unchanged evidence-v1 record. It is not an evidence JSONL record and is not accepted by the history comparator. Assessment outcomes are expectations over the embedded observation, not additional observed facts.
