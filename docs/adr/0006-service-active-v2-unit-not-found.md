# ADR 0006: service-active/v2 distinguishes a not-found unit

Status: accepted for implementation, 2026-10-31. Resolves [issue #44](https://github.com/rmednitzer/mira/issues/44). Native integration qualification remains required.

## Context and criteria

`systemctl show` succeeds for a unit name that has no unit definition. It reports `LoadState=not-found`, `ActiveState=inactive` and `SubState=dead`, and `Names` contains the requested name, so the collector's identity binding passes. `service-active/v1` deliberately ignores LoadState ([ADR 0001](0001-read-only-service-investigation.md)). A mistyped or uninstalled unit therefore yields `not_satisfied / reported_not_active`, the same assessment as an installed service that is stopped. A consumer branching on `reason` cannot tell "this service is down" from "no such unit is defined on this host" without parsing the embedded evidence. The two usually call for different operator action.

Criteria:
- Preserve the v1 command output and the v1 schema exactly.
- Keep unavailable, transitional and unrecognized evidence indeterminate.
- Do not reinterpret LoadState for active units.
- Add no collector, systemctl property, verb, dependency or privilege.
- Make the semantics checkable by an independent schema and validator.

## Options and decision

| Option | Consequence | Decision |
|---|---|---|
| Add `unit_not_found` to v1 | `reason` is a closed enum with per-reason rules in `investigation-v1.schema.json`. New output would fail strict v1 validation. | Reject |
| Document only | No contract change, but every consumer must rediscover the case | Reject |
| Make `service-active` emit v2 by default | Silently changes output for existing scripts and consumers that pin v1 | Defer as a separately announced decision |
| Explicitly selected `service-active/v2` report | Opt-in, versioned; v1 output stays byte-identical | **Select** |
| v2 assesses not-found as `indeterminate` | Treats a definite observation that no definition exists as missing evidence, which ADR 0001 keeps separate | Reject |

The closed template enum admits `service-active` and `service-active/v1` (both v1) and `service-active/v2`. Every other name, including `service-active/v3`, `service-active/` and other capitalizations, remains a usage error before collection. The unversioned name stays pinned to v1.

## v2 assessment semantics

v2 applies the v1 table unchanged, with one additional rule evaluated only after v1 yields `reported_not_active`:

| Reported LoadState / ActiveState | v2 outcome | v2 reason | Exit |
|---|---|---|---|
| `not-found` / `inactive` | not_satisfied | unit_not_found | 1 |
| `not-found` / `active`, `reloading`, `refreshing` | satisfied | reported_active | 0 |
| `not-found` / `failed`, `maintenance` | not_satisfied | reported_not_active | 1 |
| `not-found` / `activating`, `deactivating` | indeterminate | transition_in_progress | 3 |
| Any other combination | as v1 | as v1 | as v1 |

A running unit whose unit file was removed is reported by systemd as `not-found` while still `active`. LoadState describes the current definition, not whether the unit runs, so v2 keeps such a unit satisfied. The issue's earlier proposal to treat it as contradictory is withdrawn. A failed unit without a definition still records an observed failure, so it keeps `reported_not_active`. Only the `not-found`/`inactive` pair, which is the stub state systemd reports for an undefined name, gains the new reason. That pair can also describe a stopped unit whose file was later removed while systemd still references it. The reason therefore means exactly "no loadable definition and not active". It does not mean "never installed".

The outcome stays `not_satisfied` with exit 1, so exit-code consumers see no change between v1 and v2. Other LoadState values (`masked`, `error`, `bad-setting`) keep v1 reasons. A finer split for them is deferred until there is a concrete operator need.

## Contract

The report shape is unchanged apart from `investigation_version: 2` and `template: "service-active/v2"`. It embeds the same unchanged evidence-v1 service record. `schemas/investigation-v2.schema.json` adds `unit_not_found` and enforces both directions:
- `unit_not_found` requires `not_satisfied` and observed `not-found`/`inactive` evidence.
- `reported_not_active` is invalid for that pair.

The v1 schema is shipped unchanged so existing documents remain valid. Consumers dispatch on `investigation_version` and `template`.

## Authority, compatibility and rollback

No new execution capability is added. The template enum is closed dispatch, not authentication. Neither report establishes application health, package presence, root cause or freshness. Blast radius: one opt-in report variant, one schema and the associated fixtures and docs. Rollback: revert the introducing change. v1 consumers are unaffected either way, and v2 documents already produced remain valid against the published v2 schema.

## Validation

- Pure Rust tests cover the complete v2 rule table, the unchanged v1 result for every `not-found` combination, and byte-identical frozen v1 JSON.
- Native fixture modes run `not-found` with `inactive`, `active` and `failed` through the public CLI for both versions.
- Independent v2 schema fixtures include contradictions in both directions and version/template mismatches.
- An unprivileged live check compares v1 and v2 for a deliberately undefined unit name against direct `systemctl show` samples taken before and after. Querying an undefined name is read-only; systemd's transient stub object is collected without operator action.
- Existing packaging, CodeQL and exact-head review gates apply.

The oracle is systemd's documented state vocabulary, not a learned label. Tests establish behavior for the admitted cases, not fleet-wide unit-file semantics.

## Primary contracts

- [systemd 262 unit properties](https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html): LoadState values, including `not-found`, are orthogonal to ActiveState.
- [systemd 262 systemctl](https://www.freedesktop.org/software/systemd/man/262/systemctl.html): `show` reports properties of units that are not loaded.
- [JSON Schema draft 2020-12](https://json-schema.org/draft/2020-12): conditional `if`/`then`/`not` constraints.
