# ADR 0002: Complete captures and strict admission

Status: Accepted, 2026-10-30. Required validation is specified below; observed run/review evidence belongs to the implementing PR.

## Context and criteria

Flat JSONL records identify observations but cannot establish that a producer finished. Path checks before opening do not prevent a FIFO replacement from blocking. JSON duplicate keys lose information before schema validation. Package identity must be unique without rejecting multiarch installations. Host timing must describe each acquisition, not the end of a group of reads.

Criteria: offline operation, explicit unsupported/unavailable states, bounded inputs, stable existing formats, no new Rust dependencies or authority, source-bound package validation, and reversible changes.

## Options

- No change: retain ambiguous admission and completion; rejected for demonstrated correctness gaps.
- Replace evidence-v1 and the comparator: unnecessarily breaks existing consumers.
- Add a workflow engine, durable store or authenticated host identity: unrelated authority and persistence boundaries; deferred.
- Add a closed capture profile, evidence-v2 metadata and strict offline import while preserving v1: selected.

## Decision

`mira capture LABEL [--pressure]` emits one capture-v1 JSON document. LABEL is a bounded operator assertion, not host authentication. The default host/v1 profile requests exactly five existing sources. Explicit host-pressure/v1 adds memory and IO PSI to answer whether resource stalls were reported alongside memory availability and CPU contention. No pressure threshold, health verdict, trigger registration, background collection or journal access is introduced. CPU full remains literal compatibility evidence, not an operational CPU-full metric.

Collection completion means every requested source has an observed or unavailable record. It does not mean every source is available. Evidence-v2 adds elapsed monotonic milliseconds and fixed failure reasons; evidence-v1 and investigation-v1 projections remain unchanged. Each source records its wall-clock completion immediately after acquisition. Clocks and caller labels remain unverified; elapsed time is not an I/O deadline or proof of freshness.

The offline comparator admits strict UTF-8 JSON, rejects duplicate keys, nonfinite numbers, invalid Unicode, excess nesting and empty captures, opens nonblocking before descriptor validation, and retains symlink compatibility. Parent paths remain caller-controlled. Regular-file I/O has no general deadline. Capture comparisons require matching explicit labels and profiles; legacy JSONL remains supported without completion or host-binding claims. Mixed formats are refused.

Package admission rejects duplicate installed (name, architecture) identities. Different architectures remain distinct. Missing/sparse noninstalled records retain existing semantics.

CI installs the exact built package with real dependency resolution in a disposable native Ubuntu container, executes the installed CLI, verifies its managed files, and records source commit/tree, package digest, image identity and test postconditions. This is container installation/loader evidence, not a clean physical host or service deployment. The container image and apt repositories are external build-validation dependencies. No release, signature or publication is added.

## Trust boundaries and failure behavior

Untrusted capture bytes cross file admission, decoding, schema and semantic checks before comparison. None grants execution authority. Invalid input fails with a fixed diagnostic and no comparison output. Collection failures remain records with unavailable values. Capture labels must not contain secrets; public build receipts contain only source/artifact/profile identities.

STRIDE: ambiguous identities and duplicate fields threaten integrity; special files threaten availability; raw errors and host identifiers threaten disclosure. Descriptor checks, strict decoding, exact source sets and fixed errors address these paths within the declared custody limits. Hashes identify bytes, not truthful measurements or independent provenance.

## Acceptance and rollback

Require native Rust regressions for package uniqueness/multiarch, per-source timing/reasons, optional PSI and mixed source availability; strict-decoder/FIFO-replacement/complete-set negatives; independent v1/v2/capture schemas; existing live-systemd checks; both native packaging jobs; exact-head review and post-merge CI. Preserve a frozen authored source/availability matrix before evaluating it; synthetic cases do not establish fleet coverage.

Rollback: revert the new CLI/profile/schema and comparison support together. Existing v1 output remains consumable. Retain any already exported captures with their original version. No stored operational state or daemon needs migration. Genuine version-to-version upgrades need a retained distinct-version baseline; independent compilation reproducibility and signing remain separate release gates.

## Primary contracts

- https://github.com/torvalds/linux/blob/v6.17/Documentation/accounting/psi.rst
- https://docs.python.org/3/library/json.html#standard-compliance-and-interoperability
- https://man7.org/linux/man-pages/man2/open.2.html
- https://docs.docker.com/reference/cli/docker/image/inspect/

Follow-up: [ADR 0003](0003-locked-tooling-and-fresh-builds.md) adds hash-locked tooling and fresh source/target comparisons within one native runner environment; independent-host reproduction and signing remain open.
