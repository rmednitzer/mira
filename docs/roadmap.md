# Roadmap

Dependency-ordered plan; dates and release assignments are not promised. Implementation state is tied to source and [validation](testing.md), not to architectural aspiration.

## Phase 0 — product definition and foundation

The mission, source boundaries and read-only collection foundation exist. Procfs, dpkg and selected systemd observations, typed evidence, versioned JSON Lines, formal JSON Schema and offline comparison are implemented. Keep these definitions reconciled with code; this is ongoing maintenance rather than an assurance certification.

## Phase 1 — useful offline Linux investigator (in progress)

Available: host memory/uptime/kernel/CPU-pressure observations, installed package metadata, selected service state, explicit provenance/unknown states and native CLI reports. Native CI includes synthetic subprocess regressions and one unprivileged live systemd comparison.

Remaining: authenticated or explicitly scoped host identity, freshness policy, representative real-host validation, bounded journal/IO-pressure sources where justified, and read-only investigation templates. Exit: a representative Ubuntu 26.04 investigation works without elevation, external inference or system mutation, with reproducible fixtures and explicit evidence gaps. One CI service does not satisfy this exit condition.

### Packaging and test foundation

CLI-only Debian packaging has archive inspection, isolated install/reinstall/remove/purge, lintian, versioned ABI dependencies and repeatable assembly under different invoking umasks. Native subprocess fixtures use opt-in Cargo test support; Python remains separate schema/history tooling.

Next release gates: clean-system dependency resolution, genuine version-to-version upgrades/downgrades, independent reproducible compilations and signed provenance. Optional hardened collector units remain a separate design requiring justified unattended collection, bounded output/retention, verified sandbox/IPC access and explicit operator activation. No daemon or unit is installed now.

## Phase 2 — security exposure and evidence correlation

Ingest versioned distribution advisories and machine-readable security data. Reconcile package revisions/backports, runtime/configuration applicability and evidence freshness. Produce affected/not-affected/unknown with citations. Exit: representative fixtures distinguish true/false exposure without inferring vulnerability from upstream versions alone.

## Phase 3 — intent-driven adaptive workspace

Add a declared intent grammar, admitted capability selection and registered UI components. Exit: operators navigate evidence and incident workflows without gaining privileges from layout or model output. Compare against a fixed UI with matched tasks.

## Phase 4 — optional AI-assisted investigation

Evaluate interchangeable local inference and optional hosted models; hosted evaluation uses synthetic/public inputs only by default. Capture model/prompt/output revisions and failures. Exit: model failure cannot alter admitted access, and useful offline investigation remains available.

## Phase 5 — governed remediation and broader infrastructure

Only after a separate design/threat review: authenticated principals, scoped grants, dry-run, operator authorization, preconditions, postcondition verification, recovery and remote adapters. Exit: adversarial authorization/failure tests pass under stated conditions. No production-readiness claim follows automatically.

## Retained fixture

The grid simulator remains a deterministic coordination regression fixture. It is not the primary product, an identity provider or an operational control gate. Remove it only after equivalent invariants are covered in the real operations domain.
