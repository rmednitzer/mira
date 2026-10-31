# Roadmap

Dependency-ordered plan; dates and release assignments are not promised. Implementation state is tied to source and [validation](testing.md), not to architectural aspiration.

## Phase 0 — product definition and foundation

The mission, source boundaries and read-only collection foundation exist. Procfs, dpkg and selected systemd observations, typed evidence, versioned JSON Lines, formal JSON Schema and offline comparison are implemented. Keep these definitions reconciled with code; this is ongoing maintenance rather than an assurance certification.

## Phase 1 — useful offline Linux investigator (in progress)

Available: host memory/uptime/kernel/CPU-pressure observations, installed package metadata, selected service state, explicit provenance/unknown states, native CLI reports and service-active, explicit memory-headroom, explicit pressure-ceiling, package-installed, uptime-minimum and kernel-release investigations with separate expectation assessments and preserved evidence. Native CI includes synthetic subprocess regressions, an unprivileged live systemd comparison and direct procfs checks of kernel release, total memory and bracketed whole uptime. These controlled runner checks do not qualify representative hosts.

Complete capture-v1 profiles add operator-asserted labels, per-source timing/reasons and opt-in memory/IO PSI; labels are not authentication.

Remaining: authenticated host identity, freshness policy (capture timeline implemented and same-boot ordering designed in [ADR 0010](adr/0010-capture-timeline-and-freshness.md); trusted time for age at consumption is a separate decision), representative real-host validation, bounded journal sources where justified, and broader read-only investigation templates. The activation, memory-minimum, pressure-ceiling, package-installed, uptime-minimum and kernel-release templates do not establish a general diagnostic workflow. Exit: a representative Ubuntu 26.04 investigation works without elevation, external inference or system mutation, with reproducible fixtures and explicit evidence gaps. Controlled CI service/procfs comparisons do not satisfy this exit condition.

### Packaging and test foundation

CLI-only Debian packaging has archive inspection, isolated install/reinstall/remove/purge, lintian, versioned ABI dependencies and repeatable assembly under different invoking umasks. Native subprocess fixtures use opt-in Cargo test support; Python remains separate schema/history tooling with a complete version/wheel-hash lock.

Native CI also checks apt dependency resolution and installed bytes/contracts in disposable Ubuntu containers, with source/artifact/image-bound receipts.

Fresh source/target builds also compare raw binaries and full packages against selected artifacts under varied paths, timezone and umask. This is one native runner/compiler/system environment, not independent-host or hermetic proof.

Next release gates: clean physical-host qualification, genuine version-to-version upgrades/downgrades, independent-host reproduction and signed provenance. Optional hardened collector units remain a separate design requiring justified unattended collection, bounded output/retention, verified sandbox/IPC access and explicit operator activation. No daemon or unit is installed now.

## Phase 2 — security exposure and evidence correlation

Ingest versioned distribution advisories and machine-readable security data. Reconcile package revisions/backports, runtime/configuration applicability and evidence freshness. Produce affected/not-affected/unknown with citations. Exit: representative fixtures distinguish true/false exposure without inferring vulnerability from upstream versions alone.

### Conditional platform observation track

Plan Kubernetes workload/cluster evidence first and Talos node OS evidence separately, followed only where justified by bounded Prometheus-compatible queries and GitOps status. Additional local network/storage/container sources require a demonstrated diagnostic gap. See [platform integrations](platform-integrations.md) and [ADR 0004](adr/0004-staged-platform-observation.md) for ordering, exclusions, sovereignty and admission gates.

This track may proceed after the offline investigator exit and adapter-specific identity, credentials, transport and evidence contracts are validated; it is independent of AI/UI delivery and does not require remediation capability. No adapters are implemented or scheduled. A separately reviewed implementation is required; this plan adds no network, credentials or runtime dependencies.

## Phase 3 — intent-driven adaptive workspace

The CLI already has closed explicit template selection. Add a natural-language intent grammar, further admitted capabilities and registered UI components. Exit: operators navigate evidence and incident workflows without gaining privileges from layout or model output. Compare against a fixed UI with matched tasks.

## Phase 4 — optional AI-assisted investigation

Evaluate interchangeable local inference and optional hosted models; hosted evaluation uses synthetic/public inputs only by default. Capture model/prompt/output revisions and failures. Exit: model failure cannot alter admitted access, and useful offline investigation remains available.

## Phase 5 — governed remediation

Only after a separate design/threat review: authenticated principals, scoped grants, dry-run, operator authorization, preconditions, postcondition verification, recovery and any write adapters. Exit: adversarial authorization/failure tests pass under stated conditions. No production-readiness claim follows automatically.

## Retained fixture

The grid simulator remains a deterministic coordination regression fixture. It is not the primary product, an identity provider or an operational control gate. Remove it only after equivalent invariants are covered in the real operations domain.
