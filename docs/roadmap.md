# Roadmap

Dependency-ordered plan; dates and release assignments are not promised. Implementation state is tied to source and [validation](testing.md), not to architectural aspiration.

## Phase 0 — product definition and foundation

The mission, source boundaries and read-only collection foundation exist. Procfs, dpkg and selected systemd observations, typed evidence, versioned JSON Lines, formal JSON Schema and offline comparison are implemented. Keep these definitions reconciled with code; this is ongoing maintenance rather than an assurance certification.

## Phase 1 — useful offline Linux investigator (in progress)

Available: host memory/uptime/kernel/pressure observations, installed package metadata, selected service state, text-free journal event classes, explicit provenance/unknown states, native CLI reports and seven investigations (service-active, memory-headroom, pressure-ceiling, package-installed, uptime-minimum, kernel-release and journal-events) with separate expectation assessments and preserved evidence. Native CI includes synthetic subprocess regressions and live unprivileged systemd, procfs, dpkg and journal comparisons. These controlled runner checks do not qualify representative hosts.

Complete capture-v1 profiles add operator-asserted labels, per-source timing/reasons and opt-in memory/IO PSI; labels are not authentication. Capture-v2 adds a collection timeline and opt-in boot binding for same-boot ordering, and capture-v3 answers a consumer challenge. Captures and reports can be signed and verified by `mira` itself.

Done since the phase began: signer identity and document integrity ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)), capture timeline and same-boot ordering ([ADR 0010](adr/0010-capture-timeline-and-freshness.md)), age at consumption through a consumer-issued challenge ([ADR 0014](adr/0014-consumer-challenge-freshness.md)), text-free journal event classes ([ADR 0012](adr/0012-bounded-journal-events.md)) and the host qualification runner ([ADR 0013](adr/0013-host-qualification-protocol.md)).

Remaining: reviewed qualification receipts from every required host class, including a restricted-user run (only an optional `wsl` receipt is committed); further bounded sources where a diagnostic gap justifies them; challenges for investigation reports, if needed (left to a later decision by ADR 0014); and broader read-only investigation templates. Hardware-bound host identity and trusted host time stay out of scope. The seven templates do not establish a general diagnostic workflow. Exit: a representative Ubuntu 26.04 investigation works without elevation, external inference or system mutation, with reproducible fixtures and explicit evidence gaps. Controlled CI service/procfs comparisons do not satisfy this exit condition.

### Packaging and test foundation

CLI-only Debian packaging has archive inspection, isolated install/reinstall/remove/purge, lintian, versioned ABI dependencies and repeatable assembly under different invoking umasks. Native subprocess fixtures use opt-in Cargo test support; Python remains separate schema/history tooling with a complete version/wheel-hash lock.

Native CI also checks apt dependency resolution and installed bytes/contracts in disposable Ubuntu containers, with source/artifact/image-bound receipts.

Fresh source/target builds also compare raw binaries and full packages against selected artifacts under varied paths, timezone and umask. This is one native runner/compiler/system environment, not independent-host or hermetic proof.

Next release gates: clean physical-host qualification, genuine version-to-version upgrades/downgrades, independent-host reproduction and signed provenance. Optional hardened collector units remain a separate design requiring justified unattended collection, bounded output/retention, verified sandbox/IPC access and explicit operator activation. No daemon or unit is installed now.

## Phase 2 — shared mixed-initiative workspace

The operator and an AI agent investigate together in one signed, append-only session ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md), grounded in the [research basis](research/mixed-initiative.md)). Either party can act, raise findings, ask or propose. The agent's autonomy is set per function, bounded, expiring and revocable. Decisions stay with the operator. The agent's actions are exactly the read-only Phase 1 templates and captures, enforced by `mira`. It has no state-changing or communicating capability, because it reads untrusted, private host evidence (Rule of Two).

1. **Session core with a scripted agent.** Principals bound to signing keys, the closed entry kinds, ported arbitration rules (operator precedence, expiry, staleness, terminal immutability, budget), machine-checked findings, and an independent validator. Implemented, including the operator-clock delegation deadline and the optional own-assessment forcing function.
2. **Local model harness.** Optional tooling outside the CLI, with full model-I/O recording and hostile-content fixtures. Hosted models see synthetic or public sessions only. Implemented, with hostile-content fixtures; adaptive red-team rounds under the [protocol](red-team.md) are outstanding.
3. **Evaluation.** Matched tasks against an operator-only baseline, measuring correctness, time, evidence access, over-reliance on seeded wrong findings and override rate.

Exit: the evaluation is recorded, the agent never exceeded its capabilities or posted a false checked claim under hostile fixtures, and an agent failure always leaves a usable operator session. No benefit is claimed before the evaluation.

## Phase 3 — security exposure and evidence correlation

Ingest versioned distribution advisories and machine-readable security data. Reconcile package revisions/backports, runtime/configuration applicability and evidence freshness. Produce affected/not-affected/unknown with citations. Exit: representative fixtures distinguish true/false exposure without inferring vulnerability from upstream versions alone.

### Conditional platform observation track

Plan Kubernetes workload/cluster evidence first and Talos node OS evidence separately, followed only where justified by bounded Prometheus-compatible queries and GitOps status. Additional local network/storage/container sources require a demonstrated diagnostic gap. See [platform integrations](platform-integrations.md) and [ADR 0004](adr/0004-staged-platform-observation.md) for ordering, exclusions, sovereignty and admission gates.

This track may proceed after the offline investigator exit and adapter-specific identity, credentials, transport and evidence contracts are validated; it is independent of AI/UI delivery and does not require remediation capability. No adapters are implemented or scheduled. A separately reviewed implementation is required; this plan adds no network, credentials or runtime dependencies.

Advisory correlation becomes another closed, read-only capability set available to both workspace parties.

## Phase 4 — intent-driven adaptive views

The CLI already has closed explicit template selection, and the Phase 2 session gives both parties one shared record. Add a natural-language intent grammar that selects admitted capabilities, and registered UI components that render the session. Exit: operators and agents navigate evidence and incident workflows without either gaining privileges from layout or model output. Compare against a fixed UI with matched tasks.

## Phase 5 — governed remediation

Only after a separate design/threat review: dry-run, operator authorization, preconditions, postcondition verification, recovery and any write adapters, built on the Phase 2 principals and grants. In the shared workspace the agent may propose a change; the operator approves it, and an independent executor checks preconditions and postconditions. Under the Rule of Two, an agent that reads untrusted host evidence never applies a change itself. Exit: adversarial authorization/failure tests pass under stated conditions. No production-readiness claim follows automatically.

## Retained fixture

The grid simulator remains a deterministic coordination regression fixture. It is not the primary product, an identity provider or an operational control gate. Remove it only after equivalent invariants are covered in the real operations domain; ADR 0015 ports them into the shared workspace with tested, operations-domain equivalents.
