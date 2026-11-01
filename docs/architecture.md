# Architecture — baseline ADR

Status: proposed operational architecture, partially implemented. Supersedes the rover as the primary product demonstration, but retains the grid simulator only as a deterministic arbitration fixture.

## Decision
Use a local-first Rust core with typed, allowlisted Linux evidence collectors and deterministic analysis. The core provides structured observations, findings, policies and evidence references. User intent selects an admitted investigation template. A future UI composes predeclared components from that structured state. Optional models are untrusted analyzers, isolated from execution.

## Logical flow
| Stage | Implemented | Planned |
|---|---|---|
| Operator selection | Explicit CLI command, service scope and closed service-active, memory-headroom, pressure-ceiling, package-installed, uptime-minimum, kernel-release and journal-events templates | A shared operator–agent session with per-function autonomy ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)); natural-language intent and additional reviewed templates |
| Evidence acquisition | Bounded procfs/dpkg reads, selected systemd query and text-free journal event classes ([ADR 0012](adr/0012-bounded-journal-events.md)) | additional reviewed collectors; conditional platform observation adapters |
| Evidence contract | Typed observations, unavailable states, JSON Lines v1, complete capture-v1/evidence-v2, opt-in capture-v2 timeline and boot binding, OpenSSH-signed JSON documents and schemas, consumer-challenge capture-v3 with a verifier-clock age bound | trusted host time |
| Comparison and analysis | Offline comparison, same-boot capture ordering, signature and challenge-age checks, and versioned expectation templates with cited evidence | Broader diagnostic/advisory correlation |
| Presentation | Human-readable CLI, evidence JSON Lines and versioned JSON documents (captures, reports) | Registered adaptive views |
| Authority | Caller OS permissions; no operational writes (the only file write is an opt-in signature) | Authenticated scoped executor and verified recovery |

## Boundaries
TB1 operator/host session: the process runs under caller permissions; no assumed identity proof. TB2 host observations: procfs, dpkg, systemd and journal interfaces may be malformed, stale, unavailable or attacker-influenced. TB3 model inference: optional external providers receive synthetic/public inputs by default and never control authorization. TB4 UI: render registered view types and validate data; do not evaluate model-produced code. TB5 future change executor: separate admitted, scoped actor and policy, explicit approval and verification. TB6 (planned) covers remote platform endpoints, below. TB7 is the `ssh-keygen` execution boundary for signing and verification ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)). TB8 (planned) is the agent principal in a shared session ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)).

## Runtime constraints
No automatic privilege escalation, arbitrary command execution or outbound network in the collectors. MIRA executes only fixed-argument, shell-free commands under caller permissions, through one bounded runner: a read-only `systemctl show` query, read-only `/usr/bin/journalctl` queries, and `/usr/bin/ssh-keygen` when signing or verification is requested. Path roots are injectable for deterministic tests; production collection must constrain roots to approved OS interfaces. Files and outputs must have explicit byte bounds. Every subprocess call also has an execution/EOF deadline; ordinary filesystem I/O has no universal application deadline. No silent cloud fallback. No assumption that a read-only file open gives a consistent global host snapshot.

## Planned platform observation boundary

Kubernetes and Talos are separate candidate sources, not generic command tools or extensions of local capture-v1. [ADR 0004](adr/0004-staged-platform-observation.md) separates remote observation from remediation. Each adapter needs explicit endpoint/target selection, scoped credentials, verified transport, allowlisted methods and retained fields, bounded pagination/requests, an evidence/schema contract and supported-version fixtures before implementation. No implicit context/credential discovery or executable authentication plugins are admitted by the plan. Cross-source identity and freshness remain explicit uncertainties.

TB6 (planned) covers remote endpoint, credential and response handling. It does not exist in the current runtime. Existing collectors remain offline; optional remote adapters must fail without changing their behavior or core package dependencies. See [candidate scope and acceptance](platform-integrations.md) and the [planned threat analysis](threat-model.md#planned-platform-observation-boundary).

## Architectural alternatives
1. No pivot: continue rover-only simulator. Lowest cost but fails practical AIOps objective.
2. General autonomous Linux agent: fast prototype but authorization and provenance are too weak.
3. **Chosen:** narrow read-only Linux core first, then intent and adaptive interface. Slower breadth, tractable evidence and control boundaries; modular and reversible.

## Current implementation
The CLI collects bounded memory, uptime, kernel release, pressure and installed dpkg metadata, independently queries one selected systemd service, and reads text-free journal event classes. Observations share a typed evidence contract. JSON Lines v1 has an independent JSON Schema validator. Complete captures add closed profiles, per-source timing and failure reasons ([ADR 0002](adr/0002-complete-captures-and-admission.md)), an opt-in collection timeline and boot binding ([ADR 0010](adr/0010-capture-timeline-and-freshness.md)) and an answer to a consumer challenge ([ADR 0014](adr/0014-consumer-challenge-freshness.md)). An optional Python utility compares captures offline, orders same-boot captures, and verifies signatures and challenge age bounds; row-level freshness stays unknown.

Seven narrow expectation templates separate the operator's criterion from the embedded evidence and leave application health and root cause unassessed:
- service-active (v1, or explicit v2 with `unit_not_found`; [ADR 0001](adr/0001-read-only-service-investigation.md), [ADR 0006](adr/0006-service-active-v2-unit-not-found.md))
- memory-headroom/v1 ([ADR 0005](adr/0005-explicit-memory-headroom.md))
- pressure-ceiling/v1 ([ADR 0007](adr/0007-explicit-pressure-ceiling.md))
- package-installed/v1, with vulnerability exposure unassessed ([ADR 0008](adr/0008-explicit-package-installed.md))
- uptime-minimum/v1 and kernel-release/v1 ([ADR 0009](adr/0009-explicit-uptime-and-kernel-release.md))
- journal-events/v1 ([ADR 0012](adr/0012-bounded-journal-events.md))

Their closed enum dispatch introduces no new execution capability. `mira` signs and verifies its own captures and reports through `ssh-keygen` ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)). A qualification runner executes the independent validators on real hosts and writes host-identifier-free receipts ([ADR 0013](adr/0013-host-qualification-protocol.md)). The shared operator–agent workspace ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)) has its session core: a signed, append-only log with roles from the header, directives and a close receipt. Its broker and agent are not implemented yet. Native CI covers subprocess failures and live unprivileged systemd, procfs, dpkg and journal comparisons. Experimental CLI-only Debian packaging has archive, lifecycle, lintian and repeatable-assembly checks. These are observations, narrow expectation templates and packaging evidence, not a general diagnostic service, advisory correlator, natural-language intent system or UI. The retained grid simulation and in-memory verifier use caller-supplied actor/grant values, not authenticated identities.

## Required follow-up
Signer identity ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)), same-boot ordering ([ADR 0010](adr/0010-capture-timeline-and-freshness.md)) and challenge-bounded capture age ([ADR 0014](adr/0014-consumer-challenge-freshness.md)) are implemented; hardware-bound host identity and trusted host time remain open. Collect reviewed qualification receipts from the required host classes ([ADR 0013](adr/0013-host-qualification-protocol.md)); add further sources only with bounded contracts; extend read-only templates only with explicit criteria and evidence contracts before higher-level inference. Retain disposable-container dependency evidence and complete physical-host, genuine package upgrade and independent-host reproduction gates. Authentication, scoped authority and recovery remain prerequisites for any future write adapter. See [requirements](requirements.md), [roadmap](roadmap.md) and [validation](testing.md).

The [service investigation ADR](adr/0001-read-only-service-investigation.md) records pattern fit, alternatives, semantics and validation. Generic workflow engines, audit chains, transport authentication and background collection remain deferred until their boundaries are needed.

[Complete captures and admission](adr/0002-complete-captures-and-admission.md) add closed host/pressure profiles, operator-asserted scope and per-source timing/failures without introducing runtime dependencies or modifying existing v1 projections.

[ADR 0003](adr/0003-locked-tooling-and-fresh-builds.md) specifies the hash-locked validation closure and fresh source/target compilation comparisons against selected artifacts; the shared runner/compiler/system dependency environment limits that evidence.
