# Architecture — baseline ADR

Status: proposed operational architecture, partially implemented. Supersedes the rover as the primary product demonstration, but retains the grid simulator only as a deterministic arbitration fixture.

## Decision
Use a local-first Rust core with typed, allowlisted Linux evidence collectors and deterministic analysis. The core provides structured observations, findings, policies and evidence references. User intent selects an admitted investigation template. A future UI composes predeclared components from that structured state. Optional models are untrusted analyzers, isolated from execution.

## Logical flow
| Stage | Implemented | Planned |
|---|---|---|
| Operator selection | Explicit CLI command, service scope and closed service-active, memory-headroom, pressure-ceiling, package-installed, uptime-minimum and kernel-release templates | Natural-language intent and additional reviewed templates |
| Evidence acquisition | Bounded procfs/dpkg reads and selected systemd query | Additional reviewed collectors; conditional platform observation adapters |
| Evidence contract | Typed observations, unavailable states, JSON Lines v1, complete capture-v1/evidence-v2, opt-in capture-v2 timeline and boot binding, and schemas | Authenticated host identity; trusted time for evidence age |
| Comparison and analysis | Offline comparison, same-boot capture ordering and versioned expectation templates with cited evidence | Broader diagnostic/advisory correlation |
| Presentation | Human-readable CLI and JSON Lines | Registered adaptive views |
| Authority | Caller OS permissions; no operational writes | Authenticated scoped executor and verified recovery |

## Boundaries
TB1 operator/host session: the process runs under caller permissions; no assumed identity proof. TB2 host observations: procfs, dpkg and systemd interfaces may be malformed, stale, unavailable or attacker-influenced. TB3 model inference: optional external providers receive synthetic/public inputs by default and never control authorization. TB4 UI: render registered view types and validate data; do not evaluate model-produced code. TB5 future change executor: separate admitted, scoped actor and policy, explicit approval and verification.

## Runtime constraints
No automatic privilege escalation, arbitrary command execution or outbound network in the collectors. The service adapter executes only a fixed-argument, read-only systemctl query under caller permissions. Path roots are injectable for deterministic tests; production collection must constrain roots to approved OS interfaces. Files and outputs must have explicit byte bounds. Systemd queries also have an execution/EOF deadline; ordinary filesystem I/O has no universal application deadline. No silent cloud fallback. No assumption that a read-only file open gives a consistent global host snapshot.

## Planned platform observation boundary

Kubernetes and Talos are separate candidate sources, not generic command tools or extensions of local capture-v1. [ADR 0004](adr/0004-staged-platform-observation.md) separates remote observation from remediation. Each adapter needs explicit endpoint/target selection, scoped credentials, verified transport, allowlisted methods and retained fields, bounded pagination/requests, an evidence/schema contract and supported-version fixtures before implementation. No implicit context/credential discovery or executable authentication plugins are admitted by the plan. Cross-source identity and freshness remain explicit uncertainties.

TB6 (planned) covers remote endpoint, credential and response handling. It does not exist in the current runtime. Existing collectors remain offline; optional remote adapters must fail without changing their behavior or core package dependencies. See [candidate scope and acceptance](platform-integrations.md) and the [planned threat analysis](threat-model.md#planned-platform-observation-boundary).

## Architectural alternatives
1. No pivot: continue rover-only simulator. Lowest cost but fails practical AIOps objective.
2. General autonomous Linux agent: fast prototype but authorization and provenance are too weak.
3. **Chosen:** narrow read-only Linux core first, then intent and adaptive interface. Slower breadth, tractable evidence and control boundaries; modular and reversible.

## Current implementation
The CLI collects bounded memory, uptime, kernel release, CPU pressure and installed dpkg metadata, and independently queries one selected systemd service. Observations share a typed evidence contract. JSON Lines v1 has an independent JSON Schema validator; an optional Python utility compares captures offline with explicit unknown freshness. Native CI covers subprocess failures and one unprivileged live systemd service. The memory-headroom/v1 investigation compares only bounded memory evidence with an explicit operator minimum, preserving unknowns and leaving cgroup/workload health unassessed; see [ADR 0005](adr/0005-explicit-memory-headroom.md). The pressure-ceiling/v1 investigation compares one selected resource's bounded PSI `some avg10` with an explicit operator ceiling and embeds the evidence-v2 record; see [ADR 0007](adr/0007-explicit-pressure-ceiling.md). The package-installed/v1 investigation reports dpkg presence for one explicitly named package, exporting only that package's records and leaving vulnerability exposure unassessed; see [ADR 0008](adr/0008-explicit-package-installed.md). The uptime-minimum/v1 and kernel-release/v1 investigations compare existing uptime and kernel-release evidence with an explicit minimum and an exact expected release; see [ADR 0009](adr/0009-explicit-uptime-and-kernel-release.md). The opt-in service-active investigation (v1, or explicit v2 with `unit_not_found`; see [ADR 0006](adr/0006-service-active-v2-unit-not-found.md)) separates its three-state expectation assessment from the embedded evidence and leaves application health/root cause unassessed. Its closed enum dispatch introduces no new execution capability. Experimental CLI-only Debian packaging has archive, lifecycle, lintian and repeatable-assembly checks. These are observations, six narrow expectation templates and packaging evidence, not a general diagnostic service, advisory correlator, natural-language intent system or UI. The retained grid simulation and in-memory verifier use caller-supplied actor/grant values, not authenticated identities.

## Required follow-up
Establish host/process identity and freshness policies (the [ADR 0010](adr/0010-capture-timeline-and-freshness.md) capture timeline, boot binding and same-boot ordering are implemented; trusted time for age at consumption remains open); expand representative host and collector failure validation; add journal and further sources only with bounded contracts; extend read-only templates only with explicit criteria and evidence contracts before higher-level inference. Retain disposable-container dependency evidence and complete physical-host, genuine package upgrade and independent-host reproduction gates. Authentication, scoped authority and recovery remain prerequisites for any future write adapter. See [requirements](requirements.md), [roadmap](roadmap.md) and [validation](testing.md).

The [service investigation ADR](adr/0001-read-only-service-investigation.md) records pattern fit, alternatives, semantics and validation. Generic workflow engines, audit chains, transport authentication and background collection remain deferred until their boundaries are needed.

[Complete captures and admission](adr/0002-complete-captures-and-admission.md) add closed host/pressure profiles, operator-asserted scope and per-source timing/failures without introducing runtime dependencies or modifying existing v1 projections.

[ADR 0003](adr/0003-locked-tooling-and-fresh-builds.md) specifies the hash-locked validation closure and fresh source/target compilation comparisons against selected artifacts; the shared runner/compiler/system dependency environment limits that evidence.
