# Architecture — baseline ADR

Status: proposed operational architecture, partially implemented. Supersedes the rover as the primary product demonstration, but retains the grid simulator only as a deterministic arbitration fixture.

## Decision
Use a local-first Rust core with typed, allowlisted Linux evidence collectors and deterministic analysis. The core provides structured observations, findings, policies and evidence references. User intent selects an admitted investigation template. A future UI composes predeclared components from that structured state. Optional models are untrusted analyzers, isolated from execution.

## Logical flow
```text
Operator intent / selected template
    -> intent resolution (explicit session scope)
    -> read-only capability registry / policy
    -> bounded Linux collectors (procfs and later systemd, packages, journal)
    -> timestamped evidence and quality assessment
    -> rule-based findings / optional untrusted AI proposals
    -> report and trusted adaptive view
    -> explicit authorization gate (future changes only)
```

## Boundaries
TB1 operator/host session: the process runs under caller permissions; no assumed identity proof. TB2 host observations: procfs and future OS interfaces may be malformed, stale, unavailable or attacker-influenced. TB3 model inference: optional external providers receive synthetic/public inputs by default and never control authorization. TB4 UI: render registered view types and validate data; do not evaluate model-produced code. TB5 future change executor: separate admitted, scoped actor and policy, explicit approval and verification.

## Runtime constraints
No automatic privilege escalation, command execution or outbound network in the collector. Path roots are injectable for deterministic tests; production collection must constrain roots to approved OS interfaces. Files and outputs must have explicit size/time bounds. No silent cloud fallback. No assumption that a read-only file open gives a consistent global host snapshot.

## Architectural alternatives
1. No pivot: continue rover-only simulator. Lowest cost but fails practical AIOps objective.
2. General autonomous Linux agent: fast prototype but authorization and provenance are too weak.
3. **Chosen:** narrow read-only Linux core first, then intent and adaptive interface. Slower breadth, tractable evidence and control boundaries; modular and reversible.

## Current implementation
The repository has a small Rust grid simulation and in-memory experiment verifier. The new `linux` module parses bounded meminfo/uptime evidence; it is not yet a diagnostic service, advisory correlator, intent system or UI. Actor/grant values in the simulator are untrusted caller values.

## Required follow-up
Define durable evidence schema including source, freshness, collection errors and scope; add process/host identity and package provenance, independent adapters; improve delegated authority before any write operation; add integration tests on Ubuntu 26.04; establish an interactive read-only investigation before any LLM-operated action.
