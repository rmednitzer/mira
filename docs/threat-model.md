# Threat model — MIRA

> Scope (2026-10-30): implemented local Linux evidence collection, closed activation and explicit memory-expectation templates, serialization/comparison, native tests and experimental CLI packaging. The retained simulation has separate authority/control limitations below. Future natural-language intent, AI, UI, remote and write adapters require a new review; this document does not certify the proposed full operations product.

## Linux operations boundaries

- **Host evidence boundary:** procfs, systemd, journal, package databases and advisories may be stale, malformed, attacker influenced or inaccessible. Treat them as observations, never commands; bound reads, parse strictly, report collection failures.
- **Privilege boundary:** run as an ordinary user, never escalate automatically, avoid arbitrary shell and executable plugins; added privileged functionality requires a separate reviewed helper and explicit authorization.
- **Intent boundary:** natural language must only select admitted capabilities; it never grants them. AI-produced action plans are untrusted proposals.
- **Adaptive UI boundary:** only registered display components and scoped actions can be composed; never execute model-generated JavaScript or shell commands.
- **Vulnerability evidence boundary:** identifiers and upstream package versions alone do not prove exposure on Ubuntu; correlate distribution backports, package provenance and runtime applicability, preserving unknown states.
- **External inference boundary:** local is default; hosted AI receives only deliberately released synthetic/public inputs, has bounded budget and no direct execution access.
- **Future execution boundary:** remediation is out of scope for the MVP. Before adding writes, require scoped grants, operator confirmation, preconditions, independent postcondition verification and a recovery design.

### Current operational data flow

```mermaid
flowchart TD
    O["Operator: explicit command and scope"] --> C["Read-only collector under caller permissions"]
    P["Untrusted procfs and dpkg files"] --> C
    C --> S["Fixed systemctl query"]
    S --> C
    C --> E["Typed evidence and JSON Lines"]
    E --> I["Closed expectation assessment; no authority grant"]
    I --> H["Versioned report with original evidence"]
    E --> T["Optional offline schema/history tooling"]
```

Invalid UTF-8 arguments are rejected before dispatch with a fixed usage diagnostic; raw bytes are not printed. The executable search environment is supplied by the caller. Files, systemd output and stored captures cross untrusted-data boundaries; none can grant execution authority. Historical captures have no authenticated host identity or chronology.

### Collector and package controls

Uptime parsing validates both unsigned decimal fields before emitting an observed value, including the unexported aggregate idle field. Malformed or overflowing input remains unavailable without suppressing independent sources; idle greater than uptime is valid on multicore hosts. This does not authenticate procfs.

The systemd child uses fixed argv, closed stdin, no shell and no privilege escalation. A nonblocking local socket and one deadline cover execution and stdout EOF, including inherited writers after direct-child exit. Output is capped at 8 KiB and the direct child is reaped on every post-spawn return path. This bounds collection, not arbitrary descendant execution. The admitted production executable remains systemctl resolved through the caller's trusted PATH; the caller's environment is not an authentication boundary.

Selection and error flags do not erase installed-package provenance. Local dpkg records and build-distribution ELF dependency metadata are unauthenticated inputs. Package assembly derives versioned ABI dependencies with dpkg-shlibdeps and normalizes its umask; repeated assembly compares one binary under different invoking masks. A separate test compares fresh source/target compilations and selected artifacts under path/timezone/umask variations within one native runner/compiler environment; independent hosts and hermetic toolchains remain unqualified. Native Cargo subprocess fixtures are admitted only by the non-default test-support feature and are excluded from the package. They substitute a per-child PATH, never the test process environment; their inherited writer has a finite five-second lifetime. Python schema/history tooling is separate from the Rust CLI and native suite. The separate disposable-container apt test adds real dependency-resolution and installed-byte/CLI evidence; it does not establish physical-host or upgrade behavior, signed provenance or an unattended collector sandbox.

The native source-boundary matrix checks each of the seven pressure-profile sources at its exact byte budget, one byte over and with invalid UTF-8. It verifies source-specific failures and preserved independent observations through the capture path. These fixtures do not prove deadlines for arbitrary filesystems or representative host coverage.

### Capture admission and completeness

Capture-v1 uses an explicit operator label and closed source profile; neither is authenticated host identity. Evidence-v2 records add per-source monotonic elapsed time and fixed failure reasons without changing v1 exports. Missing PSI remains unavailable; no pressure threshold, trigger write or health inference is admitted. Completion means all requested results exist, not that observations are available, fresh or authentic.

Offline import opens nonblocking before descriptor validation, preserving symlink compatibility and caller responsibility for directory custody. Strict UTF-8, unique JSON keys, integer-only numeric tokens, bounded nesting and exact source coverage precede comparison. This prevents the tested FIFO replacement wait and ambiguous-key admission; arbitrary regular-file I/O still has no deadline or immutable snapshot guarantee. Decimal/exponent numeric tokens are rejected before floating-point conversion can change their meaning; valid integer tokens retain exact values. Failure-reason/error-kind consistency includes the io_failure fallback. Mismatched labels/profiles and mixed formats fail. Public captures can disclose operator-provided labels, so avoid sensitive identifiers. See [ADR 0002](adr/0002-complete-captures-and-admission.md).

### Investigation boundary

A closed enum selects service-active/v1 and validates one service scope before dispatch. It uses the existing systemctl query and no additional verb. The report binds the requested scope to its embedded evidence and a local evidence pointer. The pointer and enum are not authenticated provenance or an OS sandbox. A single assessment enum determines outcome and fixed reason, so unavailable/transitioning/unsupported states cannot silently become success. LoadState remains orthogonal to activation. Neither a satisfied condition nor schema validity grants mutation, proves application health or identifies a root cause.

New report/schema consumers must preserve that distinction and reject unsupported versions. Existing evidence-v1 output remains separate. Errors expose no arbitrary backend message in reports; human state strings are escaped. The [decision record](adr/0001-read-only-service-investigation.md) records alternatives, scope, rollback and the state-table/alias/error validation. Generic command classification, audit chains, durable stores and background supervision remain outside this increment.

### Explicit memory expectation

memory-headroom/v1 admits only a positive ASCII integer KiB criterion of at most 20 digits fitting u64. It reads only the existing bounded meminfo source. A private report binds criterion, observation and derived outcome; no model, network, new file source, command or authority is introduced. Missing/malformed evidence stays indeterminate. MemAvailable is a changing kernel estimate, not workload/cgroup capacity, application health, allocation assurance or a remediation trigger. The local/procfs scope is not authenticated identity. A separate schema preserves existing service/evidence/capture contracts. See [ADR 0005](adr/0005-explicit-memory-headroom.md).

### Planned platform observation boundary

Status: design constraints only; no remote adapter, credential loading or network request is implemented. [ADR 0004](adr/0004-staged-platform-observation.md) and the [integration plan](platform-integrations.md) require a separate implementation review.

```mermaid
flowchart TD
    O["Operator: explicit endpoint and scope"] --> A["Planned bounded Rust adapter"]
    K["Credential and trust configuration"] --> A
    A --> R["Remote API and authorization boundary"]
    R --> A
    A --> V["Allowlisted fields and evidence contract"]
    V --> E["Local evidence; uncertain cross-source identity"]
```

| Plausible threat | Planned boundary control and verification |
|---|---|
| Spoofing or wrong cluster/node | Explicit endpoint and target binding, verified TLS, no default-context fallback; wrong-target and certificate failure fixtures |
| Tampered/stale API evidence or repudiated provenance | Versioned source/object identifiers and timing, preserve partial/unknown results; conflicting identifiers and version fixtures; unsigned evidence is not independent attestation |
| Credential or personal/infrastructure data disclosure | Explicit credential loading, reject executable auth configuration, exclude secret-bearing resources/fields, redact output and diagnostics; hostile response and credential-leak tests; API read exposure must also be justified |
| Denial of service from lists, pagination or reconnects | Total deadline, byte/object/page/request and retry budgets; truncation, rate-limit and timeout tests; no unbounded watches |
| Elevation of privilege through apparently read-only calls | Exact method/resource and permission allowlists; exclude proxy/exec and mutation paths; no admin fallback; assert outbound requests in disposable targets |
| Privacy linkage across host, workload and node records | Minimize identifiers/retention, deliberate local export, no hosted telemetry by default; inspect emitted fields and require a deployment data-custody review |

These are hypotheses and admission criteria, not observed attacks or verified controls. Kubernetes RBAC and Talos roles are distinct authorization systems; access to one does not establish access to the other. A read-only role can still expose sensitive data. No hosted provider or target fleet sovereignty assessment is established by this plan.

### Operational acceptance checks

1. Malformed, missing, oversized and contradictory Linux evidence cannot become a confirmed finding.
2. Read-only inspection does not mutate host state or trigger network/model operations.
3. Stale advisories, absent package provenance and uncertain backport status must produce *unknown*, not *affected* or *fixed*.
4. UI layout/model-output changes cannot add unregistered execution capabilities.
5. Remote/privileged adapters are rejected until separately modeled and authorized.



Status: v0.1 design baseline, 2026-10-30. Review at each new trust boundary. This is a threat model, **not** a claim of security certification or control-system safety.

## Retained simulation: system and assets
The retained fixture coordinates a human and an autonomous participant in a deterministic Rust grid simulation. Inputs are caller-supplied proposals (`Actor`, `Move`, `tick`), optional time-bound grants, and scenarios. The engine applies an arbitration decision and records events in process memory. It has no built-in identity verification, network-facing APIs, persistent audit ledger, real robots, or LLM integration today.

Protect: integrity of simulation state and outcomes; validity of arbitration; availability and resource bounds; reliability of event records; source/CI integrity. Future extension assets include credentials, model requests, scenario provenance and user data.

## Retained simulation: trust boundaries and DFD

```text
 [Human input]             [Scripted / future LLM agent]
      |                                |
      | TB1 untrusted proposals        | TB1 untrusted proposals
      +------------+-------------------+
                   v
       [MIRA runner / coordination API]
                   |
          [mode + caller-supplied grant]
                   | TB2 authorization semantics
                   v
            [Arbitration engine] ----> [decision records]
                   |
                   | validated command (internal)
                   v
          [Deterministic simulation]
                   |
                   +----> [in-memory events / outcome]
                              |
                         TB3 export boundary
                         (future persistence/UI)
```

TB0: repository/CI dependency and workflow supply chain (outside runtime DFD). TB4: future hosted inference endpoint, outside the present implementation. A model's output must never be considered an authorized instruction merely because it conforms to a response schema.

## Assumptions and explicit limitations
- Caller-provided `Actor` is an assertion, not authenticated identity. A malicious caller who can invoke the library can claim either actor.
- `Grant` is supplied per step, actor-specific and expires at a tick; it is not a signed or unforgeable capability, lacks scope and revocation, and is not an external security boundary.
- `Engine::step` validates movement against the grid; this is simulation consistency, not a guarantee of physical safety.
- In-memory events enable comparison within one version; cryptographic tamper evidence, durable replay and cross-version equivalence are not implemented.
- Local use is trusted-process execution. No real-world actuator connectivity is permitted under the current design.
- LLM, web, identity and remote-user interfaces are future features only.

## STRIDE analysis

| Threat | Boundary / asset | Current state | Required mitigation before expansion |
|---|---|---|---|
| Spoofing: agent claims human role | TB1 / authority | Caller controls actor enum | Bind principal to an authenticated, transport-independent session outside the untrusted payload |
| Tampering: forged grants or proposals | TB1–TB2 / arbitration | Grant is caller supplied | Issuer-controlled scoped grant registry, revocation, nonces or bounded epochs; reject unrecognized principals |
| Repudiation: events altered after run | TB3 / provenance | Volatile in-memory trace | Versioned, canonical event representation and replay verification; cryptographic integrity if adversarial persistence is introduced |
| Information disclosure: model request leaks private state | TB4 / observations | No model adapter today | Redaction and data classification; synthetic-only hosted tests; local inference by default |
| Denial of service: excessive scenarios or proposal volume | TB1 / availability | Basic dimension and tick validation | Limits on grid size, obstacle count, run length, request size, time and resource budgets |
| Elevation of privilege: unauthorized actuation | TB2 / control | Modes and expiry, no real principal | Single non-bypassable execution gate, scoped authorization and negative tests |
| Prompt injection: hostile scenario/model content | TB1/TB4 / instructions | No LLM presently | Strict separation of data from commands, structured output validation, least-privilege tool access |
| CI compromise: untrusted code obtains workflow token | TB0 / repository | CI has read-only token | Pin third-party actions, avoid privileged PR triggers, audit permissions, retain branch review gates |

## Safety and control hazards (not interchangeable with STRIDE)
- H1: command applied contrary to human override. Constraint: override must take precedence under explicitly defined arbitration policy.
- H2: stale, duplicated or out-of-order proposal changes state. Constraint: only current-tick authorized proposals may execute.
- H3: collision, timeout and goal completion reported inconsistently. Constraint: terminal outcome precedence must be explicit and exclusive.
- H4: authority expires or transport fails mid-task and unsafe behavior persists. Constraint: fail closed / safe no-op until a new authorized decision.
- H5: assistance changes operator intent unexpectedly. Constraint: assistance policy and every accepted/rejected intervention must be inspectable.

These constraints are requirements for future assurance tests, **not verified guarantees** across all failure modes.

## Attack hypotheses and tests
1. Inject agent proposal labeled `Human`: current public API can be impersonated; document as a design limitation until authenticated principals exist.
2. Supply expired grant or a stale proposal: expect no agent movement, with recorded rejection.
3. Submit an out-of-bounds command: expect stationary state and explicit rejection.
4. Attempt an additional step after a terminal outcome: expect an error and immutable state.
5. Repeated and oversized scenarios: define strict resource limits before accepting remote inputs.
6. Attempt to substitute a hosted-model response into the arbiter without authorization: future adapter must not circumvent the execution gate.
7. Mutate recorded traces: future replay must detect mismatches under an explicitly versioned format.

## Data handling and sovereignty
Keep simulation and scripted baselines offline. Hosted inference (including GitHub Models) is an optional external trust boundary; only synthetic/public content is permitted by default. Document provider, region and access assumptions rather than equating EU hosting with legal/operational sovereignty. Never publish credentials, personal telemetry, model-provider secrets or private infrastructure details.

## Residual risk / release gates
Current v0.1 residual risk is **high if treated as an authorization or real-world control system** and bounded for its stated offline educational simulation use. Prior to adding external agents, persistent storage, browser-to-host bridges or physical hardware: revise the DFD, establish authenticated principals and scoped delegation, define replay/event schemas, apply size/time limits, fuzz parser and state transitions, and obtain independent design review.

Ownership: maintainers. Update this document with every material interface or authority change.

Schema/history tooling installs only the complete version/wheel-hash lock and refuses source builds. A changed-wheel negative test requires an actual hash mismatch before installation. These controls identify admitted artifact bytes, not uncompromised publisher identity. Fresh-build receipts preserve source/toolchain/artifact identity but are unsigned, share runner/system dependencies and are retained for only 30 days. See [ADR 0003](adr/0003-locked-tooling-and-fresh-builds.md).
