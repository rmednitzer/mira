# Architecture decision records

Material changes are decided here first, in a design pull request, and implemented in a separate one. Each record states its context, criteria, alternatives, decision, trust analysis, acceptance tests and rollback. Its status line says whether it is implemented and links the user guide.

| ADR | Decision | Status | Guide |
|---|---|---|---|
| [0001](0001-read-only-service-investigation.md) | Evidence-bound, read-only service-active investigation | Implemented | [investigations](../investigations.md) |
| [0002](0002-complete-captures-and-admission.md) | Complete scoped captures (capture-v1, evidence-v2) and strict offline admission | Implemented | [captures](../captures.md) |
| [0003](0003-locked-tooling-and-fresh-builds.md) | Hash-locked Python tooling and fresh source/target build comparisons | Implemented | [testing](../testing.md#tooling-lock-and-fresh-compilation) |
| [0004](0004-staged-platform-observation.md) | Stage Kubernetes/Talos observation separately from remediation | Planning only | [platform integrations](../platform-integrations.md) |
| [0005](0005-explicit-memory-headroom.md) | memory-headroom/v1: an explicit MemAvailable minimum | Implemented | [memory](../memory-investigation.md) |
| [0006](0006-service-active-v2-unit-not-found.md) | service-active/v2: report `unit_not_found` | Implemented | [investigations](../investigations.md#service-activev2-unit-not-found) |
| [0007](0007-explicit-pressure-ceiling.md) | pressure-ceiling/v1: an explicit PSI `some avg10` ceiling | Implemented | [pressure](../pressure-investigation.md) |
| [0008](0008-explicit-package-installed.md) | package-installed/v1: dpkg presence of one named package | Implemented | [package](../package-investigation.md) |
| [0009](0009-explicit-uptime-and-kernel-release.md) | uptime-minimum/v1 and kernel-release/v1 | Implemented | [host](../host-investigations.md) |
| [0010](0010-capture-timeline-and-freshness.md) | Capture timeline (capture-v2), opt-in boot binding and same-boot ordering | Implemented | [captures](../captures.md#collection-timeline-capture-v2) |
| [0011](0011-host-identity-and-capture-integrity.md) | Detached OpenSSH signatures made and verified by `mira` | Implemented | [signatures](../signatures.md) |
| [0012](0012-bounded-journal-events.md) | Bounded, text-free, producer-bound journal event evidence | Implemented | [journal](../journal-investigation.md) |
| [0013](0013-host-qualification-protocol.md) | Representative host qualification runner and receipts | Implemented; required-class receipts outstanding | [qualification](../qualification.md) |
| [0014](0014-consumer-challenge-freshness.md) | Consumer-challenge freshness for signed captures (capture-v3) | Implemented | [signatures](../signatures.md#freshness-answer-a-challenge) |
| [0015](0015-shared-mixed-initiative-workspace.md) | Shared mixed-initiative investigation workspace: operator and agent principals, per-function autonomy, grounded findings | Accepted; stages 1 and 2 implemented; adaptive red-team rounds and stage 3 outstanding | [sessions](../sessions.md), [research basis](../research/mixed-initiative.md) |
