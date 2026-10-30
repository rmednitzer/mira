# ADR 0004: stage platform observation separately from remediation

Status: accepted for planning only, 2026-10-30. No adapter implementation is authorized by this record alone.

## Context and decision drivers

MIRA's current product is an offline Linux investigator. Kubernetes and Talos can supply complementary workload and node OS evidence, but introduce remote identity, credentials, transport, API-version and disclosure boundaries absent from current collectors. The roadmap previously grouped broader infrastructure with governed remediation, obscuring that useful read-only integrations need transport/credential controls without requiring a write executor.

Drivers: practical diagnostic value, offline continuity, least privilege, bounded failure, Rust maintainability, digital sovereignty and evidence provenance. No fleet deployment, credential profile or compatibility range has been qualified.

## Options

| Option | Consequences |
|---|---|
| No change; remain local-only | Lowest maintenance and authority exposure; leaves platform evidence outside future investigations |
| Implement many ecosystem clients now | Faster breadth; unvalidated diagnostic value, dependency growth and poorly constrained credential/transport boundaries |
| Defer all remote reads until remediation | Avoids new boundaries now, but unnecessarily couples observation to a future write authority design |
| Stage one read-only adapter at a time | Chosen: retain local-first delivery and admit platform evidence through explicit per-adapter gates |

## Decision

Plan Kubernetes first and Talos as a distinct node OS candidate; permit an independently justified Talos investigation rather than imposing an artificial runtime dependency on Kubernetes collection. Metrics and GitOps remain conditional follow-ons. Local sources advance only when a concrete question needs them. The [integration plan](../platform-integrations.md) specifies candidates, contracts, credential/transport rules, sovereignty checks and acceptance evidence.

Do not select a client library, ship RBAC manifests or install tools in this documentation change. Require a separate implementation design, exact method/field and permission allowlists, supported-version fixtures and updated threat model. Read-only does not mean non-sensitive: even a GET can expose credentials or reach privileged proxy interfaces. No generic execution/plugin facility follows from the roadmap.

## Validation and consequences

Planning acceptance: synchronize roadmap, architecture, requirements and planned threat boundaries; validate local links and Markdown; review against primary platform documentation and existing offline constraints. Implementation acceptance requires the integration plan's negative and disposable-cluster tests, with exact requests observed. Platform documentation and passing CI for this document do not prove an adapter or deployment works.

The blast radius is documentation and future sequencing only. Local CLI, Rust dependencies, Debian relationships and schemas remain unchanged. Remote credential and dependency maintenance costs arise only if an adapter is later admitted. The tie-breaker is a reproducible investigation demonstrating useful new evidence under narrower authority than alternative workflows.

## Reversibility and rollback

Remove or reprioritize candidate entries without changing runtime or stored evidence. A future adapter must be independently disableable, preserve offline operation and introduce schema/profile changes explicitly. Its implementation ADR must state dependency removal, credential revocation and format compatibility limits before release.
