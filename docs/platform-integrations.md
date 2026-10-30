# Platform observation roadmap

Status: planned only, 2026-10-30. No Kubernetes, Talos, metrics, GitOps or container-runtime adapter is implemented. This plan adds no network access, credentials, commands or package dependencies. The offline Linux investigator remains the first product gate. See [ADR 0004](adr/0004-staged-platform-observation.md).

## Selection and order

Select integrations by a concrete diagnostic question, evidence unavailable from existing sources, bounded access, reproducible validation and maintenance cost. An ecosystem name alone is insufficient. Planning may proceed now; implementation requires the admission gates below. Kubernetes is the first platform candidate because workload and scheduling observations complement host evidence across distributions. Talos adds a separate node OS view; Kubernetes access does not confer Talos API access.

| Candidate | Useful question and proposed minimum evidence | Priority and condition |
|---|---|---|
| Kubernetes API | Why is a named workload not available? Selected workload/Pod status, owner references, namespace events and node conditions where authorized | First platform candidate; one explicit cluster/namespace/workload, fixed resource and field allowlists |
| Talos API | Does selected node OS/service evidence explain a Kubernetes node symptom? Allowlisted version, service and resource observations | Next candidate, or independently when a documented node investigation needs it; prove each API method is available under the admitted reader role |
| Prometheus-compatible metrics | Did pressure, resource use or errors change during the incident window? Fixed reviewed queries and bounded time-series results | Evaluate after target identity, timestamps and freshness can be correlated; choose one demonstrated question, not a generic query console |
| Local network, storage and container observations | Is a host condition invisible to current memory/pressure/service sources? Narrow counters, capacity or runtime metadata | Extend Phase 1 only for a fixture-backed diagnostic gap; privileged runtime sockets and arbitrary logs are not automatically admitted |
| GitOps status | Is the observed workload revision consistent with controller-reported reconciliation? Selected status/revision evidence | Defer until cluster observations provide a baseline; choose Flux or Argo CD only for a demonstrated use case and API contract |

No automatic cluster discovery, fleet crawl, continuous watch, new daemon, generic plugin framework or broad cloud/hypervisor adapter catalogue is planned in this increment. None of these candidates requires an LLM or adaptive UI. Remote observation can precede remediation; it still requires its own credential and transport design.

## Adapter admission gates

Before implementing each adapter, record:

1. A named investigation, fixed requested scope, expected evidence and comparison with no change or a smaller local-source addition.
2. A versioned evidence contract identifying the endpoint/trust configuration, explicit target selection, object/node identity and UID where available, source version, observation time, freshness limits and partial/unavailable results. Operator aliases and certificate validation alone do not establish workload identity or freshness. Cross-API snapshots are not atomic.
3. A closed request/response field allowlist and least-privilege permission manifest. Specify request count, response/decompressed byte and object limits, page limits, total deadline, concurrency and retry budget; fail explicitly on truncation or incomplete collection. Watches and unrestricted queries need separate justification.
4. Credential loading, renewal/expiry, endpoint selection and TLS verification rules. No implicit default context, automatic credential discovery, insecure TLS fallback, cross-origin credential forwarding or execution of credential plugins. An initial Kubernetes profile must reject executable authentication configuration; later plugin support would be a separately admitted execution boundary. Never export tokens, client keys, kubeconfig/talosconfig contents or raw authorization headers.
5. Version compatibility, Rust client/dependency and license review, feature/package isolation and failure behavior. Prefer maintained typed protocol clients when their scope and dependency cost are justified; compare fixed CLI wrapping before choosing. Rust implementation is required, but a new Rust dependency is not justified merely by ecosystem popularity. Neither kubectl nor talosctl becomes a core .deb dependency through this plan.
6. Synthetic hostile-response tests and a disposable supported-version integration target: authorization denied, unsupported fields/API versions, certificate/hostname failure, expired credentials, wrong target, pagination exhaustion, oversized payload, timeouts, rate limits, partial data and credential redaction. Assert exact outbound methods/resources and no attempted mutation. Verify the local offline CLI remains useful when the adapter is disabled or fails.

Kubernetes permissions must enumerate necessary get/list resources and scope. Do not use cluster-admin, wildcard resource access or the broad built-in view role as a shortcut. Do not request Secrets, ConfigMaps, logs or exec/attach/port-forward/proxy subresources in the initial profile. Exclude Pod specifications/environment from retained evidence; standard API responses can contain more fields than MIRA retains, so review this acquisition exposure explicitly. Even ordinary metadata, events and status messages can disclose personal or infrastructure information. Filtering output does not reduce what a credential can retrieve: justify unavoidable API read exposure and minimize retained fields.

For Talos, verify effective RBAC and exact version/method behavior rather than assuming the role name is sufficient. The documented `os:reader` role permits selected methods, including file listing but not file-content reads; `os:operator` also permits mutations such as reboot. Do not fall back to operator/admin credentials to make a diagnostic work. A denied necessary method is an unsupported investigation until redesigned.

## Sovereignty and data custody

The proposed adapters target operator-selected, self-hosted endpoints and preserve locally stored, versioned exports. No hosted account, proprietary control plane, remote support path or vendor cloud is required by the plan. Open protocols and exportable evidence reduce migration friction; they do not establish jurisdictional compliance or eliminate upstream dependency risk. Kubernetes and Talos ecosystem integration is not an endorsement of a hosted offering.

Before admitting a deployment profile, document controller ownership/jurisdiction, credential custody, endpoint/data residency, update and support access, foreign legal access exposure including the US CLOUD Act, offline behavior and exit/rebuild path. Unverified: these properties for any eventual target deployment; no target has been selected or assessed here. EU hosting alone does not establish sovereignty. Managed-service access or telemetry would require a separate decision and explicit authorization.

## Acceptance and deferral

Admit one adapter only when its defined investigation works with scoped credentials in disposable fixtures, negative cases preserve unknowns, secrets do not reach output and the disabled adapter changes neither offline behavior nor mandatory runtime dependencies. Then review whether the evidence adds diagnostic value over the existing workflow. If it does not, retain the design as deferred rather than shipping integration breadth.

No package, CLI command, API compatibility range or delivery date is promised. Remove the planned adapter entries to roll back this decision; existing capture-v1 and evidence-v1/v2 contracts remain unchanged. New source families require an explicit schema/profile revision rather than silently extending closed capture profiles.

## Primary-source basis

Reviewed 2026-10-30; these sources establish platform constraints, not MIRA implementation or compatibility:

- [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/): least privilege, namespace scope and risks from wildcard permissions and secret access.
- [Kubernetes kubeconfig guidance](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/): crafted configurations can execute code or expose files.
- [Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/): pagination, resource versions and watch semantics; a multi-source capture is not an atomic cluster snapshot.
- [Talos v1.14 RBAC](https://docs.siderolabs.com/talos/v1.14/security/rbac): reader/operator/admin distinctions and method-level access. This is a reviewed documentation version, not a supported MIRA target.
