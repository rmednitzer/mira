# Read-only service investigation v1

```sh
cargo run --locked -- investigate service-active ssh.service
cargo run --locked -- investigate service-active ssh.service --json
```

Selecting `service-active` explicitly asks whether one named system service reports an active activation state. It is an expectation, not a general health check. It never starts, stops, restarts, unmasks or discovers services. No model, network adapter, credentials or privilege escalation is introduced. The same existing fixed-argument systemctl collector supplies the evidence.

## Outcomes and exit status

| Reported ActiveState | Outcome | Reason | Exit |
|---|---|---|---|
| active, reloading, refreshing | satisfied | reported_active | 0 |
| inactive, failed, maintenance | not_satisfied | reported_not_active | 1 |
| activating, deactivating | indeterminate | transition_in_progress | 3 |
| Unrecognized state | indeterminate | unrecognized_active_state | 3 |
| Collection unavailable or rejected response | indeterminate | evidence_unavailable | 3 |
| Unknown template or invalid service-name invocation | No report or collection dispatch | Usage diagnostic | 2 |

Inactive or masked configuration can be intentional. LoadState is independent of ActiveState: an already active service may have a masked or invalid current definition. The template does not reinterpret SubState. Aliases remain valid when the collector binds both the requested name and canonical Id through Names.

A satisfied result does not establish application health, security, root cause or freshness. It means only that the admitted observation meets this versioned activation expectation. Transitions and unsupported future state vocabulary remain indeterminate. Permission errors, timeouts and parser failures are not evidence that a service is inactive or failed.

## Report contract

`--json` emits one report object and a trailing newline. `investigation_version` is 1 and `template` is `service-active/v1`. `scope` is the validated requested unit. `assessment` contains the outcome, fixed reason and `evidence_ref: "#/evidence"`. `application_health` and `root_cause` are both `not_assessed`.

The `evidence` member is the existing evidence-v1 service record, including source, scope, literal values or unavailable/error-kind state, recording timestamp and explicit unknown freshness/unverified clock. The JSON Pointer identifies supporting report data; it is not a digest, signature, trust label or authorization. No raw backend error message is exported. Human state values are escaped rather than emitted as terminal control sequences.

The [investigation schema](../schemas/investigation-v1.schema.json) references the unchanged [evidence schema](../schemas/evidence-v1.schema.json). Consumers must resolve that reference to their supplied local schema; validation tooling registers both locally and performs no remote schema retrieval. It also checks scope equality and that outcome/reason agree with the evidence, because structure alone does not establish those semantics. Schema validity does not authorize collection or action.

The Debian package includes both schemas under `/usr/share/mira/schemas/` and this guide under `/usr/share/doc/mira/`. Existing inspect/service commands and evidence JSON Lines v1 remain compatible. Existing evidence-history tooling consumes evidence-v1 captures, not the nested investigation report; it must not silently treat them as interchangeable formats.

## Design and validation

See [ADR 0001](adr/0001-read-only-service-investigation.md) for alternatives, semantics, bounds, authority, rollback and deferred mechanisms. Pure Rust cases cover the state table, masked-active semantics, source/identity rejection, alias-scope preservation and error redaction. Native fixture tests exercise the public CLI, rejected invocations, subprocess failures and terminal controls. Independent schema/semantic fixtures and a stable live unprivileged systemd comparison run on both native CI architectures.

This is one narrow Phase 1 template. Host identity/freshness policies, broader diagnostic workflows, advisory applicability, persistent evidence custody and representative fleet qualification remain separate work.
