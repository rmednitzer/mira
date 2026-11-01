# ADR 0015: shared mixed-initiative investigation workspace

Status: **Accepted**, 2026-11-01 (proposed and reviewed the same day). **Amended** the same day with the validated [interfaces](#interfaces-amended-2026-11-01): a stdio MCP adapter for the agent; tmux only as an optional operator layout. Not yet implemented.

## Context

MIRA's goal is a workspace in which an operator and an AI model both act, as a real mixed-initiative system. Either party can take the initiative, each contributes what it does best, and the rules about who may do what are explicit, enforced and visible to both. The [research basis](../research/mixed-initiative.md) collects the evidence this design follows.

What exists today:

| Need | Exists | Missing |
|---|---|---|
| Shared state | Typed, versioned evidence, captures and reports; explicit unknowns; signatures ([ADR 0011](0011-host-identity-and-capture-integrity.md)); same-boot order ([ADR 0010](0010-capture-timeline-and-freshness.md)); challenge-bounded age ([ADR 0014](0014-consumer-challenge-freshness.md)) | Nothing holds a whole investigation together |
| Shared actions | Seven closed, read-only templates and complete captures, with arguments validated before acquisition, all signable | No way for a second party to use them under rules |
| Initiative and authority | The retained grid kernel: Manual, Advisory, Assisted and Delegated modes, expiring grants, human precedence, stale-proposal rejection, terminal immutability, an exhaustive 720-case matrix | It is a simulation with caller-claimed actors, not part of the operations domain |
| Record | In-memory replay traces; per-document signatures | No session log; no distinct, verifiable principals |

The roadmap puts a workspace at Phase 3 and AI at Phase 4, after security-advisory correlation (Phase 2). The vision says AI "may recommend or summarize", which is less than acting. Both understate the goal.

## Criteria

From the research basis:

1. **Common ground:** one shared, ordered record. Every action, result, finding, question, proposal and decision is an entry naming its principal and the entries it rests on.
2. **Observability, predictability, directability** (Johnson et al.; Klein et al.; Chen et al.'s SAT model):
   - the agent announces its intent before acting (SAT level 1)
   - findings carry their reasoning as cited evidence (level 2)
   - proposals state the action and its expected effect (level 3)
   - transparency runs both ways: the agent reads the operator's directives, decisions and answers in the same log
   - its autonomy level and remaining budget are visible
   - operator directives take effect at once
   - the operator can stop the agent at any time
3. **Autonomy per function, below the critical boundary** (Parasuraman et al.; the Onnasch et al. meta-analysis): set separately for evidence acquisition, analysis, decision and action. It never extends past information analysis into decision or action selection, where the meta-analysis found failure costs concentrate. It is bounded, expires and is never inferred from the model. It is *adaptable* (Miller and Parasuraman): only operator directives change it. It is never *adaptive*: there is no machine-initiated trading of authority (Inagaki), because read-only investigation is not time-critical.
4. **The operator stays in the loop** (Bainbridge; Endsley and Kiris): the operator reaches the conclusion. The default autonomy is intermediate, and a model failure leaves a session the operator can continue alone.
5. **Calibrated reliance** (Lee and See; Bansal; Buçinca; Vasconcelos):
   - claims come from a closed vocabulary, never persuasive narrative
   - checkable claims are checked mechanically, and the check result is shown
   - inferences are labelled as such
   - verifying a claim is cheap
   - forcing functions are available
6. **Injection-resistant by construction** (Greshake; Rule of Two; OWASP LLM06; CaMeL): the agent reads untrusted, private host evidence, so it gets no state-changing capability and no external channel. Enforcement lives in an operator-side `mira` process that the agent does not control, never in the model or in anything the agent runs.
7. **Existing boundaries hold:**
   - read-only collection
   - no network
   - no model call inside `mira`
   - no new runtime dependency or Rust crate
   - `unsafe` stays forbidden
   - every existing format and command unchanged
8. **Evaluation before claims:** benefit is measured against an operator-only baseline before anything is claimed.

**Scope.** A session supports detection and analysis on one host, the Detect and Respond analysis activities of NIST SP 800-61 Rev. 3. Containment, eradication and recovery change state and stay in Phase 5.

## Alternatives

| Option | Consequence |
|---|---|
| A. Status quo: separate commands, AI deferred | The project's actual goal stays unaddressed |
| B. Give a model a shell or general tool access | Violates criterion 6: excessive agency, and a full Rule-of-Two violation through untrusted host data. Rejected |
| C. Embed a model client in `mira` | Adds network, credentials and a provider dependency to the core, against SEC-02 and the offline-first rule. Rejected |
| D. A chat UI first, structure later | Persuasive narrative without checkable structure is exactly what the over-reliance studies warn against. Rejected |
| E. Port the grid simulation as is | Its actors are claimed labels and its world is a grid. It keeps the right semantics but lacks identities and evidence |
| F. **A signed, append-only investigation session with a single writer side. The agent is a key-holding principal that can only submit requests. An operator-run broker executes them within `mira`'s closed read-only capabilities and ported arbitration rules, and signs every result with a key the agent cannot use. Findings are machine-checked against those results. The model runs outside `mira`** | Meets the criteria. Its value is unproven until evaluated (stage 3) |

## Decision (option F)

### Principals, keys and the broker

Enforcement must run in a process the agent does not control. If the agent invoked `mira` itself, a modified binary could skip every check. If it held a key that signs results, it could fabricate a result and a matching report without collecting anything. So the session has three keys, and its log has a single writer side. The operator's `allowed_signers` file, kept outside the session directory and passed to every session command, binds the principal names to keys. Roles come from the operator-signed header, never from an entry that claims one.

| Principal | Holder | Signs |
|---|---|---|
| operator | the human | Header, decisions, directives, close, and the operator's own entries |
| collector | the operator's account; used only by `mira session run` | Every action result and its document, and the envelope that records each agent request in the log |
| agent | the agent process, under its own OS user | Only its requests: intent with action, finding, question, proposal |

`mira session run DIR` is the **broker**. It is a foreground process the operator starts in their own terminal, not a service, and it stops on `close` or interrupt. It is the only component that executes actions for the agent. For each signed agent request in the session's inbox, it:
1. verifies the agent's signature;
2. checks the autonomy level, the budget, the closed capability set and the argument syntax;
3. runs the action with the collector key and stores the collector-signed document;
4. appends the agent's original signed bytes, the outcome and the result to the log, inside a collector-signed envelope, or appends a refusal with a fixed reason;
5. removes the request from the inbox.

All new signatures use a new namespace, `mira-session-v1@rmednitzer.github.io`.

### Session layout and separation

`mira session start DIR ...` creates `DIR` exclusively, with:
- `entries/` and `documents/`: the ordered log and the signed result documents. They are written only by operator-side processes (the operator's session commands and the broker), are owned by the operator's user, and can be read by the agent's group but not written by it.
- `inbox/`: group-writable for a dedicated agent group (`--agent-group GROUP`). The agent drops its signed requests here.

In the log, each entry is one file, `entries/NNNNNN.json` with `.sig`, created exclusively, so the operator's commands and the broker can never take the same sequence number. Entry 0 is the operator-signed header. It holds a 256-bit session ID from `/dev/urandom`, the three principal names and roles, the operator's question, the initial autonomy level, the agent's action budget, and the separation mode. Every entry carries the session ID, its sequence number, its kind, its principal and `based_on`, the sequence number of the latest entry its author had seen. The fixed layout puts the free-text note last, so `mira` can read the state fields of its own entries without a general JSON parser. A closed `session-v1` schema and an independent Python validator check entries as well.

**Separation modes.**
- **`separate_user`** is required for any model-driven agent. The agent's OS user cannot write `entries/` or `documents/`, and cannot read or use the operator's or collector's keys. The broker confirms that each inbox file belongs to the agent's user and not to its own.
- **`same_user`** is for trusted scripted agents in tests and demonstrations only. Nothing then stops the agent from writing the log or using the collector key. `show` and `verify` label such a session "not separated", and it supports no claim that the agent was contained.

**Integrity without a new hash primitive.** Each entry's signature covers its session ID and sequence number:
- modification and cross-session replay are detected
- a missing middle entry leaves a gap that is detected
- a `close` entry, signed by the operator, records the final count

Deleting the close entry, and any tail before it, would leave something indistinguishable from an open session. Two protections cover that:
- under `separate_user`, the agent cannot delete log entries at all
- `mira session close --receipt PATH` writes the signed close record, exclusively, to a path outside `DIR`; `mira session verify DIR --allowed-signers FILE --expect-close PATH` then detects truncation or a removed close

Without a receipt, the guarantee is narrower: missing entries are detected only while the close entry survives.

### Entry kinds

| Kind | Who | Meaning |
|---|---|---|
| `header` | operator | Session ID, principals, question, autonomy, budget, separation mode |
| `intent` + `action` | agent request, or operator | What the author is about to do and why, then one closed capability with arguments. An agent submits both in one request, so intent always precedes action |
| `result` | collector | The collector-signed document, and the template, outcome, reason and evidence availability that the broker itself computed |
| `finding` | agent request, or operator | A claim from a closed vocabulary, citing entries, with a confidence label and a bounded, unchecked note |
| `question` | agent request, or operator | Asks the other party, the dialog for resolving uncertainty. It queues and never interrupts |
| `proposal` | agent request | An action outside the agent's current autonomy, awaiting a decision |
| `refusal` | collector | An agent request that failed verification, autonomy, budget, capability or claim checks, with a fixed reason |
| `decision` | operator | Approves or rejects a proposal; accepts, rejects or marks a finding uncertain. Records the operator's own assessment |
| `directive` | operator | Changes the autonomy level or budget, grants delegation with an expiry, or stops the agent |
| `close` | operator | The operator's conclusion, which may cite findings, and the final entry count |

### Capabilities (the agent's entire action set)

These are exactly the existing signable, read-only commands, with their existing argument checks:
- `capture` with the `host/v1` or `host-pressure/v1` profile (always with a timeline)
- the seven `investigate` templates with `--json`

There is no shell, no file read, no network, no `verify`, no `challenge`, no `session` recursion and no new capability. `capture --bind-boot` collects a linkable identifier, so it is **operator-only**: the agent can only propose it, or request it under delegation. The broker executes every agent action in the operator's process, under the operator's permissions, and signs the result with the collector key. The agent never runs a host command and never signs a result.

### Autonomy levels (ported from the grid kernel)

| Level | Grid mode | Acquisition | Analysis | Decision | Action implementation |
|---|---|---|---|---|---|
| `manual` | Manual | Operator only | Operator only | Operator | None exists |
| `advisory` | Advisory | Agent proposes | Agent findings and questions | Operator | None exists |
| `assisted` (default) | Assisted | Agent acts within its budget | Agent findings and questions | Operator | None exists |
| `delegated` | Delegated | As assisted, plus operator-only read capabilities under an unexpired grant | As assisted | Operator | None exists |

The decision column never moves. Only the operator decides on proposals and findings and closes the session.

The kernel's invariants carry over as enforced rules, each with tests:
- **Operator precedence.** A `stop` directive sets the level to `manual` from its sequence number on. The broker refuses any agent request it has not yet executed, with reason `superseded_by_directive`, even if the request was submitted earlier.
- **Expiry.** A delegation grant ends after an entry count or an operator-clock deadline set in the directive. After that the level reverts to `assisted`.
- **Staleness.** When the operator decides on a proposal whose `based_on` is older than a newer result for the same capability and arguments, `mira` flags it stale, and approving it requires `--despite-stale`.
- **Terminal immutability.** After `close`, every append is refused.
- **Budget.** Each agent action, finding and question consumes budget, so the agent cannot flood the operator, which is the alarm-burnout failure that SOC studies report (Alahmadi et al.). At zero the agent can only propose.

### Grounded findings

Claim vocabulary, version 1. Checks use only `result` entries signed by the collector. Those record the outcome and the evidence availability the broker computed, not anything the agent reported.

| Claim | Checked against the cited collector results |
|---|---|
| `expectation_satisfied` | Every cited result is a report with outcome `satisfied` |
| `expectation_not_satisfied` | At least one cited result has outcome `not_satisfied` |
| `expectation_indeterminate` | At least one cited result has outcome `indeterminate`, for any reason, including a transition in progress or an incomplete installation on evidence that was collected |
| `evidence_unavailable` | At least one cited result records unavailable evidence (status `unavailable` with a failure reason), or a capture with an unavailable source. An indeterminate assessment over collected evidence does not satisfy it |
| `hypothesis` | Never checked; requires a confidence label (`low`, `medium` or `high`); always shown as inference |
| `no_finding` | Nothing to check |

The broker refuses a checkable claim that its citations do not support. `show` and `verify` recompute every check from the log, so a check result is never taken on trust from an entry. `mira session show DIR` renders every finding with its principal, claim, check status (`checked` or `inference`), confidence, citations and staleness. Agent notes are labelled unchecked and escaped. Optional forcing: `mira session decide --own-assessment` records the operator's own view first, and a header flag can require that before agent findings are shown.

### The agent boundary

`mira` never calls a model and opens no socket. An agent is any process that reads the session and submits signed requests to its inbox with its own key. The agent-side command `mira session request` signs and drops a request; nothing it does is trusted until the broker has verified and recorded it. Stage 1 ships a deterministic scripted agent as test tooling. A model harness (stage 2) is separate optional tooling. Per AGENTS.md, it records the model identifier, provider, prompt revision, parameters, raw output and status as session documents. Host evidence is private and attacker-influenceable, so under the Rule of Two:
- real sessions use **local** models only
- hosted models see synthetic or public sessions only (existing policy)
- the agent never gets a state-changing or communicating capability

### Interfaces (amended 2026-11-01)

The workspace is the session log plus the broker, not any terminal or protocol. Two interfaces sit on top of it. Both were validated against the sources in the [research basis](../research/mixed-initiative.md#interfaces-mcp-and-terminal-multiplexers).

**Agent interface: a thin MCP adapter (stage 2).** `mira-agent-mcp` is a separate optional binary, outside the `mira` CLI package and its trust core. A model client launches it as a stdio MCP server under the agent's OS user. It turns MCP tool calls into signed requests in the session inbox and serves read-only resources. It does nothing else.
- **Transport:** stdio only, following MCP's stdio binding. It opens no socket, and Streamable HTTP is not offered.
- **Resources:** read-only views of the session's entries and collector-signed documents.
- **Tools,** mapped one-to-one to request kinds:
  - `request_action`: a capability from the closed list, with validated arguments
  - `post_finding`: a claim from the closed vocabulary, with citations and confidence
  - `ask`
  - `propose`

  There is no general tool to run `mira` or a command, and none will be added.
- **Authority:** only the agent's OS user and signing key. Under MCP's stdio rule, credentials come from the environment. Session paths and identifiers are names, never capabilities. The broker re-checks everything, so a compromised, poisoned or replaced adapter can at worst submit requests that get refused.
- **Tool definitions:** fixed and versioned, shipped with the adapter, and their hash recorded in the session header, because MCP clients must treat tool annotations as untrusted. Descriptions contain no instructions beyond describing the tool.
- **The model client in a MIRA session connects only to this adapter.** Any other MCP server or tool, such as a shell, a file reader, web fetch or messaging, would add an external channel or a way to change state, breaking the Rule of Two. It would also allow cross-server shadowing. The stage 2 harness is a MIRA-provided client host that enforces this. A third-party client must be configured the same way, which MIRA documents but cannot enforce.
- **Human in the loop:** MCP recommends confirmation prompts for tool calls. Here the broker's autonomy level and budget play that role for read-only requests, and any proposal waits for an operator decision. A client's own confirmation prompts are welcome but not relied on.

**Operator layout: tmux is optional.** One possible layout runs the broker, a following `mira session show` and the operator's shell in separate tmux panes. That is a convenience with no role in the trust model. tmux is **never** the agent's interface:
- a writable client can type into the operator's shell
- a read-only client sees everything the operator types
- keystrokes carry no principal
- the tmux manual warns against giving untrusted users access, even read-only

The tmux server must stay private to the operator's user.

### Operator interface

`mira session` subcommands. Operator side: `start`, `run` (the broker), `act`, `note`, `ask`, `decide`, `direct`, `close [--receipt PATH]`, `show [--json]`, `pending` and `verify [--expect-close PATH]`. Agent side: `request`. `show` is the shared view: timeline, pending questions and proposals, findings with check labels, current autonomy and budget. The CLI is the first interface. Registered adaptive views remain Phase 4.

## Trust, privacy and failure analysis

- **New boundary TB8, the agent principal.** The agent is untrusted. It can only submit signed requests. A broker it does not control enforces the closed read-only capability set, the operator-signed autonomy level and budget, and the claim checks. Only collector-signed results count as evidence, and the agent has no decision rights. The worst case is a wrong but labelled `hypothesis`, a refused request, a wasted budget, or a proposal the operator rejects.
- **Forged results.** An agent cannot produce a result that counts as evidence. It holds no collector key, cannot write the log or documents under `separate_user`, and cannot make the broker sign anything it did not collect itself. A modified `mira` on the agent side gains nothing, because nothing it writes is trusted.
- **Prompt injection.** Host strings reach the model through documents. They can steer the agent's text and requests, but they cannot widen its capabilities or bypass the broker's checks. The design does not claim the agent's reasoning is uncorrupted, only that corruption cannot act or pose as checked.
- **Same-user sessions.** Under `same_user`, the agent shares the operator's account, can write the log and may reach the keys. Signatures then make tampering detectable but not preventable, and such a session is labelled "not separated". It is limited to trusted scripted agents.
- **MCP adapter.** It is untrusted, like the agent. Its tool definitions are hashed into the header, and its requests are re-checked by the broker. A poisoned client configuration with additional servers breaks the Rule of Two, so the MIRA client host refuses it. A third-party client must be configured the same way.
- **Operator keys.** The operator's key should be passphrase-protected in `ssh-agent` with confirmation, or on a FIDO2 token. The collector key is unattended by design, so it must be readable only by the operator's user and used only by the broker.
- **Over-reliance.** It is mitigated (closed claims, check labels, inference labels, cheap citations, optional forcing) but not eliminated, as the studies report. Stage 3 measures it.
- **Disclosure.** A session holds host evidence and may hold the boot ID under delegation. It is private by default (mode 0700, or a dedicated group shared only with the agent user) and must not go to hosted services.
- **Availability.** Without an agent, a session is an operator's signed investigation log. If the broker stops, agent requests wait in the inbox and nothing runs. Without `ssh-keygen`, sessions fail closed (exit 4).
- **Resources.** At most 4096 entries per session, notes of at most 1 KiB, documents under the existing 1 MiB bound, and every action is already bounded.

## Stages and acceptance

### Stage 1: session core and scripted agent

Rust: the session layout, the broker and the subcommands, with tests run against the real `ssh-keygen`:
- every entry kind and every refusal reason
- the exclusive-creation race between the operator's commands and the broker
- gap detection; truncation and close removal detected with `--expect-close`; cross-session replay
- the role taken from the header, never from a claimed entry
- an agent-signed `result`, or a document not signed by the collector, never counting as evidence
- an inbox file owned by the broker's own user refused under `separate_user`
- every autonomy level, with budget exhaustion, expiry, `stop` precedence, a stale decision, and terminal refusal
- every claim kind, checked and refused, including `expectation_indeterminate` against `evidence_unavailable` on a transition and on an incomplete installation
- operator-only `--bind-boot`
- refusal of any capability outside the closed set
- unchanged existing commands

Independent tooling: a `session-v1` schema and a validator that recomputes autonomy, staleness and claim checks; a deterministic scripted agent; a qualification group gated on `ssh_keygen`. A live separate-user test runs where the host permits creating a test user. Otherwise it is recorded as not applicable.

### Stage 2: local model harness

Optional tooling outside the CLI package: the `mira-agent-mcp` stdio adapter and a MIRA-provided client host that connects a local model to that adapter and nothing else, with full model-I/O recording. Acceptance adds:
- tool definitions whose hash matches the header
- a refused request for anything outside the request kinds
- a client host that refuses to start with any other MCP server configured
- a tool-poisoning and rug-pull fixture showing that a changed adapter description is detected Utility and security are measured together, in the style of AgentDojo:
- **Fixtures:** hostile-content fixtures put injection strings in journal unit names, dpkg versions and service states.
- **Adaptive attacks:** the tests use adaptive, human-red-team attacks, not only static strings, because adaptive attacks bypass published defenses (Nasr et al. 2025).
- **Pass condition:** under any attack, the agent never exceeds its capabilities, never gets a result recorded that the collector did not produce, and never posts a false checked claim.

No detector or filter is part of the security argument.

### Stage 3: evaluation

Matched tasks on synthetic fault fixtures compare the operator alone with the operator plus agent. They measure:
- conclusion correctness
- time
- evidence entries opened (the vision's evidence-access measure)
- over-reliance: acceptance of seeded wrong agent findings
- override rate

They use the methods of Bansal et al. and Buçinca et al. Participants are stratified by expertise, because assistance effects can differ between novices and experts (Edelman et al.). Each operator's preferred autonomy level is recorded separately from performance, because analysts may prefer the extremes (Tilbury and Flowerday 2025) even where intermediate autonomy fails less. Results, positive or negative, are recorded before any claim of benefit (UI-01).

## Consequences and rollback

- **Blast radius:** one new `session` subcommand family, one signature namespace, the session-v1 format, and test and validator tooling. Existing commands, formats and outputs are unchanged.
- **Rollback:** removing the subcommands leaves every other feature intact. Session directories are inert files.

The roadmap moves the shared workspace ahead of security-advisory correlation, and the vision states the mixed-initiative goal directly.

## Review decisions

1. **Default autonomy:** `assisted`. The agent gathers evidence within its budget and the operator decides, the intermediate level the out-of-the-loop research favours.
2. **Separation:** a separate OS user is **required** for model-driven agents. `same_user` exists only for trusted scripted agents in tests and demonstrations, and is labelled "not separated".
3. **Integrity:** per-entry signatures with sequence numbers, a signed close and an external close receipt. No hash chain, which would need a new subprocess or MIRA's first crate.
4. **Forcing functions:** opt-in, through `--own-assessment` and the header flag.
5. **Roadmap:** the shared workspace is Phase 2, ahead of security-advisory correlation.

The automated Codex review covered the first proposal, whose three findings were fixed in this PR. At the maintainer's instruction, later revisions were accepted without a further automated review.

## Primary references

See the [research basis](../research/mixed-initiative.md) for every source, with its evidence type and the design rule taken from it.
