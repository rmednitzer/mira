# ADR 0015: shared mixed-initiative investigation workspace

Status: **Proposed**, 2026-11-01.

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
2. **Observability, predictability, directability:**
   - the agent announces its intent before acting
   - its autonomy level and remaining budget are visible
   - operator directives take effect at once
   - the operator can stop the agent at any time
3. **Autonomy per function** (Parasuraman et al.): set separately for evidence acquisition, analysis, decision and action. It is bounded, expires, and is never inferred from the model.
4. **The operator stays in the loop** (Bainbridge; Endsley and Kiris): the operator reaches the conclusion. The default autonomy is intermediate, and a model failure leaves a session the operator can continue alone.
5. **Calibrated reliance** (Lee and See; Bansal; Buçinca; Vasconcelos):
   - claims come from a closed vocabulary, never persuasive narrative
   - checkable claims are checked mechanically, and the check result is shown
   - inferences are labelled as such
   - verifying a claim is cheap
   - forcing functions are available
6. **Injection-resistant by construction** (Greshake; Rule of Two; OWASP LLM06; CaMeL): the agent reads untrusted, private host evidence, so it gets no state-changing capability and no external channel. Enforcement lives in `mira`, not in the model.
7. **Existing boundaries hold:**
   - read-only collection
   - no network
   - no model call inside `mira`
   - no new runtime dependency or Rust crate
   - `unsafe` stays forbidden
   - every existing format and command unchanged
8. **Evaluation before claims:** benefit is measured against an operator-only baseline before anything is claimed.

## Alternatives

| Option | Consequence |
|---|---|
| A. Status quo: separate commands, AI deferred | The project's actual goal stays unaddressed |
| B. Give a model a shell or general tool access | Violates criterion 6: excessive agency, and a full Rule-of-Two violation through untrusted host data. Rejected |
| C. Embed a model client in `mira` | Adds network, credentials and a provider dependency to the core, against SEC-02 and the offline-first rule. Rejected |
| D. A chat UI first, structure later | Persuasive narrative without checkable structure is exactly what the over-reliance studies warn against. Rejected |
| E. Port the grid simulation as is | Its actors are claimed labels and its world is a grid. It keeps the right semantics but lacks identities and evidence |
| F. **A signed, append-only investigation session. The operator and the agent are distinct key-holding principals acting only through `mira`'s closed read-only capabilities, under ported arbitration rules, with machine-checked findings. The model runs outside `mira`** | Meets the criteria. Its value is unproven until evaluated (stage 3) |

## Decision (option F)

### Principals and roles

A session has exactly two principals, each identified by an OpenSSH signing key ([ADR 0011](0011-host-identity-and-capture-integrity.md)):
- **operator:** a human, who owns the session.
- **agent:** a process, scripted or model-driven.

The operator's `allowed_signers` file binds both principal names to keys. The operator keeps that file outside the session directory, and every session command takes it as an argument. Every entry is signed under a new namespace, `mira-session-v1@rmednitzer.github.io`. A role comes from the operator-signed session header, never from the entry that claims it. This replaces the grid kernel's caller-claimed `Actor` with verifiable identity.

### Session layout

`mira session start DIR ...` creates `DIR` exclusively. It is mode 0700 when both parties run as the operator's user, or, with `--shared-group GROUP`, group-writable and setgid for a dedicated group shared with a separate agent user. It writes:
- `entries/NNNNNN.json` with `.sig`: one entry per file. The file is created exclusively, so two writers can never take the same sequence number. The loser of a race re-reads the state and retries at the next number.
- `documents/NNNNNN.json` with `.sig`: the exact signed capture or report produced by an action entry.

Entry 0 is the header, signed by the operator. It holds:
- a 256-bit session ID from `/dev/urandom`
- both principal names and roles
- the operator's question
- the initial autonomy level and the agent's action budget

Every entry carries the session ID, its sequence number, its kind, its principal and `based_on`, the sequence number of the latest entry its author had seen. The entry layout is fixed and the free-text note comes last, so `mira` can read the state fields of its own entries without a general JSON parser. A closed `session-v1` schema and an independent Python validator check entries as well.

**Integrity without a new hash primitive.** Each entry's signature covers its session ID and sequence number:
- modification and replay are detected
- an entry copied in from another session fails
- a deleted middle entry leaves a gap that is detected
- an operator-signed `close` entry records the final count, so truncating a closed session is detected

Truncating the tail of an open session is not detectable. `mira session verify DIR --allowed-signers FILE` checks everything.

### Entry kinds

| Kind | Who | Meaning |
|---|---|---|
| `header` | operator | Session ID, principals, question, initial autonomy and budget |
| `intent` | both | What the author is about to do and why. Written in the same step as each agent action, so intent always precedes action |
| `action` / `result` | both | One closed capability with validated arguments, run by `mira`. The result names the signed document and records the outcome `mira` itself computed (template, outcome, reason, availability), so nothing is re-parsed later |
| `finding` | both | A claim from a closed vocabulary, citing entries, with a confidence label and a bounded, unchecked note |
| `question` | both | Asks the other party, the dialog for resolving uncertainty. It queues and never interrupts |
| `proposal` | agent | An action outside the agent's current autonomy, awaiting a decision |
| `decision` | operator | Approves or rejects a proposal; accepts, rejects or marks a finding uncertain. Records the operator's own assessment |
| `directive` | operator | Changes the autonomy level or budget, grants delegation with an expiry, or stops the agent |
| `close` | operator | The operator's conclusion, which may cite findings, and the final entry count |

### Capabilities (the agent's entire action set)

These are exactly the existing signable, read-only commands, with their existing argument checks:
- `capture` with the `host/v1` or `host-pressure/v1` profile (always with a timeline)
- the seven `investigate` templates with `--json`

There is no shell, no file read, no network, no `verify`, no `challenge`, no `session` recursion and no new capability. `capture --bind-boot` collects a linkable identifier, so it is **operator-only**: the agent can only propose it, or use it under delegation. `mira` executes each action in the invoking process, so it runs under the acting party's own account and permissions: a separate agent user sees what that user may read, and any difference shows up as recorded evidence gaps. `mira` signs the resulting document with the acting principal's key and stores it. The agent never runs host commands itself.

### Autonomy levels (ported from the grid kernel)

| Level | Grid mode | Acquisition | Analysis | Decision | Action implementation |
|---|---|---|---|---|---|
| `manual` | Manual | Operator only | Operator only | Operator | None exists |
| `advisory` | Advisory | Agent proposes | Agent findings and questions | Operator | None exists |
| `assisted` (default) | Assisted | Agent acts within its budget | Agent findings and questions | Operator | None exists |
| `delegated` | Delegated | As assisted, plus operator-only read capabilities under an unexpired grant | As assisted | Operator | None exists |

The decision column never moves. Only the operator decides on proposals and findings and closes the session.

The kernel's invariants carry over as enforced rules, each with tests:
- **Operator precedence.** A `stop` directive sets the level to `manual` from its sequence number on. An agent action or proposal started on an earlier `based_on` is still recorded but marked `superseded_by_directive`.
- **Expiry.** A delegation grant ends after an entry count or an operator-clock deadline set in the directive. After that the level reverts to `assisted`.
- **Staleness.** When the operator decides on a proposal whose `based_on` is older than a newer result for the same capability and arguments, `mira` flags it stale, and approving it requires `--despite-stale`.
- **Terminal immutability.** After `close`, every append is refused.
- **Budget.** Each agent action consumes budget. At zero the agent can only propose.

### Grounded findings

Claim vocabulary, version 1:

| Claim | Checked by `mira` against the cited results |
|---|---|
| `expectation_satisfied` | Every cited result is a report with outcome `satisfied` |
| `expectation_not_satisfied` | At least one cited result has outcome `not_satisfied` |
| `evidence_unavailable` | At least one cited result is indeterminate, or a capture with an unavailable source |
| `hypothesis` | Never checked; requires a confidence label (`low`, `medium` or `high`); always shown as inference |
| `no_finding` | Nothing to check |

A checkable claim whose citations do not support it is refused when it is appended, so the agent cannot post a false checked claim. `mira session show DIR` renders every finding with its principal, claim, check status (`checked` or `inference`), confidence, citations and staleness. Agent notes are labelled unchecked and escaped. Optional forcing: `mira session decide --own-assessment` records the operator's own view first, and a header flag can require that before agent findings are shown.

### The agent boundary

`mira` never calls a model and opens no socket. An agent is any process that uses only the `mira session` subcommands with its own key. Stage 1 ships a deterministic scripted agent as test tooling. A model harness (stage 2) is separate optional tooling. Per AGENTS.md, it records the model identifier, provider, prompt revision, parameters, raw output and status as session documents. Host evidence is private and attacker-influenceable, so under the Rule of Two:
- real sessions use **local** models only
- hosted models see synthetic or public sessions only (existing policy)
- the agent never gets a state-changing or communicating capability

### Operator interface

`mira session` subcommands: `start`, `act`, `note`, `ask`, `propose`, `decide`, `direct`, `close`, `show [--json]`, `pending` and `verify`. `show` is the shared view: timeline, pending questions and proposals, findings with check labels, current autonomy and budget. The CLI is the first interface. Registered adaptive views remain Phase 4.

## Trust, privacy and failure analysis

- **New boundary TB8, the agent principal.** The agent is untrusted. Its effect is bounded by `mira`'s enforcement:
  - closed read-only capabilities
  - an autonomy level and budget from operator-signed entries
  - claim checks
  - no decision rights

  The worst case is a wrong but labelled `hypothesis`, a refused checked claim, a wasted budget, or a proposal the operator rejects.
- **Prompt injection.** Host strings reach the model through documents. They can steer the agent's text and choices, but they cannot widen its capabilities or bypass checks. The design does not claim the agent's reasoning is uncorrupted, only that corruption cannot act or pose as checked.
- **Same-user agents.** An agent running under the operator's account can read and write the session directory and may reach the operator's key. Signatures make forged operator entries detectable but cannot stop file deletion or tampering. For model agents, the operator should run the agent as a separate unprivileged user that has only its own key. The operator's key should be passphrase-protected in `ssh-agent` with confirmation, or held on a FIDO2 token. Stage 1 documents this and tests detection, not prevention.
- **Over-reliance.** It is mitigated (closed claims, check labels, inference labels, cheap citations, optional forcing) but not eliminated, as the studies report. Stage 3 measures it.
- **Disclosure.** A session holds host evidence and may hold the boot ID under delegation. It is private by default (mode 0700, or a dedicated group shared only with the agent user) and must not go to hosted services.
- **Availability.** Without an agent, a session is an operator's signed investigation log. Without `ssh-keygen`, sessions fail closed (exit 4).
- **Resources.** At most 4096 entries per session, notes of at most 1 KiB, documents under the existing 1 MiB bound, and every action is already bounded.

## Stages and acceptance

### Stage 1: session core and scripted agent

Rust: the session layout and its subcommands, with tests run against the real `ssh-keygen`:
- every entry kind, the exclusive-creation race between two writers, and gap and truncation detection after `close`
- cross-session replay
- the role taken from the header, never from a claimed entry
- every autonomy level, with budget exhaustion, expiry, `stop` precedence, a stale decision, and terminal refusal
- every claim kind, checked and refused
- operator-only `--bind-boot`
- refusal of any capability outside the closed set
- unchanged existing commands

Independent tooling: a `session-v1` schema and a validator that recomputes autonomy, staleness and claim checks; a deterministic scripted agent; a qualification group gated on `ssh_keygen`.

### Stage 2: local model harness

Optional tooling outside the CLI package, driving the same subcommands, with full model-I/O recording. Hostile-content fixtures put injection strings in journal unit names, dpkg versions and service states. They must show the agent cannot exceed its capabilities or post a false checked claim.

### Stage 3: evaluation

Matched tasks on synthetic fault fixtures compare the operator alone with the operator plus agent. They measure:
- conclusion correctness
- time
- evidence entries opened (the vision's evidence-access measure)
- over-reliance: acceptance of seeded wrong agent findings
- override rate

They use the methods of Bansal et al. and Buçinca et al. Results, positive or negative, are recorded before any claim of benefit (UI-01).

## Consequences and rollback

- **Blast radius:** one new `session` subcommand family, one signature namespace, the session-v1 format, and test and validator tooling. Existing commands, formats and outputs are unchanged.
- **Rollback:** removing the subcommands leaves every other feature intact. Session directories are inert files.

The roadmap moves the shared workspace ahead of security-advisory correlation, and the vision states the mixed-initiative goal directly.

## Review questions

1. **Default autonomy:** `assisted` (the agent gathers evidence within a budget) or `advisory` (the agent only proposes)? The proposal is `assisted`, the intermediate level the out-of-the-loop research favours.
2. **Separate OS user for model agents:** recommended (proposed) or required?
3. **Integrity primitive:** per-entry signatures with sequence numbers and a signed close, or a hash chain? A chain needs either a `sha256sum` subprocess or a first crate, which ADR 0011's criteria exclude.
4. **Forcing functions:** opt-in (proposed), or required before closing?
5. **Roadmap order:** workspace before advisory correlation (proposed)?

## Primary references

See the [research basis](../research/mixed-initiative.md) for every source, with its evidence type and the design rule taken from it.
