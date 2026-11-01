# MIRA vision and product boundary

MIRA (Mixed-Initiative Reasoning and Autonomy) is a **security-first, shared workspace in which a human operator and an AI agent both act on Linux and infrastructure investigations, as a real mixed-initiative system**. Either party can take the initiative: start an action, raise a finding, ask a question or propose a next step. Each contributes what it does best, under rules that both can see and that MIRA, not the model, enforces. Together they establish system state, investigate health and security exposure, choose proportionate changes and verify outcomes.

The name states the design:
- **Mixed-initiative:** initiative moves between the operator and the agent within one shared record.
- **Reasoning:** every finding is a claim grounded in cited evidence. MIRA checks the claims the evidence can settle and labels the rest as inference.
- **Autonomy:** the agent's autonomy is set separately for each function (gathering evidence, analysing it, deciding, acting). It is bounded, expires, can be revoked by the operator at any time, and is never inferred from the model. Decisions stay with the operator.

The [research basis](research/mixed-initiative.md) records the human–automation and AI-agent security research behind these rules.

## Primary user and job
Linux/platform engineers investigating incidents, configuration drift and vulnerability applicability on systems they are authorized to operate. Primary development platform: Ubuntu 26.04 LTS.

**First usable product:** local, read-only host investigation with reproducible evidence and an interface suited to the current task. It must work without AI or a network connection, so the operator can always continue alone. **First mixed-initiative product:** the same investigation as a shared, signed session in which an agent gathers evidence and proposes findings within operator-set autonomy ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)). Natural-language intent and adaptive UI are progressive enhancements, not prerequisites.

## Differentiator
A single session joins operator intent, typed observations, evidence provenance, policy-admitted capabilities and decision outcomes, for both parties. The AI agent may start admitted read-only actions within its granted autonomy, post grounded findings, ask questions and propose anything else. It never creates its own privileges, and it never acts on anything that changes state without the operator's approval. Every entry names its principal, so it is always clear who did what and on which evidence. The interface composes registered views of evidence, not AI-generated executable controls.

## Initial scope
- bounded local Linux evidence collection from allowlisted interfaces;
- health and security-relevant observations with source, collection time and unknown states;
- evidence-backed, read-only investigation templates;
- explainable findings, uncertainty, and reproducible synthetic fixtures;
- a shared operator–agent session with explicit, per-function autonomy;
- human-controlled decisions; eventually an adaptive, trusted-component UI.

## Explicit non-goals
No production remediation, arbitrary shell execution, persistent privileged daemon, remote fleet controller, autonomous exploitation, safety-certified controller or mandatory cloud inference in the MVP. Vulnerability exposure must not be inferred solely from upstream version strings; distribution advisory/backport evidence is required.

## Future options, conditional on evidence
Scoped remote collectors; vulnerability advisory correlation; local inference and optional GitHub Models (synthetic/public inputs only); approved changes with independently checked preconditions and postconditions; richer security and reliability correlation.

## Success measures
- complete a bounded real-host read-only investigation without mutation, privilege escalation or external inference;
- distinguish observed, inferred and unknown conditions, preserving source and freshness;
- reproduce known synthetic scenarios and failures in CI;
- validate every admitted operation against an explicit capability boundary;
- show whether task-oriented views improve operator evidence access against a fixed view, instead of assuming adaptive UI is beneficial;
- show, in matched tasks, whether the operator–agent team is more correct, faster or better at finding evidence than the operator alone, and measure how often the operator accepts seeded wrong agent findings, instead of assuming that AI assistance helps.
