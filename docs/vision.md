# MIRA vision and product boundary

MIRA (Mixed-Initiative Reasoning and Autonomy) is an **intent-driven, security-first Linux and infrastructure operations environment**. It helps a human operator establish system state, investigate health and security exposure, choose proportionate changes, and verify outcomes under explicit authority controls.

## Primary user and job
Linux/platform engineers investigating incidents, configuration drift and vulnerability applicability on systems they are authorized to operate. Primary development platform: Ubuntu 26.04 LTS.

**First usable product:** local, read-only host investigation with reproducible evidence and an interface suited to the current task. It must work without AI or a network connection. Natural-language intent and adaptive UI are progressive enhancements, not prerequisites for reliable diagnostics.

## Differentiator
A single session joins operator intent, typed observations, evidence provenance, policy-admitted capabilities and decision outcomes. AI may recommend or summarize; it never creates its own privileges. The interface composes registered views of evidence, not AI-generated executable controls.

## Initial scope
- bounded local Linux evidence collection from allowlisted interfaces;
- health and security-relevant observations with source, collection time and unknown states;
- evidence-backed, read-only investigation templates;
- explainable findings, uncertainty, and reproducible synthetic fixtures;
- human-controlled interaction; eventually an adaptive, trusted-component UI.

## Explicit non-goals
No production remediation, arbitrary shell execution, persistent privileged daemon, remote fleet controller, autonomous exploitation, safety-certified controller or mandatory cloud inference in the MVP. Vulnerability exposure must not be inferred solely from upstream version strings; distribution advisory/backport evidence is required.

## Future options, conditional on evidence
Scoped remote collectors; vulnerability advisory correlation; local inference and optional GitHub Models (synthetic/public inputs only); approved changes with independently checked preconditions and postconditions; richer security and reliability correlation.

## Success measures
- complete a bounded real-host read-only investigation without mutation, privilege escalation or external inference;
- distinguish observed, inferred and unknown conditions, preserving source and freshness;
- reproduce known synthetic scenarios and failures in CI;
- validate every admitted operation against an explicit capability boundary;
- show whether task-oriented views improve operator evidence access against a fixed view, instead of assuming adaptive UI is beneficial.
