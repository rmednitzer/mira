# Roadmap

This is a dependency-ordered plan. Dates and version assignments are intentionally not promised.

## Phase 0 — product definition and foundation
Goal: one authoritative mission, architecture, requirements and threat model, plus read-only Linux evidence acquisition. Exit: documents agree with code and initial synthetic parsing tests pass. **In progress.**

## Phase 1 — useful offline Linux investigator (MVP)
Add host identity, bounded systemd/journal, CPU/memory/IO pressure and package provenance collectors; structured provenance and collection-error states; read-only investigation templates; native CLI report. Exit: a real Ubuntu 26.04 host investigation works without privilege escalation, network calls, LLM or modifications, and is reproducible with synthetic fixtures.

## Phase 2 — security exposure and evidence correlation
Ingest versioned distribution advisories and machine-readable security data; reconcile package version/backport and configuration applicability; produce affected/not-affected/unknown with citations and freshness. Exit: representative advisory fixtures detect true and false exposure without upstream-version-only inference.

## Phase 3 — intent-driven adaptive workspace
Add declared intent grammar, capability selector and browser UI built from registered views. Exit: operator can navigate health, exposure and incident workflows without granting additional privileges. Evaluate against a fixed UI using matched tasks.

## Phase 4 — optional AI-assisted investigation
Interchangeable local inference and GitHub Models evaluators; synthetic scenarios only for hosted evaluation. Exit: model prompts/outputs and errors are captured with revision/parameters, and AI failure cannot change authorized access.

## Phase 5 — governed remediation and broader infrastructure
Only after separate threat review: scoped execution grants, dry-run, verified preconditions, operator approval, postconditions, rollback and remote adapters. Exit: adversarial authorization and failure-path tests pass; no production-readiness claim without further review.

## Retained fixture
The existing rover simulator stays as a bounded coordination regression fixture, not the product's primary use case. Remove it only once equivalent control invariants are tested in the real operations domain.
