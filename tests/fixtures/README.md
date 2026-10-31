# Synthetic procfs fixture

All values are invented. Files are safe for public CI. They cover exactly the four allowlisted procfs sources. Do not place operational host data in this directory.

Native subprocess fixtures live in `tests/support/process_fixture.rs`, separate from captured evidence data. They are built only with the non-default `test-support` feature and exercised by `tests/systemd_process.rs`; they are not installed. See [validation](../../docs/testing.md).

`investigation-v1.json` is authored report-contract evidence: positive state/alias/unavailable cases and negative shape, scope, assessment and unsupported-version cases. It does not establish actual service health, source authentication or vulnerability applicability.

`investigation-v2.json` is authored service-active/v2 contract evidence: the v1 state table plus not-found combinations, and negative cases for `unit_not_found` on non-stub evidence, `reported_not_active` on the not-found/inactive stub, unavailable evidence, scope mismatch, unknown reason and version/template mismatches.

`evidence-v1.json` holds independent evidence-v1 records: valid kernel, uptime and systemd observations (including a `+` kernel suffix, an escaped unit instance and a literal escape sequence in a state), and invalid ones for version, freshness, value/status contradictions and the observed-string lexical contract.

`capture-v1.json` freezes independent authored complete and deliberately invalid capture documents, including unavailable reasons and source-coverage contradictions. Native source/availability cases live in `tests/capture.rs`; optional memory/IO PSI files are generated in isolated temporary roots. No real host data or model judge supplies expected verdicts.

`memory-headroom-v1.json` freezes seven valid and fourteen invalid memory-expectation reports, including equality, u64 bounds, unavailable evidence and contradictory assessments. They are synthetic contract cases, not host-health labels.

`uptime-minimum-v1.json` (six valid, sixteen invalid) and `kernel-release-v1.json` (five valid, seventeen invalid) freeze uptime and release expectation reports: boundaries, u64 limits, exact and near-miss releases, option-shaped criteria, unavailable evidence, source/version/scope violations, and schema-valid reports whose reason contradicts the value. They are synthetic contract cases, not host labels.

`package-installed-v1.json` freezes ten valid and twenty-nine invalid package-presence reports: every outcome, multiarch, sparse and arch-qualified selectors, unavailable evidence, vocabulary and limit violations, and nine schema-valid reports that fail selector, matching, identity or derived-reason checks. They are synthetic contract cases, not vulnerability labels.

`pressure-ceiling-v1.json` freezes eight valid and twenty invalid pressure-expectation reports across all three resources, including the 0 and 10000 bounds, equality, unavailable evidence, source/resource mismatches, availability/reason contradictions and two schema-valid reports whose reason contradicts the value-versus-ceiling relation. They are synthetic contract cases, not host-health labels.
