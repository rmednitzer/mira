# Synthetic procfs fixture

All values are invented. Files are safe for public CI. They cover exactly the four allowlisted procfs sources. Do not place operational host data in this directory.

Native subprocess fixtures live in `tests/support/process_fixture.rs`, separate from captured evidence data. They are built only with the non-default `test-support` feature and exercised by `tests/systemd_process.rs`; they are not installed. See [validation](../../docs/testing.md).

`investigation-v1.json` is authored report-contract evidence: positive state/alias/unavailable cases and negative shape, scope, assessment and unsupported-version cases. It does not establish actual service health, source authentication or vulnerability applicability.

`investigation-v2.json` is authored service-active/v2 contract evidence: the v1 state table plus not-found combinations, and negative cases for `unit_not_found` on non-stub evidence, `reported_not_active` on the not-found/inactive stub, unavailable evidence, scope mismatch, unknown reason and version/template mismatches.

`capture-v1.json` freezes independent authored complete and deliberately invalid capture documents, including unavailable reasons and source-coverage contradictions. Native source/availability cases live in `tests/capture.rs`; optional memory/IO PSI files are generated in isolated temporary roots. No real host data or model judge supplies expected verdicts.

`memory-headroom-v1.json` freezes seven valid and fourteen invalid memory-expectation reports, including equality, u64 bounds, unavailable evidence and contradictory assessments. They are synthetic contract cases, not host-health labels.
