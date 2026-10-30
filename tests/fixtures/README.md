# Synthetic procfs fixture

All values are invented. Files are safe for public CI. They cover exactly the four allowlisted procfs sources. Do not place operational host data in this directory.

Native subprocess fixtures live in `tests/support/process_fixture.rs`, separate from captured evidence data. They are built only with the non-default `test-support` feature and exercised by `tests/systemd_process.rs`; they are not installed. See [validation](../../docs/testing.md).

`investigation-v1.json` is authored report-contract evidence: positive state/alias/unavailable cases and negative shape, scope, assessment and unsupported-version cases. It does not establish actual service health, source authentication or vulnerability applicability.

`capture-v1.json` freezes independent authored complete and deliberately invalid capture documents, including unavailable reasons and source-coverage contradictions. Native source/availability cases live in `tests/capture.rs`; optional memory/IO PSI files are generated in isolated temporary roots. No real host data or model judge supplies expected verdicts.
