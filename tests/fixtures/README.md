# Synthetic procfs fixture

All values are invented. Files are safe for public CI. They cover exactly the four allowlisted procfs sources. Do not place operational host data in this directory.

Native subprocess fixtures live in `tests/support/process_fixture.rs`, separate from captured evidence data. They are built only with the non-default `test-support` feature and exercised by `tests/systemd_process.rs`; they are not installed. See [validation](../../docs/testing.md).
