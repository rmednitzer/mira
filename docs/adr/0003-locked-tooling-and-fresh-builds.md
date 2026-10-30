# ADR 0003: Hash-locked tooling and fresh build comparisons

Status: Accepted, 2026-10-30. Observed verification belongs to the implementing PR.

## Context and criteria

The Rust product has no external crates, but independent schema/history validation installs Python dependencies. Pinning only jsonschema leaves its dependency closure mutable. Reassembling one binary twice does not exercise compilation from independent source/target directories. No published release baseline exists for genuine version-to-version upgrade qualification.

Criteria: preserve the runtime dependency boundary, reject changed dependency bytes, avoid source-build execution, compare the actual selected artifact, retain bounded public evidence and avoid unsupported claims about independent hosts or provenance.

## Options and decision

- No change leaves mutable tooling and compilation repeatability untested; rejected.
- Replace the independent validator with a custom Rust JSON/schema implementation: increases product/parser complexity and removes implementation independence; rejected.
- Add a general build platform, signing authority or synthetic old-version package: unnecessary authority or misleading upgrade evidence; deferred.
- Hash-lock the existing tooling closure and compare fresh native builds: selected.

`requirements-schema.txt` preserves the dependency versions observed in the preceding successful native CI run. It admits only reviewed wheel hashes for standard-ABI CPython 3.12/3.14 on glibc Linux x86_64/aarch64. The Python 3.12-only typing-extensions dependency is explicit. Native CI executes Python 3.14; local Python 3.12 observations are separate evidence. Wheel availability is not a claim that every admitted profile has passed the complete suite. Installation requires hashes for the complete dependency closure and refuses source distributions. A negative test changes wheel bytes and requires pip's actual hash-mismatch refusal without installing that changed wheel.

Two fresh git archives and separate Cargo target directories compile release binaries under different source paths, target paths, umasks and timezones. Compare the raw binaries and assembled Debian archives with each other and the selected production artifacts. SOURCE_DATE_EPOCH, source revision, compiler/system dependency environment and architecture are held fixed. A source-bound receipt records successful equality and the exact compiler/artifact identities. Existing same-binary archive and clean-container installation checks remain separate.

## Boundaries and failure behavior

A wheel hash identifies admitted bytes; it does not establish uncompromised publisher identity, dependency safety or licence clearance. PyPI and its distribution endpoints remain acquisition dependencies; prepared wheelhouses or mirrors can provide offline installation. No package executes merely because metadata was fetched. The changed-wheel refusal test downloads trusted admitted artifacts, modifies one locally, and performs no installation of it.

Fresh compilation on one runner is not independent-host reproduction or a hermetic toolchain. System libraries, compiler and package dependency metadata are shared. Comparison failure blocks acceptance and produces no success receipt; do not weaken the gate by stripping unexpected differences or substituting a prebuilt binary. Build directories and containers are disposable, and receipts contain no source-path, hostname or operational capture values. CI uploads are unsigned integrity/test evidence, not signatures or independent provenance.

Genuine release-to-release upgrade/downgrade and physical-host qualification remain open. Do not create an invented version solely to make that gate green. No release, signing key, OIDC permission or publishing workflow is added.

## Validation and rollback

Require locked installation and pip consistency on both native CI architectures; actual modified-wheel refusal; existing Python contracts and Rust checks; fresh binary/package equality and source cleanliness; clean-container installation; exact-head review and post-merge CI. Retain both validation receipts, the tested candidate package and its checksum for 30 days. This creates actual candidate bytes for a future distinct-version test, not a published release or durable baseline archive. Independent-host and long-term release archival need separate qualification.

Rollback restores the previous tooling install and removes the additional comparison job through a PR. Runtime CLI behavior and capture formats require no migration. Preserve retained historical receipts with their original source and scope.

## Primary guidance

- https://github.com/pypa/pip/blob/26.2.2/docs/html/topics/secure-installs.md
- https://reproducible-builds.org/docs/env-variations/
- https://doc.rust-lang.org/cargo/commands/cargo-build.html
