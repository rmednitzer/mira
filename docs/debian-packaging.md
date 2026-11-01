# Debian package foundation (experimental)

`packaging/build-deb.sh` stages the already compiled release binary into a CLI-only Debian package. It installs `/usr/bin/mira`, a manual page, the Apache-2.0 license, the evidence, capture, investigation and signature guides, and all fifteen versioned evidence, capture, challenge, report and session schemas under `/usr/share/mira/schemas/`. It includes no maintainer scripts, systemd units, timers, daemon, user creation, configuration mutations or install-time activation.

Build on native Ubuntu 26.04 amd64 and arm64 with `cargo build --release --locked`, then `bash packaging/build-deb.sh`. Native `dpkg-dev` and binutils are required: `dpkg-shlibdeps` derives versioned runtime ABI requirements from the compiled binary and the build distribution metadata. The package script supports `SOURCE_DATE_EPOCH` for normalized file timestamps and derives the Debian changelog and manual-page dates from the same value. It defaults to the last commit time and rejects non-numeric values; uses root-owned package metadata, and writes a SHA-256 file. This is an initial binary packaging path, **not** a Debian source package, signed release or verified bit-for-bit reproducible build.

CI must inspect the archive for unexpected paths, validate metadata, extract and execute the CLI and test installation/removal in an isolated disposable environment before promotion. Release signing, dependency scanning, hermetic compilation, build provenance, genuine version-to-version upgrade/downgrade and apt repository publishing are later gates. Package contents should not expose host configuration or private infrastructure.

## Runtime package relationships

`Depends` is derived from the native ELF binary by `dpkg-shlibdeps`; do not hardcode library versions or their transitive dependencies. The CLI requires no Python, Rust toolchain, procps commands or JSON utilities at runtime. `dpkg` is an Essential package on the supported distribution; MIRA reads its status database directly and needs no additional versioned dependency on it. Kernel procfs and PSI availability are runtime conditions, not dependencies on procps.

`Suggests: systemd, default-dbus-system-bus | dbus-system-bus, openssh-client` advertises the optional service observation prerequisites and the optional signing tool. `openssh-client` provides `/usr/bin/ssh-keygen`, which `mira` runs only when `--signature`/`--sign-with` or `verify` is requested ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)); without it, signing and verification fail closed with exit 4. Ubuntu 26.04's `systemd` package provides `systemctl` on both supported architectures. The bus alternative allows the distribution's default provider or another compatible system bus. Host inspection and capture remain useful without them, so these are suggestions rather than mandatory or recommended installations. A working system manager, system bus and query access are still required for service observations; installing packages alone does not establish availability. Missing or inaccessible service infrastructure remains explicit unavailable evidence.

MIRA does not select an init implementation through `systemd-sysv`, request privileged operations through `polkitd`, or enable services during installation. `jq` is an optional operator convenience. Build tools (`dpkg-dev`, binutils and lintian) and Python schema/history tooling remain separate from runtime package relationships. The clean-container apt check does not request installation of suggestions.

These choices follow [Debian package relationship semantics](https://www.debian.org/doc/debian-policy/ch-relationships.html#binary-dependencies-depends-recommends-suggests-enhances-pre-depends), the [Essential package rule](https://www.debian.org/doc/debian-policy/ch-binary.html#dependencies), and Ubuntu's [systemd package metadata](https://packages.ubuntu.com/resolute/systemd).

## Optional collector: design only

Do not install or enable a unit yet. An eventual systemd oneshot + timer requires a bounded output sink, retention and atomic-write design, verified IPC access for the systemd query, explicit enablement, dynamic-user/filesystem constraints and failure/restart tests. It should be a separate `mira-collector` package if justified by a documented unattended collection requirement. Neither `ProtectSystem=strict` nor `DynamicUser=yes` alone proves sandbox isolation; validate behavior on target hosts.

## Repeatable assembly boundary

CI assembles the same compiled binary twice in separate staging directories under ordinary and restrictive invoking umasks, then compares the resulting `.deb` bytes. The builder sets umask 022 so package permissions do not inherit the caller's mask. Native test helpers are never installed. `SOURCE_DATE_EPOCH` is exported to archive tools as well as used for file timestamps. This checks deterministic archive assembly only: physical-host behavior and version-to-version upgrades remain outstanding release gates; the separate fresh-build test compares independent source/target compilations within one runner environment.

On hosted amd64 runners, dpkg-shlibdeps reports the distribution's libc6 merged-/usr loader diversion. Keep that warning visible; the native dependency metadata is not a replacement for clean-system installation and loader validation before release.

## Real dependency-resolution check

`packaging/test-clean-install.sh` installs the exact built archive into a fresh native Ubuntu 26.04 container through apt, without `--force-depends`. It compares the installed binary with the archive bytes and runs the installed demo and independently validated pressure capture. A new receipt binds the clean source commit/tree, package version/architecture/hash, installed binary hash and container image identity. The image is pulled by release tag then executed by immutable local image ID; apt repository state is current, not hermetically frozen. CI trust, registry availability and package repositories remain dependencies. No release upload or signing is performed. Clean physical hosts, real upgrades/downgrades, independent-host compilation and signed provenance remain unqualified.

Successful native CI retains the installation receipt for 30 days as a separate artifact; no host capture values are uploaded. PR receipts can identify GitHub’s synthetic merge checkout rather than the branch tip. The receipt remains unsigned and does not establish independent provenance.

## Fresh compilation comparison

`packaging/test-rebuild.sh` creates two fresh archives of the exact source revision and compiles into separate target directories under varied source/target paths, timezones and umasks. It compares unstripped release binaries, assembled archives and the selected production binary/package. Equality produces a separate new receipt bound to source commit/tree, source epoch, compiler version and artifact hashes. No successful receipt is emitted on mismatch. The compiler and native system dependencies are shared, so this closes only the stated same-runner variation check. It does not establish arbitrary-host or hermetic reproduction, signing or genuine upgrade behavior. See [ADR 0003](adr/0003-locked-tooling-and-fresh-builds.md).

Successful native CI retains the tested candidate `.deb` and its checksum with both validation receipts for 30 days. This preserves real prior package bytes for a future genuinely different version, without publishing a release or fabricating an upgrade. Retention is temporary; durable release archival and provenance need their own reviewed policy.
