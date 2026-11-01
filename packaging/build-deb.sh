#!/usr/bin/env bash
set -euo pipefail
# Package modes must not depend on the invoking user's umask.
umask 022
cd "$(dirname "$0")/.."
export LC_ALL=C
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
test -n "$version"
# One reproducible timestamp drives file mtimes and the dated package metadata.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
case "$SOURCE_DATE_EPOCH" in ""|*[!0-9]*) echo "invalid SOURCE_DATE_EPOCH" >&2; exit 2;; esac
changelog_date="$(date -u -R -d "@${SOURCE_DATE_EPOCH}")"
manual_date="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%F)"
arch="$(dpkg --print-architecture)"
case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 2;; esac
test -x target/release/mira || { echo "build target/release/mira first" >&2; exit 2; }
out="${1:-dist}"
mkdir -p "$out"
out="$(realpath "$out")"
build_root="$(mktemp -d)"
trap 'rm -rf "$build_root"' EXIT
stage="$build_root/debian/mira"
mkdir -p "$stage/DEBIAN"
chmod 755 "$stage"
install -Dm755 target/release/mira "$stage/usr/bin/mira"
strip --strip-unneeded "$stage/usr/bin/mira"
mkdir -p "$stage/usr/share/doc/mira"
cat > "$stage/usr/share/doc/mira/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: MIRA
Source: https://github.com/rmednitzer/mira

Files: *
Copyright: 2026 MIRA contributors
License: Apache-2.0
 On Debian systems the complete Apache License, Version 2.0,
 is available at /usr/share/common-licenses/Apache-2.0.
EOF
cat <<EOF | gzip -n -9 > "$stage/usr/share/doc/mira/changelog.Debian.gz"
mira (${version}-1) unstable; urgency=medium

  * Experimental CLI-only package.

 -- MIRA Project <noreply@github.com>  ${changelog_date}
EOF
mkdir -p "$stage/usr/share/man/man1"
{
printf '.TH MIRA 1 "%s" "MIRA" "User Commands"\n' "$manual_date"
cat <<'EOF'
.SH NAME
mira \- read-only Linux evidence CLI
.SH SYNOPSIS
.B mira capture LABEL [--pressure] [--timeline] [--bind-boot] [--challenge HEX] [--signature PATH --sign-with KEY]
.br
.B mira inspect [--json]
.br
.B mira service UNIT.service [--json]
.br
.B mira investigate service-active[/v1|/v2] UNIT.service [--json]
.br
.B mira investigate memory-headroom --min-available-kib N [--json]
.br
.B mira investigate pressure-ceiling --resource cpu|memory|io --max-some-avg10-basis-points N [--json]
.br
.B mira investigate package-installed PACKAGE[:ARCH] [--json]
.br
.B mira investigate uptime-minimum --min-uptime-seconds N [--json]
.br
.B mira investigate kernel-release --expect RELEASE [--json]
.br
.B mira investigate journal-events --absent CLASS[,CLASS...] [--boot current|previous-retained] [--json]
.br
.B mira verify FILE --signature SIG --allowed-signers SIGNERS --principal NAME [--revocations KRL] [--challenge-file FILE --max-age-ms N]
.br
.B mira challenge
.br
.B mira session start|ask|direct|close|request|run|act|show|verify DIR ...
.br
.B mira demo
.SH DESCRIPTION
Experimental read-only host evidence inspection, complete captures and explicit
expectation investigations, with optional signatures. No remediation or
background service.
.SH EXIT STATUS
Inspect/service: 0 for available evidence, 1 for unavailable evidence, 2 for usage.
Capture: 0 all sources available, 1 complete with unavailable sources, 2 usage.
--timeline emits capture-v2 with a monotonic collection window and per-source offsets.
--bind-boot (implies --timeline) also records the boot ID and boot-relative
window; the boot ID links captures from one boot and is never read otherwise.
--challenge HEX (64 lowercase hex, requires signing) emits capture-v3 answering
a consumer challenge.
Investigations (service-active, memory-headroom, pressure-ceiling, package-installed, uptime-minimum, kernel-release and journal-events): 0 satisfied, 1 not satisfied, 3 indeterminate, 2 rejected invocation.
Signing (--signature PATH --sign-with KEY, last, on capture or investigate --json): 4 when signing fails; nothing is printed and no signature remains.
Verify: 0 verified, 1 not verified, 2 usage, 4 ssh-keygen or the challenge file
unavailable.
Challenge: 0 issued, 4 random source or clock unavailable.
Session: 0 done or verified, 1 refused or not verified, 2 usage, 4 signing,
ssh-keygen or I/O failure.
.PP
service-active and service-active/v1 emit the unchanged v1 report.
service-active/v2 additionally reports reason unit_not_found (exit 1) when systemd
reports LoadState not-found and ActiveState inactive.
.PP
pressure-ceiling compares one resource's PSI some avg10, in basis points
(10000 = 100.00%), with an explicit operator ceiling. It does not assess
workload health, latency or root cause.
.PP
package-installed reports whether dpkg records one named package as installed
with flag ok. Transitional states and reinstreq are indeterminate (exit 3).
It does not assess vulnerability exposure or file integrity.
.PP
uptime-minimum compares whole seconds since boot with an explicit minimum.
kernel-release compares the running release name with an expected string
exactly. Neither assesses reboot cause, build identity or patch compliance.
.PP
Signatures are detached OpenSSH SSHSIG files made by /usr/bin/ssh-keygen
(openssh-client). A verified signature shows that a listed key signed the
exact bytes; it does not show the evidence is true or fresh.
mira challenge prints a random challenge with the issuing machine's time.
verify --challenge-file then bounds a challenged capture's age on the
verifier's own clock; the host clock is never trusted.
.PP
journal-events reports whether catalog OOM-kill, unit-failure or core-dump
events were recorded in the running or previous retained boot, via
/usr/bin/journalctl. It reads no message text; none recorded does not mean
none occurred.
EOF
} | gzip -n -9 > "$stage/usr/share/man/man1/mira.1.gz"
install -Dm644 docs/evidence-json.md "$stage/usr/share/doc/mira/evidence-json.md"
install -Dm644 schemas/evidence-v1.schema.json "$stage/usr/share/mira/schemas/evidence-v1.schema.json"
install -Dm644 schemas/investigation-v1.schema.json "$stage/usr/share/mira/schemas/investigation-v1.schema.json"
install -Dm644 schemas/investigation-v2.schema.json "$stage/usr/share/mira/schemas/investigation-v2.schema.json"
install -Dm644 docs/investigations.md "$stage/usr/share/doc/mira/investigations.md"
install -Dm644 schemas/evidence-v2.schema.json "$stage/usr/share/mira/schemas/evidence-v2.schema.json"
install -Dm644 schemas/capture-v1.schema.json "$stage/usr/share/mira/schemas/capture-v1.schema.json"
install -Dm644 schemas/capture-v2.schema.json "$stage/usr/share/mira/schemas/capture-v2.schema.json"
install -Dm644 schemas/capture-v3.schema.json "$stage/usr/share/mira/schemas/capture-v3.schema.json"
install -Dm644 schemas/challenge-v1.schema.json "$stage/usr/share/mira/schemas/challenge-v1.schema.json"
install -Dm644 docs/captures.md "$stage/usr/share/doc/mira/captures.md"
install -Dm644 schemas/memory-headroom-v1.schema.json "$stage/usr/share/mira/schemas/memory-headroom-v1.schema.json"
install -Dm644 docs/memory-investigation.md "$stage/usr/share/doc/mira/memory-investigation.md"
install -Dm644 schemas/pressure-ceiling-v1.schema.json "$stage/usr/share/mira/schemas/pressure-ceiling-v1.schema.json"
install -Dm644 docs/pressure-investigation.md "$stage/usr/share/doc/mira/pressure-investigation.md"
install -Dm644 schemas/package-installed-v1.schema.json "$stage/usr/share/mira/schemas/package-installed-v1.schema.json"
install -Dm644 docs/package-investigation.md "$stage/usr/share/doc/mira/package-investigation.md"
install -Dm644 schemas/uptime-minimum-v1.schema.json "$stage/usr/share/mira/schemas/uptime-minimum-v1.schema.json"
install -Dm644 schemas/kernel-release-v1.schema.json "$stage/usr/share/mira/schemas/kernel-release-v1.schema.json"
install -Dm644 docs/host-investigations.md "$stage/usr/share/doc/mira/host-investigations.md"
install -Dm644 docs/signatures.md "$stage/usr/share/doc/mira/signatures.md"
install -Dm644 schemas/journal-events-v1.schema.json "$stage/usr/share/mira/schemas/journal-events-v1.schema.json"
install -Dm644 docs/journal-investigation.md "$stage/usr/share/doc/mira/journal-investigation.md"
install -Dm644 schemas/session-v1.schema.json "$stage/usr/share/mira/schemas/session-v1.schema.json"
install -Dm644 schemas/session-request-v1.schema.json "$stage/usr/share/mira/schemas/session-request-v1.schema.json"
install -Dm644 docs/sessions.md "$stage/usr/share/doc/mira/sessions.md"
# Derive versioned ABI dependencies from the native binary and distro metadata.
printf 'Source: mira\nSection: admin\nPriority: optional\nMaintainer: MIRA Project <noreply@github.com>\n\nPackage: mira\nArchitecture: any\nDescription: Read-only Linux evidence CLI\n' > "$build_root/debian/control"
depends="$(cd "$build_root" && dpkg-shlibdeps -O -edebian/mira/usr/bin/mira)"
case "$depends" in shlibs:Depends=?*) depends="${depends#shlibs:Depends=}" ;; *) echo "missing ELF dependency metadata" >&2; exit 2 ;; esac
cat >"$stage/DEBIAN/control" <<EOF
Package: mira
Version: ${version}-1
Architecture: $arch
Maintainer: MIRA Project <noreply@github.com>
Section: admin
Priority: optional
Depends: $depends
Suggests: systemd, default-dbus-system-bus | dbus-system-bus, openssh-client
Homepage: https://github.com/rmednitzer/mira
Description: Read-only Linux infrastructure evidence CLI
 Local-first experimental Linux inspection and structured evidence reporting.
 No background service or automatic remediation is installed.
EOF
find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
dpkg-deb --root-owner-group --build "$stage" "$out/mira_${version}-1_${arch}.deb"
(cd "$out" && sha256sum "mira_${version}-1_${arch}.deb" > "mira_${version}-1_${arch}.deb.sha256")
