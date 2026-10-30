#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
test -n "$version"
arch="$(dpkg --print-architecture)"
case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 2;; esac
test -x target/release/mira || { echo "build target/release/mira first" >&2; exit 2; }
out="${1:-dist}"
mkdir -p "$out"
out="$(realpath "$out")"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
install -Dm755 target/release/mira "$stage/usr/bin/mira"
install -Dm644 LICENSE "$stage/usr/share/doc/mira/copyright"
install -Dm644 docs/evidence-json.md "$stage/usr/share/doc/mira/evidence-json.md"
install -Dm644 schemas/evidence-v1.schema.json "$stage/usr/share/mira/schemas/evidence-v1.schema.json"
mkdir -p "$stage/DEBIAN"
cat >"$stage/DEBIAN/control" <<EOF
Package: mira
Version: ${version}-1
Architecture: $arch
Maintainer: MIRA Project <noreply@github.com>
Section: admin
Priority: optional
Homepage: https://github.com/rmednitzer/mira
Description: Read-only Linux infrastructure evidence CLI
 Local-first experimental Linux inspection and structured evidence reporting.
 No background service or automatic remediation is installed.
EOF
find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$stage" "$out/mira_${version}-1_${arch}.deb"
(cd "$out" && sha256sum "mira_${version}-1_${arch}.deb" > "mira_${version}-1_${arch}.deb.sha256")
