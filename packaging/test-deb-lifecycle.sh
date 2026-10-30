#!/usr/bin/env bash
set -euo pipefail
deb="${1:?usage: bash packaging/test-deb-lifecycle.sh package.deb}"
deb="$(realpath "$deb")"
test -f "$deb"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/var/lib/dpkg/updates"
: > "$root/var/lib/dpkg/status"
run_dpkg() {
  NEEDRESTART_SUSPEND=1 dpkg --force-not-root --force-depends --log="$root/dpkg.log" --root="$root" --admindir="$root/var/lib/dpkg" "$@"
}
run_dpkg --install "$deb"
test -x "$root/usr/bin/mira"
run_dpkg --status mira | grep -q 'Status: install ok installed'
# Same-version reinstall tests idempotent package lifecycle without invented upgrade artifacts.
run_dpkg --install "$deb"
run_dpkg --status mira | grep -q 'Status: install ok installed'
run_dpkg --remove mira
test ! -e "$root/usr/bin/mira"
run_dpkg --purge mira
if run_dpkg --status mira >/dev/null 2>&1; then
  echo "package remains registered after purge" >&2
  exit 1
fi
echo "isolated install/reinstall/remove/purge passed"
