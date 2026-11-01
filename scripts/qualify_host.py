#!/usr/bin/env python3
"""Representative host qualification runner (ADR 0013).

Runs the independent validators' check groups against one MIRA binary as an
unprivileged user, records passed / failed / not applicable per group, and
writes a qualification-receipt-v1 file free of host identifiers. Exit 0 when
every group passed or was expectedly not applicable with only expected gaps,
1 when a group failed, 2 on refusal or usage error, 3 when nothing failed but
the receipt has an unexpected not-applicable group, gap or missing required gap.
"""
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from jsonschema import Draft202012Validator
from validation_status import GAP_REASON, GAP_SOURCES

ROOT = Path(__file__).resolve().parents[1]
PASSED, FAILED, USAGE, FINDING = 0, 1, 2, 3
INCONCLUSIVE = 4
ATTEMPTS = 3  # one run plus at most two retries of an inconclusive result
GROUP_TIMEOUT = 600
JOURNALCTL = '/usr/bin/journalctl'
SYSTEMCTL = '/usr/bin/systemctl'
DPKG = '/usr/bin/dpkg'
DPKG_STATUS = '/var/lib/dpkg/status'
SSH_KEYGEN = '/usr/bin/ssh-keygen'
BOOT_ID = '/proc/sys/kernel/random/boot_id'

# validator name, script, {group: required capabilities}. Denial paths are never gated:
# each validator checks MIRA's handling of a missing capability inside an ungated group.
VALIDATORS = (
    ('evidence', 'validate_evidence_schema.py',
     {'fixtures': (), 'cli': (), 'live-procfs': (), 'live-systemd': ('systemd',)}),
    ('investigation', 'validate_investigation_schema.py',
     {'fixtures': (), 'cli': (), 'live-systemd': ('systemd',)}),
    ('capture', 'validate_capture_schema.py',
     {'schema': (), 'cli': (), 'compare': (), 'live-boot': ('boot_id',),
      'signed-compare': ('ssh_keygen',), 'challenge': ('ssh_keygen',)}),
    ('memory', 'validate_memory_investigation.py', {'fixtures': (), 'cli': ()}),
    ('pressure', 'validate_pressure_investigation.py', {'fixtures': (), 'cli': ()}),
    ('package', 'validate_package_investigation.py',
     {'fixtures': (), 'cli': (), 'live-dpkg': ('dpkg',)}),
    ('host', 'validate_host_investigations.py', {'fixtures': (), 'cli': (), 'live': ()}),
    ('journal', 'validate_journal_investigation.py',
     {'fixtures': (), 'cli': (), 'live-visibility': ('journalctl',),
      'live-counts': ('journalctl', 'journal_visible')}),
)
NOT_APPLICABLE = {'systemd': 'no_systemd', 'journalctl': 'no_journal_access',
                  'journal_visible': 'no_journal_access', 'psi': 'no_psi', 'dpkg': 'no_dpkg',
                  'ssh_keygen': 'no_ssh_keygen', 'boot_id': 'no_boot_id'}
# Per class: allowed not-applicable reasons, allowed gap sources, required gap sources.
EXPECTED = {
    'physical-amd64': (set(), set(), set()),
    'physical-arm64': (set(), set(), set()),
    'vm': (set(), set(), set()),
    'container': ({'no_systemd', 'no_journal_access', 'no_ssh_keygen', 'no_boot_id'},
                  {'systemd/system', 'journal/system',
                   '/proc/sys/kernel/random/boot_id'}, set()),
    'restricted-user': ({'no_journal_access'}, {'journal/system'}, {'journal/system'}),
    'wsl': (set(), set(), set()),
    'ci-runner': (set(), set(), set()),
}


RECEIPT = Draft202012Validator(
    json.loads((ROOT / 'schemas/qualification-receipt-v1.schema.json').read_text()))


class Refused(Exception):
    """A precondition of a trustworthy receipt is not met."""


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True,
                            timeout=30, check=False)
    if result.returncode:
        raise Refused('source checkout is not a readable git work tree')
    return result.stdout


def source_identity(root):
    """The clean checkout being qualified; any change or untracked file refuses."""
    if git(root, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise Refused('source checkout is not clean')
    return git(root, 'rev-parse', 'HEAD').strip(), git(root, 'rev-parse', 'HEAD^{tree}').strip()


def executable(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def journal_visible():
    try:
        result = subprocess.run([JOURNALCTL, '--system', '--no-pager', '--quiet', '--boot', '-n',
                                 '1', '-o', 'export', '--output-fields=_PID', '_PID=1'],
                                capture_output=True, timeout=30, check=False,
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and b'\n_PID=1\n' in b'\n' + result.stdout


def os_release():
    fields = {}
    try:
        text = Path('/etc/os-release').read_text(errors='replace')
    except OSError:
        text = ''
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep and key in ('ID', 'VERSION_ID'):
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            fields[key] = value if re.fullmatch(r'[a-z0-9._-]{1,64}', value) else None
    return {'id': fields.get('ID'), 'version_id': fields.get('VERSION_ID')}


def command_line(argv, pattern):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False,
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.match(pattern, result.stdout) if result.returncode == 0 else None
    return match.group(1) if match else None


def probe_host():
    """Read-only capability probes and the coarse platform fields of the receipt."""
    systemd = os.path.isdir('/run/systemd/system') and executable(SYSTEMCTL)
    has_journalctl = executable(JOURNALCTL)
    capabilities = {
        'systemd': systemd,
        'journalctl': has_journalctl,
        'journal_visible': has_journalctl and journal_visible(),
        'psi': os.path.isdir('/proc/pressure'),
        'dpkg': os.path.isfile(DPKG_STATUS) and os.access(DPKG_STATUS, os.R_OK),
        'ssh_keygen': executable(SSH_KEYGEN),
        'boot_id': os.path.isfile(BOOT_ID),
    }
    version = command_line([SYSTEMCTL, '--version'], r'systemd ([0-9]{1,4})\b') if systemd else None
    try:
        release = Path('/proc/sys/kernel/osrelease').read_text()
    except OSError:
        release = ''
    series = re.match(r'([0-9]{1,4}\.[0-9]{1,4})(?![0-9])', release)
    platform = {
        'os': os_release(),
        'architecture': (command_line([DPKG, '--print-architecture'], r'([a-z0-9-]{1,32})\n?$')
                         if executable(DPKG) else None),
        'systemd_version': int(version) if version else None,
        'kernel_series': series.group(1) if series else None,
    }
    return capabilities, platform


def admit_gaps(status):
    """Only the closed source set and fixed-shape reasons enter the receipt."""
    if not isinstance(status, dict) or set(status) != {'observation_gaps'}:
        raise ValueError('malformed qualification status')
    gaps = set()
    for gap in status['observation_gaps']:
        if (not isinstance(gap, dict) or set(gap) != {'source', 'reason'}
                or gap['source'] not in GAP_SOURCES or not isinstance(gap['reason'], str)
                or GAP_REASON.fullmatch(gap['reason']) is None):
            raise ValueError('malformed observation gap')
        gaps.add((gap['source'], gap['reason']))
    return [{'source': source, 'reason': reason} for source, reason in sorted(gaps)]


def run_validator(argv, cwd, env, timeout):
    """Run in a new session and kill its whole process group on exit or timeout."""
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    deadline, timed_out = time.monotonic() + timeout, False
    try:
        # Wait without reaping: while the leader is unreaped its group ID cannot be reused.
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.05)
    finally:
        # Also on an interrupt: the new session does not receive the terminal's SIGINT.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = process.wait()
    if timed_out:
        raise subprocess.TimeoutExpired(argv, timeout)
    return code


def run_group(root, script, group, binary, timeout):
    """Run one group; return (result, reason, gaps) without keeping validator output."""
    with tempfile.TemporaryDirectory(prefix='mira-qualify-') as temp:
        for attempt in range(ATTEMPTS):
            status = Path(temp) / f'status-{attempt}.json'
            env = {**os.environ, 'MIRA_BINARY': binary, 'MIRA_QUALIFICATION_STATUS': str(status),
                   'PYTHONDONTWRITEBYTECODE': '1'}
            try:
                code = run_validator([sys.executable, str(root / 'scripts' / script), '--only',
                                      group], root, env, timeout)
            except (OSError, subprocess.TimeoutExpired):
                return 'failed', 'runner_error', []
            if code == INCONCLUSIVE:
                continue
            if code not in (PASSED, FAILED):
                return 'failed', 'runner_error', []
            if code == FAILED:
                return 'failed', 'validator_failed', []
            try:
                gaps = admit_gaps(json.loads(status.read_text()))
            except (OSError, ValueError, KeyError, TypeError):
                return 'failed', 'runner_error', []
            return 'passed', None, gaps
    return 'failed', 'inconclusive', []


def findings(receipt):
    """Fixed-identifier lines for every deviation from the class's expected gaps."""
    allowed_na, allowed_gaps, required_gaps = EXPECTED[receipt['host_class']]
    lines, seen = [], set()
    for check in receipt['checks']:
        name = f"{check['validator']} {check['group']}"
        if check['result'] == 'not_applicable' and check['reason'] not in allowed_na:
            lines.append(f"unexpected not_applicable: {name} {check['reason']}")
        for gap in check['observation_gaps']:
            seen.add(gap['source'])
            if gap['source'] not in allowed_gaps:
                lines.append(f"unexpected gap: {name} {gap['source']} {gap['reason']}")
    for source in sorted(required_gaps - seen):
        lines.append(f'missing required gap: {source}')
    return lines


def qualify(host_class, receipt_path, binary, *, root=ROOT, validators=VALIDATORS,
            probe=probe_host, euid=None, timeout=GROUP_TIMEOUT):
    if (euid or os.geteuid)() == 0:
        raise Refused('qualification must not run as root')
    receipt_path = Path(receipt_path)
    if os.path.lexists(receipt_path):
        raise Refused('receipt path already exists')
    binary = Path(binary).absolute()
    if not executable(binary):
        raise Refused('binary is not an executable file')
    commit, tree = source_identity(root)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    started_ms, started = time.time_ns() // 1_000_000, time.monotonic_ns()
    capabilities, platform = probe()
    checks = []
    for name, script, groups in validators:
        for group, needs in groups.items():
            missing = [need for need in needs if not capabilities[need]]
            if missing:
                checks.append({'validator': name, 'group': group, 'result': 'not_applicable',
                               'reason': NOT_APPLICABLE[missing[0]], 'duration_ms': 0,
                               'observation_gaps': []})
                continue
            began = time.monotonic_ns()
            result, reason, gaps = run_group(root, script, group, str(binary), timeout)
            checks.append({'validator': name, 'group': group, 'result': result, 'reason': reason,
                           'duration_ms': (time.monotonic_ns() - began) // 1_000_000,
                           'observation_gaps': gaps})
    # The receipt must describe the bytes and source that were actually tested.
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise Refused('binary changed during qualification')
    if source_identity(root) != (commit, tree):
        raise Refused('source checkout changed during qualification')
    try:
        binary.resolve().relative_to((root / 'target').resolve())
        origin = 'checkout-build'
    except ValueError:
        origin = 'installed'
    receipt = {
        'receipt_version': 1, 'source_commit': commit, 'source_tree': tree,
        'binary_sha256': digest,
        'binary_origin': origin, 'host_class': host_class, **platform,
        'capabilities': capabilities, 'checks': checks, 'started_unix_ms': started_ms,
        'duration_ms': (time.monotonic_ns() - started) // 1_000_000,
    }
    RECEIPT.validate(receipt)
    try:
        with receipt_path.open('x') as handle:
            handle.write(json.dumps(receipt, indent=2) + '\n')
    except FileExistsError:
        raise Refused('receipt path already exists') from None
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--host-class', required=True, choices=sorted(EXPECTED))
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--binary', default=str(ROOT / 'target/debug/mira'))
    args = parser.parse_args(argv)
    try:
        receipt = qualify(args.host_class, args.receipt, args.binary)
    except Refused as refusal:
        print(f'qualification refused: {refusal}', file=sys.stderr)
        return USAGE
    for check in receipt['checks']:
        print(f"{check['result']}: {check['validator']} {check['group']}"
              + (f" ({check['reason']})" if check['reason'] else ''))
    lines = findings(receipt)
    for line in lines:
        print(line)
    if any(check['result'] == 'failed' for check in receipt['checks']):
        return FAILED
    return FINDING if lines else PASSED


if __name__ == '__main__':
    sys.exit(main())
