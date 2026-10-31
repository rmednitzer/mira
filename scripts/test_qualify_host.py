#!/usr/bin/env python3
"""Runner, receipt and shared-contract tests for host qualification (ADR 0013)."""
import contextlib
import copy
import getpass
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import qualify_host
import validation_status
from jsonschema import ValidationError
from qualify_host import RECEIPT, VALIDATORS, Refused, findings, qualify

ROOT = Path(__file__).resolve().parents[1]
MIRA = ROOT / 'target/debug/mira'
ALL = dict.fromkeys(qualify_host.NOT_APPLICABLE, True)
PLATFORM = {'os': {'id': 'ubuntu', 'version_id': '26.04'}, 'architecture': 'amd64',
            'systemd_version': 259, 'kernel_series': '6.17'}
FAKE = '''import json, os, sys
plan = json.load(open(os.environ['FAKE_PLAN']))
group = sys.argv[sys.argv.index('--only') + 1]
spec = plan[group]
counter = os.path.join(os.environ['FAKE_STATE'], group)
with open(counter, 'a') as handle:
    handle.write('x')
attempt = len(open(counter).read()) - 1
code = spec['codes'][min(attempt, len(spec['codes']) - 1)]
if spec.get('spawn'):
    import subprocess, time
    child = subprocess.Popen(['sleep', '60'])
    with open(os.path.join(os.environ['FAKE_STATE'], 'child'), 'w') as handle:
        handle.write(str(child.pid))
    if spec['spawn'] == 'hang':
        time.sleep(60)
if spec.get('status', True):
    with open(os.environ['MIRA_QUALIFICATION_STATUS'], 'x') as handle:
        json.dump({'observation_gaps': spec.get('gaps', [])}, handle)
sys.exit(code)
'''


def commit_tree(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git = ['git', '-C', str(root), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
           '-c', 'commit.gpgsign=false']
    subprocess.run([*git, 'init', '-q'], check=True)
    subprocess.run([*git, 'add', '-A'], check=True)
    subprocess.run([*git, 'commit', '-q', '-m', 'fixture'], check=True)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix='mira-qualify-test-'))
        self.addCleanup(shutil.rmtree, self.temp)
        self.root = self.temp / 'checkout'
        self.root.mkdir()
        commit_tree(self.root, {'scripts/fake.py': FAKE})
        self.state = self.temp / 'state'
        self.state.mkdir()
        self.binary = self.temp / 'mira'
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o755)
        self.receipt = self.temp / 'receipt.json'

    def run_plan(self, plan, groups=None, capabilities=ALL, host_class='physical-amd64'):
        (self.temp / 'plan.json').write_text(json.dumps(plan))
        groups = groups or {name: () for name in plan}
        validators = (('evidence', 'fake.py', groups),)
        env = {'FAKE_PLAN': str(self.temp / 'plan.json'), 'FAKE_STATE': str(self.state)}
        with patch.dict(os.environ, env):
            return qualify(host_class, self.receipt, self.binary, root=self.root,
                           validators=validators, probe=lambda: (dict(capabilities), PLATFORM),
                           timeout=30)

    def attempts(self, group):
        path = self.state / group
        return len(path.read_text()) if path.exists() else 0

    def by_group(self, receipt):
        return {check['group']: check for check in receipt['checks']}

    def test_passed_failed_inconclusive_retry_and_runner_errors(self):
        plan = {'pass': {'codes': [0]}, 'fail': {'codes': [1]},
                'flaky': {'codes': [4, 4, 0]}, 'stuck': {'codes': [4]},
                'odd': {'codes': [7]}, 'silent': {'codes': [0], 'status': False},
                'leaky': {'codes': [0], 'gaps': [{'source': '/etc/hostname', 'reason': 'x'}]},
                'shaped': {'codes': [0], 'gaps': [{'source': 'journal/system', 'reason': 'a b'}]}}
        receipt = self.run_plan(plan)
        checks = self.by_group(receipt)
        expected = {'pass': ('passed', None), 'fail': ('failed', 'validator_failed'),
                    'flaky': ('passed', None), 'stuck': ('failed', 'inconclusive'),
                    'odd': ('failed', 'runner_error'), 'silent': ('failed', 'runner_error'),
                    'leaky': ('failed', 'runner_error'), 'shaped': ('failed', 'runner_error')}
        for group, outcome in expected.items():
            self.assertEqual((checks[group]['result'], checks[group]['reason']), outcome, group)
        # One run plus at most two retries; non-inconclusive results are never retried.
        self.assertEqual(self.attempts('flaky'), 3)
        self.assertEqual(self.attempts('stuck'), 3)
        self.assertEqual(self.attempts('fail'), 1)
        self.assertEqual(json.loads(self.receipt.read_text()), receipt)
        RECEIPT.validate(receipt)

    def child_alive(self):
        pid = (self.state / 'child').read_text()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
            except FileNotFoundError:
                return False
            if state == 'Z':
                return False
            time.sleep(0.05)
        return True

    def test_timeout_is_a_runner_error_and_kills_the_validator_group(self):
        (self.temp / 'plan.json').write_text(json.dumps({'slow': {'codes': [0], 'spawn': 'hang'}}))
        env = {'FAKE_PLAN': str(self.temp / 'plan.json'), 'FAKE_STATE': str(self.state)}
        began = time.monotonic()
        with patch.dict(os.environ, env):
            result = qualify_host.run_group(self.root, 'fake.py', 'slow', str(self.binary), 2)
        self.assertEqual(result, ('failed', 'runner_error', []))
        self.assertLess(time.monotonic() - began, 30)
        # The bound covers the work the validator started, not only the validator.
        self.assertFalse(self.child_alive())

    def test_interrupt_kills_the_validator_group(self):
        (self.temp / 'plan.json').write_text(json.dumps({'slow': {'codes': [0], 'spawn': 'hang'}}))
        env = {'FAKE_PLAN': str(self.temp / 'plan.json'), 'FAKE_STATE': str(self.state)}
        real_sleep = time.sleep

        def interrupt(seconds):
            if (self.state / 'child').exists():
                raise KeyboardInterrupt
            real_sleep(seconds)
        with patch.dict(os.environ, env), patch('qualify_host.time.sleep', interrupt), \
                self.assertRaises(KeyboardInterrupt):
            qualify_host.run_group(self.root, 'fake.py', 'slow', str(self.binary), 60)
        self.assertFalse(self.child_alive())

    def test_descendants_left_behind_by_a_finished_validator_are_killed(self):
        (self.temp / 'plan.json').write_text(json.dumps({'done': {'codes': [0], 'spawn': 'exit'}}))
        env = {'FAKE_PLAN': str(self.temp / 'plan.json'), 'FAKE_STATE': str(self.state)}
        with patch.dict(os.environ, env):
            result = qualify_host.run_group(self.root, 'fake.py', 'done', str(self.binary), 30)
        self.assertEqual(result, ('passed', None, []))
        self.assertFalse(self.child_alive())

    def test_container_without_boot_id_qualifies(self):
        capture = next(groups for name, _, groups in VALIDATORS if name == 'capture')
        plan = {group: {'codes': [0]} for group in capture}
        # signed-compare still runs and reports the unavailable boot binding it requested.
        plan['signed-compare']['gaps'] = [{'source': '/proc/sys/kernel/random/boot_id',
                                           'reason': 'not_found'}]
        receipt = self.run_plan(plan, groups=capture, host_class='container',
                                capabilities={**ALL, 'boot_id': False})
        checks = self.by_group(receipt)
        self.assertEqual(checks['live-boot']['reason'], 'no_boot_id')
        self.assertEqual(checks['signed-compare']['result'], 'passed')
        self.assertEqual(findings(receipt), [])

    def test_container_journal_denial_qualifies(self):
        journal = next(groups for name, _, groups in VALIDATORS if name == 'journal')
        plan = {group: {'codes': [0]} for group in journal}
        plan['live-visibility']['gaps'] = [{'source': 'journal/system',
                                            'reason': 'journal_not_visible'}]
        receipt = self.run_plan(plan, groups=journal, host_class='container',
                                capabilities={**ALL, 'systemd': False, 'journal_visible': False})
        self.assertEqual(self.by_group(receipt)['live-counts']['reason'], 'no_journal_access')
        self.assertEqual(findings(receipt), [])

    def test_every_not_applicable_reason_and_no_execution(self):
        groups = {f'needs-{need.replace("_", "-")}': (need,) for need in qualify_host.NOT_APPLICABLE}
        receipt = self.run_plan({}, groups=groups,
                                capabilities=dict.fromkeys(ALL, False))
        reasons = {check['reason'] for check in receipt['checks']}
        self.assertEqual(reasons, set(qualify_host.NOT_APPLICABLE.values()))
        self.assertTrue(all(check['result'] == 'not_applicable' for check in receipt['checks']))
        self.assertEqual(list(self.state.iterdir()), [])
        RECEIPT.validate(receipt)

    def test_refusals_write_nothing(self):
        cases = []
        cases.append(lambda: qualify('vm', self.receipt, self.binary, root=self.root,
                                     euid=lambda: 0))
        self.binary.chmod(0o644)
        cases.append(lambda: qualify('vm', self.receipt, self.binary, root=self.root))
        for case in cases:
            with self.assertRaises(Refused):
                case()
            self.assertFalse(self.receipt.exists())
        self.binary.chmod(0o755)
        (self.root / 'untracked').write_text('x')
        with self.assertRaises(Refused):
            qualify('vm', self.receipt, self.binary, root=self.root, probe=lambda: 1 / 0)
        self.assertFalse(self.receipt.exists())
        (self.root / 'untracked').unlink()
        (self.root / 'scripts/fake.py').write_text(FAKE + '\n')
        with self.assertRaises(Refused):
            qualify('vm', self.receipt, self.binary, root=self.root, probe=lambda: 1 / 0)
        subprocess.run(['git', '-C', str(self.root), 'checkout', '-q', '--', '.'], check=True)
        self.receipt.write_text('existing')
        with self.assertRaises(Refused):
            qualify('vm', self.receipt, self.binary, root=self.root, probe=lambda: 1 / 0)
        self.assertEqual(self.receipt.read_text(), 'existing')

    def test_root_refusal_through_main(self):
        diagnostic = io.StringIO()
        with patch('qualify_host.os.geteuid', return_value=0), \
                contextlib.redirect_stderr(diagnostic):
            code = qualify_host.main(['--host-class', 'vm', '--receipt', str(self.receipt),
                                      '--binary', str(self.binary)])
        self.assertEqual(code, 2)
        self.assertEqual(diagnostic.getvalue(),
                         'qualification refused: qualification must not run as root\n')

    def test_denial_path_runs_visibility_and_gates_only_counts(self):
        journal = next(groups for name, _, groups in VALIDATORS if name == 'journal')
        plan = {group: {'codes': [0]} for group in journal}
        plan['live-visibility']['gaps'] = [{'source': 'journal/system',
                                            'reason': 'journal_not_visible'}]
        receipt = self.run_plan(plan, groups=journal, host_class='restricted-user',
                                capabilities={**ALL, 'journal_visible': False})
        checks = self.by_group(receipt)
        self.assertEqual(checks['live-visibility']['result'], 'passed')
        self.assertEqual(self.attempts('live-visibility'), 1)
        self.assertEqual((checks['live-counts']['result'], checks['live-counts']['reason']),
                         ('not_applicable', 'no_journal_access'))
        self.assertEqual(self.attempts('live-counts'), 0)
        self.assertEqual(findings(receipt), [])
        # The same receipt without the confirmed denial does not qualify the restricted run.
        checks['live-visibility']['observation_gaps'] = []
        self.assertEqual(findings(receipt), ['missing required gap: journal/system'])
        # And on an unrestricted class, the denial itself is unexpected.
        receipt['host_class'] = 'vm'
        checks['live-visibility']['observation_gaps'] = [
            {'source': 'journal/system', 'reason': 'journal_not_visible'}]
        self.assertEqual(findings(receipt), [
            'unexpected gap: evidence live-visibility journal/system journal_not_visible',
            'unexpected not_applicable: evidence live-counts no_journal_access'])

    def test_missing_ssh_keygen_gates_only_signed_compare(self):
        capture = next(groups for name, _, groups in VALIDATORS if name == 'capture')
        receipt = self.run_plan({group: {'codes': [0]} for group in capture}, groups=capture,
                                capabilities={**ALL, 'ssh_keygen': False})
        results = {check['group']: check['result'] for check in receipt['checks']}
        self.assertEqual(results, {'schema': 'passed', 'cli': 'passed', 'compare': 'passed',
                                   'live-boot': 'passed', 'signed-compare': 'not_applicable'})

    def test_forbidden_host_data_never_enters_the_receipt(self):
        plan = {'one': {'codes': [0], 'gaps': [{'source': '/proc/pressure/io',
                                                'reason': 'not_found'}]}}
        (self.temp / 'plan.json').write_text(json.dumps(plan))
        env = {'FAKE_PLAN': str(self.temp / 'plan.json'), 'FAKE_STATE': str(self.state)}
        with patch.dict(os.environ, env):
            receipt = qualify('vm', self.receipt, self.binary, root=self.root,
                              validators=(('evidence', 'fake.py', {'one': ()}),), timeout=30)
        RECEIPT.validate(receipt)
        raw = self.receipt.read_text()
        values = set()

        def strings(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    values.add(key)
                    strings(value)
            elif isinstance(node, list):
                for value in node:
                    strings(value)
            elif isinstance(node, str):
                values.add(node)
        strings(receipt)
        forbidden = [socket.gethostname(), getpass.getuser()]
        for path in ('/etc/machine-id', '/proc/sys/kernel/random/boot_id',
                     '/proc/sys/kernel/osrelease'):
            with contextlib.suppress(OSError):
                forbidden.append(Path(path).read_text().strip())
        for value in filter(None, forbidden):
            # Short values (a user name such as "runner") are checked as whole tokens.
            if len(value) >= 8:
                self.assertNotIn(value, raw)
            tokens = {token for item in values for token in item.replace('/', '-').split('-')}
            self.assertNotIn(value, values | tokens)
        osrelease = Path('/proc/sys/kernel/osrelease').read_text().strip()
        if receipt['kernel_series'] is not None:
            self.assertTrue(osrelease.startswith(receipt['kernel_series']))
            self.assertNotEqual(receipt['kernel_series'], osrelease)


class PressureGapTests(unittest.TestCase):
    """A real pressure validator run against a binary with one unreadable PSI file."""

    @unittest.skipUnless(MIRA.is_file(), 'requires the checkout build')
    def test_unreadable_psi_passes_with_a_reported_gap(self):
        temp = Path(tempfile.mkdtemp(prefix='mira-qualify-psi-'))
        self.addCleanup(shutil.rmtree, temp)
        root = temp / 'checkout'
        files = {}
        for directory in ('scripts', 'schemas', 'tests/fixtures'):
            for path in (ROOT / directory).glob('*.py' if directory == 'scripts' else '*.json'):
                files[f'{directory}/{path.name}'] = path.read_text()
        root.mkdir()
        commit_tree(root, files)
        wrapper = temp / 'mira'
        wrapper.write_text(f'''#!{sys.executable}
import json, subprocess, sys
result = subprocess.run([{str(MIRA)!r}, *sys.argv[1:]], capture_output=True)
if 'io' in sys.argv and '--json' in sys.argv:
    report = json.loads(result.stdout)
    report['evidence'].update(status='unavailable', value=None, error_kind='PermissionDenied',
                              failure_reason='permission_denied')
    report['assessment'].update(outcome='indeterminate', reason='evidence_unavailable')
    sys.stdout.write(json.dumps(report) + '\\n')
    sys.exit(3)
sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
''')
        wrapper.chmod(0o755)
        receipt = qualify('physical-amd64', temp / 'receipt.json', wrapper, root=root,
                          validators=(('pressure', 'validate_pressure_investigation.py',
                                       {'fixtures': (), 'cli': ()}),),
                          probe=lambda: (dict(ALL), PLATFORM), timeout=120)
        cli = receipt['checks'][1]
        self.assertEqual(cli['result'], 'passed')
        self.assertIn({'source': '/proc/pressure/io', 'reason': 'permission_denied'},
                      cli['observation_gaps'])
        self.assertEqual(receipt['binary_origin'], 'installed')
        self.assertIn('unexpected gap: pressure cli /proc/pressure/io permission_denied',
                      findings(receipt))


class ReceiptSchemaTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {
            'receipt_version': 1, 'source_commit': 'a' * 40, 'source_tree': 'b' * 40,
            'binary_sha256': 'c' * 64, 'binary_origin': 'installed', 'host_class': 'vm',
            **copy.deepcopy(PLATFORM), 'capabilities': dict(ALL),
            'checks': [{'validator': 'journal', 'group': 'live-counts', 'result': 'passed',
                        'reason': None, 'duration_ms': 5,
                        'observation_gaps': [{'source': 'journal/coredump',
                                              'reason': 'limit_exceeded'}]}],
            'started_unix_ms': 1, 'duration_ms': 2}

    def test_valid_receipt(self):
        RECEIPT.validate(self.receipt)

    def test_host_identifying_or_malformed_fields_are_refused(self):
        mutations = [
            lambda r: r.update(hostname='host'),
            lambda r: r.update(kernel_series='6.17.0-1010-azure'),
            lambda r: r.update(kernel_series='6.17\n'),
            lambda r: r['os'].update(pretty_name='Ubuntu'),
            lambda r: r['capabilities'].update(user='x'),
            lambda r: r['checks'][0].update(output='sample'),
            lambda r: r['checks'][0]['observation_gaps'][0].update(source='/etc/hostname'),
            lambda r: r['checks'][0]['observation_gaps'][0].update(value=1),
            lambda r: r['checks'][0].update(result='failed', reason=None),
            lambda r: r['checks'][0].update(result='not_applicable', reason='no_psi'),
            lambda r: r['checks'][0].update(reason='inconclusive'),
            lambda r: r.update(host_class='laptop'),
            lambda r: r.update(checks=[]),
        ]
        for index, mutate in enumerate(mutations):
            receipt = copy.deepcopy(self.receipt)
            mutate(receipt)
            with self.subTest(index=index), self.assertRaises(ValidationError):
                RECEIPT.validate(receipt)

    def test_committed_receipts_conform(self):
        for path in sorted((ROOT / 'docs/qualification/receipts').glob('*.json')):
            with self.subTest(path=path.name):
                RECEIPT.validate(json.loads(path.read_text()))


class GroupContractTests(unittest.TestCase):
    def test_every_validator_lists_the_runner_groups(self):
        for name, script, groups in VALIDATORS:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts' / script),
                                     '--list-groups'], capture_output=True, text=True,
                                    timeout=60, check=False)
            with self.subTest(validator=name):
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout.split(), list(groups))

    def run_contract(self, groups, argv, opt_in=None, env=None):
        output, diagnostic = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env or {}, clear=False), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostic), \
                self.assertRaises(SystemExit) as result:
            validation_status.run('fixture validation', groups, 'all validated', argv, opt_in)
        return result.exception.code, output.getvalue(), diagnostic.getvalue()

    def test_only_runs_exactly_the_selected_groups_in_declared_order(self):
        calls = []
        groups = {name: (lambda name=name: calls.append(name)) for name in ('a', 'b', 'c', 'd')}
        self.assertEqual(self.run_contract(groups, ['--only', 'c,a'])[:2],
                         (0, 'fixture validation groups passed: a,c\n'))
        self.assertEqual(calls, ['a', 'c'])
        calls.clear()
        self.assertEqual(self.run_contract(groups, [], opt_in={'d': '--live-d'})[:2],
                         (0, 'all validated\n'))
        self.assertEqual(calls, ['a', 'b', 'c'])
        calls.clear()
        self.run_contract(groups, ['--live-d'], opt_in={'d': '--live-d'})
        self.assertEqual(calls, ['a', 'b', 'c', 'd'])
        for argv in (['--only', 'e'], ['--only', 'a,a'], ['--only', '']):
            calls.clear()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                validation_status.run('fixture validation', groups, 'x', argv)
            self.assertEqual(result.exception.code, 2)
            self.assertEqual(calls, [])

    def test_exit_statuses_and_fixed_diagnostics(self):
        def inconclusive():
            raise validation_status.Inconclusive('sampled 12345')

        def wrong():
            raise ValueError('sampled 12345')
        self.assertEqual(self.run_contract({'x': inconclusive}, []),
                         (4, '', 'fixture validation failed: Inconclusive\n'))
        self.assertEqual(self.run_contract({'x': wrong}, []),
                         (1, '', 'fixture validation failed: ValueError\n'))

    def test_status_file_reports_gaps_exclusively(self):
        temp = Path(tempfile.mkdtemp(prefix='mira-status-'))
        self.addCleanup(shutil.rmtree, temp)
        status = temp / 'status.json'

        def observe():
            validation_status.note_record({'source': '/proc/pressure/io', 'status': 'unavailable',
                                           'error_kind': 'PermissionDenied',
                                           'failure_reason': 'permission_denied'})
            validation_status.note_record({'source': '/proc/meminfo', 'status': 'unavailable',
                                           'error_kind': 'odd kind!'})
            validation_status.note_record({'source': '/proc/uptime', 'status': 'observed'})
        env = {'MIRA_QUALIFICATION_STATUS': str(status)}
        self.assertEqual(self.run_contract({'x': observe}, [], env=env)[0], 0)
        self.assertEqual(json.loads(status.read_text()), {'observation_gaps': [
            {'source': '/proc/meminfo', 'reason': 'unrecognized'},
            {'source': '/proc/pressure/io', 'reason': 'permission_denied'}]})
        self.assertEqual(stat.S_IMODE(status.stat().st_mode), 0o600)
        # An existing status file is never overwritten; the run cannot pass.
        self.assertEqual(self.run_contract({'x': observe}, [], env=env)[0], 1)
        with self.assertRaises(ValueError):
            validation_status.note_gap('/etc/hostname', 'x')

    def test_binary_input(self):
        with patch.dict(os.environ, {'MIRA_BINARY': 'relative/mira'}):
            self.assertEqual(validation_status.mira_binary(), str(Path('relative/mira').absolute()))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MIRA_BINARY', None)
            self.assertEqual(validation_status.mira_binary(), str(MIRA))


if __name__ == '__main__':
    unittest.main()
