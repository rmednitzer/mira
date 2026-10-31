#!/usr/bin/env python3
"""Each live comparison exits 4 on a forced mid-comparison change and 1 on wrong evidence."""
import contextlib
import io
import os
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

import validate_capture_schema as capture
import validate_evidence_schema as evidence
import validate_host_investigations as host
import validate_investigation_schema as investigation
import validate_journal_investigation as journal
import validate_package_investigation as package

ROOT = Path(__file__).resolve().parents[1]
BUILT = (ROOT / 'target/debug/mira').is_file()
SYSTEMD = os.path.isdir('/run/systemd/system') and shutil.which('systemctl') is not None
JOURNAL = os.path.isfile('/usr/bin/journalctl')
DPKG = os.access('/var/lib/dpkg/status', os.R_OK)


def changing(real, mutate, at=2):
    """Return the real value on every call except the at-th, which is mutated."""
    calls = []

    def sample(*args):
        calls.append(None)
        value = real(*args)
        return mutate(value) if len(calls) == at else value
    return sample


@unittest.skipUnless(BUILT, 'requires the checkout build')
class ContractTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop('MIRA_BINARY', None)
        os.environ.pop('MIRA_QUALIFICATION_STATUS', None)

    def status(self, module, group, **patches):
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(patch.object(module, name, value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            diagnostic = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            with self.assertRaises(SystemExit) as result:
                module.main(['--only', group])
        code = result.exception.code
        # Wrong evidence must fail the comparison itself, not crash the validator.
        endings = (': Inconclusive\n',) if code == 4 else (': ValueError\n', ': AssertionError\n')
        self.assertTrue(diagnostic.getvalue().endswith(endings), diagnostic.getvalue())
        return code

    def test_procfs(self):
        real = evidence.read_live_procfs
        self.assertEqual(self.status(evidence, 'live-procfs', read_live_procfs=changing(
            real, lambda s: {**s, 'total_kib': s['total_kib'] + 1})), 4)
        sample = real()
        self.assertEqual(self.status(evidence, 'live-procfs', read_live_procfs=lambda: {
            **sample, 'kernel': 'mira-wrong-kernel'}), 1)

    @unittest.skipUnless(SYSTEMD, 'requires systemd')
    def test_systemd_evidence(self):
        real = evidence.direct_unit
        self.assertEqual(self.status(evidence, 'live-systemd', direct_unit=changing(
            real, lambda d: {**d, 'SubState': 'mira-changed'})), 4)
        self.assertEqual(self.status(evidence, 'live-systemd', direct_unit=lambda unit: {
            **real(unit), 'SubState': 'mira-wrong'}), 1)

    @unittest.skipUnless(SYSTEMD, 'requires systemd')
    def test_systemd_investigation(self):
        real = investigation.direct_unit
        self.assertEqual(self.status(investigation, 'live-systemd', direct_unit=changing(
            real, lambda d: {**d, 'SubState': 'mira-changed'})), 4)
        self.assertEqual(self.status(investigation, 'live-systemd', direct_unit=lambda unit: {
            **real(unit), 'SubState': 'mira-wrong'}), 1)

    @unittest.skipUnless(DPKG, 'requires a readable dpkg database')
    def test_dpkg(self):
        real = package.read_status
        self.assertEqual(self.status(package, 'live-dpkg', read_status=changing(
            real, lambda r: (r[0] + b'\n', r[1]))), 4)

        def wrong():
            data, stanzas = real()
            return data, [{**s, 'version': 'mira-wrong'} if s['package'] == 'dpkg' else s
                          for s in stanzas]
        self.assertEqual(self.status(package, 'live-dpkg', read_status=wrong), 1)

    def test_uptime_and_kernel(self):
        self.assertEqual(self.status(host, 'live', direct_uptime=changing(
            host.direct_uptime, lambda u: u - 1_000_000)), 4)
        self.assertEqual(self.status(host, 'live', direct_kernel=changing(
            host.direct_kernel, lambda k: k + '-changed')), 4)
        self.assertEqual(self.status(host, 'live', direct_kernel=lambda: 'mira-wrong-kernel'), 1)

    @unittest.skipUnless(JOURNAL, 'requires journalctl')
    def test_journal_visibility(self):
        real = journal.independent_visibility
        self.assertEqual(self.status(journal, 'live-visibility', independent_visibility=changing(
            real, lambda v: {**v, 'visible': not v['visible']})), 4)

        def flipped(absent, boot):
            value = real(absent, boot)
            if value['visible']:
                return {'visible': False, 'access': None, 'handler': None}
            return {'visible': True, 'access': True, 'handler': None}
        self.assertEqual(self.status(journal, 'live-visibility',
                                     independent_visibility=flipped), 1)

    @unittest.skipUnless(JOURNAL and journal.visible('current'), 'requires a visible journal')
    def test_journal_counts(self):
        real = journal.independent_counts
        self.assertEqual(self.status(journal, 'live-counts', independent_counts=changing(
            real, lambda c: {k: v + 1 for k, v in c.items()})), 4)
        self.assertEqual(self.status(journal, 'live-counts', independent_counts=lambda a, b: {
            k: v + 1 for k, v in real(a, b).items()}), 1)

    @unittest.skipUnless(os.path.isfile('/proc/sys/kernel/random/boot_id'), 'requires a boot ID')
    def test_boot_binding(self):
        real = capture.direct_boot
        self.assertEqual(self.status(capture, 'live-boot', direct_boot=changing(
            real, lambda b: ('00000000-0000-0000-0000-000000000000', b[1]))), 4)
        self.assertEqual(self.status(capture, 'live-boot', direct_boot=lambda: (
            '00000000-0000-0000-0000-000000000000', real()[1])), 1)


if __name__ == '__main__':
    unittest.main()
