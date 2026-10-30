#!/usr/bin/env python3
"""Synthetic acceptance/refusal cases for the optional live procfs comparison."""
import contextlib
import copy
import io
import unittest
from unittest.mock import patch

from validate_evidence_schema import (
    check_live_procfs, check_live_procfs_values, check_record, read_live_procfs, run,
)


class LiveProcfsTests(unittest.TestCase):
    def setUp(self):
        self.before = {'total_kib': 100, 'kernel': '6.17.0-fixture', 'uptime': 10}
        self.after = {**self.before, 'uptime': 12}
        values = [('/proc/meminfo', {'total_kib': 100, 'available_kib': 50}),
                  ('/proc/sys/kernel/osrelease', '6.17.0-fixture'),
                  ('/proc/uptime', 11)]
        self.records = [
            {'schema_version': 1, 'source': source, 'scope': None,
             'recorded_unix_ms': None, 'clock_trust': 'unverified',
             'freshness': 'unknown', 'status': 'observed', 'value': value,
             'error_kind': None}
            for source, value in values
        ]
        for record in self.records:
            check_record(record)

    def check(self):
        check_live_procfs_values(self.before, self.records, self.after)

    def test_interval_endpoints_and_fluctuating_available_memory_are_valid(self):
        for uptime in (10, 11, 12):
            for available in (0, 50, 100):
                self.records[0]['value']['available_kib'] = available
                self.records[2]['value'] = uptime
                self.check()

    def test_schema_valid_but_wrong_observations_are_refused(self):
        for index, value in [(0, {'total_kib': 101, 'available_kib': 50}),
                             (1, '6.17.0-another'), (2, 9), (2, 13)]:
            with self.subTest(index=index, value=value):
                records = copy.deepcopy(self.records)
                records[index]['value'] = value
                check_record(records[index])
                with self.assertRaises(ValueError):
                    check_live_procfs_values(self.before, records, self.after)

    def test_changed_endpoint_or_reversed_time_is_inconclusive(self):
        for field, value in [('total_kib', 101), ('kernel', 'another'), ('uptime', 9)]:
            after = {**self.after, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_live_procfs_values(self.before, self.records, after)

    def test_unavailable_required_observations_cannot_pass(self):
        for index in range(3):
            records = copy.deepcopy(self.records)
            records[index].update(status='unavailable', value=None, error_kind='NotFound')
            check_record(records[index])
            with self.subTest(index=index), self.assertRaises(ValueError):
                check_live_procfs_values(self.before, records, self.after)

    def test_direct_reads_preserve_exact_whole_uptime(self):
        files = {'/proc/meminfo': b'MemTotal: 100 kB\nMemAvailable: 50 kB\n',
                 '/proc/sys/kernel/osrelease': b'6.17.0-fixture\n',
                 '/proc/uptime': b'9007199254740993.99 9999999999999999.00\n'}
        def open_fixture(path, *args, **kwargs):
            return io.BytesIO(files[str(path)])
        with patch('validate_evidence_schema.Path.open', autospec=True,
                   side_effect=open_fixture):
            sample = read_live_procfs()
        self.assertEqual(sample, {**self.before, 'uptime': 9007199254740993})

    def test_direct_reads_reject_malformed_or_oversized_sources(self):
        base = {'/proc/meminfo': b'MemTotal: 100 kB\n',
                '/proc/sys/kernel/osrelease': b'6.17.0-fixture\n',
                '/proc/uptime': b'10.00 20.00\n'}
        for path, data in [('/proc/meminfo', b'MemTotal: 100 kB\nMemTotal: 100 kB\n'),
                           ('/proc/meminfo', b'MemTotal: +100 kB\n'),
                           ('/proc/meminfo', b'x' * 65537),
                           ('/proc/sys/kernel/osrelease', b'x' * 16385),
                           ('/proc/sys/kernel/osrelease', b'kernel\nother\n'),
                           ('/proc/uptime', b'10.00 NaN\n'),
                           ('/proc/uptime', b'x' * 65537)]:
            files = {**base, path: data}
            def open_fixture(path, *args, **kwargs):
                return io.BytesIO(files[str(path)])
            with self.subTest(path=path), patch(
                    'validate_evidence_schema.Path.open', autospec=True,
                    side_effect=open_fixture), self.assertRaises(ValueError):
                read_live_procfs()

    def test_failure_diagnostic_does_not_echo_sample_values(self):
        diagnostic = io.StringIO()
        output = io.StringIO()
        with patch('validate_evidence_schema.main', side_effect=ValueError('private-sample')):
            with contextlib.redirect_stderr(diagnostic), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as result:
                    run()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(diagnostic.getvalue(), 'evidence schema validation failed: ValueError\n')

    def test_root_is_refused_before_any_acquisition(self):
        with patch('validate_evidence_schema.os.geteuid', return_value=0), patch(
                'validate_evidence_schema.read_live_procfs') as direct:
            with self.assertRaises(ValueError):
                check_live_procfs()
            direct.assert_not_called()


if __name__ == '__main__':
    unittest.main()
