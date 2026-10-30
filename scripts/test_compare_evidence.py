#!/usr/bin/env python3
import json
import os
import copy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from jsonschema import Draft202012Validator
from compare_evidence import compare, load, strict_json, MAX_BYTES, MAX_DEPTH
from capture_contract import check_capture

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/evidence-v1.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def record(source="/proc/uptime", value=10, status="observed", scope=None, time=10):
    return {"schema_version": 1, "source": source, "scope": scope,
            "recorded_unix_ms": time, "clock_trust": "unverified",
            "freshness": "unknown", "status": status,
            "value": value if status == "observed" else None,
            "error_kind": None if status == "observed" else "NotFound"}


class ComparisonTests(unittest.TestCase):
    def test_changed_with_backward_clock(self):
        a = record(time=999, value=10)
        b = record(time=1, value=20)
        result = compare({(a["source"], None): a}, {(b["source"], None): b})
        self.assertEqual(result["changes"][0]["outcome"], "changed")
        self.assertEqual(result["changes"][0]["clock_order"], "unverified")
        self.assertEqual(result["overall_freshness"], "unknown")

    def test_absence_and_failure_are_distinct(self):
        a = record()
        b = record(status="unavailable")
        key = (a["source"], None)
        self.assertEqual(compare({key: a}, {key: b})["changes"][0]["outcome"], "indeterminate")
        self.assertEqual(compare({key: a}, {})["changes"][0]["outcome"], "missing")
        self.assertEqual(compare({}, {key: a})["changes"][0]["outcome"], "added")

    def test_same_values_are_unchanged_not_fresh(self):
        a = record()
        key = (a["source"], None)
        entry = compare({key: a}, {key: a})["changes"][0]
        self.assertEqual(entry["outcome"], "unchanged")
        self.assertEqual(entry["freshness"], "unknown")

    def test_reject_duplicate_scope_and_invalid_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "evidence.jsonl"
            p.write_text(json.dumps(record()) + "\n" + json.dumps(record()) + "\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load(p, VALIDATOR)
            p.write_text(json.dumps({**record(), "schema_version": 2}))
            with self.assertRaises(Exception):
                load(p, VALIDATOR)

    def test_reject_oversized_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "evidence.jsonl"
            p.write_bytes(b"x" * (MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "exceeds"):
                load(p, VALIDATOR)

    def test_reject_semantically_invalid_memory_record(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "evidence.jsonl"
            invalid = record(source="/proc/meminfo",
                             value={"total_kib": 20, "available_kib": 30})
            p.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(ValueError, "available memory"):
                load(p, VALIDATOR)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO not supported")
    def test_reject_fifo_without_reading(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "capture"
            os.mkfifo(p)
            with self.assertRaisesRegex(ValueError, "regular file"):
                load(p, VALIDATOR)

    def test_distinct_service_scopes_never_compare_as_same(self):
        a = record(source="systemd/system", scope="ssh.service",
                   value={"id": "ssh.service", "load_state": "loaded",
                          "active_state": "active", "sub_state": "running"})
        b = {**a, "scope": "cron.service"}
        result = compare({(a["source"], a["scope"]): a},
                         {(b["source"], b["scope"]): b})
        self.assertEqual([x["outcome"] for x in result["changes"]], ["added", "missing"])


class AdmissionTests(unittest.TestCase):
    def test_decimal_and_exponent_tokens_cannot_be_rounded_into_integers(self):
        for token in ('1.0', '0.0', '-0.0', '1e0', '1E0', '1e999',
                      '9007199254740993.0', '10.0000000000000001'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, 'integer JSON tokens'):
                    strict_json(('{"value":' + token + '}').encode())
        for value in (0, 9007199254740993, 2 ** 64 - 1, 2 ** 128 - 1):
            self.assertEqual(strict_json(json.dumps({'value': value}).encode()),
                             {'value': value})
        self.assertEqual(strict_json(b'{"value":"1.0"}'), {'value': '1.0'})

    def test_legacy_and_complete_import_refuse_lossy_numeric_tokens(self):
        capture = json.loads((ROOT / 'tests/fixtures/capture-v1.json').read_text())['valid'][0]
        capture = copy.deepcopy(capture)
        uptime = next(row for row in capture['records'] if row['source'] == '/proc/uptime')
        uptime.update(status='observed', value=0, error_kind=None, failure_reason=None)
        capture['all_available'] = all(row['status'] == 'observed' for row in capture['records'])
        with tempfile.TemporaryDirectory() as temp:
            before = Path(temp) / 'before'
            after = Path(temp) / 'after'
            for document in (record(value=0), capture):
                encoded = json.dumps(document)
                before.write_text(encoded.replace('"value": 0', '"value": 9007199254740992', 1))
                after.write_text(encoded.replace('"value": 0', '"value": 9007199254740993', 1))
                report = compare(load(before, VALIDATOR), load(after, VALIDATOR))
                change = next(row for row in report['changes'] if row['source'] == '/proc/uptime')
                self.assertEqual(change['outcome'], 'changed')
                for token in ('9007199254740993.0', '10.0000000000000001', '1e0'):
                    after.write_text(encoded.replace('"value": 0', '"value": ' + token, 1))
                    with self.subTest(complete='capture_version' in document, token=token):
                        with self.assertRaisesRegex(ValueError, 'integer JSON tokens'):
                            load(after, VALIDATOR)
                        result = subprocess.run(
                            [sys.executable, str(ROOT / 'scripts/compare_evidence.py'),
                             str(before), str(after)], capture_output=True, check=False, timeout=5)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, b'')
                        self.assertEqual(result.stderr, b'evidence comparison failed: ValueError\n')

    def test_io_failure_cannot_hide_specifically_mapped_error_kinds(self):
        capture = json.loads((ROOT / 'tests/fixtures/capture-v1.json').read_text())['valid'][0]
        capture = copy.deepcopy(capture)
        capture['all_available'] = False
        row = capture['records'][0]
        row.update(status='unavailable', value=None, failure_reason='io_failure')
        for kind in ('TimedOut', 'InvalidData', 'InvalidInput', 'PermissionDenied', 'NotFound'):
            row['error_kind'] = kind
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'failure reason contradicts error kind'):
                    check_capture(capture)
        # Other can be either a typed backend failure or a generic I/O failure.
        for kind in ('Other', 'Interrupted', 'UnexpectedEof', 'FutureErrorKind'):
            row['error_kind'] = kind
            self.assertIs(check_capture(capture), capture)
        row.update(error_kind='TimedOut', failure_reason='timeout')
        self.assertIs(check_capture(capture), capture)

    def test_duplicate_keys_at_every_level_are_rejected_before_schema(self):
        for data in [b'{"schema_version":999,"schema_version":1}',
                     b'{"value":{"x":1,"x":2}}']:
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                strict_json(data)

    def test_invalid_json_unicode_and_depth_are_refused(self):
        for data in [b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                     b'{"x":1e999}', b'{"x":"\\ud800"}', b'\xff',
                     b'[' * (MAX_DEPTH + 1) + b'0' + b']' * (MAX_DEPTH + 1)]:
            with self.assertRaises((ValueError, UnicodeError)):
                strict_json(data)
        self.assertEqual(strict_json(b'{"x":"[\\\"quoted]"}'), {"x": '["quoted]'})

    def test_empty_capture_is_not_a_successful_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "empty"
            p.write_bytes(b" \n")
            with self.assertRaisesRegex(ValueError, "empty capture"):
                load(p, VALIDATOR)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO not supported")
    def test_replacement_at_open_cannot_wait_for_a_fifo_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "capture"
            fifo = Path(temp) / "fifo"
            p.write_text(json.dumps(record()))
            os.mkfifo(fifo)
            original = os.open
            seen = []
            def replace_then_open(path, flags, *args, **kwargs):
                seen.append(flags)
                os.replace(fifo, p)
                return original(path, flags, *args, **kwargs)
            with patch("compare_evidence.os.open", replace_then_open):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    load(p, VALIDATOR)
            self.assertEqual(len(seen), 1)
            self.assertTrue(seen[0] & os.O_NONBLOCK)

    def test_symlink_compatibility_and_growth_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "capture"
            link = Path(temp) / "link"
            p.write_text(json.dumps(record()))
            link.symlink_to(p)
            self.assertEqual(load(link, VALIDATOR), load(p, VALIDATOR))
            original = os.fstat
            def grow(descriptor):
                info = original(descriptor)
                p.write_bytes(b"x" * (MAX_BYTES + 1))
                return info
            with patch("compare_evidence.os.fstat", grow):
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    load(p, VALIDATOR)


if __name__ == "__main__":
    unittest.main()
