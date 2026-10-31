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
import compare_evidence
from compare_evidence import compare, load, strict_json, MAX_BYTES, MAX_DEPTH, Trust
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


TIMELINE = json.loads((ROOT / "tests/fixtures/capture-v2.json").read_text())["valid"][0]
BOOT_A = "e740207d-b13a-48dd-8e9d-595a950d6930"
BOOT_B = "00000000-0000-4000-8000-000000000000"


def timeline_capture(boot, window=7):
    document = copy.deepcopy(TIMELINE)
    document["collection"]["boot"] = boot
    document["collection"]["monotonic_window_ms"] = window
    document["collection"]["ended_unix_ms"] = document["collection"]["started_unix_ms"] + window
    return document


def bound(started, ended, boot_id=BOOT_A):
    return {"binding": "observed", "boot_id": boot_id,
            "started_uptime_cs": started, "ended_uptime_cs": ended}


class TimelineComparisonTests(unittest.TestCase):
    def compare_documents(self, before, after, max_window_ms=None):
        with tempfile.TemporaryDirectory() as temp:
            paths = []
            for name, document in (("before", before), ("after", after)):
                path = Path(temp) / name
                path.write_text(json.dumps(document))
                paths.append(path)
            return compare(load(paths[0], VALIDATOR), load(paths[1], VALIDATOR), max_window_ms)

    def test_same_boot_windows_are_ordered_or_overlapping(self):
        for first, second, order, interval in [
            ((100, 110), (200, 205), "before_precedes_after", 90),
            ((200, 205), (100, 110), "after_precedes_before", 90),
            ((100, 110), (111, 120), "before_precedes_after", 1),
            # Touching or overlapping windows cannot be ordered at 1 cs resolution.
            ((100, 110), (110, 120), "overlapping", None),
            ((100, 120), (105, 106), "overlapping", None),
            ((100, 100), (100, 100), "overlapping", None),
        ]:
            result = self.compare_documents(timeline_capture(bound(*first)),
                                            timeline_capture(bound(*second)))
            self.assertEqual(result["comparison_version"], 3)
            self.assertEqual(result["timing"]["boot_relation"], "same_boot_reported")
            self.assertEqual((result["timing"]["order"], result["timing"]["interval_cs"]),
                             (order, interval), (first, second))

    def test_other_boot_evidence_never_orders(self):
        unavailable = {"binding": "unavailable", "failure_reason": "not_found"}
        for first, second, relation in [
            (bound(100, 110), bound(200, 205, BOOT_B), "different_boot_or_host_reported"),
            (bound(100, 110), {"binding": "not_requested"}, "unknown"),
            ({"binding": "not_requested"}, {"binding": "not_requested"}, "unknown"),
            (unavailable, bound(100, 110), "unknown"),
        ]:
            timing = self.compare_documents(timeline_capture(first),
                                            timeline_capture(second))["timing"]
            self.assertEqual(timing["boot_relation"], relation)
            self.assertEqual((timing["order"], timing["interval_cs"]), ("unverified", None))
            # Freshness stays unknown at every level; timing never claims it.
            self.assertNotIn("fresh", json.dumps(timing))

    def test_window_policy_is_a_consumer_criterion(self):
        result = self.compare_documents(timeline_capture(bound(1, 2), window=7),
                                        timeline_capture(bound(3, 4), window=60), 50)
        timing = result["timing"]
        self.assertEqual(timing["max_window_ms"], 50)
        self.assertEqual((timing["before"]["window_within_policy"],
                          timing["after"]["window_within_policy"]), (True, False))
        self.assertEqual(timing["before"]["monotonic_window_ms"], 7)
        self.assertEqual(result["overall_freshness"], "unknown")
        unset = self.compare_documents(timeline_capture(bound(1, 2)),
                                       timeline_capture(bound(3, 4)))["timing"]
        self.assertIsNone(unset["max_window_ms"])
        self.assertIsNone(unset["before"]["window_within_policy"])

    def test_values_rows_and_older_versions_are_unchanged(self):
        before = timeline_capture(bound(1, 2))
        v3 = self.compare_documents(before, timeline_capture(bound(3, 4)))
        legacy = copy.deepcopy(before)
        legacy["capture_version"] = 1
        del legacy["collection"], legacy["timeline"]
        v2 = self.compare_documents(legacy, before)
        self.assertEqual(v2["comparison_version"], 2)
        self.assertNotIn("timing", v2)
        self.assertEqual(v3["changes"], v2["changes"])
        self.assertTrue(all(row["clock_order"] == "unverified" for row in v3["changes"]))
        with self.assertRaisesRegex(ValueError, "window policy"):
            self.compare_documents(legacy, before, 50)
        with self.assertRaisesRegex(ValueError, "window policy"):
            compare({}, {}, 50)

    def test_inconsistent_timelines_are_refused_before_comparison(self):
        reversed_boot = timeline_capture(bound(10, 9))
        stepped = timeline_capture(bound(1, 2))
        stepped["collection"]["wall_clock"] = "stepped_or_suspended"
        for document in (reversed_boot, stepped):
            with self.assertRaises(ValueError):
                self.compare_documents(document, timeline_capture(bound(1, 2)))

    def test_cli_reports_timing_and_refuses_bad_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            before, after = Path(temp) / "before", Path(temp) / "after"
            before.write_text(json.dumps(timeline_capture(bound(100, 110))))
            after.write_text(json.dumps(timeline_capture(bound(200, 205))))
            script = str(ROOT / "scripts/compare_evidence.py")
            run = lambda *extra: subprocess.run([sys.executable, script, str(before), str(after), *extra],
                                                capture_output=True, text=True, timeout=30, check=False)
            result = run("--max-window-ms", "10")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["timing"]["order"], "before_precedes_after")
            self.assertEqual(report["timing"]["interval_cs"], 90)
            for bad in ("-1", "x", "1.5"):
                refused = run("--max-window-ms", bad)
                self.assertEqual(refused.returncode, 2, bad)
                self.assertEqual(refused.stdout, "", bad)


INVESTIGATION_NAMESPACE = "mira-investigation-v1@rmednitzer.github.io"


def canonical(document):
    # MIRA writes compact JSON; the leading bytes select the namespace.
    return (json.dumps(document, separators=(",", ":")) + "\n").encode()


class SignedComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.key = self.dir / "host-a"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "host-a",
                        "-f", str(self.key)], check=True, stdin=subprocess.DEVNULL)
        public = " ".join(self.key.with_suffix(".pub").read_text().split()[:2])
        self.signers = self.dir / "signers"
        self.signers.write_text(f'host-a namespaces="{compare_evidence.CAPTURE_NAMESPACE},'
                                f'{INVESTIGATION_NAMESPACE}" {public}\n')

    def tearDown(self):
        self.temp.cleanup()

    def write_signed(self, name, document, namespace=compare_evidence.CAPTURE_NAMESPACE):
        path = self.dir / name
        data = canonical(document)
        path.write_bytes(data)
        result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(self.key),
                                 "-n", namespace], input=data, capture_output=True, check=True)
        Path(f"{path}.sig").write_bytes(result.stdout)
        return path

    def trust(self, principal="host-a"):
        return Trust(self.signers, principal)

    def test_verified_captures_report_integrity(self):
        before = self.write_signed("before.json", timeline_capture(bound(1, 2)))
        after = self.write_signed("after.json", timeline_capture(bound(3, 4)))
        result = compare(load(before, VALIDATOR, self.trust()), load(after, VALIDATOR, self.trust()))
        self.assertEqual(result["integrity"], {"status": "verified", "principal": "host-a",
                                               "namespace": compare_evidence.CAPTURE_NAMESPACE})
        unsigned = compare(load(before, VALIDATOR), load(after, VALIDATOR))
        self.assertNotIn("integrity", unsigned)
        with self.assertRaisesRegex(ValueError, "one principal"):
            compare(load(before, VALIDATOR, self.trust()), load(after, VALIDATOR))

    def test_every_mismatch_refuses_comparison(self):
        good = self.write_signed("good.json", timeline_capture(bound(1, 2)))
        modified = self.dir / "modified.json"
        data = bytearray(good.read_bytes())
        data[-3] ^= 1
        modified.write_bytes(bytes(data))
        Path(f"{modified}.sig").write_bytes(Path(f"{good}.sig").read_bytes())
        unsigned = self.dir / "unsigned.json"
        unsigned.write_bytes(good.read_bytes())
        foreign = self.write_signed("foreign.json", timeline_capture(bound(1, 2)),
                                    INVESTIGATION_NAMESPACE)
        for path, trust, message in [
            (modified, self.trust(), "not verified"),
            (unsigned, self.trust(), "not verified"),
            (foreign, self.trust(), "not verified"),
            (good, self.trust("host-b"), "not verified"),
        ]:
            with self.assertRaisesRegex(ValueError, message):
                load(path, VALIDATOR, trust)
        legacy = self.dir / "legacy.jsonl"
        legacy.write_text(json.dumps(record()) + "\n")
        with self.assertRaisesRegex(ValueError, "only captures"):
            load(legacy, VALIDATOR, self.trust())
        for principal in ("", "-I", "host a", "host;id"):
            with self.assertRaisesRegex(ValueError, "invalid principal"):
                Trust(self.signers, principal)
        with patch.object(compare_evidence, "SSH_KEYGEN", str(self.dir / "absent")):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                load(good, VALIDATOR, self.trust())

    def test_replacing_the_file_after_verification_cannot_change_what_is_compared(self):
        path = self.write_signed("capture.json", timeline_capture(bound(1, 2)))
        forged = timeline_capture(bound(1, 2))
        forged["capture_scope"] = "forged-scope"
        real_run = subprocess.run

        def verify_then_swap(argv, **kwargs):
            result = real_run(argv, **kwargs)
            # The attacker wins the race: the path now holds forged evidence.
            path.write_bytes(canonical(forged))
            return result

        with patch.object(compare_evidence.subprocess, "run", verify_then_swap):
            admitted = load(path, VALIDATOR, self.trust())
        self.assertEqual(admitted.scope, TIMELINE["capture_scope"])
        self.assertEqual(path.read_bytes(), canonical(forged))

    def test_cli_requires_both_trust_options_and_fails_closed(self):
        before = self.write_signed("before.json", timeline_capture(bound(1, 2)))
        after = self.write_signed("after.json", timeline_capture(bound(3, 4)))
        script = str(ROOT / "scripts/compare_evidence.py")
        run = lambda *extra: subprocess.run([sys.executable, script, str(before), str(after), *extra],
                                            capture_output=True, text=True, timeout=30, check=False)
        ok = run("--allowed-signers", str(self.signers), "--principal", "host-a")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["integrity"]["principal"], "host-a")
        for extra in (["--principal", "host-a"], ["--allowed-signers", str(self.signers)],
                      ["--revocations", "krl"],
                      ["--allowed-signers", str(self.signers), "--principal", "host-b"]):
            refused = run(*extra)
            self.assertEqual(refused.returncode, 2, extra)
            self.assertEqual(refused.stdout, "", extra)


if __name__ == "__main__":
    unittest.main()
