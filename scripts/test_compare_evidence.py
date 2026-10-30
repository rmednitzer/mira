#!/usr/bin/env python3
import json
import os
import tempfile
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator
from compare_evidence import compare, load, MAX_BYTES

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


if __name__ == "__main__":
    unittest.main()
