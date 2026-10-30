#!/usr/bin/env python3
"""Offline, bounded comparison of two MIRA evidence JSONL captures."""
import argparse
import json
import sys
import stat
import os
from pathlib import Path

from jsonschema import Draft202012Validator

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 128


def load(path, validator):
    # Only regular capture files are supported. Refuse FIFOs/devices.
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("capture must be a regular file")
    with path.open("rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("capture must be a regular file")
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("evidence file exceeds 1 MiB")
    result = {}
    for line in data.splitlines():
        if not line.strip():
            continue
        if len(result) >= MAX_RECORDS:
            raise ValueError("too many evidence records")
        record = json.loads(line)
        validator.validate(record)
        if record["source"] == "/proc/meminfo" and record["status"] == "observed":
            v = record["value"]
            if v["available_kib"] > v["total_kib"]:
                raise ValueError("available memory exceeds total memory")
        key = (record["source"], record["scope"])
        if key in result:
            raise ValueError("duplicate source/scope")
        result[key] = record
    return result


def compare(before, after):
    changes = []
    for source, scope in sorted(before.keys() | after.keys(), key=lambda k: (k[0], k[1] or "")):
        old = before.get((source, scope))
        new = after.get((source, scope))
        if old is None:
            outcome = "added"
        elif new is None:
            outcome = "missing"
        elif old["status"] != "observed" or new["status"] != "observed":
            outcome = "indeterminate"
        elif old["value"] == new["value"]:
            outcome = "unchanged"
        else:
            outcome = "changed"
        changes.append({
            "source": source, "scope": scope, "outcome": outcome,
            "before_status": None if old is None else old["status"],
            "after_status": None if new is None else new["status"],
            "freshness": "unknown",
            "clock_order": "unverified",
        })
    return {"comparison_version": 1, "overall_freshness": "unknown", "changes": changes}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/evidence-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    print(json.dumps(compare(load(args.before, validator), load(args.after, validator)),
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"evidence comparison failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        from jsonschema import ValidationError
        if isinstance(exc, ValidationError):
            print("evidence comparison failed: schema validation", file=sys.stderr)
            sys.exit(2)
        raise
