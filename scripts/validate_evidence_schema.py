#!/usr/bin/env python3
"""Validate MIRA evidence JSONL using JSON Schema draft 2020-12."""
import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/evidence-v1.schema.json").read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


def check_record(record):
    VALIDATOR.validate(record)
    if record["status"] == "observed" and record["value"] is None:
        raise AssertionError("observed record has null value")
    if record["source"] == "/proc/meminfo" and record["status"] == "observed":
        v = record["value"]
        if v["available_kib"] > v["total_kib"]:
            raise AssertionError("available memory exceeds total memory")


def check_output(args, expected_count, allowed_sources, exit_codes):
    completed = subprocess.run(
        [str(ROOT / "target/debug/mira"), *args],
        check=False, capture_output=True, text=True, timeout=15
    )
    if completed.returncode not in exit_codes:
        raise AssertionError(f"unexpected return code {completed.returncode}: {completed.stderr}")
    records = [json.loads(line) for line in completed.stdout.splitlines()]
    if len(records) != expected_count:
        raise AssertionError(f"expected {expected_count} records, got {len(records)}")
    sources = [record["source"] for record in records]
    if len(set(sources)) != len(sources) or set(sources) != set(allowed_sources):
        raise AssertionError(f"unexpected sources: {sources}")
    for record in records:
        check_record(record)
    if completed.returncode == 0 and any(r["status"] != "observed" for r in records):
        raise AssertionError("exit 0 with unavailable evidence")
    return records


def main():
    fixture = json.loads((ROOT / "tests/fixtures/evidence-v1.json").read_text())
    for record in fixture["valid"]:
        check_record(record)
    for record in fixture["invalid"]:
        try:
            check_record(record)
        except (AssertionError, ValueError):
            pass
        except Exception as exc:
            from jsonschema import ValidationError
            if not isinstance(exc, ValidationError):
                raise
        else:
            raise AssertionError(f"invalid fixture accepted: {record}")

    check_output(
        ["inspect", "--json"], 5,
        ["/proc/meminfo", "/proc/uptime", "/proc/sys/kernel/osrelease",
         "/proc/pressure/cpu", "/var/lib/dpkg/status"], {0, 1}
    )
    service = check_output(["service", "--user.service", "--json"], 1, ["systemd/system"], {1})
    if service[0]["status"] != "unavailable" or service[0]["value"] is not None:
        raise AssertionError("invalid service name must remain unavailable")
    for invalid_name in ("x", "x" * 300 + ".service"):
        rejected = check_output(
            ["service", invalid_name, "--json"], 1, ["systemd/system"], {1}
        )
        if rejected[0]["scope"] != invalid_name or rejected[0]["status"] != "unavailable":
            raise AssertionError("rejected service scope must remain explicit")
    print("evidence-v1 schema and CLI contract validated")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"evidence schema validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
