#!/usr/bin/env python3
"""Validate MIRA evidence JSONL using JSON Schema draft 2020-12."""
import argparse
import json
import os
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


def check_live_systemd():
    if os.geteuid() == 0:
        raise AssertionError("live systemd check must run without root")
    unit = "systemd-journald.service"
    argv = ["systemctl", "--system", "--no-pager", "--no-ask-password",
            "show", "--property=Id,Names,LoadState,ActiveState,SubState", "--", unit]

    def direct():
        result = subprocess.run(argv, check=True, capture_output=True,
                                text=True, timeout=5)
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    before = direct()
    records = check_output(["service", unit, "--json"], 1, ["systemd/system"], {0})
    after = direct()
    if before != after:
        raise AssertionError("live fixture changed during collection; comparison inconclusive")
    expected = {"id": before["Id"], "load_state": before["LoadState"],
                "active_state": before["ActiveState"], "sub_state": before["SubState"]}
    if before["LoadState"] != "loaded" or unit not in before["Names"].split():
        raise AssertionError("expected an installed journald fixture")
    if records[0]["scope"] != unit or records[0]["value"] != expected:
        raise AssertionError("MIRA service evidence disagrees with stable live systemd state")
    print("unprivileged live systemd evidence validated")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-systemd", action="store_true")
    args = parser.parse_args()
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
    if args.live_systemd:
        check_live_systemd()
    print("evidence-v1 schema and CLI contract validated")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"evidence schema validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
