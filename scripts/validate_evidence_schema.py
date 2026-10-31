#!/usr/bin/env python3
"""Validate MIRA evidence JSONL using JSON Schema draft 2020-12."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from validation_status import Inconclusive, mira_binary, note_record
import validation_status

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
        [mira_binary(), *args],
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


def direct_unit(unit):
    """Direct systemctl properties, independent of MIRA's parser."""
    argv = ["systemctl", "--system", "--no-pager", "--no-ask-password",
            "show", "--property=Id,Names,LoadState,ActiveState,SubState", "--", unit]
    result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=5)
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def check_live_systemd():
    if os.geteuid() == 0:
        raise AssertionError("live systemd check must run without root")
    unit = "systemd-journald.service"
    before = direct_unit(unit)
    records = check_output(["service", unit, "--json"], 1, ["systemd/system"], {0})
    after = direct_unit(unit)
    if before != after:
        raise Inconclusive("live fixture changed during collection")
    expected = {"id": before["Id"], "load_state": before["LoadState"],
                "active_state": before["ActiveState"], "sub_state": before["SubState"]}
    if before["LoadState"] != "loaded" or unit not in before["Names"].split():
        raise AssertionError("expected an installed journald fixture")
    if records[0]["scope"] != unit or records[0]["value"] != expected:
        raise AssertionError("MIRA service evidence disagrees with stable live systemd state")
    print("unprivileged live systemd evidence validated")


def read_live_procfs():
    """Direct bounded reads, independent of the Rust parser and its JSON output."""
    def read(path, limit):
        with Path(path).open('rb') as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError('direct procfs sample exceeds budget')
        return data.decode('ascii')

    memory = read('/proc/meminfo', 65536)
    totals = re.findall(r'^MemTotal:[ \t]+([0-9]+)[ \t]+kB[ \t]*$', memory, re.MULTILINE)
    if len(totals) != 1 or int(totals[0]) == 0:
        raise ValueError('invalid direct memory sample')
    kernel = read('/proc/sys/kernel/osrelease', 16384).removesuffix('\n')
    if re.fullmatch(r'[A-Za-z0-9._+\-]{1,256}', kernel) is None:
        raise ValueError('invalid direct kernel sample')
    uptime = read('/proc/uptime', 65536)
    match = re.fullmatch(r'([0-9]+)(?:\.[0-9]+)?[ \t]+[0-9]+(?:\.[0-9]+)?\n?', uptime)
    if match is None:
        raise ValueError('invalid direct uptime sample')
    return {'total_kib': int(totals[0]), 'kernel': kernel,
            'uptime': int(match.group(1))}


def check_live_procfs_values(before, records, after):
    """Compare already schema-validated records with surrounding direct samples."""
    if (before['total_kib'] != after['total_kib']
            or before['kernel'] != after['kernel']
            or before['uptime'] > after['uptime']):
        raise Inconclusive('live procfs fixture changed')
    by_source = {record['source']: record for record in records}
    for source in ('/proc/meminfo', '/proc/sys/kernel/osrelease', '/proc/uptime'):
        if by_source[source]['status'] != 'observed':
            raise ValueError('required live procfs observation unavailable')
    if by_source['/proc/meminfo']['value']['total_kib'] != before['total_kib']:
        raise ValueError('MIRA total memory disagrees with direct procfs')
    if by_source['/proc/sys/kernel/osrelease']['value'] != before['kernel']:
        raise ValueError('MIRA kernel release disagrees with direct procfs')
    if not before['uptime'] <= by_source['/proc/uptime']['value'] <= after['uptime']:
        raise ValueError('MIRA uptime outside direct procfs interval')
    # MemAvailable and PSI can move non-monotonically between samples. Endpoint
    # values cannot establish an interval bound for either observation.


def check_live_procfs():
    if os.geteuid() == 0:
        raise ValueError('live procfs check must run without root')
    before = read_live_procfs()
    records = check_output(
        ['inspect', '--json'], 5,
        ['/proc/meminfo', '/proc/uptime', '/proc/sys/kernel/osrelease',
         '/proc/pressure/cpu', '/var/lib/dpkg/status'], {0, 1}
    )
    after = read_live_procfs()
    check_live_procfs_values(before, records, after)
    for record in records:
        note_record(record)
    print('unprivileged live procfs evidence validated')


def check_fixtures():
    fixture = json.loads((ROOT / "tests/fixtures/evidence-v1.json").read_text())
    for record in fixture["valid"]:
        check_record(record)
    for record in fixture["invalid"]:
        try:
            check_record(record)
        except (AssertionError, ValueError, ValidationError):
            pass
        else:
            raise AssertionError(f"invalid fixture accepted: {record}")


def check_cli():
    for record in check_output(
        ["inspect", "--json"], 5,
        ["/proc/meminfo", "/proc/uptime", "/proc/sys/kernel/osrelease",
         "/proc/pressure/cpu", "/var/lib/dpkg/status"], {0, 1}
    ):
        note_record(record)
    service = check_output(["service", "--user.service", "--json"], 1, ["systemd/system"], {1})
    if service[0]["status"] != "unavailable" or service[0]["value"] is not None:
        raise AssertionError("invalid service name must remain unavailable")
    for invalid_name in ("x", "x" * 300 + ".service"):
        rejected = check_output(
            ["service", invalid_name, "--json"], 1, ["systemd/system"], {1}
        )
        if rejected[0]["scope"] != invalid_name or rejected[0]["status"] != "unavailable":
            raise AssertionError("rejected service scope must remain explicit")
    if not Path("/run/systemd/system").is_dir():
        # Denial path: without systemd as init, a valid query stays explicitly unavailable.
        record = check_output(["service", "systemd-journald.service", "--json"], 1,
                              ["systemd/system"], {1})[0]
        if record["status"] != "unavailable":
            raise AssertionError("service observed without systemd as init")
        note_record(record)


def main(argv=None):
    validation_status.run(
        "evidence schema validation",
        {"fixtures": check_fixtures, "cli": check_cli,
         "live-procfs": check_live_procfs, "live-systemd": check_live_systemd},
        "evidence-v1 schema and CLI contract validated", argv,
        opt_in={"live-procfs": "--live-procfs", "live-systemd": "--live-systemd"})


if __name__ == "__main__":
    main()
