#!/usr/bin/env python3
"""Offline, bounded comparison of two MIRA evidence JSONL captures."""
import argparse
import json
import sys
import stat
import os

from capture_contract import check_capture
from pathlib import Path

from jsonschema import Draft202012Validator

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 128


MAX_DEPTH = 32


class Capture(dict):
    """Legacy records have no completion or scope binding."""
    def __init__(self, records=(), *, scope=None, profile=None, version=None, collection=None):
        super().__init__(records)
        self.scope = scope
        self.profile = profile
        self.version = version
        self.collection = collection


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite JSON number")


def _float(value):
    # All current wire numeric fields use integer tokens. Reject other numeric
    # encodings before conversion can erase a fraction or round an integer.
    raise ValueError("evidence requires integer JSON tokens")


def strict_json(data):
    text = data.decode("utf-8")
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON nesting limit")
        elif character in "]}":
            depth -= 1
    result = json.loads(text, object_pairs_hook=_unique_object,
                        parse_constant=_constant, parse_float=_float)
    pending = [result]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return result


def read_capture(path):
    # Open nonblocking first: path metadata cannot authorize the opened object.
    # Symlinks retain legacy compatibility; directory custody is caller-trusted.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("capture must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_BYTES:
        raise ValueError("evidence file exceeds 1 MiB")
    if not data.strip():
        raise ValueError("empty capture")
    return data


def load(path, validator):
    data = read_capture(path)
    try:
        document = strict_json(data)
    except json.JSONDecodeError:
        document = None  # Multiple JSONL records are decoded separately below.
    if isinstance(document, dict) and "capture_version" in document:
        check_capture(document)
        return Capture((((r["source"], r["scope"]), r) for r in document["records"]),
                       scope=document["capture_scope"], profile=document["profile"],
                       version=document["capture_version"],
                       collection=document.get("collection"))
    result = Capture()
    for line in data.split(b"\n"):
        if not line.strip():
            continue
        if len(result) >= MAX_RECORDS:
            raise ValueError("too many evidence records")
        record = strict_json(line)
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


def _window(collection, max_window_ms):
    window = collection["monotonic_window_ms"]
    return {"monotonic_window_ms": window, "wall_clock": collection["wall_clock"],
            "window_within_policy": None if max_window_ms is None else window <= max_window_ms}


def timing(before, after, max_window_ms=None):
    """ADR 0010 stage 3: order only two captures that report the same boot.

    Uptime windows are centiseconds since boot. Touching or overlapping windows
    cannot be ordered at that resolution, so they are reported as overlapping.
    """
    first, second = before["boot"], after["boot"]
    relation, order, interval = "unknown", "unverified", None
    if first["binding"] == "observed" and second["binding"] == "observed":
        if first["boot_id"] != second["boot_id"]:
            relation = "different_boot_or_host_reported"
        else:
            relation = "same_boot_reported"
            if first["ended_uptime_cs"] < second["started_uptime_cs"]:
                order = "before_precedes_after"
                interval = second["started_uptime_cs"] - first["ended_uptime_cs"]
            elif second["ended_uptime_cs"] < first["started_uptime_cs"]:
                order = "after_precedes_before"
                interval = first["started_uptime_cs"] - second["ended_uptime_cs"]
            else:
                order = "overlapping"
    return {"boot_relation": relation, "order": order, "interval_cs": interval,
            "max_window_ms": max_window_ms,
            "before": _window(before, max_window_ms), "after": _window(after, max_window_ms)}


def compare(before, after, max_window_ms=None):
    before_scope = getattr(before, "scope", None)
    after_scope = getattr(after, "scope", None)
    if before_scope != after_scope or getattr(before, "profile", None) != getattr(after, "profile", None):
        raise ValueError("incompatible capture scope or profile")
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
    result = {"comparison_version": 1, "overall_freshness": "unknown", "changes": changes}
    if before_scope is not None:
        result.update(comparison_version=2, capture_scope=before_scope,
                      scope_trust="operator_asserted", collection_complete=True)
    timelines = (getattr(before, "version", None) == 2 and getattr(after, "version", None) == 2)
    if timelines:
        # Value outcomes and per-row labels are unchanged; ordering is capture-level.
        result.update(comparison_version=3,
                      timing=timing(before.collection, after.collection, max_window_ms))
    elif max_window_ms is not None:
        raise ValueError("window policy requires two timeline captures")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--max-window-ms", type=int, default=None,
                        help="report whether each capture-v2 window is within N ms")
    args = parser.parse_args(argv)
    if args.max_window_ms is not None and args.max_window_ms < 0:
        raise ValueError("window policy must be nonnegative")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/evidence-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    print(json.dumps(compare(load(args.before, validator), load(args.after, validator),
                             args.max_window_ms),
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        print(f"evidence comparison failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        from jsonschema import ValidationError
        if isinstance(exc, ValidationError):
            print("evidence comparison failed: schema validation", file=sys.stderr)
            sys.exit(2)
        raise
