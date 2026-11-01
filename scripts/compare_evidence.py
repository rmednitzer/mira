#!/usr/bin/env python3
"""Offline, bounded comparison of two MIRA evidence JSONL files or complete captures."""
import argparse
import json
import re
import subprocess
import sys
import stat
import os
import time

from capture_contract import check_capture
from pathlib import Path

from jsonschema import Draft202012Validator

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 128


MAX_DEPTH = 32
# ADR 0011: the capture namespace and tool are fixed; there is no PATH lookup.
SSH_KEYGEN = "/usr/bin/ssh-keygen"
CAPTURE_NAMESPACE = "mira-capture-v1@rmednitzer.github.io"
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}")
# ADR 0014: the exact challenge-v1 layout `mira challenge` prints, newline included.
CHALLENGE_DOCUMENT = re.compile(
    rb'\{"challenge_version":1,"challenge":"([0-9a-f]{64})","issued_unix_ms":(0|[1-9][0-9]{0,15})\}\n')
MAX_CHALLENGE_BYTES = 4096
MAX_AGE_MS = 9999999999999999


class Capture(dict):
    """Legacy records have no completion or scope binding."""
    def __init__(self, records=(), *, scope=None, profile=None, version=None, collection=None,
                 principal=None, issued=None):
        super().__init__(records)
        self.scope = scope
        self.profile = profile
        self.version = version
        self.collection = collection
        self.principal = principal
        self.issued = issued


class Issued:
    """A consumer's challenge-v1 document: the value and its issue time."""
    def __init__(self, challenge, issued_unix_ms):
        self.challenge = challenge
        self.issued_unix_ms = issued_unix_ms


class Trust:
    """Operator trust inputs for verifying captures before they are compared."""
    def __init__(self, allowed_signers, principal, revocations=None):
        if PRINCIPAL.fullmatch(principal) is None:
            raise ValueError("invalid principal")
        self.allowed_signers = Path(allowed_signers)
        self.principal = principal
        self.revocations = None if revocations is None else Path(revocations)


def verify_signature(data, path, trust):
    """Verify the in-memory capture bytes against PATH.sig.

    The same bytes are then parsed and compared, so replacing the file after
    this check cannot change what is compared. Only the exit status is trusted.
    """
    argv = [SSH_KEYGEN, "-Y", "verify", "-f", str(trust.allowed_signers),
            "-I", trust.principal, "-n", CAPTURE_NAMESPACE,
            "-s", f"{path}.sig"]
    if trust.revocations is not None:
        argv += ["-r", str(trust.revocations)]
    try:
        result = subprocess.run(argv, input=data, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("ssh-keygen unavailable") from error
    if result.returncode != 0:
        raise ValueError("capture signature not verified")


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


def read_regular(path, limit):
    # Open nonblocking first: path metadata cannot authorize the opened object.
    # Symlinks retain legacy compatibility; directory custody is caller-trusted.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("input must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise ValueError("input exceeds its size limit")
    return data


def read_capture(path):
    data = read_regular(path, MAX_BYTES)
    if not data.strip():
        raise ValueError("empty capture")
    return data


def read_challenge(path):
    """Admit only the exact challenge-v1 bytes, then check its closed schema too."""
    data = read_regular(path, MAX_CHALLENGE_BYTES)
    match = CHALLENGE_DOCUMENT.fullmatch(data)
    if match is None:
        raise ValueError("not a challenge-v1 document")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/challenge-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(strict_json(data))
    return Issued(match[1].decode("ascii"), int(match[2]))


def load(path, validator, trust=None, issued=None):
    data = read_capture(path)
    if issued is not None and trust is None:
        raise ValueError("a challenge counts only for a verified capture")
    if trust is not None:
        # Signed comparison admits only complete captures, verified as read.
        if not data.startswith(b'{"capture_version":'):
            raise ValueError("only captures can be verified for comparison")
        verify_signature(data, path, trust)
    if issued is not None:
        # ADR 0014: the answer sits at a fixed prefix of the verified bytes.
        prefix = b'{"capture_version":3,"challenge":"' + issued.challenge.encode("ascii") + b'",'
        if not data.startswith(prefix):
            raise ValueError("capture does not answer the challenge")
    try:
        document = strict_json(data)
    except json.JSONDecodeError:
        document = None  # Multiple JSONL records are decoded separately below.
    if isinstance(document, dict) and "capture_version" in document:
        check_capture(document)
        if issued is not None and document.get("challenge") != issued.challenge:
            raise ValueError("capture does not answer the challenge")
        return Capture((((r["source"], r["scope"]), r) for r in document["records"]),
                       scope=document["capture_scope"], profile=document["profile"],
                       version=document["capture_version"],
                       collection=document.get("collection"),
                       principal=None if trust is None else trust.principal,
                       issued=issued)
    if issued is not None:
        raise ValueError("capture does not answer the challenge")
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


def freshness(before, after, max_age_ms, now_ms=None):
    """ADR 0014: bound each side's age on this machine's clock, read once."""
    if before is None or after is None:
        raise ValueError("freshness requires a challenge for both captures")
    if before.challenge == after.challenge:
        raise ValueError("one challenge cannot answer two captures")
    now_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    ages = []
    for issued in (before, after):
        age = now_ms - issued.issued_unix_ms
        if age < 0:
            raise ValueError("challenge issued in the future")
        if age > max_age_ms:
            raise ValueError("capture older than policy")
        ages.append(age)
    return {"status": "within_policy", "max_age_ms": max_age_ms,
            "before_age_bound_ms": ages[0], "after_age_bound_ms": ages[1]}


def compare(before, after, max_window_ms=None, max_age_ms=None, now_ms=None):
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
    # capture-v3 is capture-v2 plus a challenge, so it has the same timing.
    timelines = (getattr(before, "version", None) in (2, 3)
                 and getattr(after, "version", None) in (2, 3))
    if timelines:
        # Value outcomes and per-row labels are unchanged; ordering is capture-level.
        result.update(comparison_version=3,
                      timing=timing(before.collection, after.collection, max_window_ms))
    elif max_window_ms is not None:
        raise ValueError("window policy requires two timeline captures")
    principals = (getattr(before, "principal", None), getattr(after, "principal", None))
    if principals != (None, None):
        if None in principals or principals[0] != principals[1]:
            raise ValueError("captures not verified under one principal")
        result["integrity"] = {"status": "verified", "principal": principals[0],
                               "namespace": CAPTURE_NAMESPACE}
    if max_age_ms is not None:
        if "integrity" not in result:
            raise ValueError("freshness requires verified captures")
        result["freshness"] = freshness(getattr(before, "issued", None),
                                        getattr(after, "issued", None), max_age_ms, now_ms)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--max-window-ms", type=int, default=None,
                        help="report whether each capture-v2 window is within N ms")
    parser.add_argument("--allowed-signers", type=Path, default=None,
                        help="verify both captures against INPUT.sig before comparing")
    parser.add_argument("--principal", default=None)
    parser.add_argument("--revocations", type=Path, default=None)
    parser.add_argument("--before-challenge", type=Path, default=None,
                        help="challenge-v1 file the before capture must answer")
    parser.add_argument("--after-challenge", type=Path, default=None)
    parser.add_argument("--max-age-ms", type=int, default=None,
                        help="require both challenges to be at most N ms old on this clock")
    args = parser.parse_args(argv)
    freshness_options = (args.before_challenge, args.after_challenge, args.max_age_ms)
    if any(option is not None for option in freshness_options):
        if any(option is None for option in freshness_options):
            raise ValueError("--before-challenge, --after-challenge and --max-age-ms go together")
        if args.allowed_signers is None:
            raise ValueError("challenges require --allowed-signers and --principal")
        if not 0 <= args.max_age_ms <= MAX_AGE_MS:
            raise ValueError("age policy must be 0 to 16 digits")
    if args.max_window_ms is not None and args.max_window_ms < 0:
        raise ValueError("window policy must be nonnegative")
    if (args.allowed_signers is None) != (args.principal is None):
        raise ValueError("--allowed-signers and --principal must be given together")
    if args.revocations is not None and args.allowed_signers is None:
        raise ValueError("--revocations requires --allowed-signers")
    trust = None if args.allowed_signers is None else Trust(
        args.allowed_signers, args.principal, args.revocations)
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/evidence-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    issued = [None, None]
    if args.max_age_ms is not None:
        issued = [read_challenge(args.before_challenge), read_challenge(args.after_challenge)]
    print(json.dumps(compare(load(args.before, validator, trust, issued[0]),
                             load(args.after, validator, trust, issued[1]), args.max_window_ms,
                             args.max_age_ms),
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
