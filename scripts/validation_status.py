#!/usr/bin/env python3
"""Shared validator contract for host qualification (ADR 0013).

Every validator takes the binary from MIRA_BINARY, exits 0 passed, 1 failed or
4 inconclusive, declares fixed check groups (--list-groups, --only) and, when
MIRA_QUALIFICATION_STATUS names a new file, reports the unavailable sources it
observed there. Only fixed source identifiers and failure reasons are written.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASSED, FAILED, USAGE, INCONCLUSIVE = 0, 1, 2, 4
BINARY_ENV = 'MIRA_BINARY'
STATUS_ENV = 'MIRA_QUALIFICATION_STATUS'
# Closed set: evidence sources, journal scopes and the boot identifier. Never a scope or value.
GAP_SOURCES = frozenset({
    '/proc/meminfo', '/proc/uptime', '/proc/sys/kernel/osrelease', '/proc/pressure/cpu',
    '/proc/pressure/memory', '/proc/pressure/io', '/var/lib/dpkg/status', 'systemd/system',
    '/proc/sys/kernel/random/boot_id', 'journal/system', 'journal/oom-kill',
    'journal/unit-failure', 'journal/coredump',
})
GAP_REASON = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}')
_GAPS = set()
_EXPLICIT = set()


class Inconclusive(Exception):
    """A live sample changed during a comparison: neither a pass nor wrong evidence."""


def mira_binary():
    value = os.environ.get(BINARY_ENV)
    return str(Path(value).absolute()) if value else str(ROOT / 'target/debug/mira')


def explicitly_selected(group):
    """True when --only named this group, as the runner does after probing its preconditions."""
    return group in _EXPLICIT


def note_gap(source, reason):
    if source not in GAP_SOURCES:
        raise ValueError('unrecognized observation gap source')
    if not isinstance(reason, str) or GAP_REASON.fullmatch(reason) is None:
        reason = 'unrecognized'
    _GAPS.add((source, reason))


def note_record(record):
    """Report an unavailable evidence-v1 or evidence-v2 record as a gap."""
    if record['status'] == 'unavailable':
        note_gap(record['source'], record.get('failure_reason') or record['error_kind'])


def write_status():
    path = os.environ.get(STATUS_ENV)
    if not path:
        return
    gaps = [{'source': source, 'reason': reason} for source, reason in sorted(_GAPS)]
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as handle:
        json.dump({'observation_gaps': gaps}, handle)


def run(label, groups, message, argv=None, opt_in=None):
    """Run the selected groups in declared order and exit with the contract status.

    groups maps each fixed name to its function. opt_in maps a group to the
    legacy flag that enables it when --only is absent, so default runs are unchanged.
    """
    opt_in = opt_in or {}
    parser = argparse.ArgumentParser(description=label)
    parser.add_argument('--list-groups', action='store_true')
    parser.add_argument('--only')
    for flag in sorted(set(opt_in.values())):
        parser.add_argument(flag, action='store_true')
    args = parser.parse_args(argv)
    if args.list_groups:
        print('\n'.join(groups))
        sys.exit(PASSED)
    if args.only is not None:
        chosen = args.only.split(',')
        if len(set(chosen)) != len(chosen) or not set(chosen) <= set(groups):
            parser.error('unknown or repeated check group')
        selected = [name for name in groups if name in chosen]
    else:
        selected = [name for name in groups if name not in opt_in
                    or getattr(args, opt_in[name].lstrip('-').replace('-', '_'))]
    _GAPS.clear()
    _EXPLICIT.clear()
    if args.only is not None:
        _EXPLICIT.update(selected)
    code, failure = PASSED, None
    try:
        for name in selected:
            groups[name]()
    except Inconclusive:
        code, failure = INCONCLUSIVE, 'Inconclusive'
    except Exception as error:
        # Exceptions can carry sampled host values; report only the type.
        code, failure = FAILED, type(error).__name__
    try:
        write_status()
    except OSError:
        if code == PASSED:
            code, failure = FAILED, 'StatusWriteFailed'
    if failure:
        print(f'{label} failed: {failure}', file=sys.stderr)
    elif args.only is not None:
        print(f'{label} groups passed: {",".join(selected)}')
    else:
        print(message)
    sys.exit(code)
