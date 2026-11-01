"""Offline capture validation. References resolve only to repository-local schemas."""
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / 'schemas/evidence-v2.schema.json').read_text())
SCHEMA = json.loads((ROOT / 'schemas/capture-v1.schema.json').read_text())
SCHEMA_V2 = json.loads((ROOT / 'schemas/capture-v2.schema.json').read_text())
SCHEMA_V3 = json.loads((ROOT / 'schemas/capture-v3.schema.json').read_text())
Draft202012Validator.check_schema(EVIDENCE)
Draft202012Validator.check_schema(SCHEMA)
Draft202012Validator.check_schema(SCHEMA_V2)
Draft202012Validator.check_schema(SCHEMA_V3)
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)
VALIDATOR_V2 = Draft202012Validator(SCHEMA_V2, registry=REGISTRY)
VALIDATOR_V3 = Draft202012Validator(SCHEMA_V3, registry=REGISTRY)
REASON_KINDS = {'timeout': {'TimedOut'}, 'limit_exceeded': {'InvalidData'},
                'malformed_data': {'InvalidData', 'InvalidInput'},
                'permission_denied': {'PermissionDenied'}, 'not_found': {'NotFound'},
                'backend_failed': {'Other'}}
# Other also represents generic I/O errors, not only typed backend failures.
SPECIFIC_KINDS = {kind for kinds in REASON_KINDS.values() for kind in kinds} - {'Other'}


def wall_clock(started, ended, window):
    """Independent restatement of ADR 0010's fixed wall-clock rule."""
    if started is None or ended is None:
        return 'unknown'
    tolerance = max(window // 100, 50)
    if ended >= started and abs((ended - started) - window) <= tolerance:
        return 'consistent'
    return 'stepped_or_suspended'


def _check_records(capture):
    if re.fullmatch(r'[A-Za-z0-9._-]{1,64}', capture['capture_scope']) is None:
        raise ValueError('invalid capture scope')
    records = capture['records']
    sources = [record['source'] for record in records]
    if sources != capture['expected_sources']:
        raise ValueError('missing, duplicate or reordered capture source')
    available = all(record['status'] == 'observed' for record in records)
    if capture['all_available'] != available:
        raise ValueError('availability contradicts records')
    for record in records:
        reason = record['failure_reason']
        kind = record['error_kind']
        if ((reason in REASON_KINDS and kind not in REASON_KINDS[reason])
                or (reason == 'io_failure' and kind in SPECIFIC_KINDS)):
            raise ValueError('failure reason contradicts error kind')
        if record['source'] == '/proc/meminfo' and record['status'] == 'observed':
            if record['value']['available_kib'] > record['value']['total_kib']:
                raise ValueError('available memory exceeds total memory')


def _check_timeline(capture):
    collection = capture['collection']
    window = collection['monotonic_window_ms']
    timeline = capture['timeline']
    if [entry['source'] for entry in timeline] != [r['source'] for r in capture['records']]:
        raise ValueError('timeline does not match capture records')
    previous = 0
    for entry, record in zip(timeline, capture['records']):
        if entry['elapsed_ms'] != record['elapsed_ms']:
            raise ValueError('timeline elapsed time contradicts record')
        if entry['offset_ms'] < previous:
            raise ValueError('timeline offsets decrease')
        if entry['offset_ms'] + (entry['elapsed_ms'] or 0) > window:
            raise ValueError('acquisition outside the collection window')
        previous = entry['offset_ms']
    if collection['wall_clock'] != wall_clock(collection['started_unix_ms'],
                                              collection['ended_unix_ms'], window):
        raise ValueError('wall-clock label contradicts window and edges')
    boot = collection['boot']
    if boot['binding'] == 'observed' and boot['ended_uptime_cs'] < boot['started_uptime_cs']:
        raise ValueError('boot uptime window reversed')


def check_capture(capture):
    """Dispatch on capture_version; v2 adds timeline checks to the v1 rules, and
    v3 is v2 plus the consumer's challenge (ADR 0014)."""
    version = capture.get('capture_version') if isinstance(capture, dict) else None
    if version in (2, 3):
        (VALIDATOR_V2 if version == 2 else VALIDATOR_V3).validate(capture)
        _check_records(capture)
        _check_timeline(capture)
    else:
        VALIDATOR.validate(capture)
        _check_records(capture)
    return capture
