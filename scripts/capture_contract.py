"""Offline capture validation. References resolve only to repository-local schemas."""
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / 'schemas/evidence-v2.schema.json').read_text())
SCHEMA = json.loads((ROOT / 'schemas/capture-v1.schema.json').read_text())
Draft202012Validator.check_schema(EVIDENCE)
Draft202012Validator.check_schema(SCHEMA)
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)
REASON_KINDS = {'timeout': {'TimedOut'}, 'limit_exceeded': {'InvalidData'},
                'malformed_data': {'InvalidData', 'InvalidInput'},
                'permission_denied': {'PermissionDenied'}, 'not_found': {'NotFound'},
                'backend_failed': {'Other'}}
# Other also represents generic I/O errors, not only typed backend failures.
SPECIFIC_KINDS = {kind for kinds in REASON_KINDS.values() for kind in kinds} - {'Other'}


def check_capture(capture):
    VALIDATOR.validate(capture)
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
    return capture
