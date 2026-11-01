#!/usr/bin/env python3
"""mira-agent-mcp: the agent's stdio MCP adapter for one MIRA session (ADR 0015 stage 2).

Optional tooling outside the `mira` CLI package and its trust core. A model
client launches it as a stdio MCP server under the agent's OS user. It turns
tool calls into signed requests through `mira session request` and serves
read-only views of the session. It does nothing else: no shell, no file
access beyond the session's own entries and documents, no network.

Authority comes only from the environment (MCP's stdio rule):
  MIRA_SESSION           the session directory
  MIRA_ALLOWED_SIGNERS   the operator's allowed_signers file
  MIRA_AGENT_KEY         the agent's signing key
  MIRA_BINARY            the mira binary (default: mira on PATH)

The adapter is as untrusted as the agent: the broker re-checks every
request. It refuses to start unless the session header pins exactly these
tool definitions (`mira session start --agent-tools HASH`).

  mira_agent_mcp.py --tools-hash   print the SHA-256 to pin, and exit
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

TOOLS_FILE = Path(__file__).resolve().with_name('tools-v1.json')
SERVER_INFO = {'name': 'mira-agent-mcp', 'version': '1'}
MODERN = '2026-07-28'
LEGACY = ('2025-11-25', '2025-06-18')
MAX_LINE = 1024 * 1024
MAX_ENTRIES = 4096
MAX_DOCUMENT = 1024 * 1024
# Tool calls per rolling minute; the broker's budget is the real bound.
RATE_LIMIT = 30
URI = re.compile(r'session://(state|timeline|entries/([0-9]{6})|documents/([0-9]{6}))')


def tools():
    return json.loads(TOOLS_FILE.read_text())


def tools_hash(definitions):
    """SHA-256 of the canonical JSON of the tool definitions, as clients see them."""
    canonical = json.dumps(definitions, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def header(session):
    line = (session / 'entries' / '000000.entry').read_bytes().split(b'\n', 1)[0]
    entry = json.loads(line)
    if entry.get('kind') != 'header':
        raise ValueError('entry 0 is not a header')
    return entry


def check(schema, value, path='arguments'):
    """Validate a value against the closed subset of JSON Schema the tools use."""
    kind = schema.get('type')
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError(f'{path}: not one of the allowed values')
    if kind == 'object':
        if not isinstance(value, dict):
            raise ValueError(f'{path}: must be an object')
        properties = schema.get('properties', {})
        for name in schema.get('required', []):
            if name not in value:
                raise ValueError(f'{path}: {name} is required')
        for name, item in value.items():
            if name not in properties:
                raise ValueError(f'{path}: {name} is not allowed')
            check(properties[name], item, f'{path}.{name}')
    elif kind == 'string':
        if not isinstance(value, str) or '\x00' in value:
            raise ValueError(f'{path}: must be a string without NUL')
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', 1 << 30):
            raise ValueError(f'{path}: length out of range')
        if 'pattern' in schema and re.search(schema['pattern'], value) is None:
            raise ValueError(f'{path}: not in the allowed form')
    elif kind == 'integer':
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f'{path}: must be an integer')
        if value < schema.get('minimum', value) or value > schema.get('maximum', value):
            raise ValueError(f'{path}: out of range')
    elif kind == 'array':
        if not isinstance(value, list) or len(value) > schema.get('maxItems', 1 << 30):
            raise ValueError(f'{path}: must be an array of bounded length')
        for index, item in enumerate(value):
            check(schema['items'], item, f'{path}[{index}]')


def request_arguments(name, arguments):
    """The `mira session request` options for one validated tool call."""
    if name in ('request_action', 'propose'):
        options = ['--capability', arguments['capability'], '--arguments', arguments['arguments']]
        return (['--propose'] if name == 'propose' else []) + options + ['--text', arguments['reason']]
    if name == 'post_finding':
        options = ['--claim', arguments['claim']]
        if 'confidence' in arguments:
            options += ['--confidence', arguments['confidence']]
        cites = sorted(set(arguments['cites']))
        if cites:
            options += ['--cites', ','.join(str(seq) for seq in cites)]
        return options + ['--text', arguments['reason']]
    return ['--question', '--text', arguments['question']]


class RpcError(Exception):
    def __init__(self, code, message, data=None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


class Adapter:
    def __init__(self, environ):
        self.session = Path(environ['MIRA_SESSION'])
        self.signers = environ['MIRA_ALLOWED_SIGNERS']
        self.key = environ['MIRA_AGENT_KEY']
        self.mira = environ.get('MIRA_BINARY', 'mira')
        self.tools = tools()
        self.by_name = {tool['name']: tool for tool in self.tools}
        self.legacy = None
        self.calls = []

    def mira_run(self, *arguments, timeout=60):
        try:
            return subprocess.run([self.mira, 'session', *arguments], capture_output=True,
                                  timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return subprocess.CompletedProcess([], 4, b'', b'mira could not be run')

    def check_version(self, method, params):
        if method == 'initialize':
            return
        meta = params.get('_meta') if isinstance(params, dict) else None
        version = meta.get('io.modelcontextprotocol/protocolVersion') if isinstance(meta, dict) else None
        if version is None and self.legacy is not None:
            return
        if version != MODERN:
            raise RpcError(-32022, 'Unsupported protocol version',
                           {'supported': [MODERN, *LEGACY], 'requested': version})

    def handle(self, method, params):
        self.check_version(method, params)
        if method == 'initialize':
            requested = params.get('protocolVersion') if isinstance(params, dict) else None
            self.legacy = requested if requested in LEGACY else LEGACY[0]
            return {'protocolVersion': self.legacy, 'capabilities': {'tools': {}, 'resources': {}},
                    'serverInfo': SERVER_INFO}
        if method == 'ping':
            return {}
        if method == 'server/discover':
            return {'resultType': 'complete', 'supportedVersions': [MODERN, *LEGACY],
                    'capabilities': {'tools': {}, 'resources': {}},
                    '_meta': {'io.modelcontextprotocol/serverInfo': SERVER_INFO}}
        if method == 'tools/list':
            return {'resultType': 'complete', 'tools': self.tools}
        if method == 'tools/call':
            return self.call(params)
        if method == 'resources/list':
            return {'resultType': 'complete', 'resources': self.resources()}
        if method == 'resources/read':
            uri = params.get('uri') if isinstance(params, dict) else None
            return {'resultType': 'complete', 'contents': [self.read(uri)]}
        raise RpcError(-32601, f'Method not found: {method}')

    def call(self, params):
        name = params.get('name') if isinstance(params, dict) else None
        if name not in self.by_name:
            raise RpcError(-32602, f'Unknown tool: {name}')
        arguments = params.get('arguments', {})
        try:
            check(self.by_name[name]['inputSchema'], arguments)
        except ValueError as error:
            return self.result(f'refused before submission: {error}', True)
        now = time.monotonic()
        self.calls = [moment for moment in self.calls if now - moment < 60] + [now]
        if len(self.calls) > RATE_LIMIT:
            return self.result('refused: too many tool calls in the last minute', True)
        done = self.mira_run('request', str(self.session), '--allowed-signers', self.signers,
                             '--key', self.key, *request_arguments(name, arguments))
        if done.returncode != 0:
            reason = (done.stdout or done.stderr).decode(errors='replace').strip()[:512]
            return self.result(f'not submitted (exit {done.returncode}): {reason}', True)
        return self.result('submitted; the broker decides, and its decision appears in the session', False)

    @staticmethod
    def result(text, error):
        return {'resultType': 'complete', 'content': [{'type': 'text', 'text': text}],
                'isError': error}

    def resources(self):
        listed = [{'uri': 'session://state', 'name': 'state', 'mimeType': 'application/json'},
                  {'uri': 'session://timeline', 'name': 'timeline', 'mimeType': 'text/plain'}]
        names = sorted(os.listdir(self.session / 'entries'))[:MAX_ENTRIES]
        for name in names:
            if re.fullmatch(r'[0-9]{6}\.entry', name):
                listed.append({'uri': f'session://entries/{name[:6]}', 'name': f'entry {name[:6]}',
                               'mimeType': 'application/json'})
        for name in sorted(os.listdir(self.session / 'documents'))[:MAX_ENTRIES]:
            if re.fullmatch(r'[0-9]{6}\.json', name):
                listed.append({'uri': f'session://documents/{name[:6]}',
                               'name': f'document {name[:6]}', 'mimeType': 'application/json'})
        return listed

    def read(self, uri):
        """Resolve a fixed URI form to one session view. A URI is a name, never a path."""
        match = URI.fullmatch(uri) if isinstance(uri, str) else None
        if match is None:
            raise RpcError(-32602, 'Unknown resource')
        if match.group(1) in ('state', 'timeline'):
            shown = self.mira_run('show', str(self.session),
                                  *(['--json'] if match.group(1) == 'state' else []))
            text, mime = shown.stdout.decode(errors='replace'), 'text/plain'
            if match.group(1) == 'state':
                mime = 'application/json'
        elif match.group(2):
            path = self.session / 'entries' / f'{match.group(2)}.entry'
            text, mime = self.bounded(path).split(b'\n', 1)[0].decode(errors='replace'), 'application/json'
        else:
            path = self.session / 'documents' / f'{match.group(3)}.json'
            text, mime = self.bounded(path).decode(errors='replace'), 'application/json'
        return {'uri': uri, 'mimeType': mime, 'text': text}

    @staticmethod
    def bounded(path):
        try:
            with open(path, 'rb') as file:
                data = file.read(MAX_DOCUMENT + 1)
        except OSError:
            raise RpcError(-32602, 'Unknown resource') from None
        if len(data) > MAX_DOCUMENT:
            raise RpcError(-32603, 'Resource too large')
        return data


def lines(reader):
    """Newline-delimited messages, each read with a bound; an oversized one is skipped whole."""
    while True:
        raw = reader.readline(MAX_LINE + 1)
        if not raw:
            return
        if len(raw) > MAX_LINE and not raw.endswith(b'\n'):
            while raw and not raw.endswith(b'\n'):
                raw = reader.readline(MAX_LINE + 1)
            yield None
            continue
        yield raw


def serve(adapter, reader, writer):
    for raw in lines(reader):
        if raw is None:
            reply = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Message too large'}}
        else:
            try:
                message = json.loads(raw)
            except ValueError:
                reply = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}
            else:
                if not isinstance(message, dict) or 'method' not in message:
                    continue
                if 'id' not in message:
                    continue  # notifications need no reply
                try:
                    result = adapter.handle(message['method'], message.get('params') or {})
                    reply = {'jsonrpc': '2.0', 'id': message['id'], 'result': result}
                except (TypeError, AttributeError, KeyError, ValueError):
                    # Never die on hostile input: every message gets an answer.
                    reply = {'jsonrpc': '2.0', 'id': message['id'],
                             'error': {'code': -32602, 'message': 'Invalid params'}}
                except RpcError as error:
                    body = {'code': error.code, 'message': error.message}
                    if error.data is not None:
                        body['data'] = error.data
                    reply = {'jsonrpc': '2.0', 'id': message['id'], 'error': body}
        writer.write(json.dumps(reply, ensure_ascii=False, separators=(',', ':')) + '\n')
        writer.flush()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ['--tools-hash']:
        print(tools_hash(tools()))
        return 0
    if argv:
        print('usage: mira_agent_mcp.py [--tools-hash]', file=sys.stderr)
        return 2
    try:
        adapter = Adapter(os.environ)
        pinned = header(adapter.session).get('agent_tools')
    except (KeyError, OSError, ValueError):
        print('mira-agent-mcp: MIRA_SESSION, MIRA_ALLOWED_SIGNERS and MIRA_AGENT_KEY must name a '
              'readable session and the agent key', file=sys.stderr)
        return 2
    if pinned != tools_hash(adapter.tools):
        print('mira-agent-mcp: the session header does not pin these tool definitions; '
              'start the session with --agent-tools', file=sys.stderr)
        return 1
    serve(adapter, sys.stdin.buffer, sys.stdout)
    return 0


if __name__ == '__main__':
    sys.exit(main())
