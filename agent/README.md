# MIRA agent harness

Optional tooling for ADR 0015 stage 2. It lets a local model act as the agent in a [shared session](../docs/sessions.md). It is outside the `mira` CLI package and its trust core, and nothing here is a security boundary for the session: the broker re-checks every request. Both programs use only the Python standard library.

| File | Role |
|---|---|
| `mira_agent_mcp.py` | **mira-agent-mcp**, the agent's stdio MCP server for one session |
| `tools-v1.json` | its fixed, versioned tool definitions |
| `mira_agent_host.py` | the client host: one local model, connected to this adapter and nothing else |
| `fixtures/poisoned_adapter.py` | a malicious stand-in, used only by the tests |
| `test_agent_harness.py` | the tests, against a real session, broker and `ssh-keygen` |

## The adapter

The adapter speaks MCP revision 2026-07-28 over stdio (newline-delimited JSON-RPC). It also answers a legacy `initialize` for 2025-11-25 and 2025-06-18 clients. It opens no socket.

**Tools.** They map one to one onto request kinds:

| Tool | Becomes |
|---|---|
| `request_action` | `mira session request --capability … --arguments …` |
| `post_finding` | `mira session request --claim … [--confidence …] [--cites …]` |
| `ask` | `mira session request --question` |
| `propose` | `mira session request --propose --capability …` |

There is no tool that runs a command or reads a file, and none will be added. An unknown tool is a JSON-RPC error (`-32602`). Arguments are validated against the closed tool schema before anything is signed: no extra fields, the fixed capability and claim lists, and arguments in the capability token form, so no option can be injected. A failed validation is a tool error with nothing submitted. At most 30 calls are accepted per rolling minute; the broker's budget is the real bound.

**Resources.** The views are read-only: `session://state` and `session://timeline` (from `mira session show`), plus `session://entries/NNNNNN` and `session://documents/NNNNNN`. A URI is a name in one of these fixed forms, never a path.

**Authority.** It comes only from the environment, as MCP's stdio binding prescribes: `MIRA_SESSION`, `MIRA_ALLOWED_SIGNERS`, `MIRA_AGENT_KEY`, and optionally `MIRA_BINARY` and `SSH_AUTH_SOCK` (for an agent key held in `ssh-agent`). The host passes exactly these and nothing else from its own environment. Run the adapter as the agent's OS user, with the agent's key.

**Pinning.** The adapter refuses to start unless the session header pins exactly its tool definitions. The pin is the SHA-256 of the canonical JSON (sorted keys, no whitespace) of the `tools` array that `tools/list` returns:

```sh
python3 agent/mira_agent_mcp.py --tools-hash
mira session start DIR … --agent-tools HASH --question TEXT
```

## The client host

```sh
python3 agent/mira_agent_host.py --session DIR --allowed-signers SIGNERS --key AGENT-KEY \
  (--model-socket PATH | --model-url http://127.0.0.1:PORT/v1 | --replay FILE) --model NAME \
  --record NEW-DIR [--mcp-config FILE] \
  [--max-turns 8] [--turn-delay 1] [--temperature 0] [--mira PATH]
```

The host enforces what a third-party client could only be asked to do:
- **One server.** It launches the shipped adapter as its only MCP server. Given `--mcp-config`, a standard `mcpServers` file, it refuses any file that names another server, or anything but the shipped adapter run by Python without options. The host still launches the adapter itself; the file is only checked. Another server would give the model an external channel or a way to change state, breaking the Rule of Two, and would allow cross-server shadowing.
- **Pinned tools.** The adapter's tool definitions must hash to the session header's pin. This is checked at start and again before every turn, so a poisoned description, or one changed after approval (a rug pull), stops the run with exit 3.
- **Local models only.** The model is an OpenAI-compatible chat completions endpoint, such as llama.cpp server, Ollama or vLLM. It is reached without proxy, and no redirect is ever followed, so a response cannot send the session view elsewhere. There are two ways to reach it:
  - **`--model-socket PATH`** (preferred): a Unix socket, served at `/v1/chat/completions`. The host requires the socket to be owned by the agent's user, in a directory owned by that user that nobody else can write. On every connection, before sending anything, it also checks the connected peer's user ID (`SO_PEERCRED`). That authenticates the listener even if the path is swapped through a writable ancestor: only a server running as the agent's user is ever sent the session view.
  - **`--model-url`**: plain `http` on a loopback address, without credentials, query or fragment. A loopback TCP port is not authenticated: if the intended server has not bound it, another local user can, receive the session view and answer as the model. The broker still checks every request, but use the socket wherever the server supports one.

  `--replay FILE` instead plays a JSON list of responses, one per turn, for tests and scripted red-team runs. Hosted models see synthetic or public sessions only; this host does not connect to them.
- **Offered tools only.** A tool call naming anything the adapter does not list is never forwarded. It is recorded as refused by the host.

Each turn the model gets:
- a fixed system prompt (revision `mira-agent-prompt-v1`)
- as untrusted data: the session's state and timeline, and the latest 4 collector-signed result documents, each bounded to 8 KiB, so it can reason over the evidence and not only the outcomes
- the outcome of its previous tool calls

Tool-call arguments must be a JSON-encoded object, as the chat completions format defines; anything else is refused by the host and recorded, and the run continues. The run ends when the model replies without a tool call, or after `--max-turns`.

**Recording.** `--record` names a new directory (0700). Its `transcript.jsonl` holds, in order:
- one `run` record: model, provider, parameters, prompt revision, the pinned tools hash
- per turn, a `model` record: the full request, the raw response and its status
- a `tool` record per call: name, arguments and the adapter's reply, or the host's refusal
- a final `stop` record: `idle`, `max_turns`, `tools_changed` or `invalid_model_response`

The transcript is the agent side's own record, written under the agent's user. It is not a session document, because the agent cannot write the session. The broker never trusts it.

Exit status: 0 done, 1 refused to start, 2 usage, 3 stopped because the tool definitions changed, 4 model or adapter failure.

## Tests

```sh
cargo build --locked
python3 -W error::ResourceWarning agent/test_agent_harness.py
```

The tests cover:
- the pin and the refusal of an unpinned session
- the protocol revision on every request
- unknown tools, option-shaped or extra arguments and control characters, all refused with nothing submitted
- resource names that are not one of the fixed forms
- other or altered MCP servers in the client configuration
- non-loopback model URLs, a redirect from the model (never followed), and Unix sockets that are absent, not sockets, or in a directory others can write
- tool-call arguments that are not a JSON string, and the result documents reaching the model
- a socket listener of another user refused on connection, NUL in tool text refused while the adapter keeps serving, and an agent key held in `ssh-agent`
- a poisoned adapter, and a rug pull
- a red-team replay: a shell call, option injection, an operator-only capture, findings citing the header or without confidence, and an injected question. Against the real broker none of them runs, no result or finding is recorded, and the session verifies.
- a loopback HTTP model, with every exchange in the transcript

Hostile host-content fixtures, with injection strings in unit names, dpkg versions and service states, come next. So does the adaptive red-team protocol.
