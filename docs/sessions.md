# Shared investigation sessions

A session is the shared, signed record in which an operator and an AI agent investigate together ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)). **Stage 1a is implemented:** the session log, operator entries, autonomy directives, closure with an external receipt, `show` and `verify`.

Not yet implemented:
- the broker and agent requests (stage 1b)
- actions and results (stage 1b)
- findings with claim checks, decisions and proposals (stage 1c)
- the scripted agent (stage 1c)

Until stage 1b, only the operator writes to a session.

## Keys

A session names three principals, each with its own OpenSSH signing key:

| Principal | Holder | Signs (stage 1a) |
|---|---|---|
| operator | you | Header, questions, directives, close |
| agent | the agent process, under its own OS user | Nothing yet; requests arrive in stage 1b |
| collector | your account, used only by the broker | Nothing yet; results arrive in stage 1b |

Keep an `allowed_signers` file outside the session directory, listing all three under the session namespace:

```text
operator namespaces="mira-session-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
agent namespaces="mira-session-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
collector namespaces="mira-session-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
```

## Commands

```sh
mira session start DIR --allowed-signers SIGNERS --key KEY --operator NAME --agent NAME --collector NAME \
  [--autonomy manual|advisory|assisted] [--budget N] --question TEXT
mira session ask DIR --allowed-signers SIGNERS --key KEY --text TEXT
mira session direct DIR --allowed-signers SIGNERS --key KEY (--stop | --level manual|advisory|assisted | --budget N | --delegate-until SEQ) [--text TEXT]
mira session close DIR --allowed-signers SIGNERS --key KEY --conclusion TEXT [--receipt PATH]
mira session show DIR [--json]
mira session verify DIR --allowed-signers SIGNERS [--expect-close PATH]
```

- **`start`** creates `DIR` exclusively (mode 0700) and writes the operator-signed header as entry 0:
  - a 256-bit session ID
  - the three principal names
  - the separation mode: `same_user` in stage 1a; `separate_user` arrives with the broker
  - the initial autonomy, `assisted` by default; `delegated` can only be granted with an expiry
  - the agent's budget, 10 by default
  - your question

  If the key does not verify as the operator, nothing is left behind. An existing directory is never reused or removed.
- **`ask`** and **`direct`** append entries as the operator named in the header. A directive can:
  - stop the agent: the level becomes `manual`
  - set the level
  - set the budget
  - delegate until a later sequence number, after which the level returns to `assisted`

  Delegation ends after a number of entries. The operator-clock deadline the ADR also allows is not implemented.
- **`close`** appends your conclusion and the final entry count. After it, every append is refused. With `--receipt PATH`, the close entry's exact bytes and signature are also written, exclusively, to `PATH` and `PATH.sig` outside the session. An existing receipt path is refused before anything is written.
- **`show`** prints the timeline and current state, or the state alone with `--json`. It reads the log's structure but does not check signatures.
- **`verify`** checks everything:
  - contiguous sequence numbers from 0, each with a signature
  - each entry's exact canonical bytes
  - one session ID throughout
  - every entry written by a principal with the role for its kind, as named in the header
  - nothing after the close
  - every signature, under the session namespace, for the principal the entry names

  With `--expect-close PATH`, the receipt must also match the session's final entry byte for byte. This detects a removed close entry or a truncated tail.

Exit codes:
- **0:** done, or verified.
- **1:** refused by the session state (closed, or a contradictory directive), an invalid session, or not verified. A fixed reason is printed.
- **2:** usage.
- **4:** signing, `ssh-keygen` or I/O failure, including a key that is not listed for the operator.

## How entries are written

Each entry is one JSON line in a fixed field order, ending with a bounded free-text `note`. The schema is [`session-v1`](../schemas/session-v1.schema.json). `mira` accepts an entry only if rendering it again reproduces the file's exact bytes, so there is one way to write each entry.

To append, `mira`:
1. signs the entry into a pending file
2. checks that signature against your `allowed_signers` as the principal it names
3. claims the next sequence number by an exclusive hard link

A wrong key or a lost race between two writers therefore never leaves a partial entry. The writer that loses re-reads the session and takes the next number.

Notes are at most 1 KiB, on one line. They refuse control characters (C0, DEL, C1) and bidirectional embedding, override, isolate and mark characters, so displaying them cannot steer a terminal or reorder text.

## What a verified session shows, and what it does not

A verified session shows that the listed keys wrote these exact entries, in this order, for this session, each within its role. It does not show that anything in a note is true.

Truncating the tail of an open session is not detectable; a closed session with a receipt is. In stage 1a every entry is written by the operator's own account, so this stage makes no containment claim about agents. That comes with the broker and the `separate_user` mode in stage 1b.
