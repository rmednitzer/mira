# Shared investigation sessions

A session is the shared, signed record in which an operator and an AI agent investigate together ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)).

**Implemented:**
- **Stage 1a:** the session log, operator entries, autonomy directives, closure with an external receipt, `show` and `verify`.
- **Stage 1b:** agent requests, the broker that admits and runs them, the operator's own actions, collector-signed results, and the `separate_user` mode.

**Not yet implemented (stage 1c):** findings with claim checks, decisions and proposals, and the scripted agent.

The agent never writes the log. It submits signed requests, and the broker decides.

## Keys

A session names three principals, each with its own OpenSSH signing key:

| Principal | Holder | Signs |
|---|---|---|
| operator | you | Header, questions, directives, close, your own actions |
| agent | the agent process, under its own OS user | Only its requests, in `inbox/` |
| collector | your account, used only by the broker and `act` | Relayed requests, results, refusals, and every result document |

Keep an `allowed_signers` file outside the session directory. List all three under the session namespace, and the collector under the capture and investigation namespaces too, because it signs the result documents:

```text
operator namespaces="mira-session-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
agent namespaces="mira-session-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
collector namespaces="mira-session-v1@rmednitzer.github.io,mira-capture-v1@rmednitzer.github.io,mira-investigation-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
```

The collector key is used unattended by the broker. Keep it readable only by your own user. The agent must never be able to read it or use it.

## Commands

```sh
mira session start DIR --allowed-signers SIGNERS --key KEY --operator NAME --agent NAME --collector NAME \
  [--separation same_user | --separation separate_user --agent-group GROUP] \
  [--autonomy manual|advisory|assisted] [--budget N] --question TEXT
mira session run DIR --allowed-signers SIGNERS --key COLLECTOR-KEY [--once]
mira session act DIR --allowed-signers SIGNERS --key KEY --collector-key COLLECTOR-KEY --capability NAME [--arguments TOKENS] [--text TEXT]
mira session request DIR --allowed-signers SIGNERS --key AGENT-KEY (--capability NAME [--arguments TOKENS] | --question) --text TEXT
mira session ask DIR --allowed-signers SIGNERS --key KEY --text TEXT
mira session direct DIR --allowed-signers SIGNERS --key KEY (--stop | --level manual|advisory|assisted | --budget N | --delegate-until SEQ) [--text TEXT]
mira session close DIR --allowed-signers SIGNERS --key KEY --conclusion TEXT [--receipt PATH]
mira session show DIR [--json]
mira session verify DIR --allowed-signers SIGNERS --operator NAME [--expect-close PATH]
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
- **`close`** appends your conclusion and the final entry count. After it, every append is refused. While an action is still pending (admitted but without a result), `close` refuses, because a result could otherwise arrive after the immutable close. `--abandon-pending` first appends an operator-signed `abandon` entry for each pending action, for example after an interrupted broker; a broker that later finishes such an action records nothing. With `--receipt PATH`, the close record (entry and signature) is also written, exclusively, to `PATH`. That path must be in an existing directory outside the session, resolved through symbolic links. An existing path, a path inside the session or a missing directory is refused before anything is written.
- **`show`** prints the timeline and current state, or the state alone with `--json`. It reads the log's structure but does not check signatures. No command prints the session ID; it is in entry 0 for anyone who reads the log.
- **`verify`** checks everything against the operator you name with `--operator`, including every relayed agent request and every result document. It never takes the operator from the session's own header: any key in `allowed_signers`, the agent's included, could otherwise write a header naming itself operator and sign a counterfeit session. It checks:
  - the header names exactly that operator
  - contiguous sequence numbers from 0, each with a signature
  - each entry's exact canonical bytes
  - one session ID throughout
  - every entry written by a principal with the role for its kind, as named in the header
  - nothing after the close
  - every signature, under the session namespace, for the principal the entry names
  - each relayed `action` or `question` against the agent's stored request: signed by the agent and identical in session, request ID, `based_on`, capability, arguments and note
  - each result's document: present, signed by the collector under its capture or investigation namespace, with exactly the signature the result commits to

  With `--expect-close PATH`, the receipt must also match the session's final entry byte for byte. This detects a removed close entry or a truncated tail.

Exit codes:
- **0:** done, or verified.
- **1:** refused by the session state (closed, or a contradictory directive), an invalid session, or not verified. A fixed reason is printed.
- **2:** usage.
- **4:** signing, `ssh-keygen` or I/O failure, including a key that is not listed for the operator.

## Agent requests and the broker

The agent runs `mira session request` under its own key. It names one capability with its arguments, or asks a question, and states why. `mira` signs the request as the header's agent, checks that signature, and publishes the request in `inbox/` by one exclusive hard link. Nothing the agent writes is trusted until the broker has checked and recorded it.

You start the broker yourself with `mira session run`, in your own terminal; it is not a service. It checks its key as the collector before doing anything, then processes the inbox every 250 ms until the session is closed. With `--once` it makes one pass and stops. For each request, the broker:
1. under `separate_user`, refuses a file owned by the broker's own user (`owner`)
2. verifies the agent's signature (`signature`) and the exact request layout (`malformed`)
3. stores the agent's signed record under `requests/`, where the agent cannot change it
4. decides against the session state at that moment: the session ID, `based_on`, the request ID, the capability set, the autonomy level and the budget
5. records the decision in a collector-signed entry: an `action` or `question` that relays the request, or a `refusal` with a fixed reason
6. for an admitted action, runs it and appends a `result`

**Refusal reasons:**

| Reason | Meaning |
|---|---|
| `signature` | not signed by the header's agent |
| `malformed` | not the exact request layout, or named or attributed wrongly |
| `owner` | under `separate_user`, written by the broker's own user |
| `session_mismatch` | written for another session |
| `stale` | based on an entry that does not exist yet |
| `capability` | outside the closed capability set, or with option-shaped arguments |
| `autonomy` | the level is `manual` (questions and actions) or `advisory` (actions) |
| `superseded_by_directive` | as `autonomy`, but a directive arrived after the request was written |
| `operator_only` | `capture` with `bind-boot`, below `delegated` |

**Budget.** Every entry the agent causes costs one unit: a relayed action, a relayed question, or a refusal. When no budget is left, the broker drops further requests without recording anything. A request whose ID already has an entry is also dropped rather than recorded twice. The last 64 of the 4,096 entries are reserved for you and for pending results, so an agent flooding the inbox can never leave you unable to stop, abandon or close.

**Capabilities.** These are the agent's entire action set: exactly the existing read-only captures and investigations. Arguments are space-separated tokens. Each token comes from `A-Za-z0-9._:+@,/=-` and never starts with `-`, so a request cannot inject an option.

| Capability | Arguments | Runs |
|---|---|---|
| `capture` | `host` or `host-pressure`, optionally followed by `bind-boot` (operator or delegation only) | `capture mira-session [--pressure] --timeline [--bind-boot]` |
| `service-active`, `/v1`, `/v2` | `UNIT.service` | `investigate service-active[/vN] UNIT --json` |
| `memory-headroom` | `KIB` | `investigate memory-headroom --min-available-kib KIB --json` |
| `pressure-ceiling` | `RESOURCE BASIS-POINTS` | `investigate pressure-ceiling --resource … --max-some-avg10-basis-points … --json` |
| `package-installed` | `PACKAGE[:ARCH]` | `investigate package-installed … --json` |
| `uptime-minimum` | `SECONDS` | `investigate uptime-minimum --min-uptime-seconds … --json` |
| `kernel-release` | `RELEASE` | `investigate kernel-release --expect … --json` |
| `journal-events` | `CLASSES [BOOT]` | `investigate journal-events --absent … [--boot …] --json` |

**Execution.** The broker runs `mira` itself, under your account, with that fixed argument vector followed by `--signature documents/NNNNNN.json.sig --sign-with COLLECTOR-KEY`. It drains the output under a 120-second deadline and a 1 MiB limit, and stores the document as `documents/NNNNNN.json`, where `NNNNNN` is the action's sequence number. The `result` records the exit status and the fixed outcome it maps to:

| Captures | Investigations | Both |
|---|---|---|
| 0 `complete_available`, 1 `complete_unavailable` | 0 `satisfied`, 1 `not_satisfied`, 3 `indeterminate` | 2 `refused_arguments`, 4 `signing_failed`, anything else `runner_error` |

Only the first two columns produce a document. A result with a document carries the collector's exact armored signature over it, so the collector-signed entry commits to those bytes. Another genuine collector-signed document cannot be swapped in. An admitted agent action costs its unit even if the template then refuses its arguments.

Decisions use the autonomy level that applies to the entry about to be written. A delegation that covers entries only up to the current last one has already lapsed for the next.

If the broker stops after storing a request but before recording it, the next run resumes that request, provided the stored copy matches the inbox file. A request whose ID already has an entry is discarded.

**The operator's own actions.** `mira session act` records an `action` signed by you and runs it immediately. The result is signed with the collector key you pass, and no budget applies.

## Separation

With `--separation separate_user --agent-group GROUP`, which is required for any model-driven agent, the session belongs to `GROUP`. You must be a member of it; the agent's user is too.

| Path | Mode | The agent can |
|---|---|---|
| the session directory | 0750 | enter |
| `entries/`, `documents/`, `requests/` | 2750 (setgid) | read |
| `inbox/` | 2770 (setgid) | write requests |

All files are created 0640, set through the open file descriptor so a restrictive umask cannot change it, so the group can read them and nobody else can. The broker refuses any inbox file owned by its own user, because under `separate_user` such a file was not written by the agent.

`same_user` (the default) makes everything 0700. It is for trusted scripted agents in tests and demonstrations only. Nothing then stops an agent from writing the log or using the collector key, so such a session supports no claim that the agent was contained.

## How entries are written

Each entry is one JSON line in a fixed field order, ending with a bounded free-text `note`. The schema is [`session-v1`](../schemas/session-v1.schema.json). `mira` accepts an entry only if rendering it again reproduces the exact bytes, so there is one way to write each entry. Notes are checked against the rules below on reading as well as writing. Operator questions written by stage 1a, without a `request_id` field, are still accepted in their original signed layout.

Each entry is stored with its signature in a single record file, `entries/NNNNNN.entry`: the entry line, newline included, followed by the armored SSHSIG signature over exactly that line. To check one record by hand:

```sh
head -n 1 entries/000001.entry > entry && tail -n +2 entries/000001.entry > entry.sig
ssh-keygen -Y verify -f SIGNERS -I PRINCIPAL -n mira-session-v1@rmednitzer.github.io -s entry.sig < entry
```

To append, `mira`:
1. signs the entry into a pending file
2. checks that signature against your `allowed_signers` as the principal it names
3. publishes the whole record under the next sequence number by one exclusive hard link

Readers therefore only ever see complete, signed records, even while others are writing. A wrong key, a lost race or an interrupted writer never leaves a partial entry. Pending files (`.pending-*`) are ignored. The writer that loses a race re-reads the session and takes the next number.

Notes are at most 1 KiB, on one line. They refuse control characters (C0, DEL, C1) and bidirectional embedding, override, isolate and mark characters, so displaying them cannot steer a terminal or reorder text.

## What a verified session shows, and what it does not

A verified session shows that the operator you named, and the keys the operator's header lists, wrote these exact entries, in this order, each within its role. It does not show that anything in a note is true. Without a receipt it also does not show which session you are looking at: an older, genuine session by the same operator would verify too. The receipt pins the exact closed session.

Truncating the tail of an open session is not detectable; a closed session with a receipt is. In stage 1a every entry is written by the operator's own account, so this stage makes no containment claim about agents. That comes with the broker and the `separate_user` mode in stage 1b.
