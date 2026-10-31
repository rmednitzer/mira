# ADR 0011: host identity and capture integrity

Status: **Proposed**, 2026-10-31. Design only; no code, schema or CLI change is made by this record. Implementation would follow in separate, staged PRs after review.

## Context

A capture's scope is an operator-typed label (`scope_trust: "operator_asserted"`). The comparator refuses mismatched labels, but equal labels do not show that two captures came from the same machine, and nothing shows that a capture file is the one MIRA wrote. ADR 0010 added reported same-boot ordering and states its limit: anyone who can write a capture file can forge a consistent timeline and boot binding. "Host identity" covers two different needs:

| Need | Question | What would answer it |
|---|---|---|
| N1. **Correlation** | Do these two captures come from the same machine? | A stable machine identifier, which is not authenticated |
| N2. **Authenticity and integrity** | Did a host I trust produce exactly these bytes? | A signature by a key the verifier already trusts |

N1 without N2 is a convenience that a forger can copy. N2 answers N1 as a side effect, as far as the signing key is bound to the machine.

Observed on the development host: OpenSSH 10.2 is installed, and its file-signature mode (`ssh-keygen -Y sign` / `-Y verify`, the SSHSIG format) works. It rejected a modified file, a wrong-namespace signature, a key listed only for another principal, and a key in a revocation list (`-r`), each with exit 255. Two keys listed for one principal both verified. `/etc/machine-id` is readable. There are no SSH host keys (no sshd) and no TPM, so neither can be assumed everywhere.

## Criteria

- Detect modification of a capture between production and comparison, and name the key holder that produced it.
- Keep MIRA free of hand-written or vendored cryptography and of new Rust crates (`unsafe` stays forbidden).
- Offline: no network, no hosted service, no certificate authority.
- No elevation: signing must not require reading root-only keys.
- Opt-in, and existing outputs unchanged by default.
- Never claim more than the mechanism shows: a signature proves possession of a key, not truthful measurements, freshness or hardware identity.

## Alternatives

| Option | N1 | N2 | Consequence |
|---|---|---|---|
| A. Status quo | No | No | Honest; labels remain the only scope |
| B. Export `/etc/machine-id` (opt-in) | Yes, unauthenticated | No | Readable without privilege, but cloned images often share it, containers vary, and it is a stable, highly linkable identifier. Copyable by any forger |
| C. SSH host key: fingerprint plus signature | Yes | Yes | Signing needs the root-only host private key (elevation). Many hosts, including this one, run no sshd |
| D. **Dedicated operator-provisioned signing key; detached OpenSSH SSHSIG signatures; verification against an operator-maintained `allowed_signers` file** | Via the key | Yes | No crypto in MIRA; uses a widely deployed, audited implementation; key custody is the operator's |
| E. TPM attestation (AK quote) | Yes, hardware-bound | Yes | Strongest binding, but needs TPM access (root or the tss group), vendor variance and a much larger design |
| F. Implement Ed25519 in Rust | — | — | Rejected: hand-written cryptography, or a new crate, for a problem OpenSSH already solves |
| G. Sign inside the JSON document | — | — | Rejected: needs a canonical encoding to sign, and breaks byte-for-byte compatibility of existing formats |

## Proposed decision (option D, staged)

### Format

A signature is a **detached** SSHSIG file next to the capture (`capture.json.sig`), covering the exact capture bytes, with namespace **`mira-capture-v1@rmednitzer.github.io`**. The namespace binds a signature to this use, so a signature made for git commits or another tool cannot be replayed as a capture signature, and vice versa. Capture formats are unchanged; an unsigned capture is still a valid capture.

### Stage 1: verification in the offline comparator

`compare_evidence.py before.json after.json --allowed-signers FILE --principal NAME`

- For each input, it requires `INPUT.sig` and runs one fixed-argument command with no shell: `/usr/bin/ssh-keygen -Y verify -f FILE -I NAME -n NAMESPACE -s INPUT.sig`. The bytes it verifies are passed on stdin, and they are the same bytes the comparator then parses, read once within the existing 1 MiB bound.
- Both inputs are verified against the **same** principal NAME, which answers N1 through N2 without a separate option. A capture signed by a key listed for another principal is refused. One principal may list several keys, for example during rotation; that is the `allowed_signers` file's decision, and both keys then verify as that principal (observed).
- With these options, comparison output gains `integrity: {"status": "verified", "principal": NAME, "namespace": "..."}`. A missing signature, a failed verification or a missing `ssh-keygen` makes the comparison **fail with exit 2**, never degrade silently. Without the options, output is unchanged and carries no integrity claim. Giving only one of the two options is a usage error.
- Optional `--revocations KRL` passes an OpenSSH key revocation list (`-r`).

### Stage 2 (optional, see open questions): producer-side signing

`mira capture ... --output PATH --sign-with KEY` would write the capture to a new file PATH (refusing to overwrite) and then run `/usr/bin/ssh-keygen -Y sign -f KEY -n NAMESPACE PATH`, fixed argv and no shell, which writes `PATH.sig`. Stdout output without `--output` would stay unchanged. The alternative is to document that operators run that `ssh-keygen` command themselves, which keeps MIRA's runtime free of any new command execution.

### Not proposed

`machine-id` export (option B) is not proposed: an unauthenticated stable identifier adds linkability without integrity. TPM attestation (option E) remains a possible later decision for hardware-bound identity.

## Trust, privacy and failure analysis

- **What a verified signature means.** The holder of a key listed in `allowed_signers` signed these exact bytes for this namespace. It does not mean the measurements are true, that the host is uncompromised, that the evidence is fresh, or that the key lives on the machine its principal names. A compromised host can sign whatever it likes.
- **Replay.** A valid old capture stays valid. Signatures add no freshness. ADR 0010 same-boot ordering helps only for captures from one boot, and a replayed pair orders as it did originally.
- **Key custody.** The private key must be readable by the capturing user and protected from others. A key copied to another machine signs as that principal. Rotation and revocation are the operator's job, through `allowed_signers` (which supports `valid-before`/`valid-after` and namespace restrictions) and OpenSSH revocation lists.
- **New execution boundary (TB7).** The comparator, and the CLI if stage 2 is adopted, would execute `ssh-keygen`. Mitigations:
  - an absolute path (`/usr/bin/ssh-keygen`), a fixed argument vector and no shell
  - file paths passed as arguments, and bytes on stdin
  - a bounded runtime, and only the exit status trusted, never parsed output (which is why the principal is explicit rather than discovered with `find-principals`)
  - principal names validated against a conservative syntax before use as an argument
  This is a reviewed, read-only use of an installed tool, analogous to the fixed `systemctl show` query (ADR 0001).
- **Disclosure.** Principal names and key fingerprints appear in comparison output and identify operators or hosts. They are only present when `--allowed-signers` is used.
- **Availability.** Missing `ssh-keygen` or an old OpenSSH without `-Y` support is a hard failure under `--allowed-signers`, never an unsigned pass.

## Acceptance for implementation

Stage 1:

- Tests run against the real `ssh-keygen` with throwaway keys in temporary directories, for:
  - a valid signature
  - one modified byte
  - a wrong namespace
  - a signature for a different file
  - an unknown key
  - an expired `valid-before`
  - multiple matching principals
  - a missing `.sig` file
  - a key listed only for another principal
  - two keys listed for one principal (both verify, by design)
  - a revoked key (`--revocations`)
  - a missing `ssh-keygen` (simulated with an empty PATH and an absolute-path override in tests)
- Unchanged output without the option.
- Proof that the verified bytes and the compared bytes are the same read.
- CI on both architectures, where `openssh-client` is present on the runners.

Stage 2, if adopted:

- Refusal to overwrite an existing `--output` path.
- A signature that verifies with stage 1.
- No change without `--sign-with`.
- A fixed-argv test like the systemctl fixture.

## Consequences and rollback

Blast radius: one opt-in comparator option (stage 1) and possibly one opt-in capture option (stage 2). Existing formats and outputs are unchanged. Signatures are separate files, so removing the feature leaves every capture valid. No operational state requires rollback.

## Open questions for review

1. **Mechanism:** is OpenSSH SSHSIG (option D) acceptable, or should integrity wait for TPM-backed identity (option E)?
2. **Producer signing:** add `mira capture --sign-with KEY` (stage 2), or only document operator-run `ssh-keygen -Y sign`, keeping MIRA's runtime free of new command execution?
3. **Namespace string:** `mira-capture-v1@rmednitzer.github.io` (a domain-style name, per the SSHSIG recommendation), or something else?
4. **Scope:** should investigation reports also be signable under a separate namespace, or captures only for now?

## Primary references

- [OpenSSH PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
- [ssh-keygen(1): -Y sign, verify, find-principals; ALLOWED SIGNERS](https://man.openbsd.org/ssh-keygen)
- [machine-id(5)](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html)
