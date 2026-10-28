# Aienet-0 P0 job path profile (matmul_u32 over MJB1/MJR1)

Status: IMPLEMENTED and EXERCISED on two machines (DGX Spark requester and
verifier, MacBook Air M2 worker) on 2026-10-28. Evidence:
`evidence/aienet0-20261028/`. Profile version 1.

This profile is the job half of the Aienet-0 P0 interop profile
(`specs/aienet/P0_INTEROP_PROFILE.md`, PR #63). It reuses MJB1/MJR1 and the
`aien-microjob` reader, validator and `DagRun` receipt ledger (PR #53)
unchanged, and the Open Humanity signed, encrypted transport
(`aien-dev/open-humanity`, `oh-core::transport`). It adds no wallet, no
currency, no compiler and no remote execution: the worker runs one
allowlisted, integer-exact function and nothing else.

Code: `crates/aien-microjob/src/aienet0.rs` (profile records and checks),
`specs/aienet/jobpath/matmul_u32_recompute.om` (the verifier's independent
recompute, built by `build.sh` with the pinned seed-born `omc`), and in
open-humanity `crates/oh-core/src/carrier.rs`,
`crates/oh-coordinator/src/bin/aienet0-run.rs`,
`crates/oh-volunteer/src/bin/aienet0-serve.rs`.

## Roles and pins

| Role | Machine | Keys it holds | Keys it pins out of band |
|---|---|---|---|
| submitter + verifier (`aienet0-run`) | Spark | transport Ed25519 seed, submitter P-256, verifier P-256 | worker transport Ed25519, executor P-256 |
| worker (`aienet0-serve`) | enrolled machine | transport Ed25519 seed, executor P-256 | coordinator transport Ed25519, submitter P-256 |

Nothing is trusted on first use. Every key a peer presents is compared with
the pinned key before anything that depends on it.

## The job: `matmul_u32`

The only allowlisted kind. Payload and digest are Core PR #662
`crates/aien-hetjob/src/task.rs` byte for byte.

- Payload, 15 bytes: kind `0x01`, `m`, `k`, `n` (u16 BE), `seed` (u64 BE).
- `A` (`m x k`) then `B` (`k x n`) are drawn from splitmix64(`seed`), each
  output truncated to u32. `C = A x B` mod 2^32.
- Output digest: SHA-256(`"AIEN-HETJOB-MATMUL-U32-V1"` || m || k || n || seed
  || C as u32 BE, row-major).
- Bounds: each of `m`, `k`, `n` in 1..=256.

## Bundle `AN0B` (requester to worker)

| Offset | Bytes | Field |
|---|---|---|
| 0 | 4 | `AN0B` |
| 4 | 1 | version `1` |
| 5 | 1 | reserved `0` |
| 6 | 2 | payload length (u16 BE, <= 256) |
| 8 | 4 | document length (u32 BE) |
| 12 | 33 | submitter P-256 key (compressed) |
| 45 | 64 | submitter signature (P-256, low-S, r||s) |
| 109 | plen | payload |
| 109+plen | dlen | MJB1 document |

The signature covers `"AIENET0-MJB1-SUBMIT-V1\0"` || `dag_digest(document)`
|| SHA-256(payload). MJB1 itself carries no submitter signature; this
detached signature is the profile's answer to that gap, and the MJB1
`approval_ref` names it: SHA-256(`"AIENET0-APPROVAL-V1\0"` || submitter key ||
nonce).

The document is one MJB1 node: kind COMPUTE, op MATMUL, verifier RECOMPUTE,
effect COMPUTE, retry NEVER, one attempt, one CONTENT operand whose digest is
SHA-256(payload), no deps, time 120000 ms, work = fuel = m·k·n, memory =
4(mk + kn + mn) bytes, `expires_at` = issue time + 3600 s.

## Worker admission (`admit_bundle`, then the replay set)

In order, each a distinct refusal:

1. Well-formed bundle (`AN0_BAD_BUNDLE`).
2. Submitter key equals the pinned key and its signature verifies
   (`AN0_BAD_SUBMITTER`).
3. MJB1 decodes and validates (`MJB_*`), not expired (`MJB_BAD_EXPIRY`).
4. Exactly one node of the allowlisted shape above (`AN0_NOT_ALLOWLISTED`).
5. The operand names this payload (`AN0_PAYLOAD_MISMATCH`).
6. The payload kind is `matmul_u32` (`AN0_NOT_ALLOWLISTED`).
7. Dimensions within bounds and node caps cover the job (`AN0_OVER_BUDGET`).
8. `dag_digest` never admitted before (`AN0_REPLAY`). The worker appends it
   to `state/seen` and fsyncs before executing, so a crash cannot re-run it.

The worker then runs the kernel and returns an MJR1 COMPLETED receipt signed
by its executor key, with `verifier_verdict` = SHA-256(
`"AIENET0-RECOMPUTE-MATCH-V1\0"` || dag_digest || job_id || output digest),
`source_hash` = SHA-256 of the worker binary and `policy_hash` = SHA-256 of
its admission policy text.

## Verifier (`aienet0-run`)

1. `check_receipt`: the receipt passes `DagRun::admit` + `apply` with only the
   pinned executor key trusted, is new, and leaves the node DONE (`MJB_*`,
   `AN0_REPLAYED_RECEIPT`).
2. Recompute: the Omega program, pinned by SHA-256 of its binary
   (`AN0_RECOMPUTE_UNPINNED`), reads the payload and prints the digest.
3. `countersign`: the receipt's output digest equals the recompute
   (`AN0_RECOMPUTE_MISMATCH`) and its verdict commitment equals the rebuilt
   one (`AN0_VERDICT_MISMATCH`); then the verifier signs.
4. Writes `<dag>.an0b`, `<dag>.mjr1`, `<dag>.mjv` (tmp, fsync, rename, dir
   fsync; an existing output is refused) and prints
   `VERIFIED <dag_id> <mjr1_sha256> <mjr1_path>`.

MJR1 has one signature slot, used by the executor. The verifier's signature
is the detached record below.

## Escrow order (TUR ledger, aien-sovereign-core #792)

`aienet0-run bundle` signs a job without sending it and prints
`BUNDLE <dag_id> <path>`; escrow is reserved on that dag_id; `aienet0-run run
--resend <path>` then sends exactly those bytes. The worker's replay set
holds only bundles it has admitted, so the first send is not a replay. On
`VERIFIED <dag_id> <mjr1_sha256> ...` the requester settles
`settle <dag_id> <mjr1_sha256> PAYP PAYV BACK` once (a repeat is
`already-settled` and writes nothing); on any other outcome it refunds and
never settles. `scripts/aienet0/settle-run.sh` in open-humanity is that
sequence; evidence in `evidence/aienet0-20261028/settlement/`.

## Countersignature `AN0V` (236 bytes)

| Offset | Bytes | Field |
|---|---|---|
| 0 | 4 | `AN0V` |
| 4 | 1 | version `1` |
| 5 | 3 | reserved `0` |
| 8 | 32 | SHA-256 of the MJR1 receipt |
| 40 | 32 | dag_digest |
| 72 | 32 | recomputed output digest |
| 104 | 32 | verdict commitment |
| 136 | 33 | verifier P-256 key |
| 169 | 3 | reserved `0` |
| 172 | 64 | signature over `"AIENET0-MJR1-VERIFY-V1\0"` || bytes 0..172 |

`check_countersign` (and `aienet0-run check`) re-verifies a stored triple
against pinned keys; a settlement ledger keys its `settle` on the dag_id and
the MJR1 SHA-256 printed in the VERIFIED line.

## Carrier (open-humanity `oh-core::carrier`)

Frames inside one pinned, encrypted Open Humanity session (X25519 +
ChaCha20-Poly1305, Ed25519 identities): tag u8, body length u32 BE, body.
Tag 1 bundle (<= 109 + 256 + 192 + 64·448 bytes), tag 2 receipt (exactly 404
bytes), tag 3 refusal text (<= 512 bytes). An unknown tag or out-of-bound
length is refused before the body is read. The volunteer dials; each side
refuses a peer whose transport key is not the pinned one before sending any
payload.

## Exit codes

| Code | `aienet0-run` | `aienet0-serve` |
|---|---|---|
| 0 | VERIFIED | receipt sent |
| 2 | usage or key file | usage or key file |
| 10 | transport (incl. unpinned worker key) | transport (incl. unpinned coordinator key) |
| 11 | worker refused (refusal frame) | job refused (refusal frame sent) |
| 12 | receipt refused | - |
| 13 | recompute unpinned, failed or mismatched | - |
| 14 | verdict commitment mismatch | - |
| 15 | I/O, output exists | I/O |

## Evidence classes

- HOST_TESTED: `evidence/aienet0-20261028/host-tested/` (both ends on the
  Spark), `parity.log`, `xcheck662.log`, both mutant logs.
- EXERCISED: `evidence/aienet0-20261028/exercised/` (Spark coordinator,
  MacBook Air worker over the LAN). Not a hardware qualification.

The Spark's nftables input policy drops LAN TCP except an allowlisted port
set; the EXERCISED run used port 14323 from that existing set
(`ip saddr 192.168.1.0/24 tcp dport 14318-14323 accept`). No firewall rule was
changed.
