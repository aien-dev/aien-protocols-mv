# Pi-Spark Task Message: PST1

**Status**: Draft v0.3 (ALLEN Pi/Spark lane C1, 2026-10-16; C3 added the magic, the check order and two codes; C5 added the session rules, section 10; C6 added tool-call tasks, section 11). Not yet produced or read by any runtime. Reference checker and vectors: `tools/pst_verify.c`, `vectors/`.
**Contract version**: 0.1.0 (major zero: may change by minor bump, see VERSIONING.md)
**Wire version**: 1 (the `version` byte below)
**License**: Community Specification License 1.0
**Tracking**: aien-dev/aien-protocols-mv#28 (C1), parent #27, lane C of aien-dev/aien-architecture-mv#231
**Not in this document**: the Spark gate (C2), the Rust reader (C4), network framing and retry (aienos-mv#398).

## 1. Purpose

The Pi and the Spark need one agreed way to say "please do this task", "here is how it is going" and "here is the receipt". PST1 is that agreement: one bounded message that rides inside exactly one message of the existing reliable channel (M6-A), which rides inside the existing secure session (M6-B).

PST1 is a control-plane application format. It is not a network stack, not a scheduler, not an authorization layer and not a replacement for INTERPLANE. No PST1 message grants a capability or a permission (section 9).

## 2. Inventory of what already exists

| Existing piece | Where | Reused? | Reason |
|---|---|---|---|
| M6-A reliable channel | AIENOS `native/net/aienos_ctl.h` | Yes, as the carrier | In-order, exactly-once delivery inside one session. `CT_MAX_PAYLOAD` is 1024. Big-endian. |
| M6-B secure session | AIENOS `native/net/aienos_sec.h` | Yes, as the trust anchor | Mutual authentication against a pinned roster of one peer key, and an 8-byte `session_id`. TEST keys only today. |
| Cause id and origin run id | aien-architecture `docs/hardening/causal-id-join-v0.md` sections 2.1 and 2.3 (DRAFT, ADR 0025 PROPOSED) | Yes, as header fields | One 32-byte cause id is copied across every handoff, never minted again by the receiver. No runtime mints it yet. |
| Objective id | aien-sovereign-core `crates/aien-runtime/src/objective.rs` | Yes, as a header field | SHA-256 of `AIEN_E2E_OBJECTIVE_V1`, a newline, and the objective text. Written on the Spark by the operator tool, never by the daemon. |
| Effect ledger | aien-sovereign-core `crates/aien-runtime/src/effects.rs` | Yes, as the reconciliation authority | States OPEN, DONE, NOT_DONE, UNRESOLVED. Uncertain results are reconciled against it. |
| ALLEN subject | AIENOS `docs/adr/0018-allen-subject-state-object.md` | Yes, as a reference | The 32-byte agent id. No key material travels. |
| `aien-event-protocol`, `aien-action-protocol` | this repository, `crates/` | No | JSON with unbounded text and free-form `serde_json::Value` payloads. They cannot meet a fixed size limit. |
| TRN1 | this repository, `specs/execution-transcript/` | Pattern only | The house pattern for a byte format with a C reference checker and refusal codes. TRN1 is little-endian; PST1 is not (section 6). |
| INTERPLANE core | `interplane` `rust/crates/interplane-core` | Its canonical request is carried unchanged, only for real tool calls (section 11) | It translates tool requests. It is not a scheduler, a link or an authority. |

## 3. Layering

| Layer | Proves or does | Trust |
|---|---|---|
| M6-B | Who the peer is (the pinned key) and which session this is (`session_id`). | Trusted because the transport proved it. |
| M6-A | Delivers each message in order, exactly once, inside one session. | Trusted because the transport proved it. |
| PST1 | Says what the message means: which task, which objective, which kind of event. | Every PST1 field is a claim by the sender. |

Rules that follow:

1. The peer and the session are never read from a PST1 field. A receiver takes them from the transport and ignores any PST1 field that claims otherwise. PST1 has no peer field and no session field.
2. A PST1 field that the receiver can check against its own authoritative records (objective id, ALLEN subject id, effect state) is checked before it is believed.
3. A transport acknowledgement means "the message arrived". It never means "the work is done" (section 8).

## 4. Fixed header

One PST1 message is a 224-byte fixed header followed by `payload_len` bytes of payload. All integers are big-endian. Every reserved byte is zero on send and refused if non-zero on receipt.

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | The ASCII bytes `PST1` (0x50 0x53 0x54 0x31) |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `type` | 1 to 16 (section 5) |
| 6 | 2 | `reserved0` | 0 |
| 8 | 32 | `cause_id` | Not all zero |
| 40 | 32 | `origin_run_id` | Any value (opaque, copied) |
| 72 | 32 | `objective_id` | Not all zero for `request`; copied on every later message |
| 104 | 32 | `subject_id` | The ALLEN subject reference (ADR 0018); no key material |
| 136 | 16 | `parent_task_id` | All zero means "no parent" |
| 152 | 16 | `task_id` | Not all zero |
| 168 | 16 | `idempotence_key` | Not all zero; see section 8 |
| 184 | 4 | `ordinal` | u32; see section 5 |
| 188 | 1 | `effect_class` | 0 NONE, 1 COMPUTE, 2 EFFECT |
| 189 | 1 | `reserved1` | 0 |
| 190 | 2 | `payload_len` | 0 to 800 |
| 192 | 32 | `payload_digest` | SHA-256 of the payload bytes (of the empty string when `payload_len` is 0) |

Total header: 224 bytes.

Change from Draft v0 (C3, aien-protocols-mv#30): Draft v0 had no magic, so a receiver could not tell a PST1 message from any other 1024-byte blob, and the C3 vectors could not test a "bad magic" refusal. The 4-byte magic now opens the header. To keep the header at 224 bytes (and the 800-byte payload cap), `reserved1` shrank from 3 bytes to 1 and `reserved2` was removed. Every field after `type` moved by 4 bytes, except `payload_digest`, which stays at 192.

`effect_class` is a claim about the work, not a permission. EFFECT work still needs a real grant from the Spark approval desk (lane G, G6).

### 4.1 Check order

A receiver checks one message in this order and reports the first rule that fails. The C reference checker (`tools/pst_verify.c`) and every other reader follow the same order, so the same bytes always give the same code.

1. Fewer than 224 bytes, or more than 1024 bytes: `PST_BAD_LENGTH`.
2. `magic` is not `PST1`: `PST_BAD_MAGIC`.
3. `version` is 0 (below the lowest version this receiver accepts): `PST_DOWNGRADE`. `version` above 1: `PST_BAD_VERSION`.
4. `type` is 0 or above 16: `PST_BAD_TYPE`.
5. `reserved0` or `reserved1` is non-zero: `PST_RESERVED_NONZERO`.
6. The bytes after the header are fewer than `payload_len`: `PST_BAD_LENGTH`. (A `payload_len` above 800 always lands here or in step 1, since 224 plus 801 is more than 1024.)
7. The bytes after the header are more than `payload_len`: `PST_TRAILING_BYTES`.
8. `effect_class` above 2: `PST_BAD_EFFECT_CLASS`.
9. `cause_id` all zero: `PST_NO_CAUSE`.
10. `task_id` all zero, then `idempotence_key` all zero: `PST_NO_TASK`.
11. `type` is `request` or `tool_call_request` and `objective_id` is all zero: `PST_NO_OBJECTIVE`.
12. `payload_digest` differs from the SHA-256 of the payload: `PST_DIGEST_MISMATCH`.
13. `type` is `tool_call_request` and the payload is not exactly 36 bytes, or its canonical length is 0 or above 102400: `PST_BAD_TOOL_HEAD` (section 11.2).

The checks that need more than one message (`PST_WRONG_SIDE`, `PST_SUBJECT_MISMATCH`, a version lower than the one already used in the session, and the tool-call body checks of section 11.3) come after these and belong to the session rules (sections 10 and 11).

## 5. Message types

`request`, `cancel request`, `resume request`, `tool_call_request` and `tool_call_chunk` are sent by the Pi. Every other type is sent by the Spark. A message of a type from the wrong side is refused.

| Value | Type | Side | Payload |
|---|---|---|---|
| 1 | `request` | Pi | Task description bytes (UTF-8 text, or the request body named by the task kind) |
| 2 | `accepted` | Spark | Empty |
| 3 | `queued` | Spark | Empty |
| 4 | `running` | Spark | Empty |
| 5 | `text_chunk` | Spark | One piece of streamed text |
| 6 | `waiting_for_approval` | Spark | The 32-byte digest of the action awaiting approval |
| 7 | `completed` | Spark | The 32-byte digest of the result |
| 8 | `failed` | Spark | A short reason code and text |
| 9 | `cancelled` | Spark | Empty |
| 10 | `uncertain_after_disconnect` | Spark | Empty. Means "not known whether it happened" (section 8) |
| 11 | `resume_snapshot` | Spark | The state of one task as read from the authoritative records |
| 12 | `receipt_reference` | Spark | The 32-byte digest of a receipt held on the Spark |
| 13 | `cancel_request` | Pi | Empty |
| 14 | `resume_request` | Pi | Empty |
| 15 | `tool_call_request` | Pi | The 36-byte tool-call head: the INTERPLANE request digest and length (section 11) |
| 16 | `tool_call_chunk` | Pi | The next piece of the INTERPLANE canonical request bytes (section 11) |

`ordinal` numbers the messages of one task from the sender's side, starting at 0 and rising by one. `text_chunk` messages of one task carry consecutive ordinals so a lost or repeated chunk is visible. The order rules between types are in section 10.

Status is derived from authoritative execution state on the Spark. A `completed`, `failed` or `cancelled` message is only sent after the authoritative record says so. Events are hints until the receiver has checked what it can.

## 6. Size and byte order

1. One PST1 message (224 header bytes plus up to 800 payload bytes, so at most 1024) fits in one M6-A message (`CT_MAX_PAYLOAD`, 1024). A message that would be longer is refused with `PST_BAD_LENGTH`.
2. A long text stream is split into numbered `text_chunk` messages. There is no reassembly of one PST1 message across several transport messages. The receiver joins chunks by ordinal, not by transport framing. The body of a tool-call task is the one other joined body: its INTERPLANE request travels in numbered `tool_call_chunk` messages (section 11), each still one complete PST1 message.
3. **Byte order is big-endian**, to match the M6-A and M6-B headers PST1 rides inside, so one implementation reads one convention on the whole link. TRN1 chose little-endian for a file format that never rides on this link. This choice is a recommendation made without a measurement; it is not final until C3 vectors and the aienos lane both accept it.

## 7. Refusal codes

A receiver refuses the message and takes no action. It reports one of these, choosing by the check order in section 4.1. A refusal never changes task state.

| Code | Meaning |
|---|---|
| `PST_BAD_MAGIC` | The first 4 bytes are not `PST1` |
| `PST_BAD_VERSION` | `version` is above 1 (unknown version) |
| `PST_DOWNGRADE` | `version` is 0 (below the lowest accepted version), or lower than the version already used in this session |
| `PST_BAD_TYPE` | `type` is 0 or above 16 |
| `PST_WRONG_SIDE` | A Pi-only type from the Spark, or the reverse |
| `PST_BAD_LENGTH` | Fewer than 224 bytes, more than 1024 bytes, `payload_len` above 800, or fewer payload bytes than `payload_len` |
| `PST_TRAILING_BYTES` | More payload bytes than `payload_len` (and the total is at most 1024) |
| `PST_RESERVED_NONZERO` | Any reserved byte is non-zero |
| `PST_NO_CAUSE` | `cause_id` is all zero |
| `PST_NO_TASK` | `task_id` or `idempotence_key` is all zero |
| `PST_NO_OBJECTIVE` | A `request` whose `objective_id` is all zero (added in C3: Draft v0 stated the rule but named no code) |
| `PST_DIGEST_MISMATCH` | `payload_digest` does not match the payload |
| `PST_BAD_EFFECT_CLASS` | `effect_class` above 2 |
| `PST_SUBJECT_MISMATCH` | `subject_id` differs from the subject bound to this session |
| `PST_BAD_ORDER` | A message the session rules (section 10.2) do not allow in the task's current state |
| `PST_SECOND_FINAL` | A second `completed`, `failed` or `cancelled` for one task |
| `PST_ORDINAL_GAP` | An `ordinal` higher than the next expected one for that task and side |
| `PST_ORDINAL_REPEAT` | An `ordinal` lower than the next expected one for that task and side |
| `PST_IDEMPOTENCE_CONFLICT` | An `idempotence_key` reused for another task, or a known task repeated with another key or payload digest |
| `PST_UNKNOWN_TASK` | A message other than `request` for a task the session has no `request` for |
| `PST_CONTEXT_MISMATCH` | A copied field differs from the task's `request` (section 10.3, step 5) |
| `PST_SESSION_FULL` | A new task beyond the receiver's task limit |
| `PST_BAD_RECORDING` | A recorded session file (section 10.4) that does not parse; test vectors only |
| `PST_BAD_TOOL_HEAD` | A `tool_call_request` payload that is not exactly the 36-byte head, or whose canonical length is 0 or above 102400 (section 11.2) |
| `PST_TOOL_CHUNK_SIZE` | A `tool_call_chunk` that is not exactly 800 bytes, or exactly the bytes still missing when fewer than 800 are left; this covers extra bytes past the end of the request (section 11.3) |
| `PST_TOOL_DIGEST_MISMATCH` | The joined tool-call bytes do not have the SHA-256 the head names (section 11.3) |
| `PST_TOOL_INCOMPLETE` | A Spark message other than `failed` or `cancelled` for a tool-call task whose bytes are not all in and checked (section 11.3) |
| `PST_NOT_TOOL_TASK` | A `tool_call_chunk` for a task opened by `request`: an ordinary task never carries a tool-call payload (section 11.1) |

A receiver that gets work with no cause id refuses it (`PST_NO_CAUSE`); it does not mint one. The cause id is minted once, where the outside request first enters AIEN (on the Pi, at the user's turn), per the causal id join spec.

## 8. Exactly once has limits

1. A transport acknowledgement is not "done". M6-A delivers a message once; it says nothing about whether the work ran.
2. A repeated `request` with the same `idempotence_key` and the same `task_id` is recognised as the same request and does not start a second task.
3. When the link drops while an effect is in flight, the Spark reports `uncertain_after_disconnect`. It does not report `failed` or `cancelled` when it does not know.
4. An effect whose outcome is unknown is reconciled against the Spark effect ledger (OPEN, DONE, NOT_DONE, UNRESOLVED) before anything is retried. A possibly committed effect is never sent again on the strength of a retry alone.
5. A local model's routing choice on the Pi grants nothing. Model output is never an authorization.

## 9. No capability, no permission

No message type, field or value in PST1 grants a capability, a permission, an approval or an identity. `waiting_for_approval` asks; it does not decide. Approvals come from the Spark approval desk and are not carried as PST1 fields. The ALLEN subject stays the authority on the Pi.

## 10. Session rules (C5)

A message can be well formed and still be a lie in its place: "completed" for a task that was never accepted, a second final answer, a missing text chunk, a completion claimed by the Pi. This section says which message may follow which inside one M6-B session. A receiver checks every message against it, after the single-message checks of section 4.1, and refuses at the first broken step. A refusal changes no task state.

Scope of this first cut (aien-protocols-mv#32): the normal life of a task (request, accepted, optionally queued, running, text chunks, completed) and the failed and cancelled endings, the Pi's `cancel_request` and `resume_request`, and repeated requests. `waiting_for_approval`, `uncertain_after_disconnect`, `resume_snapshot` and `receipt_reference` are refused with `PST_BAD_ORDER` in a session until their rules are written (open question 5).

### 10.1 Who may send what

The side comes from the transport (section 3, rule 1), never from a PST1 field. The Pi sends only `request` (1), `cancel_request` (13), `resume_request` (14), `tool_call_request` (15) and `tool_call_chunk` (16). The Spark sends every other type. Anything else is `PST_WRONG_SIDE`; this is how a completion or an approval claimed by the Pi is refused.

### 10.2 Allowed sequence for one task

| Type | Sent by | Allowed when the task is | Task becomes |
|---|---|---|---|
| `request` (new `task_id`) | Pi | (no task yet) | REQUESTED |
| `request` (known `task_id`, same `idempotence_key` and `payload_digest`) | Pi | any state | unchanged: a recognised repeat (section 8, item 2) |
| `accepted` | Spark | REQUESTED | ACCEPTED |
| `queued` | Spark | ACCEPTED | QUEUED |
| `running` | Spark | ACCEPTED or QUEUED | RUNNING |
| `text_chunk` | Spark | RUNNING | RUNNING |
| `completed` | Spark | RUNNING | FINAL |
| `failed`, `cancelled` | Spark | REQUESTED, ACCEPTED, QUEUED or RUNNING | FINAL |
| `cancel_request`, `resume_request` | Pi | any state | unchanged |
| `tool_call_request` (new `task_id`) | Pi | (no task yet) | COLLECTING (section 11) |
| `tool_call_request` (known `task_id`, same `idempotence_key` and `payload_digest`) | Pi | any state | unchanged: a recognised repeat |
| `tool_call_chunk` | Pi | COLLECTING, task opened by `tool_call_request` | COLLECTING, or REQUESTED once the last chunk is in and its digest matches |
| `failed`, `cancelled` | Spark | COLLECTING | FINAL |

So a normal task reads: `request`, `accepted`, (`queued`), `running`, `text_chunk` any number of times, `completed`. Tasks of one session may interleave; each task follows its own row.

### 10.3 Check order for one message in a session

1. The single-message checks (section 4.1).
2. Side (10.1): `PST_WRONG_SIDE`.
3. Subject: the first message of the session binds its `subject_id`; any later different `subject_id` is `PST_SUBJECT_MISMATCH`.
4. Task: a `request` or `tool_call_request` with a new `task_id` whose `idempotence_key` already belongs to another task is `PST_IDEMPOTENCE_CONFLICT`. A `request` or `tool_call_request` for a known `task_id` with a different `idempotence_key`, `payload_digest` or opening type is `PST_IDEMPOTENCE_CONFLICT`. Any other type naming a `task_id` the session has no `request` for is `PST_UNKNOWN_TASK` (this covers a `resume_request` for an unknown task). A new task beyond the receiver's limit is `PST_SESSION_FULL`; the reference checker allows 16 tasks per session.
5. Context: `cause_id`, `origin_run_id`, `objective_id`, `parent_task_id`, `idempotence_key` and `effect_class` must equal the task's `request`: `PST_CONTEXT_MISMATCH`. A recognised repeat of the `request` stops here and changes nothing.
6. Ordinal: per task and per side, the first message carries 0 and each next one carries one more. Higher than expected is `PST_ORDINAL_GAP` (a message, for example a text chunk, was skipped); lower is `PST_ORDINAL_REPEAT`.
7. Tool-call body (section 11.3), for a `tool_call_chunk` or a Spark message on a COLLECTING task.
8. Order (10.2): a final type (`completed`, `failed`, `cancelled`) after FINAL is `PST_SECOND_FINAL`; any other step not allowed by the table is `PST_BAD_ORDER`.

Version inside a session: the first message binds the version; a later lower version is `PST_DOWNGRADE` and a later higher one `PST_BAD_VERSION`. While version 1 is the only accepted version this cannot happen past step 1, so the reference checker has no separate check for it yet.

### 10.4 Recording format (test vectors only)

A recorded session (`vectors/sessions/*.pss`) is the 4 bytes `PSS1`, then for each delivered message in delivery order: 1 byte side (1 Pi, 2 Spark), 2 bytes big-endian length, the message bytes. This is a test container, not a wire format. A recording that does not parse is refused with `PST_BAD_RECORDING`. The verdict line is `ok steps=N tasks=T` or `refuse CODE step=N`, where step N is the 1-based message position.

## 11. Tool-call tasks (C6)

When the model asks to run a tool, the task carries the tool request in INTERPLANE's agreed form, byte for byte, so the Pi and the Spark hash the same bytes. Ordinary chat never uses this path. Tracking: aien-protocols-mv#33.

Ground truth: aien-dev/interplane-mv at commit `83df0f074b2c572473cd535c89f767df48933f4a`. INTERPLANE's canonical form is RFC 8785 canonical JSON, and its digest is `sha256:` followed by the lower-case hex SHA-256 of those bytes (`rust/crates/interplane-core/src/jcs.rs`, `canonicalize` and `digest_bytes`). The carried value is one INTERPLANE `tool_request` payload (`kind` `tool_request`, `rust/crates/interplane-core/src/types.rs`), canonicalized by interplane-core.

### 11.1 Which tasks are tool calls

1. The message that opens a task fixes its kind for the life of the task. `request` (1) opens an ordinary task. `tool_call_request` (15) opens a tool-call task.
2. Only a tool-call task carries `tool_call_chunk` (16) messages. A `tool_call_chunk` for a task opened by `request` is refused with `PST_NOT_TOOL_TASK`: an ordinary task never carries a tool-call payload.
3. A tool call is never read out of an ordinary task's text. A receiver does not parse a `request` payload as INTERPLANE, even when it looks like JSON. A repeat of the opening message with the other opening type is `PST_IDEMPOTENCE_CONFLICT` (section 10.3, step 4).

### 11.2 The head (`tool_call_request` payload)

The payload of a `tool_call_request` is exactly 36 bytes, and nothing else:

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 32 | `interplane_digest` | SHA-256 of the INTERPLANE canonical request bytes: the 32 bytes whose lower-case hex is the part of its `sha256:` digest after the prefix |
| 32 | 4 | `canonical_len` | u32, big-endian; 1 to 102400 |

A head of any other length (an extra field, a missing length) or a `canonical_len` of 0 or above 102400 is refused with `PST_BAD_TOOL_HEAD` (section 4.1, step 13). 102400 is 128 chunks of 800 bytes; it is above INTERPLANE's 65536-byte argument limit (`spec/CORE.md`), leaving room for the rest of the request. A longer request cannot travel as one tool-call task. The header's `objective_id` must not be all zero, as for `request`.

### 11.3 The chunks and the check

1. The canonical bytes follow in `tool_call_chunk` messages from the Pi, Pi-side ordinals 1, 2, 3 and on (the head carries ordinal 0). Each chunk payload is the next piece of the canonical bytes, in order, with nothing added: every chunk is exactly 800 bytes except the last, which is exactly the bytes still missing. So one request always gives the same chunks. A chunk of any other size is refused with `PST_TOOL_CHUNK_SIZE`; this covers a short chunk and a last chunk with bytes past the end of the request.
2. The chunks are sent even when the request is shorter than 800 bytes (then there is one chunk). The request bytes are never put into the head.
3. When the joined bytes reach `canonical_len`, the receiver computes their SHA-256 and compares it with `interplane_digest`. A difference (a changed byte, a head naming another request) is refused with `PST_TOOL_DIGEST_MISMATCH`. Each chunk's own `payload_digest` (section 4) is checked first, as for any message; it covers that chunk only.
4. While the bytes are not all in and checked, the task is COLLECTING. A Spark message other than `failed` or `cancelled` for a COLLECTING task is refused with `PST_TOOL_INCOMPLETE`: the Spark does not accept, queue or run a tool call it has not received in full. A truncated request (the Pi stops early) therefore never reaches `accepted`. The Spark may end a COLLECTING task with `failed` or `cancelled`.
5. After the check passes, the task is REQUESTED and follows section 10.2 like any other. A further `tool_call_chunk` is refused with `PST_BAD_ORDER`.
6. The checked bytes are handed to INTERPLANE unchanged. PST1 checks bytes, length and digest only; it does not parse JSON. Whether the bytes are a valid, canonical INTERPLANE request is decided by interplane-core on the Spark, not by PST1.

### 11.4 No authority moves

Carrying a tool request moves no permission. INTERPLANE core "executes nothing and authorizes nothing" (`rust/crates/interplane-core/src/lib.rs`, line 3), and neither does PST1 (section 9). Approval of the tool call stays with the existing Spark approval desk and with AIENOS authority (the ALLEN subject on the Pi). A `tool_call_request`, its `effect_class` and its chunks are a claim about what the model asked for, never an approval.

### 11.5 Vectors

The carried request is `vectors/interplane-tool-request.json` (1743 bytes, digest `sha256:78dbef7ee689b20ad9ae530fd7fa8417fb671778667b27f910484156776990d6`), written by `tools/interplane-request` (interplane-core at the commit above) and embedded in `tools/pst_verify.c`, which refuses to generate vectors if the embedded bytes no longer have that digest.

| Vector | Verdict |
|---|---|
| `ok-tool-call-request.pst`, `ok-tool-call-chunk.pst` | accepted single messages (the head, the first chunk) |
| `bad-tool-head-extra-field.pst`, `bad-tool-head-short.pst`, `bad-tool-head-zero-length.pst`, `bad-tool-head-over-limit.pst` | `PST_BAD_TOOL_HEAD` |
| `bad-tool-request-no-objective.pst` | `PST_NO_OBJECTIVE` |
| `sessions/ok-tool-call.pss` | the head, three chunks (800, 800, 143), then `accepted`, `running`, `completed` |
| `sessions/ok-tool-call-failed-while-collecting.pss` | the Spark ends an incomplete tool call with `failed` |
| `sessions/bad-tool-digest-mismatch.pss` | the head names another digest: `PST_TOOL_DIGEST_MISMATCH` |
| `sessions/bad-tool-altered-byte.pss` | one byte of the second chunk changed: `PST_TOOL_DIGEST_MISMATCH` |
| `sessions/bad-tool-extra-bytes.pss` | the last chunk has one byte past the request: `PST_TOOL_CHUNK_SIZE` |
| `sessions/bad-tool-short-chunk.pss` | a first chunk of 799 bytes: `PST_TOOL_CHUNK_SIZE` |
| `sessions/bad-tool-chunk-after-complete.pss` | a chunk after the request is complete: `PST_BAD_ORDER` |
| `sessions/bad-tool-truncated.pss` | `accepted` with the last chunk missing: `PST_TOOL_INCOMPLETE` |
| `sessions/bad-tool-payload-in-chat-task.pss` | a chat task carries a tool-call chunk: `PST_NOT_TOOL_TASK` |

The Rust reader (`crates/aien-pi-spark-task`, `tests/tool_call.rs`) reads the same files and must print the same verdict line for every tool session, and its joined bytes must equal `interplane-tool-request.json` byte for byte.

## 12. Open questions

These are stated plainly so the C3 vectors and the neighbouring lanes can settle them. None is decided here.

1. Task id width (16 bytes here) and whether it should instead be derived from the cause id. UNVERIFIED.
2. Whether `resume_snapshot` needs its own payload layout, or a task-kind byte inside the payload. To be fixed by G3 and C5.
3. The aienos lane (aienos-mv#398) must confirm it can carry 1024-byte messages end to end and agree the framing.
4. Whether big-endian stays (section 6, item 3).
5. Session rules for `waiting_for_approval`, `uncertain_after_disconnect`, `resume_snapshot` and `receipt_reference` (section 10). Until then a session refuses them with `PST_BAD_ORDER`.
6. Whether a tool-call task should carry the full INTERPLANE envelope instead of the `tool_request` payload alone (section 11). The payload was chosen because the envelope's source and destination repeat facts the transport proves (section 3). To settle with aien-dev/interplane-mv#101 before merge.
7. Whether the 102400-byte tool-call limit (section 11.2) is right for real tool requests. Chosen without a measurement.
