# Typed Bounded Microjob DAG and Receipt: MJB1 / MJR1

**Status**: Draft v0.1 (SI-MICROFORGE C1, 2026-10-24). Not yet produced or read by any runtime. Reference checker and vectors: `tools/mjb_verify.c`, `vectors/`. Rust reader, writer and receipt ledger: `crates/aien-microjob`.
**Contract version**: 0.1.0 (major zero: may change by minor bump, see VERSIONING.md)
**Wire version**: 1 (the `version` byte of both records)
**License**: Community Specification License 1.0
**Tracking**: aien-dev/aien-protocols-mv#50 (C1), parent aien-dev/aien-architecture-mv#307 and #306. Binds the Discovery Capsule ABI of aien-protocols-mv#51 (`specs/discovery-capsule/`) by digest only.
**Not in this document**: who plans the DAG (Allen, allen#13), who runs a node (Omega scheduler, FORGE placement), who approves an effect (AEGIS / the Spark approval desk), the network carrier (PST1, OSH stream ABI #43), payment of any kind.

## 1. Purpose

Allen and SI Fusion need one portable typed envelope for small computational steps instead of one prose prompt per agent operation. MJB1 is that envelope: one objective expressed as an explicit, bounded, acyclic dependency graph of typed microjobs, each with hard token, time, fuel, memory and work caps, a required verifier and explicit cancel and retry semantics. MJR1 is the receipt that binds what one microjob actually produced and consumed.

MJB1 is a proposal format. A valid MJB1 document is **not** an authorization, and an MJB1 node is not a receipt. No field in MJB1 or MJR1 grants a capability (section 9).

## 2. Inventory of what already exists

| Existing piece | Where | Reused? | Reason |
|---|---|---|---|
| PST1 task message | `specs/pi-spark-task/` | Yes, as carrier and house pattern | A PST1 `request` payload is at most 800 bytes, so an MJB1 document travels by digest in the PST1 header (`objective_id`, `payload_digest`) and its bytes through the content store. Same byte order (big-endian), same check-order discipline, same C checker plus vectors plus mutants pattern. |
| Objective id | aien-sovereign-core `crates/aien-runtime/src/objective.rs` | Yes, as a header field | Copied, never minted by a receiver. |
| ALLEN subject | AIENOS ADR 0018 | Yes, as `subject_id` | 32-byte subject reference; no key material. |
| Effect classes | PST1 section 4 (`effect_class`) | Yes, same values | 0 NONE, 1 COMPUTE, 2 EFFECT. |
| Effect ledger | aien-sovereign-core `crates/aien-runtime/src/effects.rs` | Yes, as reconciliation authority | An UNCERTAIN effect is reconciled there before any new attempt. |
| P-256 ECDSA signatures | `crates/aien-provenance` (`p256`) | Yes, same primitive | MJR1 signatures use the curve and hash already used by the signed source grants of this repository. No new cryptosystem. |
| OSH stream and task ABI | `specs/osh-platform/STREAM_TASK.md` (#43) | Not changed | MJB1 does not define streams; a node result travels as a typed content reference. |

## 3. Encoding rules

1. All integers are big-endian and unsigned. Digests are 32 raw bytes (SHA-256), printed as 64 lower-case hex digits.
2. Every reserved byte, every unused dependency slot, every unused operand slot and every unused shape dimension is zero on send and refused if non-zero on receipt.
3. Every enumerated byte has a closed value set. An unknown value is refused (`MJB_BAD_ENUM`).
4. The canonical identity of an MJB1 document is `dag_digest = SHA-256(all document bytes)`. Every byte is defined, so one document has exactly one encoding. The canonical identity of an MJR1 receipt is `receipt_digest = SHA-256(receipt bytes [0, 340))`; the signature is excluded.

## 4. MJB1 document

One document is a 192-byte header followed by exactly `node_count` node records of 448 bytes each. Largest document: 192 + 64 x 448 = 28864 bytes.

### 4.1 Header, 192 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `MJB1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `effect_ceiling` | 0 NONE, 1 COMPUTE, 2 EFFECT: the widest effect the original user approval covers |
| 6 | 2 | `node_count` | 1 to 64 |
| 8 | 32 | `objective_id` | Not all zero |
| 40 | 32 | `tenant_id` | Not all zero: the privacy and tenant scope of the whole objective |
| 72 | 32 | `subject_id` | Not all zero: the ALLEN subject the work is for |
| 104 | 32 | `approval_ref` | Not all zero: digest of the original approval record held by the approval desk |
| 136 | 4 | `incarnation` | At least 1; a re-plan of the same objective takes a higher incarnation |
| 140 | 4 | `reserved0` | 0 |
| 144 | 8 | `expires_at` | Unix seconds, not zero |
| 152 | 8 | `budget_time_ms` | Upper bound on the sum of node `time_ms` caps |
| 160 | 8 | `budget_fuel` | Upper bound on the sum of node `fuel` caps |
| 168 | 8 | `budget_memory` | Upper bound on every single node `memory` cap (peak, not sum) |
| 176 | 8 | `budget_work` | Upper bound on the sum of node `work` caps |
| 184 | 4 | `budget_input_tokens` | Upper bound on the sum of node `input_tokens` caps |
| 188 | 4 | `budget_output_tokens` | Upper bound on the sum of node `output_tokens` caps |

### 4.2 Node record, 448 bytes

Node `i` (zero-based) starts at offset `192 + 448 i`.

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 16 | `job_id` | Not all zero; unique in the document |
| 16 | 16 | `idempotence_key` | Not all zero; unique in the document |
| 32 | 4 | `generation` | At least 1; the version of this node's inputs and definition |
| 36 | 1 | `kind` | 1 COMPUTE (zero neural tokens), 2 NEURAL |
| 37 | 1 | `op` | COMPUTE: 1 ARITH, 2 MATMUL, 3 REDUCE, 4 COMPARE, 5 COMPILE, 6 VERIFY. NEURAL: 1 ROUTE, 2 EXTRACT, 3 PROPOSE, 4 SUMMARIZE |
| 38 | 1 | `profile` | 0 ZERO, 1 MINIMAL 64/16, 2 DEFAULT 128/32, 3 LARGE 256/64, 4 SPECIALIST 512/128 (input/output tokens) |
| 39 | 1 | `effect_class` | 0 NONE, 1 COMPUTE, 2 EFFECT |
| 40 | 2 | `input_tokens` | Input token cap |
| 42 | 2 | `output_tokens` | Output token cap |
| 44 | 2 | `required_input_tokens` | Smallest input that carries the node's essential operands without loss, as measured by the planner |
| 46 | 2 | `required_output_tokens` | Smallest output that can represent the declared result type |
| 48 | 1 | `verifier_kind` | 1 RECOMPUTE, 2 CHECKER, 3 JUDGE (0 is the missing-verifier refusal) |
| 49 | 1 | `retry_class` | 1 NEVER, 2 IDEMPOTENT, 3 RECONCILE_FIRST |
| 50 | 1 | `max_attempts` | 1 to 8 |
| 51 | 1 | `cancel_mode` | 1 DISCARD (no partial state survives), 2 CHECKPOINT (resumable; the commit is atomic with the receipt) |
| 52 | 1 | `precision` | 0 EXACT, 1 FP32, 2 BF16, 3 FP16, 4 FP8, 5 INT8, 6 INT4 |
| 53 | 1 | `substrate_mask` | Bit 0 CPU, bit 1 GPU, bit 2 NPU; not zero; bits 3 to 7 zero |
| 54 | 1 | `dep_count` | 0 to 8 |
| 55 | 1 | `operand_count` | 0 to 4 |
| 56 | 1 | `result_type` | 1 BYTES, 2 INT, 3 FLOAT, 4 TENSOR, 5 BOOL, 6 TEXT, 7 DIGEST |
| 57 | 1 | `result_rank` | 0 to 4 |
| 58 | 1 | `pure` | 0 or 1: 1 means deterministic recomputation is admissible |
| 59 | 1 | `reserved1` | 0 |
| 60 | 4 | `time_ms` | Not zero |
| 64 | 8 | `fuel` | Not zero |
| 72 | 8 | `memory` | Bytes, not zero |
| 80 | 8 | `work` | Abstract work units, not zero |
| 88 | 8 | `expires_at` | Unix seconds, not zero, at most the header `expires_at` |
| 96 | 16 | `result_dims` | 4 x u32; dimensions past `result_rank` are zero |
| 112 | 32 | `capability_ref` | Not all zero: the currently authorized capability (Omega skill / World authorization) the node runs under |
| 144 | 32 | `tenant_id` | Equal to the header `tenant_id` |
| 176 | 32 | `model_ref` | All zero for COMPUTE; not all zero for NEURAL (model, tokenizer and quantization digest) |
| 208 | 32 | `verifier_ref` | All zero for RECOMPUTE; not all zero for CHECKER and JUDGE |
| 240 | 48 | `deps` | 8 slots of 6 bytes: `index` u16 (a node of this document), `generation` u32 (the generation of that node this node was planned against) |
| 288 | 160 | `operands` | 4 slots of 40 bytes: `kind` u8, `reserved` 3 bytes (zero), `generation` u32 (at least 1), `digest` 32 bytes (not all zero) |

Operand kinds: 1 CORTEX_STATE (typed Cortex record, Omega), 2 WORLD_STATE (World / J-Space state digest), 3 CONTENT (typed content blob in the content store), 4 CAPSULE (a DCP1 capsule digest, `specs/discovery-capsule/`), 5 EXPERIENCE (an Omega experience event digest, omega-mv#699). An operand is a typed reference, never inline bytes; essential context is passed this way and is never truncated to fit a token cap.

### 4.3 Token profiles

| Code | Name | Input cap | Output cap |
|---|---|---|---|
| 0 | ZERO | 0 | 0 |
| 1 | MINIMAL | 64 | 16 |
| 2 | DEFAULT | 128 | 32 |
| 3 | LARGE | 256 | 64 |
| 4 | SPECIALIST | 512 | 128 |

A COMPUTE node uses profile ZERO with both caps 0 and `model_ref` all zero: deterministic math spends no neural tokens. A NEURAL node uses profile 1 to 4, with caps not zero and not above the profile; the optimizer may choose caps below the profile. The profile is a per-node contract, not a limit on the objective or on global context: a long objective is many small nodes.

**No silent truncation.** If `required_input_tokens > input_tokens` or `required_output_tokens > output_tokens` the node is refused with `MJB_NEEDS_EXPANSION`. The planner must then choose a larger profile or split the node. A receiver never trims an operand to fit.

### 4.4 Check order

A receiver checks one document in this order and reports the first rule that fails. The C reference checker and the Rust reader follow the same order, so the same bytes always give the same code.

Header:

1. Fewer than 192 bytes: `MJB_BAD_LENGTH`.
2. `magic` is not `MJB1`: `MJB_BAD_MAGIC`.
3. `version` 0: `MJB_DOWNGRADE`; above 1: `MJB_BAD_VERSION`.
4. `node_count` 0 or above 64: `MJB_BAD_COUNT`.
5. Length differs from `192 + 448 node_count`: `MJB_BAD_LENGTH`.
6. `reserved0` not zero: `MJB_RESERVED_NONZERO`.
7. `effect_ceiling` above 2: `MJB_BAD_ENUM`.
8. `objective_id` all zero: `MJB_NO_OBJECTIVE`. `tenant_id` all zero: `MJB_NO_TENANT`. `subject_id` all zero: `MJB_NO_SUBJECT`. `approval_ref` all zero: `MJB_NO_APPROVAL`. `incarnation` 0: `MJB_NO_OBJECTIVE`.
9. `expires_at` 0 has no rule of its own: every node then fails rule 22 with `MJB_BAD_EXPIRY`.

Then each node in index order, all rules for node 0 before node 1:

10. `job_id`, `idempotence_key` all zero, or `generation` 0: `MJB_NO_JOB`.
11. `reserved1`, any byte of an unused dependency slot, any byte of an unused operand slot, the reserved bytes of a used operand slot, or a `result_dims` entry past `result_rank`: `MJB_RESERVED_NONZERO`.
12. Out-of-range `kind`, `op` (for that kind), `profile`, `effect_class`, `verifier_kind` above 3, `retry_class`, `max_attempts`, `cancel_mode`, `precision`, `substrate_mask`, `dep_count`, `operand_count`, `result_type`, `result_rank`, `pure`, or an operand `kind`: `MJB_BAD_ENUM`.
13. `tenant_id` differs from the header: `MJB_CROSS_TENANT`.
14. `capability_ref` all zero: `MJB_NO_CAPABILITY`.
15. `effect_class` above the header `effect_ceiling`: `MJB_UNAUTHORIZED_EFFECT`.
16. `verifier_kind` 0; or CHECKER or JUDGE with `verifier_ref` all zero; or RECOMPUTE with `verifier_ref` not zero; or RECOMPUTE on a node that is not `pure`: `MJB_NO_VERIFIER`.
17. `pure` is 1 on a NEURAL node or on an EFFECT node: `MJB_IMPURE`.
18. COMPUTE with profile not ZERO, a token cap not zero, a required token count not zero, or `model_ref` not zero; NEURAL with profile ZERO, a zero token cap, a cap above the profile, or `model_ref` all zero: `MJB_TOKEN_PROFILE`.
19. `required_input_tokens > input_tokens` or `required_output_tokens > output_tokens`: `MJB_NEEDS_EXPANSION`.
20. `retry_class` NEVER with `max_attempts` above 1; or EFFECT with `retry_class` IDEMPOTENT: `MJB_BAD_RETRY`.
21. `time_ms`, `fuel`, `memory` or `work` zero: `MJB_ZERO_CAP`.
22. `expires_at` zero or above the header `expires_at`: `MJB_BAD_EXPIRY`.
23. A used operand with `generation` 0 or `digest` all zero: `MJB_MISSING_OPERAND`.

Then the whole graph:

24. Two nodes share a `job_id` or an `idempotence_key`: `MJB_DUPLICATE_JOB`.
25. A dependency `index` that is the node itself or not below `node_count` (an orphaned required input): `MJB_MISSING_DEP`.
26. A dependency `generation` that differs from the `generation` of the node it names: `MJB_STALE_GENERATION`.
27. The dependency graph has a cycle: `MJB_CYCLE`.
28. A sum of node caps above its header budget (time, fuel, work, input tokens, output tokens; sums are exact, and a sum that does not fit in 64 bits is over budget), or one node `memory` above `budget_memory`: `MJB_OVER_BUDGET`.

An accepted document has one canonical execution order: Kahn's algorithm, always taking the lowest-index ready node first. The checker prints it.

## 5. MJR1 receipt, 404 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `MJR1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `outcome` | 1 COMPLETED, 2 REFUSED, 3 FAILED, 4 CANCELLED, 5 UNCERTAIN |
| 6 | 1 | `attempt` | 1 to `max_attempts` of the node |
| 7 | 1 | `reserved0` | 0 |
| 8 | 32 | `dag_digest` | The MJB1 `dag_digest` |
| 40 | 16 | `job_id` | The node's `job_id` |
| 56 | 16 | `idempotence_key` | The node's `idempotence_key` |
| 72 | 4 | `generation` | The node's `generation` |
| 76 | 4 | `used_time_ms` | Consumed wall time |
| 80 | 2 | `used_input_tokens` | Consumed |
| 82 | 2 | `used_output_tokens` | Consumed |
| 84 | 4 | `reserved1` | 0 |
| 88 | 8 | `used_fuel` | Consumed |
| 96 | 8 | `used_memory` | Peak bytes |
| 104 | 8 | `used_work` | Consumed |
| 112 | 32 | `input_binding` | Section 5.1 |
| 144 | 32 | `output_digest` | Not zero for COMPLETED; zero otherwise |
| 176 | 32 | `source_hash` | Not zero: the program / `.om` source that ran |
| 208 | 32 | `model_hash` | Equal to `model_ref` (zero for COMPUTE) |
| 240 | 32 | `policy_hash` | Not zero: the routing / admission policy in force |
| 272 | 32 | `verifier_verdict` | Not zero for COMPLETED: digest of the verifier verdict |
| 304 | 33 | `signer_key` | SEC1 compressed P-256 key of the executor (first byte 0x02 or 0x03) |
| 337 | 3 | `reserved2` | 0 |
| 340 | 64 | `signature` | ECDSA P-256 / SHA-256 over bytes `[0, 340)`, `r` then `s`, 32 bytes each, low-S only |

### 5.1 Input binding

`input_binding = SHA-256("MJR1-BIND" || for each dependency in slot order: receipt_digest of that dependency's COMPLETED receipt || for each operand in slot order: kind (1 byte) || generation (4 bytes) || digest (32 bytes))`.

A receipt whose binding differs from the binding recomputed from the receiver's own accepted dependency receipts and the node's declared operands was computed from a missing or replaced operand and is refused (`MJB_BINDING_MISMATCH`).

### 5.2 Receipt rules

A receiver keeps one ledger per accepted document and applies receipts one at a time. It refuses a receipt, with no state change, when:

| Code | Rule |
|---|---|
| `MJB_BAD_RECEIPT` | Wrong length, magic, version, reserved byte, outcome, or signer key prefix; or the COMPLETED / non-COMPLETED zero rules on `output_digest`, `verifier_verdict` are broken; or `source_hash` / `policy_hash` zero |
| `MJB_FORGED_RECEIPT` | The signer is not in the receiver's local trusted executor set, or the signature does not verify, or is high-S |
| `MJB_WRONG_DAG` | `dag_digest` is not this document |
| `MJB_UNKNOWN_JOB` | No node has this `job_id`, or its `idempotence_key` differs |
| `MJB_STALE_GENERATION` | `generation` differs from the node |
| `MJB_MODEL_MISMATCH` | `model_hash` differs from the node `model_ref` |
| `MJB_RECEIPT_OVER_BUDGET` | Any `used_*` value above the node cap |
| `MJB_DEP_NOT_DONE` | A COMPLETED receipt for a node whose dependencies are not all COMPLETED |
| `MJB_BINDING_MISMATCH` | Section 5.1 |
| `MJB_DOUBLE_COMMIT` | The node is already terminal and the receipt is not byte-identical to the one that made it so |
| `MJB_BAD_RETRY` | A further attempt on a node whose `retry_class` is NEVER, an attempt number not above the last one, or above `max_attempts` |
| `MJB_CANCELLED` | The objective was cancelled before this receipt was applied |

A byte-identical repeat of an applied receipt is a replay: accepted, no state change. This is what makes interrupt and resume safe: a restarted receiver replays its stored receipts and arrives at the same state, and a second commit of the same node with different bytes is refused.

COMPLETED, REFUSED and CANCELLED are terminal. FAILED and UNCERTAIN are not: another attempt may follow when `retry_class` allows it. An UNCERTAIN effect is reconciled against the effect ledger before the next attempt; a possibly committed effect is never re-run on the strength of a retry alone, which is why EFFECT nodes may not be IDEMPOTENT.

### 5.3 Derived node state

From the document and the ledger a receiver derives, per node: DONE (COMPLETED receipt), REFUSED, CANCELLED, BLOCKED (a dependency is REFUSED, CANCELLED, BLOCKED or out of attempts), READY (every dependency DONE), WAITING otherwise. This is a pure function of accepted bytes; it is not a scheduler and chooses nothing.

Cancellation is atomic with respect to receipts: a receipt applied before the cancel stands, a receipt arriving after it is refused with `MJB_CANCELLED`, and every non-terminal node becomes CANCELLED.

Dependency-version invalidation: a node whose inputs change takes a higher `generation`, and every node that depends on it must name the new generation (rule 26), which changes the document and so its `dag_digest`. Receipts of the old document are refused (`MJB_WRONG_DAG`). A pure node whose bytes and whose ancestors' bytes are unchanged may be recomputed deterministically and must give the same `output_digest`.

## 6. Refusal codes

`MJB_BAD_LENGTH`, `MJB_BAD_MAGIC`, `MJB_DOWNGRADE`, `MJB_BAD_VERSION`, `MJB_BAD_COUNT`, `MJB_RESERVED_NONZERO`, `MJB_BAD_ENUM`, `MJB_NO_OBJECTIVE`, `MJB_NO_TENANT`, `MJB_NO_SUBJECT`, `MJB_NO_APPROVAL`, `MJB_BAD_EXPIRY`, `MJB_NO_JOB`, `MJB_CROSS_TENANT`, `MJB_NO_CAPABILITY`, `MJB_UNAUTHORIZED_EFFECT`, `MJB_NO_VERIFIER`, `MJB_IMPURE`, `MJB_TOKEN_PROFILE`, `MJB_NEEDS_EXPANSION`, `MJB_BAD_RETRY`, `MJB_ZERO_CAP`, `MJB_MISSING_OPERAND`, `MJB_DUPLICATE_JOB`, `MJB_MISSING_DEP`, `MJB_STALE_GENERATION`, `MJB_CYCLE`, `MJB_OVER_BUDGET` (document, section 4.4) and `MJB_BAD_RECEIPT`, `MJB_FORGED_RECEIPT`, `MJB_WRONG_DAG`, `MJB_UNKNOWN_JOB`, `MJB_MODEL_MISMATCH`, `MJB_RECEIPT_OVER_BUDGET`, `MJB_DEP_NOT_DONE`, `MJB_BINDING_MISMATCH`, `MJB_DOUBLE_COMMIT`, `MJB_CANCELLED` (receipts, section 5.2).

## 7. Expiry

Expiry is checked by the receiver against its own clock at admission (`MJB_BAD_EXPIRY` when `expires_at` is in the past). The C checker has no clock and checks only the static rules of section 4.4.

## 8. Relation to the Turing Compute Network

The same document can later ride a voluntary compute network. This pilot contract has **no wallet, currency, price, public job market or escrow field**. Spendable credit stays with the existing Sovereign Core ledger (aien-sovereign-core-mv#734); a receipt is evidence of execution, never of novelty or scientific gain.

## 9. No capability, no permission

No field grants anything. `capability_ref` and `approval_ref` name authorizations that the receiver checks against the real authority (Omega skill / World authorization, AEGIS, the approval desk); a reference it cannot resolve is a refusal at admission. A node's effect can never be wider than `effect_ceiling`, and `effect_ceiling` can never be wider than the original user approval it names. Model output, a routing choice, a valid document or a valid receipt is never an authorization.

## 10. Open questions

1. Node count cap (64) and slot counts (8 dependencies, 4 operands) are first-cut bounds without a measurement; a wider fan-in is expressed today by a REDUCE node chain.
2. Whether Omega carries the same layout as a seeded `.om` value or as an opaque byte record (owner: omega-mv).
3. Whether the executor signer set is per tenant or per host (owner: the Spark receipt signer).
