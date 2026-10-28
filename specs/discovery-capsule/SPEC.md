# Discovery Capsule, Owner Consent, Retraction and Experience Lineage: DCP1 family

**Status**: Draft v0.1 (SI GENESIS C2, 2026-10-24). Not yet produced or read by any runtime. Reference checker and vectors: `tools/dcp_verify.c`, `vectors/`. Rust reader, signature checks and recipient rules: `crates/aien-discovery-capsule`.
**Contract version**: 0.1.0 (major zero: may change by minor bump, see VERSIONING.md)
**Wire version**: 1 (the `version` byte of every record)
**License**: Community Specification License 1.0
**Tracking**: aien-dev/aien-protocols-mv#51 (C2), parent aien-dev/aien-architecture-mv#307; consumes the microjob ABI of #50 (`specs/microjob/`) by digest; bootstrap issues aien-architecture-mv#310 (si-genesis) and #312 (si-legacy) consume this contract and must not define a second schema.
**Not in this document**: transport and publication (Open Humanity), storage (Omega Cortex is the one local store), effect approval (AEGIS), scientific gain (Spark RSI and the independent judge), spendable credit (Sovereign Core ledger), a new cryptosystem.

## 1. Purpose

A Discovery Capsule carries one reusable, proof-carrying result (a typed `.om` claim or procedure, or a reference to it) from the owner who found it to recipients who may check and reuse it. It binds exactly what was found, how it was built, under which preconditions it holds, how it was independently verified, where it fails, what the owner consents to, and where the owner's retraction chain stood when it was signed.

Five fixed-width records make up the family:

| Magic | Record | Signed by | Length |
|---|---|---|---|
| `DCP1` | `DiscoveryCapsuleV1` | owner | 676 |
| `DCC1` | `OwnerConsentV1` | owner | 388 |
| `DCR1` | `OwnerRetractionV1` | owner or a declared custodian | 284 |
| `DCA1` | `RetractionAckV1` | recipient | 148 |
| `DCL1` | `ExperienceLineageV1` | owner | 588 |

## 2. What a capsule is not

1. **A capsule never authorizes itself.** It has no approval field, no grant, no capability token. Possessing a capsule, or its digest, gives no tool access, no GPU code execution and no proof. A recipient may execute a capsule only after its *own* independent verifier, run under the recipient's platform, passes it, and only within capabilities the recipient's authority (AEGIS, Omega skill / World authorization) grants. A verdict produced by the capsule's owner key is refused as self-authorization.
2. Discoverability, reproducible correctness (the verifier and evidence references), the source signature, consent to **read**, consent to **redistribute** and permission to **train** are distinct fields. None implies another, except that redistributing or training requires reading.
3. **Private is the default.** A `PRIVATE` capsule carries no permission bit. Nothing in this family uploads Cortex content; a capsule carries digests and a typed reference, and the bytes behind a reference move only through Open Humanity under the owner's consent.
4. **Retraction is not deletion.** A retraction stops future availability, retrieval, training eligibility and republication at every compliant recipient that acknowledges it. It does not and cannot delete disconnected third-party copies or undo training already absorbed into weights. The wire format has no "erased" state, and a retraction that claims erasure is refused (`DCP_FALSE_ERASURE_CLAIM`).

## 3. Inventory of what already exists

| Existing piece | Where | Reused? | Reason |
|---|---|---|---|
| P-256 ECDSA / SHA-256 | `crates/aien-provenance` | Yes | Same primitive as the signed source grants of this repository; low-S only. No new cryptosystem. |
| `GrantPermissions` (READ, TRAIN, REDISTRIBUTE...) | `crates/aien-provenance` | Pattern only | Its bits are a JSON grant; this family needs fixed-width bytes and a separate DISCOVER bit. Bit names match where they overlap. |
| MJB1 microjob DAG | `specs/microjob/` (#50) | Yes, by digest | `microjob_ref` names the MJB1 `dag_digest` that produced the capsule; an MJB1 operand of kind CAPSULE names a capsule digest. |
| PST1 / OSH stream ABI | `specs/pi-spark-task/`, `specs/osh-platform/` (#43) | Carrier only | Records travel as opaque bytes; this family defines no transport. |
| Open Humanity consent and retraction | open-humanity #26/#27/#28, #33, #34 | Owner of transport and human approval | This family is the wire contract they carry; OH owns publishing, privacy and delivery. |
| Omega experience event | omega-mv#699 | Yes, by digest | `ExperienceLineageV1.content_digest` names one verified experience. |

## 4. Encoding rules

1. All integers are big-endian and unsigned. Digests are 32 raw bytes (SHA-256). Keys are 33-byte SEC1 compressed P-256 points (first byte 0x02 or 0x03).
2. Every reserved byte and every unused slot is zero on send and refused if non-zero on receipt. Every enumerated byte or bit set is closed; an unknown value is refused.
3. Each record ends in a 64-byte signature: ECDSA P-256 / SHA-256 over every byte before it, `r` then `s`, low-S only.
4. A record's identity is `record_digest = SHA-256(every byte before the signature)`. The signature is excluded, so re-signing never changes identity.

## 5. DiscoveryCapsuleV1 (`DCP1`), 676 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | `DCP1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `share_scope` | 0 PRIVATE, 1 NAMED, 2 COMMUNITY, 3 PUBLIC |
| 6 | 1 | `permissions` | bit 0 DISCOVER, bit 1 READ, bit 2 REDISTRIBUTE, bit 3 TRAIN; bits 4 to 7 zero |
| 7 | 1 | `precision` | 0 EXACT, 1 FP32, 2 BF16, 3 FP16, 4 FP8, 5 INT8, 6 INT4 |
| 8 | 2 | `license` | 1 Apache-2.0, 2 MIT, 3 CC-BY-4.0, 4 CC-BY-SA-4.0, 5 CDLA-Permissive-2.0, 6 OWNER-CONSENT-ONLY |
| 10 | 2 | `failure_count` | Number of known counterexamples / failure cases |
| 12 | 4 | `abi_version` | Not zero: the Omega / OSC ABI the executable targets |
| 16 | 4 | `required_capabilities` | bit 0 CPU_COMPUTE, 1 GPU_COMPUTE, 2 CORTEX_READ, 3 WORLD_READ, 4 WORLD_EFFECT, 5 NETWORK; bits 6 to 31 zero. A request, never a grant |
| 20 | 1 | `precondition_rank` | 0 to 4 |
| 21 | 3 | `reserved0` | 0 |
| 24 | 16 | `precondition_dims` | 4 x u32; entries past the rank are zero |
| 40 | 8 | `valid_from` | Unix seconds, not zero |
| 48 | 8 | `expires_at` | Above `valid_from` |
| 56 | 8 | `revocation_seq` | The owner's retraction chain head sequence when signed; 0 = no retraction yet |
| 64 | 32 | `meaning_digest` | Not zero: the typed `.om` claim / procedure (the published fragment) |
| 96 | 32 | `source_digest` | Not zero |
| 128 | 32 | `compiler_digest` | Not zero |
| 160 | 32 | `executable_digest` | Not zero |
| 192 | 32 | `preconditions_digest` | Not zero: valid input preconditions and shape |
| 224 | 32 | `verifier_ref` | Not zero: the independent verifier |
| 256 | 32 | `evidence_digest` | Not zero: benchmark provenance and verification evidence |
| 288 | 32 | `failure_cases_digest` | Not zero exactly when `failure_count` is not zero |
| 320 | 32 | `utility_verdict_ref` | Quality / utility verdict reference; zero = NOT_RUN |
| 352 | 32 | `science_verdict_ref` | Strict scientific-T verdict reference; zero = NOT_RUN. Never implied by the other fields |
| 384 | 32 | `recipient_policy_digest` | Not zero: the policy a recipient must run before reuse |
| 416 | 32 | `recipient_set_digest` | Not zero exactly when `share_scope` is NAMED (section 9) |
| 448 | 32 | `consent_ref` | `record_digest` of the `OwnerConsentV1`; required when any of READ, REDISTRIBUTE, TRAIN is set or the scope is not PRIVATE |
| 480 | 32 | `revocation_head` | `record_digest` of the retraction at `revocation_seq`; zero exactly when `revocation_seq` is 0 |
| 512 | 32 | `parent_capsule` | `record_digest` of the capsule this one derives from; zero = none |
| 544 | 32 | `microjob_ref` | MJB1 `dag_digest` that produced it; zero = none |
| 576 | 33 | `owner_key` | Pseudonymous owner key |
| 609 | 3 | `reserved1` | 0 |
| 612 | 64 | `signature` | By `owner_key` |

## 6. OwnerConsentV1 (`DCC1`), 388 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | `DCC1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `purposes` | Same bits as `permissions`; not zero |
| 6 | 1 | `custodian_count` | 0 to 4 |
| 7 | 1 | `reserved0` | 0 |
| 8 | 4 | `consent_version` | At least 1; a newer consent for the same fragment has a higher version |
| 12 | 4 | `notice_seconds` | Advance notice the owner gives before a change takes effect |
| 16 | 8 | `issued_at` | Unix seconds, not zero |
| 24 | 8 | `retention_end` | Above `issued_at`; no use after it |
| 32 | 32 | `provenance_digest` | Not zero |
| 64 | 32 | `recipient_digest` | Not zero: the exact recipient or destination set |
| 96 | 32 | `fragment_digest` | Not zero: the published fragment (equals the capsule `meaning_digest`) |
| 128 | 32 | `payload_digest` | Not zero: the canonical payload digest |
| 160 | 128 | `custodians` | 4 slots of SHA-256(custodian key); used slots not zero, unused slots zero. Successors or custodians exist only when declared here |
| 288 | 33 | `owner_key` | |
| 321 | 3 | `reserved1` | 0 |
| 324 | 64 | `signature` | By `owner_key` |

## 7. OwnerRetractionV1 (`DCR1`), 284 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | `DCR1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `scope` | bit 0 FUTURE_AVAILABILITY, bit 1 RETRIEVAL, bit 2 TRAINING, bit 3 REPUBLICATION; not zero; bits 4 to 7 zero |
| 6 | 1 | `erasure_claim` | 0 (NONE). Any other value is refused: no record may claim deletion of copies or trained weights |
| 7 | 1 | `reserved0` | 0 |
| 8 | 8 | `seq` | At least 1; the owner's chain is strictly monotonic |
| 16 | 8 | `effective_at` | Unix seconds, not zero |
| 24 | 32 | `target_digest` | Not zero: a capsule `record_digest`, a capsule `meaning_digest`, or an experience `content_digest` (the lineage root) |
| 56 | 32 | `prev_retraction` | `record_digest` of the retraction at `seq - 1`; zero exactly when `seq` is 1 |
| 88 | 32 | `provenance_digest` | Not zero |
| 120 | 32 | `tombstone_digest` | Not zero: digest of the minimal privacy-safe tombstone (no private bytes) |
| 152 | 33 | `owner_key` | Whose chain this is |
| 185 | 33 | `signer_key` | `owner_key`, or a custodian declared in the owner's consent |
| 218 | 2 | `reserved1` | 0 |
| 220 | 64 | `signature` | By `signer_key` |

## 8. RetractionAckV1 (`DCA1`), 148 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | `DCA1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `status` | 1 ENFORCED (future use stopped, no retained derived artifacts), 2 ENFORCED_WITH_RETAINED (future use stopped; the recipient holds copies or trained descendants it marks affected) |
| 6 | 2 | `reserved0` | 0 |
| 8 | 8 | `acked_at` | Unix seconds, not zero |
| 16 | 32 | `retraction_digest` | Not zero: the `record_digest` acknowledged |
| 48 | 33 | `recipient_key` | |
| 81 | 3 | `reserved1` | 0 |
| 84 | 64 | `signature` | By `recipient_key` |

## 9. ExperienceLineageV1 (`DCL1`), 588 bytes

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | `DCL1` |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `parent_count` | 0 to 4 |
| 6 | 1 | `influenced_count` | 0 to 8 |
| 7 | 1 | `reserved0` | 0 |
| 8 | 32 | `content_digest` | Not zero: one verified experience (omega-mv#699 event) |
| 40 | 32 | `dataset_id` | Not zero: the dataset this experience belongs to |
| 72 | 32 | `consent_ref` | Not zero: the owner's consent record |
| 104 | 128 | `parents` | 4 slots: `content_digest` of parent experiences; used slots not zero, distinct and not this record's own `content_digest`; unused zero |
| 232 | 256 | `influenced` | 8 slots: checkpoint or capsule digests this experience influenced; used not zero, unused zero |
| 488 | 33 | `owner_key` | |
| 521 | 3 | `reserved1` | 0 |
| 524 | 64 | `signature` | By `owner_key` |

Named recipient set: `recipient_set_digest = SHA-256("DCP1-RECIPIENTS" || keys)`, keys sorted bytewise ascending, no duplicates.

## 10. Static check order

One checker reads any record of the family and reports the first failing rule:

1. Fewer than 5 bytes: `DCP_BAD_LENGTH`.
2. Magic not one of the five: `DCP_BAD_MAGIC`.
3. `version` 0: `DCP_DOWNGRADE`; above 1: `DCP_BAD_VERSION`.
4. Length differs from the record length: `DCP_BAD_LENGTH`.
5. A reserved byte, an unused slot or a dimension past the rank is not zero: `DCP_RESERVED_NONZERO`.
6. An enumerated value or bit set is outside its closed set, including a zero `purposes` or `scope`, or a count above its slot count: `DCP_BAD_ENUM`.
7. (`DCP1`) `license` is not 1 to 6: `DCP_UNKNOWN_LICENSE`.
8. (`DCR1`) `erasure_claim` is not 0: `DCP_FALSE_ERASURE_CLAIM`.
9. A field marked "not zero" is zero (including `abi_version`, `consent_version`, `seq`, a used slot): `DCP_MISSING_FIELD`.
10. A key whose first byte is not 0x02 or 0x03: `DCP_BAD_KEY`.
11. A time rule fails (`valid_from` zero or `expires_at` not above it; `retention_end` not above `issued_at`; `issued_at`, `effective_at` or `acked_at` zero): `DCP_BAD_VALIDITY`.
12. A paired rule fails (`failure_count` vs `failure_cases_digest`; `revocation_seq` vs `revocation_head`; `seq` vs `prev_retraction`): `DCP_INCONSISTENT`.
13. (`DCP1`) PRIVATE with any permission bit; or `recipient_set_digest` zero for NAMED, or not zero for another scope: `DCP_SCOPE_CONFLICT`.
14. (`DCP1`, `DCC1`) REDISTRIBUTE or TRAIN without READ: `DCP_PERMISSION_AMPLIFICATION`.
15. (`DCP1`) `consent_ref` zero while READ, REDISTRIBUTE or TRAIN is set or the scope is not PRIVATE: `DCP_NO_CONSENT`.
16. (`DCL1`) A parent equal to the record's own `content_digest`: `DCP_ANCESTOR_CYCLE`. The same parent twice: `DCP_DUPLICATE`.

## 11. Recipient rules (stateful)

These need keys, a clock and the recipient's own records, so they live in the Rust crate, not the C checker. A refusal changes no state.

| Code | Rule |
|---|---|
| `DCP_BAD_SIGNATURE` | The signature does not verify under the record's signing key, or is high-S. An edited capsule lands here |
| `DCP_OWNER_MISMATCH` | Consent, retraction or lineage owner differs from the capsule owner |
| `DCP_NO_CONSENT` | `consent_ref` is not the digest of the consent supplied, or the consent `fragment_digest` is not the capsule `meaning_digest` |
| `DCP_PERMISSION_AMPLIFICATION` | Capsule permissions not a subset of the consent purposes, or of the parent capsule's permissions |
| `DCP_PRIVATE` | A PRIVATE capsule offered to anyone but its owner |
| `DCP_NOT_RECIPIENT` | NAMED scope and the recipient is not in the set whose digest the capsule binds; or an ack from a key that was not sent the retraction |
| `DCP_EXPIRED` | Outside `[valid_from, expires_at]`, or after the consent `retention_end` |
| `DCP_STALE` | The capsule names a `revocation_seq` the recipient's copy of the owner's chain has not reached (the recipient must sync first), a newer `consent_version` for the same fragment is known, or the recipient holds no chain for the owner of a lineage ancestor |
| `DCP_REVOKED` | A retraction in the owner's chain targets the capsule (record or meaning digest) or a lineage ancestor, with a scope covering the requested use: serving needs neither FUTURE_AVAILABILITY nor RETRIEVAL; training needs no TRAINING; republication needs no REPUBLICATION |
| `DCP_NOT_PERMITTED` | The requested use (READ, REDISTRIBUTE, TRAIN) is not in the capsule permissions |
| `DCP_CONFLICT` | A retraction with a sequence already used but different bytes (concurrent conflicting owner operations), a sequence gap, a `prev_retraction` that is not the current head, a capsule whose `revocation_head` differs from the chain at its `revocation_seq`, a second different ack from one recipient, or an ack for another retraction. Fails closed |
| `DCP_UNKNOWN_CUSTODIAN` | A retraction signed by a key that is neither the owner nor a custodian declared in the owner's consent |
| `DCP_SELF_AUTHORIZED` | An execution verdict produced by the capsule owner's key |
| `DCP_UNVERIFIED` | No passing verdict from the recipient's own verifier for this exact capsule digest and recipient platform |
| `DCP_CAPABILITY_DENIED` | The recipient's grant does not cover `required_capabilities` |
| `DCP_DUPLICATE` | Two different lineage records for one `content_digest` |
| `DCP_CROSS_DATASET` | A lineage parent from another `dataset_id` (cross-dataset injection) |
| `DCP_ANCESTOR_CYCLE` | The lineage parents form a cycle |
| `DCP_UNKNOWN_PARENT` | A lineage parent the recipient does not hold when checking ancestry for training, or a `parent_capsule` the recipient was not given |

A byte-identical repeat of an applied retraction or ack is a replay: accepted, no state change.

### 11.1 Retraction status is honest

For each retraction the owner's node tracks every recipient it was sent to as PENDING, ACKNOWLEDGED (with the ack status) or UNREACHABLE. A recipient that never answers stays PENDING; an offline recipient is never shown as acknowledged, and no state anywhere says "erased". ENFORCED_WITH_RETAINED acks are listed separately, with the influenced checkpoints of the affected lineage, so trained descendants can be quarantined, rebuilt or retired by their owner (aien-train#20).

## 12. Refusal codes

`DCP_BAD_LENGTH`, `DCP_BAD_MAGIC`, `DCP_DOWNGRADE`, `DCP_BAD_VERSION`, `DCP_RESERVED_NONZERO`, `DCP_BAD_ENUM`, `DCP_UNKNOWN_LICENSE`, `DCP_FALSE_ERASURE_CLAIM`, `DCP_MISSING_FIELD`, `DCP_BAD_KEY`, `DCP_BAD_VALIDITY`, `DCP_INCONSISTENT`, `DCP_SCOPE_CONFLICT`, `DCP_PERMISSION_AMPLIFICATION`, `DCP_NO_CONSENT`, `DCP_ANCESTOR_CYCLE`, `DCP_DUPLICATE` (static, section 10) and `DCP_BAD_SIGNATURE`, `DCP_OWNER_MISMATCH`, `DCP_PRIVATE`, `DCP_NOT_RECIPIENT`, `DCP_EXPIRED`, `DCP_STALE`, `DCP_REVOKED`, `DCP_NOT_PERMITTED`, `DCP_CONFLICT`, `DCP_UNKNOWN_CUSTODIAN`, `DCP_SELF_AUTHORIZED`, `DCP_UNVERIFIED`, `DCP_CAPABILITY_DENIED`, `DCP_CROSS_DATASET`, `DCP_UNKNOWN_PARENT` (recipient, section 11).

## 13. Privacy

No record carries private bytes: only digests, keys, counts, times and closed enumerations. The tombstone is referenced by digest and holds only what is needed to recognise the retracted target. Receipts and public metadata that cite a capsule cite its `record_digest`.

## 14. Open questions

1. The license registry (6 entries) and the capability bits (6) are first-cut closed sets; additions are a minor version bump.
2. Whether a custodian may also issue consent (today only retractions).
3. How Open Humanity maps its transport identities to the 33-byte keys (owner: open-humanity#33/#34).
