# Changelog

All notable changes to the versioned specification surface are recorded here.
Reference implementation changes in `crates/` follow the same entries unless
noted. Dates are UTC. Versions follow semantic versioning as defined in
VERSIONING.md.

## [Unreleased]

### Security: Aienet-0 audit repairs (2026-10-28)

- `aien-microjob` 0.2.0 closes A6/A7/A8: stored countersignatures must
  bind the rebuilt commitment in both AN0V and MJR1; admission refuses
  insufficient matmul fuel and expired nodes, including `DagRun` admission.
  MJB1, MJR1, AN0B and AN0V wire bytes and versions are unchanged.
- A15 is a security API cutover: `DagRun::log` and `restore` now exchange
  ordered receiver-local `LedgerEvent::Receipt` and `LedgerEvent::Cancelled`
  values, preserving cancellation across restart. Receipt replay and repeated
  cancellation remain idempotent; restoration rejects a new receipt after
  cancellation. Migrate every persistence caller to store both event kinds
  atomically in its own durable storage, bound to the accepted document.
  No stable serialization is defined by this Rust enum. Historical
  receipt-only logs do not establish cancellation history: do not silently
  wrap them as receipt events and resume. Migration requires independently
  trusted receiver state establishing cancellation status. The security
  exception removes the receipt-only API without a compatibility fallback.
- A4/A5: `parity.sh` refuses failed builds, missing tools and malformed or
  empty oracle output with exit 2; exit 1 denotes a behavioral mismatch.
  `mutants.sh` requires the pinned Omega prerequisites, establishes baseline
  parity, and never counts invalid setup/output as a killed Omega mutant.
  `specs/aienet/jobpath/check-harness.sh` injects deterministic runner faults.
  Historical evidence under `evidence/aienet0-20261028` is unchanged and is
  not a receipt for these repairs.

### Aienet-0 authenticated ledger test adapter

- Restore the archived settlement runner as `scripts/aienet0/settle-run.sh` and
  migrate it to Core's `tur-ledger-2` CLI: pinned authority configuration,
  issuer-signed funding/reservation/refund and issuer-plus-verifier settlement.
  Recheck the actual signed bundle, MJR1 and AN0V before signing the complete
  quote-bound payout. Honest completion settles once; forged receipt or mutated
  AN0V refunds. Evidence is local host testing, not Core RPC or independent
  machine qualification. The historical baseline and wire formats are unchanged.
- Reconcile ambiguous reserve/settle failures against native journal state,
  refund only open reservations, and expose exact operator recovery instructions
  if I/O/signing remains unavailable. Add failure-injection controls and guard
  mutants; re-run actual artifact admission against the 0.2.0 carrier dependency.

### Security: approved framed digest cutover (SECNET-02, 2026-10-26)

- `SourceGrant` signs a domain-separated v2 transcript with u64 little-endian
  byte lengths for source URI, SPDX license and issuer, and a one-byte
  expiration presence tag. The former concatenation allowed a valid signed
  `LicenseRef-MIT` grant to be presented as `MIT` by moving `LicenseRef-`
  into the URI without changing the signed bytes. Legacy signatures are
  refused, not tried as a fallback. Migration: authorized issuers must
  reissue grants, and active provenance consumers must adopt the new commit
  together. Archived consumers are not silently reactivated.
- The adjacent plan, evaluator outcome and base evaluation receipt digests
  likewise gain distinct domain tags, lengths, option tags and list counts.
  Base receipt signing and verification refuse protocol versions 1 and 2.
  AEI1 verification also requires version 3; its low-level signer can construct
  negative-control legacy versions, but those are never accepted. Migration:
  active `spark-rsi` consumers must re-evaluate plans and outcomes or treat old
  digest references as untrusted. Existing signed receipts, including AEI1
  version 2, need reissuance after evaluation;
  digest-keyed caches, logs and stored references need an explicit mapping
  or invalidation. Preserve historical receipts and label them as legacy
  rather than rewriting them. No legacy acceptance switch is supplied.
- Drake approved the breaking contract and coordinated consumer cutover on
  2026-10-26. `CONSUMERS.md` records the active consumer audit and adoption PRs.
  Historical evidence is retained without byte changes and explicitly
  superseded where a new fixture replaces an old one. No `v0.2.0` tag is
  created here; a minor release remains a separate action.

### Specifications

- `specs/microjob` and `crates/aien-microjob` (SI-MICROFORGE C1,
  aien-protocols-mv#50): MJB1 Draft v0.1, the typed bounded microjob DAG
  (192-byte header, 448-byte nodes, at most 64 nodes): token profiles ZERO,
  64/16, 128/32, 256/64, 512/128 with explicit `MJB_NEEDS_EXPANSION` instead
  of truncation, time/fuel/memory/work caps and header budgets, a required
  verifier, retry and cancel classes, typed operand references (Cortex,
  World, content, capsule, experience), effect ceiling bound to the original
  approval, acyclicity and generation checks, and a canonical Kahn order.
  MJR1 receipt (404 bytes, P-256 signed) and the `DagRun` ledger: input
  binding, double-commit, retry, cancel and restart-by-replay rules. C
  checker `tools/mjb_verify.c` with 104 vectors and 58 mutants, all killed;
  the Rust crate gives the same verdict on every vector and re-encodes every
  accepted document byte for byte.
- `specs/discovery-capsule` and `crates/aien-discovery-capsule` (SI GENESIS
  C2, aien-protocols-mv#51): DCP1 family Draft v0.1: `DiscoveryCapsuleV1`,
  `OwnerConsentV1`, `OwnerRetractionV1` (no erasure claim allowed),
  `RetractionAckV1` and `ExperienceLineageV1`. Distinct DISCOVER, READ,
  REDISTRIBUTE and TRAIN bits, PRIVATE by default, closed license registry,
  capsule never self-authorizes. Recipient rules: owner retraction chain
  (replay, conflict, custodian), use checks for serving, training and
  republication, execution admission only on the recipient's own verdict and
  grant, honest PENDING / ACKNOWLEDGED / UNREACHABLE delivery status, and
  lineage withdrawal with affected-descendant marking. C checker
  `tools/dcp_verify.c` with 96 vectors and 62 mutants, all killed.
- `crates/aien-provenance`: `p256_compressed_key`, `p256_sign_low_s` and
  `p256_verify_low_s` for the fixed-width records above (low-S only).
- `specs/osh-platform`: OSH Platform ABI v1 DRAFT revision 2, still not
  frozen and still `abi_version` 1 (aien-protocols-mv#43). New
  `STREAM_TASK.md` makes streams and tasks precise: platform call frame and
  draft op ids, handle check order, byte-stream semantics, capability domain
  check order, task binding, cancellation, launch and partial launch,
  `OUTCOME_UNKNOWN`, receipt pins, and nine open freeze items.
  Incompatible draft change: `STREAM_DUP(src_stream, dst_fd)` is replaced by
  the capability form `STREAM_DUP(src_stream, rights, target)`.
  `AUDIT_STREAM_TASK.md` compares the draft with Omega's Linux host adapter
  and the AIENOS native pipe. Adds 37 shared stream and task vectors
  (`vectors/s*.vec`, `vectors/t*.vec`), the C reference model
  `tools/osh_sv_ref.c`, `tools/check-stream-vectors.sh` and
  `tools/mutate-stream-ref.sh` (22 checks, 22 mutants killed). The 20
  shell-core vectors are unchanged.
- `specs/pi-spark-task`: PST1 Draft v0.2 (C5, aien-protocols-mv#32): session
  rules (section 10): who may send which type, the allowed sequence for one
  task, the check order inside a session, and a recording container for test
  vectors; nine new codes. `pst_verify` gains `--session` and
  `--session-fuzz`; 19 recorded sessions in `vectors/sessions/`; 26 checks,
  26 mutants killed.
- `crates/aien-pi-spark-task` (C4, aien-protocols-mv#31): Rust reader and
  writer for the PST1 fixed header, no `unsafe`, no JSON, fixed bounds. Its
  test walks `specs/pi-spark-task/vectors/expected.txt` and requires the same
  verdict line as the C checker and byte-identical re-encoding.
- `specs/pi-spark-task`: PST1 Draft v0.1 (C3, aien-protocols-mv#30): a 4-byte
  `PST1` magic now opens the header (`reserved1` shrank to 1 byte and
  `reserved2` was removed, so the header stays 224 bytes; fields after `type`
  moved by 4), a fixed check order (section 4.1), and two codes
  (`PST_BAD_MAGIC`, `PST_NO_OBJECTIVE`). Version 0 is refused as
  `PST_DOWNGRADE`. Adds the C reference checker and encoder
  `tools/pst_verify.c` (C99, libc only, no heap), 23 header vectors with
  `vectors/expected.txt`, `tools/check-vectors.sh` and
  `tools/mutate-verifier.sh` (15 checks, 15 mutants killed).
- `specs/pi-spark-task`: PST1 Draft v0, the Pi-Spark task message for
  ALLEN Pi/Spark lane C1 (aien-protocols-mv#28): inventory of reused formats,
  layering over M6-A and M6-B, 224-byte big-endian header, 14 message types,
  size and refusal rules, the limits of exactly once, and a no-permission
  clause. No code and no vectors yet (C3).
- `specs/osh-platform`: OSH Platform ABI v1 DRAFT (not frozen) for the
  Omega-native shell of aien-architecture#158: step and status protocol,
  request record, platform operations, authority and interrupted-effect
  rules, and 20 conformance vectors. First implementation: omega `src/osh`
  (omega#337, #339, #340); its deltas (refusals 246 to 250, the 239 list,
  host cells `S_NOSKIP` and `S_EOI`, the variable-answer sentinel) are folded in.
- `specs/osc-unit-artifact`: OSC Unit Artifact v1 DRAFT, frozen pending ADR reconciliation (2026-10-08), the signed
  container in which an OSC-compiled Omega unit (A64 code plus canonical IR) is
  admitted and launched by AIENOS or the host adapter. Named refusal codes,
  launch result shape, bounded exact-match entry names, instruction-subset code scan, 47 refusal and 5 acceptance container vectors plus lookup, loader-state and launch-argument scenarios, shell generator and
  shell reference checker. No loader implements it yet.
- `specs/crumb-visible`: Crumb Reader Contract 1.0.0 for the CRB1 visible
  record (wire schema 1), numbered refusal codes, check order, determinism
  rule, and a shared conformance corpus (122 family vectors, 5 edge
  positives, 44 refusals) with a shell generator. Extracted from the running
  Rust reference; no new format features.
- `specs/execution-transcript`: TRN1 contract 0.2.0. Adds wire schema 3
  with record types 17 CAUSE, 18 RECEIPT_BIND, 19 RUN_LINK and 21 RESOURCE
  (32-byte cause id); type 20 TRAIN_DISPATCH reserved without a layout.
  Schema 1 files and every 0.1.0 vector keep their outcomes; schema 2 stays
  unassigned. Reference verifier accepts schemas 1 and 3; 0.2 goldens,
  forged histories, 23 refusal vectors and a join expectation list
  (`vectors/join.txt`). Sources: aien-architecture causal-id-join-v0
  (fa46a26) and resource-contract-v0 (ddc17b7).
- `specs/verified-crumb`: Verified Crumb V1 (VC1) contract 0.1.0, new. Canonical
  byte encoding of VerifiedCrumbV1 (big-endian, domain tag
  `AIEN_VERIFIED_CRUMB_V1`, sorted unique lists, no padding), VC id = SHA-256
  of the canonical bytes, resolve rule (lock, semantic id, store, identity,
  receipt, transitive closure, refuse on any failure), 9 resolve refusal codes
  plus 13 format refusal codes and the VC1 addition `VERIFIER_TOO_OLD`, the omega-dev (tainted) and omega-build
  (verified only) domains, and the `omega.lock` text format. Receipt id binds
  to the aien-proof BLAKE3 id. 17 golden vectors (4 accept, 13 refuse), a C
  checker (`tools/vc1-check.c`), and `tools/check-golden.sh` with 3 vector
  mutants and 9 checker mutants. No consumer pins it yet. Open design items
  are listed in SPEC.md sections 4 and 11 (`digest_kind` byte, 0x01 source / 0x02 IR, is part of the encoding).
  Contract 0.2.0 (VC1-RECONCILE): SPEC section 6.2 fixes one meaning per declaration code.
  `UNDECLARED_IMPORT` is only "the program uses something its dependency list
  does not declare" (ARCH-0029 code 7); a lock line, manifest entry or
  `dependencies[]` entry with no import behind it is `UNVERIFIED_DEPENDENCY`;
  an import with no lock line is `DEPENDENCY_NOT_PINNED`. SPEC step 8 now also
  refuses a `dependencies[]` entry the stored source does not import. No byte
  layout, id or golden vector changes. Migration: omega `omega_resolve.c` used
  `UNDECLARED_IMPORT` for a lock line with no import and must move to
  `UNVERIFIED_DEPENDENCY`; aien-closure already agrees.
- `specs/evidence-receipt`: partial extraction of aien-proof EvidenceReceiptV1
  (`SUBSET.md`): only the identity derivation and fields VC1 binds to,
  pinned to aien-sovereign-core `40dd373`. Full extraction is owed.

## [v0.1.0] - 2026-09-23

First versioned snapshot. No compatibility commitments predate this tag.

### Specifications

- Agent state, evaluation, and inference specs as present in `specs/`.
- Community Specification License 1.0 (`LICENSE-SPEC`).

### Reference crates

- Nine crates at `0.1.0`: protocol types, action protocol, agent state ABI,
  evaluation protocol, event protocol, inference client, inference protocol,
  probe, provenance. Apache-2.0 (`LICENSE-CODE`).

### Known consumers at this tag

Recorded in CONSUMERS.md. Consumers pin this version until a newer tag and
migration notes exist.
