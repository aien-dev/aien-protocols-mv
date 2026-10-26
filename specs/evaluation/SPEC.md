# Unified Evaluator Protocol Specification

**Status**: Draft  
**Version**: 1.0.0  
**License**: Community Specification License 1.0  

## Abstract

The Unified Evaluator Protocol establishes the verifier boundary for autonomous candidate evaluation, self-modification, and regression testing.

## Core Concepts

1. **Evaluator SPI**: Independent evaluators (static analysis, regression suites, benchmarks) produce native measurements and findings under a frozen `EvaluationPlan`.
2. **Immutability Invariant**: Candidate Engine N+1 may propose an artifact but may never evaluate itself or modify evaluator rules, thresholds, or verifier keys.
3. **Protected Verifier**: Signed evaluation receipts (`SignedEvaluationReceipt`) are issued exclusively by an isolated verifier identity bound to hardware TPM 2.0 keys.

## Verdict identity domains (registry)

A verdict identity is a lowercase hex SHA-256 over a domain tag, one LF, then lines of exact text joined by LF with no trailing LF. Nothing with a timestamp, host name, path or floating-point value enters it, so two machines that agree on every row produce the same identity. A producer adds its domain here before emitting it; a tag is never reused with a different byte layout.

| domain tag | names | defined in | status |
|---|---|---|---|
| `AIEN_E2E_OBJECTIVE_V1` | the objective identity of the WHOLE-SYSTEM-E2E acceptance test (tag, LF, objective text) | aien-architecture `docs/plans/release-readiness/ACCEPTANCE_E2E.md` section 1 | FROZEN 2026-10-10 |
| `AIEN_E2E_VERDICT_V1` | the verdict identity of the WHOLE-SYSTEM-E2E acceptance test (tag, LF, `objective_id`, `contract_sha256`, rows E1 to E6, CTRL-E1 to CTRL-E6) | same file, section 1, byte layout pinned at freeze | FROZEN 2026-10-10 |

Producers: the harness `scripts/whole_system_e2e.sh` and the verifier `tools/aien-verify` in aien-sovereign-core. The verifier, not the executor, computes the verdict identity (aien-architecture#190, lane L4).

## Draft digest transcript revision for the next minor release

The Rust reference uses distinct, versioned SHA-256 transcript domains for
`EvaluationPlan`, `EvaluatorOutcome`, and `EvaluationReceipt`. These digests
are not a JSON or transport encoding. In this revision, `str` means the
string's UTF-8 bytes preceded by its **byte** length as unsigned u64
little-endian; `count` is an unsigned u64 little-endian element count; UUID
means 16 raw bytes; `digest` means exactly 32 bytes. Integers and IEEE-754
`f64` bits are little-endian. Options use one byte: `0` for absent and `1`
before a present value. Lists include their count even when empty. No padding
or string normalization occurs.

- Plan: ASCII `AIEN_EVALUATION_PLAN_V2` and a zero byte, evaluation UUID,
  subject artifact UUID, subject digest, profile str, evaluator count,
  evaluators sorted by `(evaluator_id, version, required)` (each as ID str,
  version str, required byte `0`/`1`), baseline option (artifact UUID and
  digest if present), sandbox profile str, policy digest, manifest digest.
- Outcome: ASCII `AIEN_EVALUATOR_OUTCOME_V2` and a zero byte, evaluator ID
  str, version str, binary digest, config digest, status byte (`0` Passed,
  `1` Failed, `2` Inconclusive, `3` TimedOut), finding count, each finding's
  severity str, rule ID str, message str and location option str; measurement
  count, each metric str, value's `f64::to_bits()` as u64 and unit str;
  evidence count, then each artifact UUID and digest.
- Receipt: ASCII `AIEN_EVALUATION_RECEIPT_V3` and a zero byte, u32
  `protocol_version`, evaluation UUID, request, subject, plan, evidence-root
  and outcomes-root digests, verdict byte (`0` Pass, `1` Fail, `2`
  Indeterminate), verifier principal ID str, key ID str, trust epoch u64,
  trusted-build digest, policy-bundle digest, start timestamp u64, completion
  timestamp u64. Timestamps retain the existing `Timestamp` microsecond unit.
  The only supported signed receipt `protocol_version` is `3`.

No verifier retries the old unframed digest. Plan and outcome digest values
also change without a change to their containing Rust struct's serialized
shape. Existing digest-keyed storage and references require an explicit
consumer migration, including re-evaluation where old digests cannot be
trusted. The AEI1 signed outer receipt includes this base receipt digest and
therefore requires `protocol_version` 3 as well. Drake approved this breaking
cutover on 2026-10-26; coordinated consumer adoption is recorded in
`CONSUMERS.md`. Approval and source adoption do not imply deployment.
