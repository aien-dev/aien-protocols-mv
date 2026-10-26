# aien-protocols

This repository holds the written contracts that the parts of AIEN agree on: the byte formats and rules for agent state, inference requests, evaluation, evidence receipts, crumbs, execution transcripts, compiled Omega units, the Omega shell boundary and the task messages between a Raspberry Pi and the DGX Spark. Each contract is a specification in `specs/`, often with test vectors (fixed input files with the verdict a reader must give) and a small C checker that proves the vectors match the text. Next to the specifications sit reference Rust crates in `crates/`. The repository holds contracts only, never private implementations.

Part of [AienOS](https://github.com/aien-dev/aienix), the core tree of AIEN. Start there for how the pieces fit together.

**Status 2026-10-19: research-grade, pre-alpha.** One specification is frozen (osc-unit-artifact v1, 2026-10-08), one is marked stable (crumb-visible), the rest are drafts. No protocol here is claimed as qualified on hardware. The status of the whole system is owned by [aien-architecture-mv](https://github.com/aien-dev/aien-architecture-mv), in [CURRENT_EXECUTION_PLAN.md](https://github.com/aien-dev/aien-architecture-mv/blob/main/CURRENT_EXECUTION_PLAN.md).

## Specifications

The status column quotes the `Status` line at the top of each specification on `main`.

| Specification | What it defines | Status | Checked in this repo by |
|---|---|---|---|
| [agent-state](specs/agent-state/SPEC.md) | Portable agent state snapshot | Draft | nothing yet |
| [inference](specs/inference/SPEC.md) | Inference requests and responses | Draft | nothing yet |
| [evaluation](specs/evaluation/SPEC.md) | Evaluator interface and verdict identity domains | Draft | Rust tests in `aien-evaluation-protocol` |
| [evidence](specs/evidence/ADAPTIVE_EVIDENCE_INTERFACE.md) | Adaptive Evidence Interface (AEI1) requirements | Draft for freeze, 2026-10-11 | Rust tests in `aien-evaluation-protocol` (the AEI1 receipt) |
| [evidence-receipt](specs/evidence-receipt/SUBSET.md) | The parts of the evidence receipt that VC1 binds to | Partial extraction, 2026-10-02; full extraction is owed | nothing yet |
| [verified-crumb](specs/verified-crumb/SPEC.md) | Verified Crumb V1 (VC1) byte encoding and resolve rule | Draft v0, 2026-10-02 | `tools/check-golden.sh` (C checker, 17 golden vectors) |
| [crumb-visible](specs/crumb-visible/CRUMB_READER_CONTRACT.md) | Reader contract for the CRB1 visible crumb record | Stable | vector generator only (`tools/make-vectors.sh`) |
| [execution-transcript](specs/execution-transcript/TRN1_TRANSCRIPT_SPEC.md) | TRN1 execution transcript, contract 0.2.0 | Draft v0, 2026-10-01; not yet produced by any runtime | `tools/check-corpus.sh` (C verifier, see [tools/README.md](specs/execution-transcript/tools/README.md)) |
| [osc-unit-artifact](specs/osc-unit-artifact/OSC_UNIT_ARTIFACT.md) | Signed container for a compiled Omega unit | v1 FROZEN, 2026-10-08 | `tools/check-vectors.sh` (see [vectors/README.md](specs/osc-unit-artifact/vectors/README.md)) |
| [osh-platform](specs/osh-platform/OSH_PLATFORM_ABI.md) | Boundary between the Omega shell core and its platform | v1 DRAFT, not frozen | vector generator only (see [vectors/README.md](specs/osh-platform/vectors/README.md)) |
| [pi-spark-task](specs/pi-spark-task/SPEC.md) | PST1, the task message between a Pi and the Spark | Draft v0.1, 2026-10-16; not yet produced or read by any runtime | `tools/check-vectors.sh` (C checker, 23 header vectors) and the Rust crate `aien-pi-spark-task` |

The vector counts come from [CHANGELOG.md](CHANGELOG.md). Where a contract has an implementation, it lives with its owner, not here. On 2026-10-19 the `main` branches showed these: omega keeps pinned copies of the VC1 golden vectors and the CRB1 vectors (`tests/vcstore/golden/PIN`, `tests/crumbline/crb1/PIN`) and runs the 20 OSH vectors in `tests/osh/`; aienos has an OSC unit admission check in C (`native/kernel/artifact/osc_unit.c`) with a copy of the osc-unit-artifact vectors. This repository does not run those tests.

## Reference crates

All ten crates are Apache-2.0 (from `cargo metadata`). They follow aien-architecture [ADR 0024](https://github.com/aien-dev/aien-architecture-mv/blob/main/docs/adr/0024-rust-scaffolding-omega-destination.md): Rust is scaffolding and Omega is the destination, so the specifications are the lasting part.

The purpose column is shortened from the `description` field in each crate's `Cargo.toml`.

| Crate | Purpose |
|---|---|
| `aien-protocol-types` | Identifiers, primitives and digests shared by the other crates |
| `aien-agent-state-abi` | Agent state snapshot, transition events and lineage checks |
| `aien-inference-protocol` | Inference contract, including leased KV cache pinning and copy-on-write context branches |
| `aien-inference-client` | Client for the inference protocol |
| `aien-action-protocol` | Actions, capability grants and confinement authorization |
| `aien-event-protocol` | Event envelopes and streaming telemetry |
| `aien-evaluation-protocol` | Evaluator interface, verifier attestations, evaluation receipts and the AEI1 receipt |
| `aien-provenance` | Digests, Merkle trees and signature checks |
| `aien-probe` | Probe evaluation engine (see [its README](crates/aien-probe/README.md)) |
| `aien-pi-spark-task` | Reader and writer for the PST1 header; its test reads every PST1 vector |

Who uses which crate is recorded in [CONSUMERS.md](CONSUMERS.md).

### Source grant signature transcript (draft for next minor release)

`SourceGrant::compute_unsigned_digest` hashes the following bytes in order with
SHA-256: ASCII `AIEN_SOURCE_GRANT_V2` plus a zero byte; 16 raw grant UUID bytes;
the UTF-8 `source_uri` with its byte length as u64 little-endian; the UTF-8
`license_spdx` with the same length prefix; permission bits as u32
little-endian; the UTF-8 `issuer` with the same length prefix; one byte `0`
for no expiration, or `1` followed by `expires_at_epoch_sec` as u64
little-endian. There is no normalization or padding. The P-256 signature
continues to cover the 32-byte SHA-256 result, not the JSON representation.
Legacy concatenated-field signatures are never tried by the verifier.
Adopting this proposed digest requires explicit consumer approval and
reissuing every previously signed grant; see `CHANGELOG.md`.

## Layout

```text
specs/         Specifications (Community Specification License 1.0), one directory each,
               with tools/ (generators and C checkers) and vectors/ where they exist
crates/        Reference Rust crates (Apache-2.0)
tests/gates/   Gate manifests and run.sh, the entry point the Spark judge runs
.aien/         Spark judge settings: always-run gates and the bundle public key
docs/          PIPELINE.md, how a pull request is tested and merged
```

Governance and policy files: [GOVERNANCE.md](GOVERNANCE.md), [SCOPE.md](SCOPE.md), [VERSIONING.md](VERSIONING.md), [CHANGELOG.md](CHANGELOG.md), [CONSUMERS.md](CONSUMERS.md), [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md), [NOTICES.md](NOTICES.md), [TRADEMARKS.md](TRADEMARKS.md).

## Rule of direction

Protocols point inward to nothing. Implementations point downward to protocols. They never point sideways at each other: any deployment needing two implementations in one process is composed from above.

## How this fits with the other repositories

- [omega-mv](https://github.com/aien-dev/omega-mv) and [aienos-mv](https://github.com/aien-dev/aienux) implement some of the contracts in C (see Specifications above).
- [aien-sovereign-core-mv](https://github.com/aien-dev/aien-sovereign-core-mv), the Rust host runtime, uses some of the reference crates ([CONSUMERS.md](CONSUMERS.md)). It also holds the Spark test judge (`tools/aien-test`).
- [aien-architecture-mv](https://github.com/aien-dev/aien-architecture-mv) owns the plan, the ADRs and the status of the whole system.
- [aien-receipts](https://github.com/aien-dev/aien-receipts) stores the signed test results for this repository.

## Standing rules

Language rule: Rust is scaffolding, Omega is the destination, and C or assembly stay only where hardware, boot, ABI or measurement justifies them (ADR 0024, which supersedes the old "C is the target, no new Rust" rule). No Python, no CUDA toolkit, no systemd, no outside dependencies in the trusted base.

## Build and test

The reference crates need a Rust toolchain. These are the commands the gates run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The spec checkers need only bash, coreutils and a C99 compiler:

```bash
bash specs/verified-crumb/tools/check-golden.sh
bash specs/osc-unit-artifact/tools/check-vectors.sh
bash specs/execution-transcript/tools/check-corpus.sh
bash specs/pi-spark-task/tools/check-vectors.sh
```

`tests/gates/run.sh <step>` runs one gate step by name. The steps are `crumb-verify`, `fmt`, `check`, `clippy`, `test`, `zero-disk-secrets`, `anti-slop` and `c-vectors`. The `c-vectors` step runs every `specs/*/tools/check-*.sh` (the four above) and passes only when all of them pass. The `anti-slop` step fails on any em dash or en dash in `crates/`, `docs/`, `README.md` and `ANTI_ENCLOSURE.md`.

On 2026-10-19 all of the commands above passed on the Spark on `main` at `fb5fca9`, and `crumb verify .` printed `OK: 41 crumbs current`.

## Testing and evidence

The DGX Spark is the only test judge for pull requests (aien-architecture [ADR 0033](https://github.com/aien-dev/aien-architecture-mv/blob/main/docs/adr/0033-aien-verification-pipeline.md); the Spark judge started on 2026-10-16, PR #25). On 2026-10-18 the hosted test workflow `ci.yml` was deleted (PR #42). The one workflow left, `.github/workflows/aien-verification.yml`, does not build or test the code: it checks the result the Spark signed. On 2026-10-19 [docs/PIPELINE.md](docs/PIPELINE.md) was updated to match (PR #45), and the `.crumb` files stopped storing generated data; the crumb tool computes it on demand (PR #44).

- The Spark runs the gates in `tests/gates/` that a change touches, plus the gates listed in `.aien/always` (`CRUMB-VERIFY`, `PROTO-ZERO-DISK-SECRETS`, `PROTO-ANTI-SLOP`), and posts the commit status "AIEN Verification (Spark)".
- The signed results are published in [aien-receipts/aien-protocols](https://github.com/aien-dev/aien-receipts/tree/main/aien-protocols), one directory per commit.
- [docs/PIPELINE.md](docs/PIPELINE.md) explains the flow and the merge rules.

## Open work

These issues and pull requests were open on 2026-10-19:

- Issue #27 tracks the whole Pi and Spark protocol lane. Its next parts are session rules (issue #32, pull request #38) and tool-call tasks (issue #33, pull request #41).
- Issue #43: freeze the OSH stream and task ABI vectors.

## Contributing

Open a pull request against `main` with the commands you ran and their output. Specification changes follow [GOVERNANCE.md](GOVERNANCE.md) and [VERSIONING.md](VERSIONING.md). A pull request merges only after the Spark judge passes it and a maintainer adds the `ready-to-merge` label. Contact: aien@aienos.com.

## Licensing

Specifications: [Community Specification License 1.0](LICENSE-SPEC). Code and crates: [Apache License 2.0](LICENSE-CODE) (Apache-2.0). Anti-enclosure commitments: [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md).
