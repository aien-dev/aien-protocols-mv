# aien-protocols

Versioned specifications and reference crates for AIEN: what portable agent state, inference requests, actions, evaluation and provenance receipts mean. It holds contracts, never private implementations.

Part of [Aienix](https://github.com/aien-dev/aienix), the core tree of AIEN. Start there for how the pieces fit together.

**Status 2026-10-18: research-grade, pre-alpha.** Some specifications are frozen and checked against our own C implementations; others are drafts. No protocol here is claimed as qualified on hardware.

## Current state

Research-grade and pre-alpha. The specifications and reference Rust crates (AGPL-3.0-or-later) in this repository follow the language rule of aien-architecture ADR 0024: Rust is scaffolding and Omega is the destination. The reference crates are that scaffolding (they still receive changes, for example the AEI1 receipt in `aien-evaluation-protocol`), and the specifications are the durable part. Some contracts already have C implementations with their owners (omega, aienos), checked against the vectors in `specs/`: verified-crumb, crumb-visible and osc-unit-artifact. Status of the whole system is owned by [aien-architecture](https://github.com/aien-dev/aien-architecture): [CURRENT_EXECUTION_PLAN.md](https://github.com/aien-dev/aien-architecture/blob/main/CURRENT_EXECUTION_PLAN.md). No protocol here is claimed as qualified on hardware.

## Layout

```text
specs/       Normative specifications (Community Specification License 1.0):
             agent-state, inference, evaluation, crumb-visible, execution-transcript,
             evidence (AEI1, draft), evidence-receipt (partial), verified-crumb,
             osc-unit-artifact (v1 frozen), osh-platform (draft)
crates/      Reference Rust crates (AGPL-3.0-or-later), scaffolding:
             aien-protocol-types, aien-agent-state-abi, aien-inference-protocol,
             aien-inference-client, aien-action-protocol, aien-event-protocol,
             aien-evaluation-protocol, aien-provenance, aien-probe
```

Governance and policy files: [GOVERNANCE.md](GOVERNANCE.md), [SCOPE.md](SCOPE.md), [VERSIONING.md](VERSIONING.md), [CHANGELOG.md](CHANGELOG.md), [CONSUMERS.md](CONSUMERS.md), [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md), [NOTICES.md](NOTICES.md), [TRADEMARKS.md](TRADEMARKS.md).

## Rule of direction

Protocols point inward to nothing. Implementations point downward to protocols. They never point sideways at each other: any deployment needing two implementations in one process is composed from above.

## How this fits with the other repositories

[omega](https://github.com/aien-dev/omega) and [aienos](https://github.com/aien-dev/aienos) implement some of the contracts in C (see Current state); [aien-sovereign-core](https://github.com/aien-dev/aien-sovereign-core), the Rust host runtime, uses some of the reference crates ([CONSUMERS.md](CONSUMERS.md)); [aien-architecture](https://github.com/aien-dev/aien-architecture) owns status.

## Standing rules

Language rule: Rust is scaffolding, Omega is the destination, and C or assembly stay only where hardware, boot, ABI or measurement justifies them (aien-architecture ADR 0024, which supersedes the old "C is the target, no new Rust" rule). No Python, no CUDA toolkit, no systemd, no outside dependencies in the trusted base.

## Build and test

The reference crates need a Rust toolchain:

```bash
cargo check --workspace --all-targets
cargo test --workspace
```

The C-checked specs ship conformance vectors with shell checkers that need only a C compiler and standard tools: `specs/verified-crumb/tools/check-golden.sh`, `specs/osc-unit-artifact/tools/check-vectors.sh` and `specs/execution-transcript/tools/check-corpus.sh`. `tests/gates/run.sh <step>` is the entry point for the local gates (steps: `crumb-verify`, `fmt`, `check`, `clippy`, `test`, `zero-disk-secrets`, `anti-slop`).

Since 2026-10-16 the DGX Spark is the only test judge for pull requests (aien-architecture ADR 0033). It runs the manifests in `tests/gates/` and signs the result; [docs/PIPELINE.md](docs/PIPELINE.md) explains the flow. The verdict of record is the commit status "AIEN Verification (Spark)".

## Contributing

Open a pull request against `main` with the commands you ran and their output. Specification changes follow [GOVERNANCE.md](GOVERNANCE.md) and [VERSIONING.md](VERSIONING.md). A pull request merges only after the Spark judge passes it and a maintainer adds the `ready-to-merge` label. Contact: aien@aienos.com.

## Licensing

Specifications: [Community Specification License 1.0](LICENSE-SPEC). Code and crates: [GNU Affero General Public License v3.0 or later](LICENSE-CODE) (AGPL-3.0-or-later). Anti-enclosure commitments: [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md).
