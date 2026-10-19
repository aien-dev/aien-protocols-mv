---
name: protocols-basics
description: How to build, test and gate aien-protocols (specifications in specs/ with C checkers and vectors, reference Rust crates in crates/), the rules that must not move, where receipts live, and the paths agents must not touch. Read before editing anything in this repository.
---

# aien-protocols basics

This repository holds the written contracts the parts of AIEN agree on: each contract is a specification in `specs/<name>/`, often with test vectors and a small C checker, next to reference Rust crates in `crates/`. It holds contracts only, never private implementations. Status: research-grade, pre-alpha; the README table quotes each specification's own `Status` line. Status for the whole system belongs to aien-architecture.

## Build and test

The reference crates need a Rust toolchain. These are the commands the gates run (README.md, "Build and test"):

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

## Gates

`tests/gates/run.sh <step>` runs one gate step by name: `crumb-verify`, `fmt`, `check`, `clippy`, `test`, `zero-disk-secrets`, `anti-slop`, `c-vectors`.

- `c-vectors` runs every `specs/*/tools/check-*.sh` and passes only when all of them pass.
- `anti-slop` fails on any em dash or en dash in `crates/`, `docs/`, `README.md` and `ANTI_ENCLOSURE.md`.
- Always run on every commit (`.aien/always`): `CRUMB-VERIFY`, `PROTO-ZERO-DISK-SECRETS`, `PROTO-ANTI-SLOP`.
- The DGX Spark is the only test judge for pull requests (aien-architecture ADR 0033). The one hosted workflow, `.github/workflows/aien-verification.yml`, does not build or test the code; it checks the result the Spark signed. `docs/PIPELINE.md` explains the flow and the merge rules.

## Rules that must not move

- Rule of direction: protocols point inward to nothing; implementations point downward to protocols, never sideways at each other.
- Contracts only. Implementations live with their owner (omega, aienos, aien-sovereign-core), not here.
- osc-unit-artifact v1 is FROZEN (2026-10-08). Do not change its text or vectors; a change is a new version.
- Spec changes follow `GOVERNANCE.md` and `VERSIONING.md`: while major is zero a breaking change needs a minor bump and migration notes in `CHANGELOG.md`; deprecated items stay marked for at least one minor release before removal.
- A change to a specification's vectors or its C checker must leave `tests/gates/run.sh c-vectors` passing.
- Licences stay split: specifications under the Community Specification License 1.0 (`LICENSE-SPEC`), code and crates under AGPL-3.0-or-later (`LICENSE-CODE`).
- Language rule (aien-architecture ADR 0024): Rust is scaffolding, Omega is the destination, C or assembly only where hardware, boot, ABI or measurement justifies it. No Python, no CUDA toolkit, no systemd, no outside dependencies in the trusted base.
- Who uses which crate is recorded in `CONSUMERS.md`; keep it current when a consumer changes.

## Receipts and evidence

Signed Spark judge results are published in `aien-dev/aien-receipts`, directory `aien-protocols/`, one directory per commit. The vector counts quoted in the README come from `CHANGELOG.md`.

## Do not touch

Agents must not edit `.crumb` files, `crumb.lock`, `.aien/`, `tests/gates/`, `.github/workflows/`, `.forgejo/` or `tools/aien-test/`, and must not run `crumb compile`. Those are pipeline paths; a person changes them on purpose. The hook `tools/agent-hooks/protected-paths.sh` enforces this.

## Pull requests

Open against `main` with the commands you ran and their output. A pull request merges only after the Spark judge passes it and a maintainer adds the `ready-to-merge` label. No em dashes or en dashes anywhere.
