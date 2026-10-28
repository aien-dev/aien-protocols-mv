# aien-protocols (the written contracts between the parts of AIEN)

> Specifications for the byte formats and rules the parts of AienOS (the whole AIEN system) agree on: agent state, inference, evaluation, evidence receipts, crumbs, execution transcripts, compiled Omega units, the Omega shell platform boundary and the task messages between a Raspberry Pi and the DGX Spark. Each contract is a specification in `specs/`, often with test vectors and a small C checker that proves the vectors match the text. Reference Rust crates live in `crates/`. The repository holds contracts only, never private implementations.

Shared rules: read https://www.aienos.com/agents/RULES.md first. This file adds what is specific to this repository; where the two differ, this file wins here.

## Scope

- Applies to the whole repository.
- `specs/<name>/`: one directory per specification (Community Specification License 1.0), with `tools/` (generators and C checkers) and `vectors/` where they exist. The `Status` line at the top of each specification says whether it is Draft, Stable or FROZEN.
- `crates/`: ten reference Rust crates (Apache-2.0) in one Cargo workspace. Rust is scaffolding and Omega is the destination (aien-architecture ADR 0024), so the specifications are the lasting part.
- Implementations of a contract live with their owner, not here: the Omega language repository (omega-mv) and the Aienux kernel (https://github.com/aien-dev/aienux) implement some contracts in C; aien-sovereign-core-mv uses some crates (`CONSUMERS.md`).
- Rule of direction: protocols point inward to nothing, implementations point downward to protocols, and implementations never point sideways at each other.

## Installation

```bash
git clone https://github.com/aien-dev/aien-protocols-mv.git
cd aien-protocols-mv
cargo check --workspace --all-targets
```

The crates need a stable Rust toolchain (there is no `rust-toolchain.toml`). The spec checkers need only bash, coreutils and a C99 compiler (`cc`). No Python, no CUDA toolkit and no outside dependencies in the trusted base.

## Configuration

- There is no runtime configuration. The crates are libraries and the checkers take no settings.
- `tests/gates/*.gate` and `tests/gates/run.sh` define the Spark gates. `.aien/always` lists the gates that run on every change (`CRUMB-VERIFY`, `PROTO-ZERO-DISK-SECRETS`, `PROTO-ANTI-SLOP`); `.aien/unmapped-ok` lists the paths that need only those.
- `tests/gates/run.sh crumb-verify` uses the `crumb` binary on `PATH`, or the one named by `CRUMB`. CI builds it from aien-architecture at the commit pinned in `.github/workflows/aien-verification.yml`.

## Usage

```bash
# The Rust gates
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# The spec checkers (each builds its C checker with cc and runs the vectors)
bash specs/verified-crumb/tools/check-golden.sh
bash specs/osc-unit-artifact/tools/check-vectors.sh
bash specs/execution-transcript/tools/check-corpus.sh
bash specs/pi-spark-task/tools/check-vectors.sh
bash specs/osh-platform/tools/check-stream-vectors.sh
```

Every gate is also one step of `tests/gates/run.sh <step>`: `crumb-verify`, `fmt`, `check`, `clippy`, `test`, `zero-disk-secrets`, `anti-slop` and `c-vectors`. `c-vectors` runs every `specs/*/tools/check-*.sh` and passes only when all of them pass, so a new checker named `check-*.sh` is picked up automatically. `anti-slop` fails on any em dash or en dash in `crates/`, `docs/`, `README.md` and `ANTI_ENCLOSURE.md`.

The `make-*.sh` scripts in `specs/*/tools/` regenerate vectors. Run one only when the specification itself changes, and commit the regenerated vectors together with the text.

## Conventions

- Specification changes follow `GOVERNANCE.md` and `VERSIONING.md`. Specifications and crates are versioned together with `vX.Y.Z` tags; while the major version is zero a breaking change needs a minor bump and migration notes in `CHANGELOG.md`.
- A FROZEN specification (osc-unit-artifact v1) does not change without explicit approval; consumers carry copies of its vectors.
- A specification and its vectors change in the same pull request, and the checker must pass on them. Do not edit a vector by hand to make a checker pass.
- Deprecate before removing: mark the item and name its replacement for at least one minor release, then list the removal in `CHANGELOG.md`.
- A consumer that adopts a new tag records it in `CONSUMERS.md` in the same change.
- No em dashes or en dashes in prose; the `PROTO-ANTI-SLOP` gate enforces it for the paths above.
- Keep `.crumb` files exactly what the pinned crumb compiler produces; `crumb verify .` must pass.

## Safety and approvals

- The DGX Spark is the only test judge (`docs/PIPELINE.md`); GitHub checks on pull requests are advisory and build nothing from this repository.
- A change to `.aien/`, `tests/gates/` or `.github/workflows/` is `BLOCKED_OPERATOR`: it runs only when the operator starts it by hand. Ask before touching those paths, and never relax a gate or a checker to make a change pass.
- Ask before changing the `Status` of a specification, freezing one, or changing a wire format that a consumer in `CONSUMERS.md` depends on.
- No plaintext secrets: `.env*` files fail `PROTO-ZERO-DISK-SECRETS`. Never commit keys or tokens.
- Contributions are licensed under the Community Specification License 1.0 (specifications) and Apache-2.0 (code) under the Developer Certificate of Origin. Keep `ANTI_ENCLOSURE.md` commitments intact.
- Open a pull request against `main` with the commands you ran and their output. Nothing on GitHub gates a merge and `main` requires no status check (`.github/workflows/aien-verification.yml`); the local Spark pipeline merges a pull request only after a maintainer adds the `ready-to-merge` label and its gates pass on the current head (see `docs/PIPELINE.md`).

## Further reading

- `README.md`: the specification table, the crate table and the build steps.
- `GOVERNANCE.md`, `SCOPE.md`, `VERSIONING.md`, `CHANGELOG.md`, `CONSUMERS.md`: process, scope, versioning, history and consumers.
- `ANTI_ENCLOSURE.md`, `NOTICES.md`, `TRADEMARKS.md`: licensing commitments and notices.
- `docs/PIPELINE.md`: how the Spark gates test and merge a pull request.
- https://github.com/aien-dev/aien-architecture-mv: the plan, the ADRs and the status of the whole system.
