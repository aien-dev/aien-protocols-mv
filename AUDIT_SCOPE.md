# Audit scope

Written for an outside, independent security audit. Revision described:
`f3785177fcaaab7c0f2ce1126616e9fecb4e47b4` on `main`, 2026-10-26. Everything below is taken from
the repository's own files at that revision; items marked NOT_RUN were not executed while writing
this document.

## What this repository is

The written contracts the parts of AIEN agree on: byte formats and rules for agent state,
inference, evaluation, evidence receipts, crumbs, execution transcripts, compiled Omega units, the
Omega shell platform boundary, and task messages between a Raspberry Pi and the DGX Spark. Each
contract is a specification in `specs/`, often with test vectors and a small C checker. Ten
reference Rust crates live in `crates/`. Implementations live with their owners, not here.
Status (README, 2026-10-19): research grade, pre-alpha. `osc-unit-artifact` v1 is FROZEN,
`crumb-visible` is Stable, the rest are drafts. No protocol is claimed as qualified on hardware.

## What to review, in priority order

1. `specs/osc-unit-artifact/`: the signed container for a compiled Omega unit (frozen; consumers
   carry copies of its vectors). Signature coverage, canonical encoding, the committed public keys
   `keys/owner1.pub` and `keys/test1.pub`, `tools/check-vectors.sh`.
2. `crates/aien-provenance`: digests, Merkle trees, signature checks.
3. `crates/aien-action-protocol`: actions, capability grants, confinement authorization;
   `SourceGrant::compute_unsigned_digest` (the V2 transcript described in the README, a breaking
   change approved 2026-10-26).
4. `specs/verified-crumb/` (VC1) and `specs/evidence-receipt/`, `specs/evidence/` (AEI1),
   `crates/aien-evaluation-protocol`.
5. `specs/execution-transcript/` (TRN1) C verifier; `specs/pi-spark-task/` (PST1) C checker and
   `crates/aien-pi-spark-task` reader and writer.
6. `specs/osh-platform/`, `specs/crumb-visible/`, remaining crates.
7. `tests/gates/run.sh` (steps `crumb-verify`, `fmt`, `check`, `clippy`, `test`,
   `zero-disk-secrets`, `anti-slop`, `c-vectors`), `.aien/always`, `.aien/unmapped-ok`,
   `.aien/verify.pub`.
8. Workflows: `aien-verification.yml` (pull request and push, `contents: read`, advisory; checks
   the Spark's signed result) and `sbom.yml` (SPDX inventory artifact, `contents: read`, actions
   pinned by commit sha, gates nothing).

AGENTS.md: a change to `.aien/`, `tests/gates/` or `.github/workflows/` is `BLOCKED_OPERATOR` and
runs only when the operator starts it by hand.

## Trust boundaries

- Untrusted: every byte stream a conforming reader parses (artifacts, transcripts, PST1 headers,
  crumb records); pull request heads.
- Trusted: signing keys named by each specification; `.aien/verify.pub` on `main`.
- The DGX Spark is the only test judge and runs `tests/gates/run.sh`; GitHub checks are advisory
  and build nothing from this repository (AGENTS.md, `docs/PIPELINE.md`).
- Rule of direction: protocols point inward to nothing; implementations point downward.

## Threat model summary

- Assets: the meaning of each wire format; signature and digest bindings; vectors that consumers
  copy.
- Attackers considered: a producer of crafted input aiming for a reader to accept it or to parse it
  differently from another reader; a pull request that edits vectors to make a checker pass.
- Defended: vectors with fixed verdicts and C checkers that must pass in the same pull request as
  any text change; frozen status for osc-unit-artifact v1; zero-disk-secrets gate.
- Not defended: draft specifications may change; several have no checker in this repository
  ("nothing yet" in the README table); TRN1 and PST1 are not yet produced by any runtime.
- Explicitly out of scope: owner implementations in other repositories.

## Build from source at a pin

Stable Rust (no `rust-toolchain.toml`); bash, coreutils and a C99 compiler for the checkers.
`Cargo.lock` is committed.

```sh
git clone https://github.com/aien-dev/aien-protocols-mv.git
cd aien-protocols-mv
git checkout f3785177fcaaab7c0f2ce1126616e9fecb4e47b4
cargo check --workspace --all-targets
```

## Run every test

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash specs/verified-crumb/tools/check-golden.sh
bash specs/osc-unit-artifact/tools/check-vectors.sh
bash specs/execution-transcript/tools/check-corpus.sh
bash specs/pi-spark-task/tools/check-vectors.sh
bash specs/osh-platform/tools/check-stream-vectors.sh
tests/gates/run.sh c-vectors
tests/gates/run.sh zero-disk-secrets
tests/gates/run.sh anti-slop
tests/gates/run.sh crumb-verify
```

- `.aien/always`: `CRUMB-VERIFY`, `PROTO-ZERO-DISK-SECRETS`, `PROTO-ANTI-SLOP`.
- `crumb-verify` uses `crumb` on `PATH` or the one named by `CRUMB`.
- README: on 2026-10-19 all of these passed on the Spark on `main` at `fb5fca9`, and
  `crumb verify .` printed `OK: 41 crumbs current`.
- All commands above: NOT_RUN while writing this document.

## Known limitations and NOT_RUN

- `evidence-receipt` is a partial extraction; the full extraction is owed.
- `agent-state` and `inference` have no checker here.
- The SourceGrant V2 digest requires reissuing every previously signed grant.
- `aien-verification.yml` sets `REPO_SLUG: aien-dev/aien-protocols` while this repository is
  `aien-dev/aien-protocols-mv`; whether GitHub redirects this is unknown from the repository.
- No fuzzing campaign is recorded in the repository.

## Dependencies and provenance

- Crates.io dependencies locked in `Cargo.lock` (197 packages). The C checkers use only a C99
  compiler and coreutils; no outside dependencies in the trusted base (AGENTS.md).
- Licences: specifications under the Community Specification License 1.0 (`LICENSE-SPEC`), code
  under Apache-2.0 (`LICENSE-CODE`, `LICENSE`); see also `NOTICES.md`, `ANTI_ENCLOSURE.md`.
- SPDX SBOM produced as a workflow artifact by `sbom.yml` per commit.

## Evidence

- There is no `evidence/` directory; test vectors live under `specs/*/vectors/`.
- Signed Spark bundles: `aien-dev/aien-receipts` at `aien-protocols/<sha>/bundle.json` (workflow
  path). Receipts are append-only and never edited.
