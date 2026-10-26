# Security policy

## Reporting a vulnerability

Report privately. Do not open a public issue, pull request or discussion about it.

1. GitHub: open this repository's Security tab and choose "Report a vulnerability". This
   creates a private advisory that only the maintainers can see. If that option is not shown,
   private vulnerability reporting has not been enabled for this repository yet; use email.
2. Email: drake@aienos.com with the subject `[aien-protocols-mv] security report`.

Include the commit or release you tested, the component (path), steps to reproduce, and what an
attacker gains. If the report involves a secret, say where it was exposed and do not send the
secret itself. Encrypted mail is not required; do not post proof-of-concept payloads publicly.

## Response targets

This project has one maintainer; the targets below are best effort and stated honestly.

- Acknowledgement: within 3 working days.
- Triage and severity: within 7 days of acknowledgement.
- Fix or mitigation for confirmed issues: aim for 30 days for high and critical, 90 days
  otherwise, with a status update at least every 14 days until closed.
- Disclosure: coordinated. An advisory is published with credit (unless you ask otherwise)
  once the fix is on the default branch. Default embargo 90 days, negotiable.

## Scope

In scope:

- Specification flaws that let a conforming reader accept a forged or ambiguous input: signed
  OSC unit artifacts, VC1 encoding and resolve, TRN1 transcripts, PST1 headers, CRB1 records.
- The C checkers and generators in `specs/*/tools/` and the vectors they check.
- The reference crates in `crates/`, especially `aien-provenance` (digests, Merkle trees,
  signature checks), `aien-action-protocol` (capability grants, confinement authorization) and
  the `SourceGrant` digest and P-256 signature.
- `tests/gates/run.sh`, `.aien/`, `.github/workflows/`.

Out of scope: implementations that live with their owners (omega-mv, aienux,
aien-sovereign-core-mv); report those to the owning repository. The Spark test judge itself
(`aien-test`, in aien-sovereign-core-mv).

## Supported versions

Only the default branch `main`. The README names no release; `CHANGELOG.md` records a `v0.1.0`
tag (2026-09-23) that is not maintained separately. Fixes land on the default branch only.

## Status

Research grade, pre-alpha. One specification is frozen, one is stable, the rest are drafts. There
is no certification and no bug bounty. See AUDIT_SCOPE.md for what to review and how to build and
test it.
