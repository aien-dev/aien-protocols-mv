# Aienet-0: Verifiable Agent Compute Exchange (draft interoperability profile)

Status: DRAFT v0.1, 2026-10-27. Design and conformance target only. NETWORK_NOT_RUN.
License: Community Specification License 1.0, subject to repository licensing.
Tracking: [architecture #311](https://github.com/aien-dev/aien-architecture-mv/issues/311), [typed microjob #50](https://github.com/aien-dev/aien-protocols-mv/issues/50), [Core escrow #738](https://github.com/aien-dev/aien-sovereign-core-mv/issues/738), [Open Humanity #32](https://github.com/aien-dev/open-humanity/issues/32).

## The proposition

Independent, explicitly enrolled agents offer bounded computation, accept a typed job, return independently checkable evidence, and receive a transferred, pre-funded **TUR test-credit** payment. The goal is an interoperable verifiable-compute layer, not another general messaging standard, wallet, blockchain, or unconstrained execution environment.

The existing A2A agent interoperability standard and x402 HTTP payment standard are possible **edge adapters**. They are not dependencies of this v0. They do not automatically make our scientific Turing measurement fungible with money. Reference protocols: https://a2a-protocol.org/ and https://www.x402.org/.

## Existing owners: no duplicate implementation

| Function | Authority | Initial v0 source |
| --- | --- | --- |
| Work, capability and result schema | aien-protocols | MJB1/MJR1, draft PR #53, `specs/microjob/SPEC.md` |
| Cryptographic identity, private transport, consent | Open Humanity | `crates/oh-core/src/transport.rs`, `oh-core` signed receipts |
| Scientific gain and evaluation | Omega / independent evaluator / Open Humanity | Frozen Turing measurement profile, explicitly named baseline and heldout split |
| Spendable TUR balances, escrow and refund | Sovereign Core | Existing service-credit authority, extension tracked by Core #734/#738 |
| Pure computation and verification | Omega | Seeded handwritten `.om` and qualified CPU/GB10 backend |
| Physical resource admission | FORGE / device owner | Explicit bounded lease, no inference-server or GPU bypass |

A valid MJB1 is a proposal, **not an authorization**. Network peers cannot expand its capability or privacy scope. A result does not authorize itself. No new wire grammar becomes authoritative until the existing protocol owner accepts it.

## First four peers

The four roles can initially run as isolated local identities on one host:
1. Spark AIEN requester: requests one typed, pure computation.
2. Pi-class CPU provider: offers a bounded deterministic arithmetic or compiler-check operation.
3. iMac-class verifier: independently recomputes or checks the result.
4. Volunteer observer/alternate provider: operates under a separate explicit identity.

Those labels are role names, not declarations of active physical peers. Each peer has an owner-approved public key, permitted compute offer, expiry, endpoint and disable flag in a **signed, static manifest**. Never auto-enroll, discover via scanning, propagate code, collect credentials, or run arbitrary remote shell commands. Owner withdrawal stops new jobs, then drains already-admitted work within the agreed bound.

## Minimum exchange (logical operations, NOT a new binary wire encoding)

`OFFER` binds an owner's signed key, capability, permitted job classes, resource limits and expiry.

`REQUEST` binds the canonical MJB1 document digest, logical job ID, idempotency key, requester identity and privacy scope.

`QUOTE` binds that job ID, provider identity, maximum work and expiration, pre-funded max TUR cost, independent verifier and refund rules. Changing any of these fields requires a new quote.

`ACCEPT` is valid only after Core successfully reserves the quote's maximum and both endpoints accept the frozen capabilities.

`RESULT` binds the MJR1 result digest, observed resource use, exact code/profile identity and provider signature.

`VERIFY` binds the result digest to an independently checked verdict. A proof of execution alone is not scientific novelty.

`SETTLE` is requested only by the authoritative Core ledger after verification. It debits escrow once, pays the provider and verifier, and refunds surplus. A transport replay or reconnect must never create another settlement. `CANCEL/LEAVE` uses bounded drain and idempotent refund or reconcile-first semantics.

All records require fixed upper length bounds, a protocol version, domain-separated identity, expiry, accepted peer scope, replay/idempotency identity and refusal of unrecognized fields. Bind them to the established transport and MJB1 owners; do not implement another signing scheme here.

## Two different TUR quantities

1. **Scientific T** is a profile-bound measure of independently checked, complexity-adjusted explanatory compression gain. It is nonspendable evidence. Different profiles cannot be silently mixed.
2. **TUR service credit** is a fixed-point, policy-governed accounting denomination used for compute jobs. It is not money, a tokenized asset or an automatic right to payment in v0.

Ordinary compute jobs transfer already-escrowed TUR credits. A qualified scientific contribution may receive a separate payment **only from a prefunded capped research pool** under a published policy. Models never mint credit from self-evaluation, raw token count, claimed cleverness, duplicated training samples or forged receipts.

One conservation fixture (integer units):
- Opening requester/provider/verifier/observer: 100 / 0 / 0 / 0.
- Reserve 40 from requester: spendable requester 60, escrow 40.
- On verified completion: provider 27, verifier 3, requester refund 10.
- Closing balances: requester/provider/verifier/observer = 70 / 27 / 3 / 0; escrow = 0; total = 100.
- Bad logical job ID, duplicate settlement, excessive payout or insufficient balance must refuse without changing state.

### Authenticated local ledger adapter

`scripts/aienet0/settle-run.sh` is host-test orchestration for Core
[#794](https://github.com/aien-dev/aien-sovereign-core-mv/pull/794), not a production
signer, Core RPC, new network format or wallet. It restores the archived `.at-run`
adapter without changing [the immutable historical baseline](BASELINE.md).
MJB1, MJR1, AN0B, AN0V and this draft's status are unchanged.

Provision `AUTHORITY` outside the runner: the exact no-LF `genesis tur-ledger-2`
config specified by Core's `om/tur-ledger/README.md`. Supply separate tmpfs
`ISSUER_KEY` and `VERIFIER_KEY` P-256 PEM test keys matching its public-key pins,
plus the existing carrier environment documented in the script. These are
external test-signing oracles, never keys in the ledger or repository.
OpenSSL 3.0.13 signs the canonical test records; Omega alone verifies admission.
A production signer, vault integration and native constant-time Omega signing
replacement are not implemented or qualified by this adapter.

For this fixed conservation fixture, `QUOTE` contains exactly
`quote tur-ledger-2 requester provider verifier 40 27 3 10` with no trailing LF.
Its SHA-256 is the authority config's policy pin and the reserve's quote pin.
The three owner/node pins hash the raw public submitter, volunteer transport
and AN0V verifier keys, respectively, not the private scalars or textual hex.
The runner checks those bindings and both authority public keys before funding.

Every prefund, reserve and refund receives an issuer authorization. Before
both settlement authorizations, the runner rechecks the actual signed bundle,
MJR1 and AN0V through `aienet0-run check`, requires its exact dag/result match,
recomputes the MJR1 hash and compares the reserved bundle bytes. It signs the
complete payout plus SHA-256 of the signed AN0B bundle and AN0V bytes, bound to
the reservation authorization digest. A repeated settle must leave the journal
unchanged. `tampered-receipt` and `tampered-attestation` must be refused by the
real artifact verifier and refunded, not merely rejected by a hash-shape check.

Run with fresh output directories:

```sh
bash scripts/aienet0/settle-run.sh FRESH_OUTPUT honest
bash scripts/aienet0/settle-run.sh FRESH_OUTPUT tampered-receipt
bash scripts/aienet0/settle-run.sh FRESH_OUTPUT tampered-attestation
```

New local receipts live in `evidence/aienet0-ledger-auth-20261028/receipt.txt`.
They are HOST_TESTED only: distinct test keys on one machine are not independent
operators, and a local CLI retry is not an interrupted-RPC qualification.

The runner arms reconciliation before attempting reserve. On an ambiguous failed
reserve/settle response or a trapped interruption it queries the native journal,
refunds only an actually open reservation, and reports the exact job/journal.
Already-settled jobs are not refunded. If the journal or signer remains unavailable,
it fails with `RECOVERY REQUIRED` rather than claiming escrow was closed.
Untrappable process loss still requires operator reconciliation using the retained
reservation-intent transcript; this is not an autonomous durable recovery service.

`bash scripts/aienet0/settle-check.sh FRESH_EVIDENCE` provisions disposable tmpfs
test keys and checks honest/forged artifacts, false `VERIFIED` stdout, reserve
failure before/after write, settle failure before/after write, and persistent
write failure with explicit operator recovery. It requires the carrier environment
above plus `CARRIER_SOURCE_SHA` and `CARRIER_PROTOCOLS_SHA`; these record provenance,
not a new wire or signing authority. Two mutants must fail the native-state
assertions: removing exit reconciliation, and bypassing actual artifact admission.
Infrastructure failure alone does not count as a killed mutant. Final integrated
receipts and exact pins are in
`evidence/aienet0-ledger-auth-audit-final-20261028/receipt.txt`;
the separately named old-pin controls are not final carrier integration evidence.

## Prove before making a public claim

**P0 HOST:** four distinct local identities, one valid signed work offer, one bounded 10+ node MJB1 objective, a provider result, a separate verifier result, and one durable/once-only settlement. Missing signer/unknown wire/version, duplicate/expired/reordered message, unauthorized effect, cross-tenant request, bad computation, invalid fee, forged T profile, two concurrent reservations, restart at each transaction boundary and replay must each fail as intended. A fixture that merely hardcodes a successful arithmetic balance is NOT this gate.

**P1 PHYSICAL:** two separately owned or independently administered physical computers exchange one actual authorized job and check each other's authenticated identity. The existing live Spark 35B loopback server and all GPU locks remain untouched. Evidence includes exact source, compiler, protocol, target and machine identities, external verifier and raw latency/cost measures. No public listener, model checkpoint transfer or private trace sharing.

**P2 FEDERATED:** four independent physical peers, redundant routing between consenting nodes, direct completion after bootstrap is offline, owner-controlled discovery/revocation and cross-process crash-safe reconciliation. This gate is NOT_RUN until observed.

## Publication and compatibility boundary

Publish protocol drafts, source, fixed public test vectors, evidence and failure cases. Invite compatible independently implemented clients only after at least two runtimes demonstrate interoperability; do not advertise formal Internet standardization or network-wide currency acceptance before evidence. Operators retain control of their machines, data, identities and credit budgets. No internet-scale launch, real-money tokens, speculative conversion rate, auto-deployment or self-replicating agent network is authorized by this draft.

This file asserts a narrow **public technical direction**: trustworthy, cross-hardware, proof-carrying compute exchanges with auditable resource settlement. It intentionally makes no claim of exclusive rights, a functioning public network or an independently qualified implementation.
