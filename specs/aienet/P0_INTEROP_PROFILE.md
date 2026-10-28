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

## Prove before making a public claim

**P0 HOST:** four distinct local identities, one valid signed work offer, one bounded 10+ node MJB1 objective, a provider result, a separate verifier result, and one durable/once-only settlement. Missing signer/unknown wire/version, duplicate/expired/reordered message, unauthorized effect, cross-tenant request, bad computation, invalid fee, forged T profile, two concurrent reservations, restart at each transaction boundary and replay must each fail as intended. A fixture that merely hardcodes a successful arithmetic balance is NOT this gate.

**P1 PHYSICAL:** two separately owned or independently administered physical computers exchange one actual authorized job and check each other's authenticated identity. The existing live Spark 35B loopback server and all GPU locks remain untouched. Evidence includes exact source, compiler, protocol, target and machine identities, external verifier and raw latency/cost measures. No public listener, model checkpoint transfer or private trace sharing.

**P2 FEDERATED:** four independent physical peers, redundant routing between consenting nodes, direct completion after bootstrap is offline, owner-controlled discovery/revocation and cross-process crash-safe reconciliation. This gate is NOT_RUN until observed.

## Publication and compatibility boundary

Publish protocol drafts, source, fixed public test vectors, evidence and failure cases. Invite compatible independently implemented clients only after at least two runtimes demonstrate interoperability; do not advertise formal Internet standardization or network-wide currency acceptance before evidence. Operators retain control of their machines, data, identities and credit budgets. No internet-scale launch, real-money tokens, speculative conversion rate, auto-deployment or self-replicating agent network is authorized by this draft.

This file asserts a narrow **public technical direction**: trustworthy, cross-hardware, proof-carrying compute exchanges with auditable resource settlement. It intentionally makes no claim of exclusive rights, a functioning public network or an independently qualified implementation.
