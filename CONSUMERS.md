# Protocol Consumers

This is a source-adoption inventory, not a deployment or qualification claim.
No `v0.2.0` release tag is implied by the owner-approved 2026-10-26 digest
cutover below. Historical evidence retains the protocol pin under which it ran.

| Consumer | Uses | Pre-cutover reference version |
| :--- | :--- | :---: |
| `aegis-runtime` | protocol-types, action-protocol, probe, agent-state-abi, inference-protocol, inference-client | v0.1.0 |
| `aien-local-stack` | protocol-types, agent-state-abi, inference-protocol, inference-client, provenance | v0.1.0 |
| `spark-inquisitor` | protocol-types, evaluation-protocol, probe | v0.1.0 |
| `spark-rsi` | protocol-types, evaluation-protocol, probe | v0.1.0 |
| `aien-sovereign-core` (`spark-harvester`, `spark-mail-rs`) | protocol-types, provenance, probe | v0.1.0 |
| `aien-sovereign-core` (Spark side of the Pi link, lane D, aien-sovereign-core-mv#585; planned, not yet a dependency) | pi-spark-task (`crates/aien-pi-spark-task`, PST1 Draft v0.1) | v0.1.0 |

## Pending LTP0 consumers (NL-3)

`specs/latent-payload` extends the draft MJB1 CONTENT profile from
protocols #50/#54 / draft PR #53, not any released crate. No production
consumer has adopted LTP0. The coordinated NL4 typed-proposal boundary,
NL5 read-only synthetic shadow and NL6 frozen experiment design are
research consumers, not permission or runtime integration evidence.
The reference validator receives an independently
admitted context; it does not manufacture signed receipts, capability
grants or durable reservations. Exact source pins and host-only synthetic
conformance are recorded beside the draft. Existing consumers require no
cutover until they explicitly opt in.

## Approved strict digest cutover, 2026-10-26

Drake approved `aien-protocols-mv#59`: framed SourceGrant v2 and evaluation
receipt v3, with separately framed plan and outcome digests. Old signatures
are refused, never retried. The adoption wave includes these active consumers:

- `aien-sovereign-core-mv/crates/spark-harvester` (adoption:
  [aien-sovereign-core-mv#772](https://github.com/aien-dev/aien-sovereign-core-mv/pull/772)):
  reads grants from JSON and
  verifies them in `client.rs` and `rights_gate.rs`. The prior git dependency
  was pinned at `7ac6facb630ca7e9a6ab4125b292203fe2bb6687`, not a sibling
  path. Its migration advances the provenance/type pin and proves old signed
  grants refused and newly issued grants accepted with synthetic identities.
  Grants supplied by operators must be reissued by their authorized issuers;
  the source merge does not manufacture or migrate private live grants.
- `spark-rsi-mv` (adoption:
  [spark-rsi-mv#78](https://github.com/aien-dev/spark-rsi-mv/pull/78)):
  `src/safety_envelope.rs` constructs plans and signed
  evaluation receipts using sibling-path protocol crates. Its migration
  adopts receipt version 3 and adds a newly pinned golden receipt, retaining
  the prior frozen golden material unchanged as superseded history.

The audit searched every clone under `/tmp/secrev` for `SourceGrant`,
`EvaluationPlan`, `EvaluatorOutcome`, `EvaluationReceipt`, signed-receipt
types, digest methods and protocol dependency references. In particular:

- `interplane-mv`: its ledger grant/intent/ack digests and retained receipts
  use a separate format, not `aien-provenance::SourceGrant`.
- `synapse`: repository capability grants and evidence attachments use its
  own formats, not these protocol digests.
- `aegis-runtime-mv`: sibling protocol dependencies resolve the changed
  crates transitively, but no source consumer stores/verifies these grants
  or evaluation receipts. Its host suite is exercised against the new source.
- Core's `spark-mail-rs` retains an older `aien-probe` git pin. Its probe
  backend does not store or verify the changed grant/receipt formats; the
  older transitive packages in `Cargo.lock` are not a legacy acceptance path
  in the migrated harvester.
- `aien-local-stack` and `spark-inquisitor` are archived consumers. They are
  not reactivated or represented as migrated. Any future reactivation must
  first adopt the strict contract and reissue active grants/receipts.

Historical receipts and digest references are not rewritten. Supersession
notes identify replacement fixtures; a historical signature never authorizes
current work under the new contract. No live deployment is authorized by
this inventory.
