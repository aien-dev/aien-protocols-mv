# Optional microjob latent payload: LTP0

Status: Draft v0.1, PROPOSED; endpoint adoption and model communication NOT_RUN.
License: Community Specification License 1.0.
Tracking: aien-protocols-mv#69; architecture-mv#349; existing owners #50, #54 and omega-mv#663.

## Authority and compatibility

LTP0 is the opt-in `latent_payload.v0` content profile of an existing MJB1 CONTENT operand (kind 3), not another task, transport, receipt or capability protocol. MJB1/MJR1 are authoritative in draft PR #53 at the source revision recorded in `sources.json`; neither their bytes nor enumerations change. MJB1 is not on this repository's base main. Adoption remains pending that owner review. The consumer operand's generation equals LTP0 `generation`, the producer node generation; the consumer node's own generation remains independent. The operand digest is SHA-256 of the **entire** serialized LTP0 frame, including its embedded integrity digest. Ordinary consumer MJR1 `input_binding` continues to bind every operand kind, generation and digest. No existing frozen format changes. Unknown/declined LTP0 falls back to a newly admitted full typed message/Omegese under existing MJB1 versioning, never reinterprets a semantic-codebook id (#54), never silently truncates.

NLE1 in omega-mv draft #919 is a discrete, hand-authored codebook, not a continuous tensor. Reused requirements: bounded framing; exact producer/decoder/configuration identities; metadata-plus-payload checksum; refusal before decoding; ordinary checked execution. Its 78-byte layout and registry numbers are NOT reused. The compiler in #919 is the committed compiler at baseline `6999fa9e6dae4847c155ef4eacaece74f491d3ca`, SHA-256 `d6290c7663c2b4bafb59eb3fdf812476e977f4c144def71095c6248ef9b96b84`, not the older harness examples' binaries. No new compiler feature is needed.

## Byte-exact encoding

One frame is exactly 1024 header bytes followed by `payload_bytes` bytes, no padding or suffix. Maximum payload is 4096 bytes; all bounds are profile choices, not measured optimal values. All integers and IEEE-754 binary32 bit containers are **big-endian**; all unsigned unless explicitly signed below. Digests are 32 raw SHA-256 bytes, never ASCII hex. IDs are opaque nonzero byte strings, not pointer handles or authority. No varints, normalization, compression, network negotiation or warmed abbreviation exists in v0. Every message pays the full header plus payload and its carrier/MJB overhead.

|Offset|Width bytes|Field|Range / rejection|
|---|---|---|---|
|0|4|magic|ASCII `LTP0` only|
|4|1|version|0 only; any other version refused|
|5|1|profile|1 synthetic learned-message experiment; 2 model-native state; receiver must explicitly admit the exact profile|
|6|1|classification|1 proposal_only; no execution/receipt/grant class exists|
|7|1|privacy|1 private-local; network/public transfer unsupported|
|8|2|header_bytes|1024 only|
|10|1|dtype|1 binary32; 2 signed int8|
|11|1|rank|1..4; scalar encoded as shape [1]|
|12|1|precision|existing MJB1 1 FP32 for dtype1; 5 INT8 for dtype2|
|13|1|quantization|0 NONE for binary32; 1 tensor-wide affine for int8|
|14|1|encoding|1 canonical dense row-major big-endian only|
|15|1|decode_status|0 undecoded; producer cannot claim a verified intent|
|16|4|payload_bytes|1..4096, equals element_count times scalar width|
|20|4|element_count|1..4096, exact checked product of used dimensions|
|24|16|dims|4 unsigned u32 dimensions; used 1..4096, unused zero|
|40|16|strides|4 unsigned u32 byte strides; last used stride = scalar width; preceding stride = next stride times next dimension; unused zero; no overlap/broadcast/padding|
|56|4|scale_bits|binary32: exact IEEE encoding of 1; int8: strictly positive finite binary32, including positive subnormal|
|60|4|zero_point|signed i32 two's complement; binary32 zero; int8 -128..127|
|64|8|issued_at|nonzero receiver-clock Unix seconds, at most now|
|72|8|expires_at|strictly after now and issued_at, at most admitted template expiry|
|80|8|sequence|strictly greater than trusted lastseq; no wrap accepted|
|88|4|generation|nonzero, exact producer node and consumer CONTENT operand generation|
|92|4|layer|u32; exact reviewed readout registry value, zero allowed|
|96|4|incarnation|nonzero, exact producer MJB1 header incarnation|
|100|1|readout|1 projected; 2 pooled; 3 token; exact registry value|
|101|1|effect_class|existing MJB1 0 NONE, 1 COMPUTE, 2 EFFECT; exact producer node value, within its header ceiling; never a grant|
|102|1|verifier_kind|existing MJB1 2 CHECKER or 3 JUDGE; exact node value; verifier_ref nonzero|
|103|1|source_rank|1..4, exact reviewed source shape|
|104|4|max_steps|nonzero decoder work bound, exact receiver-admitted value|
|108|4|max_payload|1..4096, exact admitted bound, at least payload_bytes|
|112|16|source_dims|4 unsigned u32; used nonzero, unused zero; source tensor need not fit the transmitted projection|
|128|16|job_id|producer MJB1 selected node|
|144|16|idempotence_key|producer MJB1 selected node|
|160|32|objective_id|producer and consumer MJB1 headers, equal|
|192|32|producer_dag_digest|SHA-256 of the producer MJB1 document, which does not contain this output as an operand|
|224|32|producer_input_binding|Unmodified MJR1 section 5.1 binding of producer node dependencies and all its operands, in slot order|
|256|32|tenant_id|producer/consumer MJB1 header and node, authenticated receiver tenant|
|288|32|subject_id|producer and consumer MJB1 headers, equal|
|320|32|approval_ref|producer MJB1 header; consumer independently checks its own approval|
|352|32|capability_ref|producer MJB1 node; consumer independently resolves its own capability|
|384|32|model_id|immutable producer registry/model identity; synthetic profile identifies a synthetic producer explicitly|
|416|32|checkpoint_hash|immutable reviewed producer artifact (synthetic artifact for profile1)|
|448|32|tokenizer_hash|exact tokenizer/preprocessor manifest hash|
|480|32|source_revision|SHA-256 of immutable source/readout revision manifest, not a friendly revision name|
|512|32|projection_id|reviewed basis/adapter identity, never a discrete codebook index|
|544|32|projection_hash|exact immutable adapter artifact digest|
|576|32|semantic_contract|typed proposed-intent/effect schema identity|
|608|32|operation_registry|exact accepted typed operation registry digest|
|640|32|provenance|private-local provenance manifest digest, not a signature or authority|
|672|32|consent_ref|existing revocable consent/privacy record digest|
|704|32|verifier_ref|producer MJB1 checker/judge identity; consumer verifier remains independently required|
|736|16|challenge|receiver-issued nonzero one-use operand-admission challenge|
|752|16|session_id|receiver-issued nonzero session identity|
|768|32|model_config|producer architecture/layer/precision/configuration manifest digest|
|800|32|decoder_id|exact immutable decoder artifact identity|
|832|32|decoder_config|exact decoder configuration digest|
|864|128|reserved|every byte zero|
|992|32|integrity|SHA-256(header bytes [0,992) concatenated with payload [1024,end)); excludes only this digest field|
|1024|payload_bytes|tensor values|binary32 big-endian raw IEEE bits or int8 two's-complement byte values|

All ID fields from 128 through 863 are nonzero **per field**. Source dimensions are identity metadata, not an instruction to allocate the source tensor. A receiver never allocates using received dimensions. Multiplication uses division-before-multiply bounds to refuse overflow. Every finite binary32 bit pattern is preserved, including signed zero and subnormals; exponent 255 (all NaNs and both infinities) is refused. Int8 values are all byte patterns; affine interpretation is `real = (signed_value - zero_point) * scale`. No per-channel scales, int4, bf16, fp16, fp8 or implicit conversion is admitted. Unknown precision/quantization is refusal, not coercion.

## Trusted admission, lifetime and replay

The native reference function is `lpvalid(a view uchar *, c view uchar *, now ulong, lastseq ulong) to int`. `a` is the exact received frame; `c` is a receiver-owned 1024-byte admitted-header template. The template is **not a second wire protocol** and must never be accepted from the sender. A receiver constructs it from three independently admitted sources:

1. Accepted producer MJB1 document/node supply job, idempotence, generation, incarnation, objective, producer DAG digest, unmodified producer MJR1 input binding, tenant, subject, producer approval/capability, producer effect_class and verifier kind/ref. Its COMPLETED MJR1 receipt must verify under the existing trusted signer/verifier set, match that producer document/node and bind `output_digest = SHA-256(entire LTP0 frame)`. The separately admitted consumer MJB1 CONTENT operand must have that same digest and producer generation. Producer and consumer header objective_id, tenant_id and subject_id must match; their job/idempotence IDs, incarnation, node generation, operation, budgets, approval/capability and verifier may differ and remain independently checked under existing MJB1 admission. Their documents are distinct: the producer document must not reference its own LTP0 output, so neither document's digest is self-referential. Every producer/consumer dependency receipt and the full producer/consumer input bindings remain checked unchanged by MJR1 section 5.1; no omitted-slot hash, new derivation authority or cross-document scheduler is defined. An absent producer receipt or relation mismatch is refusal. These caller-side document/receipt checks are NOT_RUN in this pure byte-validator suite.
2. Reviewed producer/projection/decoder/semantic registry: exact profile, source shape/layer/readout, tensor shape/dtype/strides/quantization, model/checkpoint/tokenizer/source/projection/configuration IDs, semantic schema, operations, max_steps/max_payload. Shape-compatible but basis-incompatible models are refused. Unknown revision, unsupported projection or decoder is refused.
3. Current consent/privacy authority and receiver-local session/challenge state: exact privacy/consent/provenance scope, receiver challenge/session, expiry ceiling, trusted clock and lastseq. A nonzero hash is not proof of permission or of authentic provenance. Resolve and recheck revocation/lifetime through existing authorities at consumption; missing authority means refuse.

Template metadata matches frame bytes [0,16), [24,64), [88,864) exactly; its max_payload and max_steps are exact admitted caps. The template's `expires_at` is an upper bound. Dynamic frame fields are payload length/count (constrained by declared shape), issue/expiry/sequence and checksum; all remaining template bytes are not interpreted. Bad template length fails closed. Template manufacture/admission, revocation lookup, producer/consumer MJB validation and receipt verification are caller obligations, not claimed implemented by a pure byte validator. Reusing an existing operand validation outcome never reuses execution authorization: each consumer is independently admitted and authorized, including on retry.

Replay key is `(tenant_id, subject_id, session_id, job_id, generation)`, where job/generation identify the producer. `lastseq` is durable and monotonic within that key, not supplied by the producer; highest possible sequence closes the session rather than wrapping. The challenge is allocated to **one admitted immutable operand**, not freshly changed for each attempt. Before decoding, caller atomically compares the still-current high-water and challenge and reserves `(key, sequence, challenge, full_operand_digest)` in durable state. Two validations against a stale snapshot cannot both consume it. A byte-identical retransmission returns the already recorded outcome; it does not create another attempt or effect. A permitted consumer MJB1 retry references the same reserved operand; retry/reconciliation/cancel/max-attempt rules remain existing MJB1/MJR1 authority. Already-reserved identical retransmits/retries are looked up by full digest before the fresh-admission call: do not rerun `lpvalid` with the advanced high-water and weaken its sequence guard to admit them. Changing the frame/challenge requires newly admitted producer output and consumer operand/document generation, never substitution under the old digest. Current MJR1 ledger does **not** implement this reservation; consumer integration remains NOT_RUN until implemented and challenged. Session teardown/restart retains reservations or refuses outstanding sessions; loss of state never resets acceptance.

Hold immutable validated bytes (or reopen by verified immutable digest) from digest check through reservation and decode. Recheck cancellation, capability, consent and expiry before any actual execution. Numerical messages carry information, never authority: valid tensors cannot mint capabilities, signed receipts, credits, money, execution rights or broader effects. Decoding must produce a bounded typed proposal or abstain, then use the existing Omega verifier and independent authorized executor. The validator emits no source, receipt or effect. Native host words have ambient permissions; absent a properly confined existing executor, refuse effects. The reference harness only re-emits validated tensor frame bytes.

## Deterministic rejection order

`0` means structural/admission-template match only. The first failing check wins. No output is permitted on refusal.

|Status|Check, in order|
|---|---|
|10|frame shorter than1024, larger than5120, or template length not1024|
|11|magic/version/header length mismatch|
|12|unknown profile/classification/privacy/encoding/decode status/readout/effect/verifier|
|13|unsupported dtype/precision/quantization combination or invalid scale/zero_point|
|14|rank/source-rank outside1..4, source dimension zero/unused nonzero, or tensor bad dimension/product/stride/unused shape|
|15|payload length/count mismatch, truncation, trailing byte, max_payload outside1..4096 or exceeded|
|16|reserved byte nonzero|
|17|zero generation/incarnation/max_steps or a required ID field zero|
|18|issue/expiry invalid at trusted now, or above admitted expiry|
|19|sequence not above lastseq|
|20|trusted template mismatch in the exact comparison ranges above (covers model/revision/tenant/capability/challenge/session/etc)|
|21|nonfinite binary32 payload|
|22|integrity mismatch|
|80|test-driver input error or malformed context prefix|
|81|test-driver output error|

The pure function performs no mutation. Reserved bytes and IDs are checked independently even when a registry/template is wrong. Production caller additionally refuses invalid MJB1/operand digest, unreserved/replayed challenge, missing/revoked authority, unknown registry, invalid provenance, mutable/replaced content and missing verification. Those obligations cannot be promoted to PASS by this conformance suite.

## Reference conformance and independent controls

`validator.om` is the seeded handwritten reference, composed with the existing pinned `om/tls/sha2.om`; `driver.om` is a synthetic conformance driver, never an executor. Driver stdin is **test-only** 1024 trusted fixture-template bytes followed by one frame; fixture clock/lastseq are declared in its source. This combined input is not a production encoding. `host.cases` uses the unchanged pinned native Omega conductor from #919, with positive exact-byte preservation, malformed fixtures, and guard-bypass/wrong-checksum mutants. Independent fixture generation uses standard-library Buffer/crypto only as a verification oracle outside the product path. Fixed `.wire` fixtures and oracle provenance are committed; no JavaScript/Python runtime participates in validation or the repeatable native suite.

Run from this repository root using pinned Omega sources; exact commands and observed host-only results are recorded in `results.json` after execution. The gate does not access models, network, GPU, live service, private activations or production. Public fixtures contain synthetic bytes only. There are no runtime consumers yet; adoption requires owner review under GOVERNANCE.md and VERSIONING.md. This draft does not freeze a protocol or prove learned communication, independent scientific gain, hardware qualification, signed Spark qualification or deployment.

### Reproduce the native suite

From this repository root, supply `OMEGA_SRC` as a clean checkout of the exact Omega revision in `sources.json`. Use its committed `omc`; do not substitute a newer compiler without a separately recorded rerun.

```sh
mkdir -p build
ln -s "$OMEGA_SRC" build/nl3-omega
ln -s "$OMEGA_SRC/seed" seed
if build/nl3-omega/seed/out/omc < build/nl3-omega/seed/qualification/om2/gate.om > build/nl3-gate; then
  chmod +x build/nl3-gate &&
  build/nl3-gate build/nl3-omega/seed/out/omc d6290c7663c2b4bafb59eb3fdf812476e977f4c144def71095c6248ef9b96b84 specs/latent-payload/host.cases build/nl3-run
else
  exit 1
fi
```

The temporary root `seed` symlink supplies the unchanged conductor's fixed SHA constant-fixture paths. It is not a protocol implementation or a committed dependency copy; remove that symlink after the run. The conductor validates its compiler identity and SHA constants before executing any case.

`host.cases` declares each expected exit and complete stdout oracle. Positive cases preserve bytes exactly; negative cases must emit nothing. A `kill` case requires both its declared mutant exit and a mismatch against the unmutated stdout oracle. Thirteen guard-bypass substitutions return success at the guarded point for nonempty frames, making invalid bytes observable to the harness rather than merely changing a refusal code; an additional integrity-coverage substitution hashes 991 rather than 992 prefix bytes and must reject a valid independent golden frame. These controls prove the harness detects these injected bypasses, not that every guard is independently necessary when other defenses remain. `vectors/*.from` / `*.to` are conductor mutation data, not product code. Synthetic fixture construction used Bun 1.4.4 standard-library Buffer/crypto only as an independent verification oracle, never as a permanent implementation or conformance runner.

### Mathematical oracle

Raw tool calls and results from a fresh isolated OMP process are in `wolfram.jsonl`; this file contains only Wolfram requests/results, not model activations or private traces. Verification calls: `WolframLanguageEvaluator: Integrate[x^2,{x,0,1}] -> 1/3`; `WolframAlpha: sqrt(27)/2 -> (3 sqrt(3))/2`. Integer representability query `WolframLanguageEvaluator: {2^16-1,2^32-1,2^64-1,2^15-1,2^31-1,2^63-1} -> {65535,4294967295,18446744073709551615,32767,2147483647,9223372036854775807}`. These results are dimensionless mathematical facts, not measured model, performance or hardware evidence. Tensor interpretation and scale are definitions above; fixtures compare raw IEEE bits without host float conversion.
