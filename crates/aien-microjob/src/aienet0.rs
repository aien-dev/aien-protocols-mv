//! Aienet-0 P0 job path profile over MJB1/MJR1
//! (`specs/aienet/jobpath/PROFILE.md`).
//!
//! The profile carries exactly one allowlisted job kind, `matmul_u32`
//! (payload layout and digest of Core PR #662,
//! `crates/aien-hetjob/src/task.rs`), in a one-node MJB1 document. MJB1 has
//! no submitter signature and MJR1 has one signature, so the profile adds two
//! detached records: the submitter's signature inside the `AN0B` bundle and
//! the verifier's countersignature `AN0V`. Neither record grants anything; a
//! receiver checks each against a key it pinned out of band.
//!
//! Every guard in this file is a single statement tagged `AN0-GUARD <name>`;
//! `specs/aienet/jobpath/mutants.sh` removes each one and requires the unit
//! tests below to fail.

use crate::{
    cancel, compute_op, dag_digest, decode, decode_receipt, effect, encode, encode_receipt,
    input_binding, kind, operand, outcome, profile, retry, sign_receipt, verifier, Applied, Dag,
    DagRun, Header, Node, NodeState, Operand, Receipt, Refusal, MAX_DOCUMENT, RECEIPT_LEN,
};
use aien_provenance::{p256_compressed_key, p256_sign_low_s, p256_verify_low_s};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

/// The four bytes that open a bundle.
pub const BUNDLE_MAGIC: [u8; 4] = *b"AN0B";
/// The four bytes that open a verifier countersignature.
pub const VERDICT_MAGIC: [u8; 4] = *b"AN0V";
/// The only profile version.
pub const PROFILE_VERSION: u8 = 1;
/// Payload `kind` byte of `matmul_u32` (Core #662 `KIND_MATMUL_U32`).
pub const KIND_MATMUL_U32: u8 = 1;
/// Bytes in a `matmul_u32` payload.
pub const PAYLOAD_LEN: usize = 15;
/// Largest payload a bundle may carry (any kind).
pub const MAX_PAYLOAD: usize = 256;
/// Largest `m`, `k` or `n` the worker admits.
pub const MAX_DIM: u16 = 256;
/// Digest domain of Core #662 `MATMUL_DOMAIN`.
pub const MATMUL_DOMAIN: &[u8] = b"AIEN-HETJOB-MATMUL-U32-V1";
/// Bytes before the payload in a bundle.
pub const BUNDLE_HEAD: usize = 4 + 1 + 1 + 2 + 4 + 33 + 64;
/// Largest bundle.
pub const MAX_BUNDLE: usize = BUNDLE_HEAD + MAX_PAYLOAD + MAX_DOCUMENT;
/// Bytes of a countersignature covered by its signature.
pub const VERDICT_SIGNED_LEN: usize = 4 + 4 + 32 * 4 + 33 + 3;
/// Bytes in a countersignature.
pub const VERDICT_LEN: usize = VERDICT_SIGNED_LEN + 64;
/// Seconds a built document stays admissible.
pub const DOCUMENT_TTL: u64 = 3600;
/// Per-node time cap written into built documents.
pub const NODE_TIME_MS: u32 = 120_000;

const SUBMIT_DOMAIN: &[u8] = b"AIENET0-MJB1-SUBMIT-V1\0";
const VERIFY_DOMAIN: &[u8] = b"AIENET0-MJR1-VERIFY-V1\0";
const VERDICT_DOMAIN: &[u8] = b"AIENET0-RECOMPUTE-MATCH-V1\0";

/// Why the profile refused a bundle, a receipt or a countersignature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum An0Refusal {
    /// Bundle or countersignature framing is malformed.
    BadBundle,
    /// The submitter key is not the pinned one, the signature does not
    /// verify, or `approval_ref` does not name that key.
    BadSubmitter,
    /// The MJB1/MJR1 validator refused.
    Mjb(Refusal),
    /// Not the one allowlisted job shape.
    NotAllowlisted,
    /// Dimensions or caps outside the worker's bounds.
    OverBudget,
    /// The operand digest does not name the carried payload.
    PayloadMismatch,
    /// A receipt that the ledger had already applied.
    ReplayedReceipt,
    /// The receipt's output digest differs from the verifier's recompute.
    RecomputeMismatch,
    /// The receipt's verdict commitment does not match the recompute.
    VerdictMismatch,
    /// The countersignature does not verify against the pinned verifier key.
    BadCountersign,
}

impl An0Refusal {
    /// Stable refusal code printed by the job path.
    pub fn name(self) -> &'static str {
        match self {
            An0Refusal::BadBundle => "AN0_BAD_BUNDLE",
            An0Refusal::BadSubmitter => "AN0_BAD_SUBMITTER",
            An0Refusal::Mjb(r) => r.name(),
            An0Refusal::NotAllowlisted => "AN0_NOT_ALLOWLISTED",
            An0Refusal::OverBudget => "AN0_OVER_BUDGET",
            An0Refusal::PayloadMismatch => "AN0_PAYLOAD_MISMATCH",
            An0Refusal::ReplayedReceipt => "AN0_REPLAYED_RECEIPT",
            An0Refusal::RecomputeMismatch => "AN0_RECOMPUTE_MISMATCH",
            An0Refusal::VerdictMismatch => "AN0_VERDICT_MISMATCH",
            An0Refusal::BadCountersign => "AN0_BAD_COUNTERSIGN",
        }
    }
}

impl From<Refusal> for An0Refusal {
    fn from(r: Refusal) -> Self {
        An0Refusal::Mjb(r)
    }
}

fn guard(ok: bool, r: An0Refusal) -> Result<(), An0Refusal> {
    if ok {
        Ok(())
    } else {
        Err(r)
    }
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn id16(parts: &[&[u8]]) -> [u8; 16] {
    let d = sha(parts);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// One `matmul_u32` job: `C = A x B`, `A` is `m x k`, `B` is `k x n`, all
/// entries drawn from splitmix64(`seed`) truncated to u32, arithmetic mod 2^32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatmulU32 {
    pub m: u16,
    pub k: u16,
    pub n: u16,
    pub seed: u64,
}

impl MatmulU32 {
    /// The 15-byte payload: kind, m, k, n (u16 BE), seed (u64 BE).
    pub fn encode(&self) -> [u8; PAYLOAD_LEN] {
        let mut p = [0u8; PAYLOAD_LEN];
        p[0] = KIND_MATMUL_U32;
        p[1..3].copy_from_slice(&self.m.to_be_bytes());
        p[3..5].copy_from_slice(&self.k.to_be_bytes());
        p[5..7].copy_from_slice(&self.n.to_be_bytes());
        p[7..15].copy_from_slice(&self.seed.to_be_bytes());
        p
    }

    /// Parse a payload. Any kind byte other than `matmul_u32` is not on the
    /// allowlist.
    pub fn decode(p: &[u8]) -> Result<Self, An0Refusal> {
        guard(
            p.first() == Some(&KIND_MATMUL_U32),
            An0Refusal::NotAllowlisted,
        )?; // AN0-GUARD payload-kind
        guard(p.len() == PAYLOAD_LEN, An0Refusal::BadBundle)?;
        let u16_at = |i: usize| u16::from_be_bytes([p[i], p[i + 1]]);
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&p[7..15]);
        Ok(MatmulU32 {
            m: u16_at(1),
            k: u16_at(3),
            n: u16_at(5),
            seed: u64::from_be_bytes(seed),
        })
    }

    /// Multiply-adds the job performs.
    pub fn work(&self) -> u64 {
        self.m as u64 * self.k as u64 * self.n as u64
    }

    /// Bytes of A, B and C.
    pub fn memory(&self) -> u64 {
        let (m, k, n) = (self.m as u64, self.k as u64, self.n as u64);
        4 * (m * k + k * n + m * n)
    }

    /// Every dimension in `1..=MAX_DIM`.
    pub fn in_bounds(&self) -> bool {
        [self.m, self.k, self.n]
            .iter()
            .all(|&d| (1..=MAX_DIM).contains(&d))
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The worker kernel (i-k-j loop order, as Core #662's worker). Returns the
/// output digest: SHA-256(domain || m || k || n || seed || C as u32 BE).
pub fn matmul_u32_digest(j: &MatmulU32) -> [u8; 32] {
    let (m, k, n) = (j.m as usize, j.k as usize, j.n as usize);
    let mut s = j.seed;
    let a: Vec<u32> = (0..m * k).map(|_| splitmix64(&mut s) as u32).collect();
    let b: Vec<u32> = (0..k * n).map(|_| splitmix64(&mut s) as u32).collect();
    let mut c = vec![0u32; m * n];
    for i in 0..m {
        for p in 0..k {
            let x = a[i * k + p];
            for q in 0..n {
                c[i * n + q] = c[i * n + q].wrapping_add(x.wrapping_mul(b[p * n + q]));
            }
        }
    }
    let mut h = Sha256::new();
    h.update(MATMUL_DOMAIN);
    h.update(j.m.to_be_bytes());
    h.update(j.k.to_be_bytes());
    h.update(j.n.to_be_bytes());
    h.update(j.seed.to_be_bytes());
    for v in &c {
        h.update(v.to_be_bytes());
    }
    h.finalize().into()
}

/// `approval_ref` of a profile document: names the submitter key and nonce.
pub fn approval_ref(submitter: &[u8; 33], nonce: &[u8; 16]) -> [u8; 32] {
    sha(&[b"AIENET0-APPROVAL-V1\0", submitter, nonce])
}

/// The tenant every Aienet-0 test document runs under (prefunded TUR test
/// credits, no wallet).
pub fn tenant() -> [u8; 32] {
    sha(&[b"AIENET0-TENANT-TUR-TEST-V1"])
}

/// The capability the single allowlisted job runs under.
pub fn capability() -> [u8; 32] {
    sha(&[b"AIENET0-CAPABILITY-MATMUL-U32-V1"])
}

/// Build the one-node MJB1 document for `payload`. `op` is the MJB1 compute
/// op; only `compute_op::MATMUL` is admitted by a worker, other values exist
/// for the negative control. Caps come from the payload when it parses as
/// `matmul_u32`, else 1.
pub fn build_document(
    payload: &[u8],
    op: u8,
    nonce: [u8; 16],
    submitter: &[u8; 33],
    now: u64,
) -> Vec<u8> {
    let (work, memory) = match MatmulU32::decode(payload) {
        Ok(j) => (j.work().max(1), j.memory().max(1)),
        Err(_) => (1, 1),
    };
    let expires_at = now + DOCUMENT_TTL;
    let header = Header {
        effect_ceiling: effect::COMPUTE,
        objective_id: sha(&[b"AIENET0-OBJECTIVE-V1\0", &nonce]),
        tenant_id: tenant(),
        subject_id: sha(&[b"AIENET0-SUBJECT-V1\0", payload]),
        approval_ref: approval_ref(submitter, &nonce),
        incarnation: 1,
        expires_at,
        budget_time_ms: NODE_TIME_MS as u64,
        budget_fuel: work,
        budget_memory: memory,
        budget_work: work,
        budget_input_tokens: 0,
        budget_output_tokens: 0,
    };
    let node = Node {
        job_id: id16(&[b"AIENET0-JOB-V1\0", &nonce]),
        idempotence_key: id16(&[b"AIENET0-IDEM-V1\0", &nonce]),
        generation: 1,
        kind: kind::COMPUTE,
        op,
        profile: profile::ZERO,
        effect_class: effect::COMPUTE,
        input_tokens: 0,
        output_tokens: 0,
        required_input_tokens: 0,
        required_output_tokens: 0,
        verifier_kind: verifier::RECOMPUTE,
        retry_class: retry::NEVER,
        max_attempts: 1,
        cancel_mode: cancel::DISCARD,
        precision: 0,
        substrate_mask: 1,
        result_type: 7,
        result_rank: 0,
        pure: true,
        time_ms: NODE_TIME_MS,
        fuel: work,
        memory,
        work,
        expires_at,
        result_dims: [0; 4],
        capability_ref: capability(),
        tenant_id: tenant(),
        model_ref: [0; 32],
        verifier_ref: [0; 32],
        deps: Vec::new(),
        operands: vec![Operand {
            kind: operand::CONTENT,
            generation: 1,
            digest: sha(&[payload]),
        }],
    };
    encode(&Dag {
        header,
        nodes: vec![node],
    })
    .expect("one node fits")
}

fn submit_message(digest: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut m = SUBMIT_DOMAIN.to_vec();
    m.extend_from_slice(digest);
    m.extend_from_slice(&sha(&[payload]));
    m
}

/// Seal a bundle: `AN0B`, version, reserved, payload length (u16 BE),
/// document length (u32 BE), submitter key (33), submitter signature (64),
/// payload, document. The signature covers the domain, `dag_digest` and
/// SHA-256(payload).
pub fn seal_bundle(document: &[u8], payload: &[u8], key: &SigningKey) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD && document.len() <= MAX_DOCUMENT);
    let sig = p256_sign_low_s(key, &submit_message(&dag_digest(document), payload));
    let mut b = Vec::with_capacity(BUNDLE_HEAD + payload.len() + document.len());
    b.extend_from_slice(&BUNDLE_MAGIC);
    b.push(PROFILE_VERSION);
    b.push(0);
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(&(document.len() as u32).to_be_bytes());
    b.extend_from_slice(&p256_compressed_key(key));
    b.extend_from_slice(&sig);
    b.extend_from_slice(payload);
    b.extend_from_slice(document);
    b
}

/// A bundle the worker admitted.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub document: Vec<u8>,
    pub payload: Vec<u8>,
    pub dag: Dag,
    pub digest: [u8; 32],
    pub job: MatmulU32,
}

/// Parsed bundle fields: submitter key, signature, borrowed payload and document.
pub type BundleParts<'a> = ([u8; 33], [u8; 64], &'a [u8], &'a [u8]);

/// Split a bundle into (submitter key, signature, payload, document).
pub fn split_bundle(b: &[u8]) -> Result<BundleParts<'_>, An0Refusal> {
    guard(
        b.len() >= BUNDLE_HEAD && b.len() <= MAX_BUNDLE && b[..4] == BUNDLE_MAGIC,
        An0Refusal::BadBundle,
    )?;
    guard(b[4] == PROFILE_VERSION && b[5] == 0, An0Refusal::BadBundle)?;
    let plen = u16::from_be_bytes([b[6], b[7]]) as usize;
    let dlen = u32::from_be_bytes([b[8], b[9], b[10], b[11]]) as usize;
    guard(
        plen <= MAX_PAYLOAD && BUNDLE_HEAD + plen + dlen == b.len(),
        An0Refusal::BadBundle,
    )?;
    let mut key = [0u8; 33];
    key.copy_from_slice(&b[12..45]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&b[45..109]);
    Ok((
        key,
        sig,
        &b[BUNDLE_HEAD..BUNDLE_HEAD + plen],
        &b[BUNDLE_HEAD + plen..],
    ))
}

/// Worker admission at clock `now` (Unix seconds): submitter pinned and
/// signature valid, MJB1 valid and unexpired, exactly the allowlisted shape,
/// payload named by the operand, dimensions and caps within bounds. Replay
/// (a dag_digest seen before) is the caller's persistent check.
pub fn admit_bundle(
    b: &[u8],
    pinned_submitter: &[u8; 33],
    now: u64,
) -> Result<Admitted, An0Refusal> {
    let (key, sig, payload, document) = split_bundle(b)?;
    guard(key == *pinned_submitter, An0Refusal::BadSubmitter)?; // AN0-GUARD submitter-pin
    let digest = dag_digest(document);
    guard(
        p256_verify_low_s(&key, &submit_message(&digest, payload), &sig).is_ok(),
        An0Refusal::BadSubmitter,
    )?; // AN0-GUARD submitter-sig
    let dag = decode(document)?;
    guard(
        dag.header.expires_at >= now,
        An0Refusal::Mjb(Refusal::BadExpiry),
    )?;
    guard(dag.nodes.len() == 1, An0Refusal::NotAllowlisted)?;
    let node = &dag.nodes[0];
    guard(
        node.kind == kind::COMPUTE && node.op == compute_op::MATMUL,
        An0Refusal::NotAllowlisted,
    )?; // AN0-GUARD op-allowlist
    guard(
        node.verifier_kind == verifier::RECOMPUTE && node.effect_class == effect::COMPUTE,
        An0Refusal::NotAllowlisted,
    )?;
    guard(
        node.operands.len() == 1 && node.deps.is_empty(),
        An0Refusal::NotAllowlisted,
    )?;
    guard(
        node.operands[0].kind == operand::CONTENT,
        An0Refusal::NotAllowlisted,
    )?;
    guard(
        node.operands[0].digest == sha(&[payload]),
        An0Refusal::PayloadMismatch,
    )?; // AN0-GUARD payload-binding
    let job = MatmulU32::decode(payload)?;
    guard(job.in_bounds(), An0Refusal::OverBudget)?; // AN0-GUARD dim-bounds
    guard(
        node.work >= job.work() && node.memory >= job.memory(),
        An0Refusal::OverBudget,
    )?; // AN0-GUARD node-caps
    Ok(Admitted {
        document: document.to_vec(),
        payload: payload.to_vec(),
        digest,
        job,
        dag,
    })
}

/// The verdict commitment an executor writes into `verifier_verdict` and the
/// verifier rebuilds from its own recompute.
pub fn verdict_commitment(digest: &[u8; 32], job_id: &[u8; 16], output: &[u8; 32]) -> [u8; 32] {
    sha(&[VERDICT_DOMAIN, digest, job_id, output])
}

/// Executor side: a signed COMPLETED receipt for an admitted job.
pub fn executor_receipt(
    a: &Admitted,
    output: [u8; 32],
    used_time_ms: u32,
    source_hash: [u8; 32],
    policy_hash: [u8; 32],
    key: &SigningKey,
) -> [u8; RECEIPT_LEN] {
    let node = &a.dag.nodes[0];
    let mut r = Receipt {
        outcome: outcome::COMPLETED,
        attempt: 1,
        dag_digest: a.digest,
        job_id: node.job_id,
        idempotence_key: node.idempotence_key,
        generation: node.generation,
        used_time_ms,
        used_input_tokens: 0,
        used_output_tokens: 0,
        used_fuel: a.job.work(),
        used_memory: a.job.memory(),
        used_work: a.job.work(),
        input_binding: input_binding(&[], &node.operands),
        output_digest: output,
        source_hash,
        model_hash: [0; 32],
        policy_hash,
        verifier_verdict: verdict_commitment(&a.digest, &node.job_id, &output),
        signer_key: [0; 33],
        signature: [0; 64],
    };
    sign_receipt(&mut r, key);
    encode_receipt(&r)
}

/// Verifier side, before the recompute: the receipt passes the MJR1 ledger
/// with only the pinned executor key trusted, is new, and leaves the node
/// DONE.
pub fn check_receipt(
    document: &[u8],
    receipt: &[u8],
    pinned_executor: [u8; 33],
    now: u64,
) -> Result<Receipt, An0Refusal> {
    let trusted = vec![pinned_executor]; // AN0-GUARD executor-pin
    let mut run = DagRun::admit(document, trusted, now)?;
    let applied = run.apply(receipt)?;
    guard(applied == Applied::New, An0Refusal::ReplayedReceipt)?;
    guard(
        run.state(0) == NodeState::Done,
        An0Refusal::Mjb(Refusal::BadReceipt),
    )?;
    Ok(decode_receipt(receipt)?)
}

fn verdict_message(rec: &[u8]) -> Vec<u8> {
    let mut m = VERIFY_DOMAIN.to_vec();
    m.extend_from_slice(&rec[..VERDICT_SIGNED_LEN]);
    m
}

/// Verifier side, after the recompute: refuse unless the receipt's output
/// digest and verdict commitment both match `recomputed`, then countersign.
/// Record: `AN0V`, version, 3 reserved, SHA-256(MJR1), dag_digest,
/// recomputed digest, verdict commitment, verifier key (33), 3 reserved,
/// signature (64) over the domain and the first 172 bytes.
pub fn countersign(
    receipt: &[u8],
    recomputed: [u8; 32],
    key: &SigningKey,
) -> Result<[u8; VERDICT_LEN], An0Refusal> {
    let r = decode_receipt(receipt)?;
    guard(r.output_digest == recomputed, An0Refusal::RecomputeMismatch)?; // AN0-GUARD recompute-match
    let commit = verdict_commitment(&r.dag_digest, &r.job_id, &recomputed);
    guard(r.verifier_verdict == commit, An0Refusal::VerdictMismatch)?; // AN0-GUARD verdict-match
    let mut rec = [0u8; VERDICT_LEN];
    rec[..4].copy_from_slice(&VERDICT_MAGIC);
    rec[4] = PROFILE_VERSION;
    rec[8..40].copy_from_slice(&sha(&[receipt]));
    rec[40..72].copy_from_slice(&r.dag_digest);
    rec[72..104].copy_from_slice(&recomputed);
    rec[104..136].copy_from_slice(&commit);
    rec[136..169].copy_from_slice(&p256_compressed_key(key));
    let sig = p256_sign_low_s(key, &verdict_message(&rec));
    rec[VERDICT_SIGNED_LEN..].copy_from_slice(&sig);
    Ok(rec)
}

/// Check a countersignature against the receipt it names and the pinned
/// verifier key.
pub fn check_countersign(
    rec: &[u8],
    receipt: &[u8],
    pinned_verifier: &[u8; 33],
) -> Result<(), An0Refusal> {
    guard(
        rec.len() == VERDICT_LEN && rec[..4] == VERDICT_MAGIC,
        An0Refusal::BadBundle,
    )?;
    guard(
        rec[4] == PROFILE_VERSION && rec[5..8] == [0; 3] && rec[169..172] == [0; 3],
        An0Refusal::BadBundle,
    )?;
    guard(rec[8..40] == sha(&[receipt]), An0Refusal::BadCountersign)?;
    guard(
        rec[136..169] == pinned_verifier[..],
        An0Refusal::BadCountersign,
    )?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&rec[VERDICT_SIGNED_LEN..]);
    guard(
        p256_verify_low_s(pinned_verifier, &verdict_message(rec), &sig).is_ok(),
        An0Refusal::BadCountersign,
    )?; // AN0-GUARD countersign-sig
    let r = decode_receipt(receipt)?;
    guard(
        rec[40..72] == r.dag_digest && rec[72..104] == r.output_digest,
        An0Refusal::BadCountersign,
    )?;
    Ok(())
}

/// Lowercase hex.
pub fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Parse exactly `N` bytes of hex (surrounding whitespace ignored).
pub fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim().as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = nib(s[2 * i])? << 4 | nib(s[2 * i + 1])?;
    }
    Some(out)
}

/// A P-256 signing key from 64 hex characters (a test identity file).
pub fn signing_key_from_hex(s: &str) -> Option<SigningKey> {
    SigningKey::from_slice(&from_hex::<32>(s)?).ok()
}

/// The SEC1 compressed public key of `key`.
pub fn public_key(key: &SigningKey) -> [u8; 33] {
    p256_compressed_key(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_slice(&[b; 32]).unwrap()
    }

    /// Per-test nonce, derived from the test name so each fixture is distinct and deterministic.
    fn nonce(tag: &str) -> [u8; 16] {
        let d = Sha256::digest(tag.as_bytes());
        let mut n = [0u8; 16];
        n.copy_from_slice(&d[..16]);
        n
    }

    fn job() -> MatmulU32 {
        MatmulU32 {
            m: 7,
            k: 5,
            n: 3,
            seed: 0xA1E7_0001,
        }
    }

    fn bundle_with(payload: &[u8], op: u8, sub: &SigningKey) -> Vec<u8> {
        let doc = build_document(payload, op, nonce("bundle_with"), &public_key(sub), NOW);
        seal_bundle(&doc, payload, sub)
    }

    fn bundle() -> Vec<u8> {
        bundle_with(&job().encode(), compute_op::MATMUL, &key(1))
    }

    fn admitted() -> Admitted {
        admit_bundle(&bundle(), &public_key(&key(1)), NOW).unwrap()
    }

    fn receipt_for(a: &Admitted, out: [u8; 32], exec: &SigningKey) -> [u8; RECEIPT_LEN] {
        executor_receipt(a, out, 5, [0x5C; 32], [0x9F; 32], exec)
    }

    #[test]
    fn payload_round_trip_and_core_662_layout() {
        let p = job().encode();
        assert_eq!(p.len(), 15);
        assert_eq!(p[0], 1);
        assert_eq!(&p[1..7], &[0, 7, 0, 5, 0, 3]);
        assert_eq!(MatmulU32::decode(&p).unwrap(), job());
    }

    #[test]
    fn kernel_matches_naive_ijk() {
        for j in [
            MatmulU32 {
                m: 1,
                k: 1,
                n: 1,
                seed: 0,
            },
            job(),
            MatmulU32 {
                m: 16,
                k: 9,
                n: 31,
                seed: u64::MAX,
            },
        ] {
            let (m, k, n) = (j.m as usize, j.k as usize, j.n as usize);
            let mut s = j.seed;
            let a: Vec<u32> = (0..m * k).map(|_| splitmix64(&mut s) as u32).collect();
            let b: Vec<u32> = (0..k * n).map(|_| splitmix64(&mut s) as u32).collect();
            let mut h = Sha256::new();
            h.update(MATMUL_DOMAIN);
            h.update(j.m.to_be_bytes());
            h.update(j.k.to_be_bytes());
            h.update(j.n.to_be_bytes());
            h.update(j.seed.to_be_bytes());
            for i in 0..m {
                for q in 0..n {
                    let mut acc = 0u32;
                    for p in 0..k {
                        acc = acc.wrapping_add(a[i * k + p].wrapping_mul(b[p * n + q]));
                    }
                    h.update(acc.to_be_bytes());
                }
            }
            let want: [u8; 32] = h.finalize().into();
            assert_eq!(matmul_u32_digest(&j), want);
        }
    }

    #[test]
    fn built_document_is_valid_mjb1() {
        let doc = build_document(
            &job().encode(),
            compute_op::MATMUL,
            nonce("built_document_is_valid_mjb1"),
            &public_key(&key(1)),
            NOW,
        );
        assert!(crate::verdict_line(&doc).starts_with("ok nodes=1 "));
    }

    #[test]
    fn admits_the_allowlisted_job() {
        let a = admitted();
        assert_eq!(a.job, job());
        assert_eq!(a.payload, job().encode());
    }

    #[test]
    fn refuses_unpinned_submitter() {
        let b = bundle_with(&job().encode(), compute_op::MATMUL, &key(2));
        assert_eq!(
            admit_bundle(&b, &public_key(&key(1)), NOW).unwrap_err(),
            An0Refusal::BadSubmitter
        );
    }

    #[test]
    fn refuses_bad_submitter_signature() {
        let mut b = bundle();
        b[50] ^= 1;
        assert_eq!(
            admit_bundle(&b, &public_key(&key(1)), NOW).unwrap_err(),
            An0Refusal::BadSubmitter
        );
    }

    #[test]
    fn refuses_a_changed_document() {
        let mut b = bundle();
        let last = b.len() - 1;
        b[last] ^= 1;
        assert_eq!(
            admit_bundle(&b, &public_key(&key(1)), NOW).unwrap_err(),
            An0Refusal::BadSubmitter
        );
    }

    #[test]
    fn refuses_op_not_on_allowlist() {
        let b = bundle_with(&job().encode(), compute_op::COMPILE, &key(1));
        assert_eq!(
            admit_bundle(&b, &public_key(&key(1)), NOW).unwrap_err(),
            An0Refusal::NotAllowlisted
        );
    }

    #[test]
    fn refuses_payload_kind_not_on_allowlist() {
        let mut p = job().encode();
        p[0] = 2;
        let b = bundle_with(&p, compute_op::MATMUL, &key(1));
        assert_eq!(
            admit_bundle(&b, &public_key(&key(1)), NOW).unwrap_err(),
            An0Refusal::NotAllowlisted
        );
    }

    #[test]
    fn refuses_over_budget_dimensions() {
        let big = MatmulU32 {
            m: 512,
            k: 4,
            n: 4,
            seed: 1,
        };
        let b = bundle_with(&big.encode(), compute_op::MATMUL, &key(1));
        assert_eq!(
            admit_bundle(&b, &public_key(&key(1)), NOW).unwrap_err(),
            An0Refusal::OverBudget
        );
    }

    #[test]
    fn refuses_caps_below_the_job() {
        let p = job().encode();
        let sub = key(1);
        let doc = build_document(
            &p,
            compute_op::MATMUL,
            nonce("refuses_caps_below_the_job"),
            &public_key(&sub),
            NOW,
        );
        let mut d = decode(&doc).unwrap();
        d.nodes[0].work = 1;
        let b = seal_bundle(&encode(&d).unwrap(), &p, &sub);
        assert_eq!(
            admit_bundle(&b, &public_key(&sub), NOW).unwrap_err(),
            An0Refusal::OverBudget
        );
    }

    #[test]
    fn refuses_a_payload_the_operand_does_not_name() {
        let sub = key(1);
        let doc = build_document(
            &job().encode(),
            compute_op::MATMUL,
            nonce("refuses_a_payload_the_operand_does_not_name"),
            &public_key(&sub),
            NOW,
        );
        let other = MatmulU32 { seed: 2, ..job() }.encode();
        let b = seal_bundle(&doc, &other, &sub);
        assert_eq!(
            admit_bundle(&b, &public_key(&sub), NOW).unwrap_err(),
            An0Refusal::PayloadMismatch
        );
    }

    #[test]
    fn refuses_an_expired_document() {
        assert_eq!(
            admit_bundle(&bundle(), &public_key(&key(1)), NOW + DOCUMENT_TTL + 1).unwrap_err(),
            An0Refusal::Mjb(Refusal::BadExpiry)
        );
    }

    #[test]
    fn full_path_verifies_and_countersigns() {
        let a = admitted();
        let out = matmul_u32_digest(&a.job);
        let r = receipt_for(&a, out, &key(3));
        let got = check_receipt(&a.document, &r, public_key(&key(3)), NOW).unwrap();
        assert_eq!(got.output_digest, out);
        let rec = countersign(&r, out, &key(4)).unwrap();
        check_countersign(&rec, &r, &public_key(&key(4))).unwrap();
    }

    #[test]
    fn refuses_receipt_from_unpinned_executor() {
        let a = admitted();
        let r = receipt_for(&a, matmul_u32_digest(&a.job), &key(5));
        assert_eq!(
            check_receipt(&a.document, &r, public_key(&key(3)), NOW).unwrap_err(),
            An0Refusal::Mjb(Refusal::ForgedReceipt)
        );
    }

    #[test]
    fn refuses_receipt_changed_after_signing() {
        let a = admitted();
        let mut r = receipt_for(&a, matmul_u32_digest(&a.job), &key(3));
        r[150] ^= 1;
        assert_eq!(
            check_receipt(&a.document, &r, public_key(&key(3)), NOW).unwrap_err(),
            An0Refusal::Mjb(Refusal::ForgedReceipt)
        );
    }

    #[test]
    fn refuses_signed_wrong_output() {
        let a = admitted();
        let good = matmul_u32_digest(&a.job);
        let mut bad = good;
        bad[0] ^= 1;
        let r = receipt_for(&a, bad, &key(3));
        check_receipt(&a.document, &r, public_key(&key(3)), NOW).unwrap();
        assert_eq!(
            countersign(&r, good, &key(4)).unwrap_err(),
            An0Refusal::RecomputeMismatch
        );
    }

    #[test]
    fn refuses_wrong_verdict_commitment() {
        let a = admitted();
        let out = matmul_u32_digest(&a.job);
        let mut r = decode_receipt(&receipt_for(&a, out, &key(3))).unwrap();
        r.verifier_verdict = [0x77; 32];
        sign_receipt(&mut r, &key(3));
        let bytes = encode_receipt(&r);
        assert_eq!(
            countersign(&bytes, out, &key(4)).unwrap_err(),
            An0Refusal::VerdictMismatch
        );
    }

    #[test]
    fn refuses_countersign_from_unpinned_verifier() {
        let a = admitted();
        let out = matmul_u32_digest(&a.job);
        let r = receipt_for(&a, out, &key(3));
        let rec = countersign(&r, out, &key(6)).unwrap();
        assert_eq!(
            check_countersign(&rec, &r, &public_key(&key(4))).unwrap_err(),
            An0Refusal::BadCountersign
        );
    }

    #[test]
    fn refuses_countersign_with_forged_signature() {
        let a = admitted();
        let out = matmul_u32_digest(&a.job);
        let r = receipt_for(&a, out, &key(3));
        let mut rec = countersign(&r, out, &key(4)).unwrap();
        rec[VERDICT_SIGNED_LEN + 7] ^= 1;
        assert_eq!(
            check_countersign(&rec, &r, &public_key(&key(4))).unwrap_err(),
            An0Refusal::BadCountersign
        );
    }

    #[test]
    fn receipt_round_trips_through_the_ledger_once() {
        let a = admitted();
        let r = receipt_for(&a, matmul_u32_digest(&a.job), &key(3));
        let mut run = DagRun::admit(&a.document, vec![public_key(&key(3))], NOW).unwrap();
        assert_eq!(run.apply(&r).unwrap(), Applied::New);
        assert_eq!(run.apply(&r).unwrap(), Applied::Replay);
    }
}
