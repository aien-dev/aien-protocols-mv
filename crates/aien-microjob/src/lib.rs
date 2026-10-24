//! MJB1, the typed bounded microjob DAG, and MJR1, its receipt.
//!
//! Spec: `specs/microjob/SPEC.md` (Draft v0.1, contract 0.1.0, wire version
//! 1). The C reference checker is `specs/microjob/tools/mjb_verify.c`; this
//! crate gives the same verdict on the same document bytes (the test in
//! `tests/vectors.rs` walks the shared vectors).
//!
//! A valid document is a proposal, not an authorization, and a node is not a
//! receipt. [`DagRun`] is the receipt ledger of section 5: it derives node
//! state from accepted bytes and chooses nothing (it is not a scheduler).
#![forbid(unsafe_code)]

use aien_provenance::{p256_compressed_key, p256_sign_low_s, p256_verify_low_s};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

/// Bytes in the document header.
pub const HEADER_LEN: usize = 192;
/// Bytes in one node record.
pub const NODE_LEN: usize = 448;
/// Most nodes in one document.
pub const MAX_NODES: usize = 64;
/// Dependency slots per node.
pub const MAX_DEPS: usize = 8;
/// Operand slots per node.
pub const MAX_OPERANDS: usize = 4;
/// Largest document.
pub const MAX_DOCUMENT: usize = HEADER_LEN + MAX_NODES * NODE_LEN;
/// The four bytes that open a document.
pub const MAGIC: [u8; 4] = *b"MJB1";
/// The four bytes that open a receipt.
pub const RECEIPT_MAGIC: [u8; 4] = *b"MJR1";
/// The only wire version.
pub const VERSION: u8 = 1;
/// Bytes in one receipt.
pub const RECEIPT_LEN: usize = 404;
/// Bytes of a receipt covered by its signature and its digest.
pub const RECEIPT_SIGNED_LEN: usize = 340;

/// Node `kind` values.
pub mod kind {
    pub const COMPUTE: u8 = 1;
    pub const NEURAL: u8 = 2;
}
/// COMPUTE `op` values.
pub mod compute_op {
    pub const ARITH: u8 = 1;
    pub const MATMUL: u8 = 2;
    pub const REDUCE: u8 = 3;
    pub const COMPARE: u8 = 4;
    pub const COMPILE: u8 = 5;
    pub const VERIFY: u8 = 6;
}
/// NEURAL `op` values.
pub mod neural_op {
    pub const ROUTE: u8 = 1;
    pub const EXTRACT: u8 = 2;
    pub const PROPOSE: u8 = 3;
    pub const SUMMARIZE: u8 = 4;
}
/// Token `profile` values (section 4.3).
pub mod profile {
    pub const ZERO: u8 = 0;
    pub const MINIMAL: u8 = 1;
    pub const DEFAULT: u8 = 2;
    pub const LARGE: u8 = 3;
    pub const SPECIALIST: u8 = 4;
}
/// `effect_class` and `effect_ceiling` values (same as PST1).
pub mod effect {
    pub const NONE: u8 = 0;
    pub const COMPUTE: u8 = 1;
    pub const EFFECT: u8 = 2;
}
/// `verifier_kind` values.
pub mod verifier {
    pub const RECOMPUTE: u8 = 1;
    pub const CHECKER: u8 = 2;
    pub const JUDGE: u8 = 3;
}
/// `retry_class` values.
pub mod retry {
    pub const NEVER: u8 = 1;
    pub const IDEMPOTENT: u8 = 2;
    pub const RECONCILE_FIRST: u8 = 3;
}
/// `cancel_mode` values.
pub mod cancel {
    pub const DISCARD: u8 = 1;
    pub const CHECKPOINT: u8 = 2;
}
/// Operand `kind` values.
pub mod operand {
    pub const CORTEX_STATE: u8 = 1;
    pub const WORLD_STATE: u8 = 2;
    pub const CONTENT: u8 = 3;
    pub const CAPSULE: u8 = 4;
    pub const EXPERIENCE: u8 = 5;
}
/// Receipt `outcome` values.
pub mod outcome {
    pub const COMPLETED: u8 = 1;
    pub const REFUSED: u8 = 2;
    pub const FAILED: u8 = 3;
    pub const CANCELLED: u8 = 4;
    pub const UNCERTAIN: u8 = 5;
}

/// Input and output token caps of a profile, `None` for an unknown profile.
pub fn profile_caps(p: u8) -> Option<(u16, u16)> {
    match p {
        profile::ZERO => Some((0, 0)),
        profile::MINIMAL => Some((64, 16)),
        profile::DEFAULT => Some((128, 32)),
        profile::LARGE => Some((256, 64)),
        profile::SPECIALIST => Some((512, 128)),
        _ => None,
    }
}

/// A refusal code from SPEC.md section 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadLength,
    BadMagic,
    Downgrade,
    BadVersion,
    BadCount,
    ReservedNonzero,
    BadEnum,
    NoObjective,
    NoTenant,
    NoSubject,
    NoApproval,
    BadExpiry,
    NoJob,
    CrossTenant,
    NoCapability,
    UnauthorizedEffect,
    NoVerifier,
    Impure,
    TokenProfile,
    NeedsExpansion,
    BadRetry,
    ZeroCap,
    MissingOperand,
    DuplicateJob,
    MissingDep,
    StaleGeneration,
    Cycle,
    OverBudget,
    BadReceipt,
    ForgedReceipt,
    WrongDag,
    UnknownJob,
    ModelMismatch,
    ReceiptOverBudget,
    DepNotDone,
    BindingMismatch,
    DoubleCommit,
    Cancelled,
}

impl Refusal {
    /// The code name as written in SPEC.md and printed by the C checker.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::BadLength => "MJB_BAD_LENGTH",
            Refusal::BadMagic => "MJB_BAD_MAGIC",
            Refusal::Downgrade => "MJB_DOWNGRADE",
            Refusal::BadVersion => "MJB_BAD_VERSION",
            Refusal::BadCount => "MJB_BAD_COUNT",
            Refusal::ReservedNonzero => "MJB_RESERVED_NONZERO",
            Refusal::BadEnum => "MJB_BAD_ENUM",
            Refusal::NoObjective => "MJB_NO_OBJECTIVE",
            Refusal::NoTenant => "MJB_NO_TENANT",
            Refusal::NoSubject => "MJB_NO_SUBJECT",
            Refusal::NoApproval => "MJB_NO_APPROVAL",
            Refusal::BadExpiry => "MJB_BAD_EXPIRY",
            Refusal::NoJob => "MJB_NO_JOB",
            Refusal::CrossTenant => "MJB_CROSS_TENANT",
            Refusal::NoCapability => "MJB_NO_CAPABILITY",
            Refusal::UnauthorizedEffect => "MJB_UNAUTHORIZED_EFFECT",
            Refusal::NoVerifier => "MJB_NO_VERIFIER",
            Refusal::Impure => "MJB_IMPURE",
            Refusal::TokenProfile => "MJB_TOKEN_PROFILE",
            Refusal::NeedsExpansion => "MJB_NEEDS_EXPANSION",
            Refusal::BadRetry => "MJB_BAD_RETRY",
            Refusal::ZeroCap => "MJB_ZERO_CAP",
            Refusal::MissingOperand => "MJB_MISSING_OPERAND",
            Refusal::DuplicateJob => "MJB_DUPLICATE_JOB",
            Refusal::MissingDep => "MJB_MISSING_DEP",
            Refusal::StaleGeneration => "MJB_STALE_GENERATION",
            Refusal::Cycle => "MJB_CYCLE",
            Refusal::OverBudget => "MJB_OVER_BUDGET",
            Refusal::BadReceipt => "MJB_BAD_RECEIPT",
            Refusal::ForgedReceipt => "MJB_FORGED_RECEIPT",
            Refusal::WrongDag => "MJB_WRONG_DAG",
            Refusal::UnknownJob => "MJB_UNKNOWN_JOB",
            Refusal::ModelMismatch => "MJB_MODEL_MISMATCH",
            Refusal::ReceiptOverBudget => "MJB_RECEIPT_OVER_BUDGET",
            Refusal::DepNotDone => "MJB_DEP_NOT_DONE",
            Refusal::BindingMismatch => "MJB_BINDING_MISMATCH",
            Refusal::DoubleCommit => "MJB_DOUBLE_COMMIT",
            Refusal::Cancelled => "MJB_CANCELLED",
        }
    }
}

/// The document header (section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub effect_ceiling: u8,
    pub objective_id: [u8; 32],
    pub tenant_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub approval_ref: [u8; 32],
    pub incarnation: u32,
    pub expires_at: u64,
    pub budget_time_ms: u64,
    pub budget_fuel: u64,
    pub budget_memory: u64,
    pub budget_work: u64,
    pub budget_input_tokens: u32,
    pub budget_output_tokens: u32,
}

/// One dependency slot: a node of the same document and the generation of
/// that node this node was planned against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dep {
    pub index: u16,
    pub generation: u32,
}

/// One typed operand reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: u8,
    pub generation: u32,
    pub digest: [u8; 32],
}

/// One node record (section 4.2). `deps` and `operands` hold the used slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub job_id: [u8; 16],
    pub idempotence_key: [u8; 16],
    pub generation: u32,
    pub kind: u8,
    pub op: u8,
    pub profile: u8,
    pub effect_class: u8,
    pub input_tokens: u16,
    pub output_tokens: u16,
    pub required_input_tokens: u16,
    pub required_output_tokens: u16,
    pub verifier_kind: u8,
    pub retry_class: u8,
    pub max_attempts: u8,
    pub cancel_mode: u8,
    pub precision: u8,
    pub substrate_mask: u8,
    pub result_type: u8,
    pub result_rank: u8,
    pub pure: bool,
    pub time_ms: u32,
    pub fuel: u64,
    pub memory: u64,
    pub work: u64,
    pub expires_at: u64,
    pub result_dims: [u32; 4],
    pub capability_ref: [u8; 32],
    pub tenant_id: [u8; 32],
    pub model_ref: [u8; 32],
    pub verifier_ref: [u8; 32],
    pub deps: Vec<Dep>,
    pub operands: Vec<Operand>,
}

/// One accepted document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dag {
    pub header: Header,
    pub nodes: Vec<Node>,
}

/// Why [`encode`] could not write a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    TooManyNodes,
    TooManyDeps,
    TooManyOperands,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(arr(b, at))
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(arr(b, at))
}
fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&b[at..at + N]);
    out
}
fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

const H_MAGIC: usize = 0;
const H_VERSION: usize = 4;
const H_CEILING: usize = 5;
const H_COUNT: usize = 6;
const H_OBJECTIVE: usize = 8;
const H_TENANT: usize = 40;
const H_SUBJECT: usize = 72;
const H_APPROVAL: usize = 104;
const H_INCARNATION: usize = 136;
const H_RES0: usize = 140;
const H_EXPIRES: usize = 144;
const H_B_TIME: usize = 152;
const H_B_FUEL: usize = 160;
const H_B_MEMORY: usize = 168;
const H_B_WORK: usize = 176;
const H_B_IN: usize = 184;
const H_B_OUT: usize = 188;

const N_JOB: usize = 0;
const N_IDEM: usize = 16;
const N_GEN: usize = 32;
const N_KIND: usize = 36;
const N_OP: usize = 37;
const N_PROFILE: usize = 38;
const N_EFFECT: usize = 39;
const N_IN: usize = 40;
const N_OUT: usize = 42;
const N_REQ_IN: usize = 44;
const N_REQ_OUT: usize = 46;
const N_VERIFIER: usize = 48;
const N_RETRY: usize = 49;
const N_ATTEMPTS: usize = 50;
const N_CANCEL: usize = 51;
const N_PRECISION: usize = 52;
const N_SUBSTRATE: usize = 53;
const N_DEPS_N: usize = 54;
const N_OPS_N: usize = 55;
const N_RTYPE: usize = 56;
const N_RANK: usize = 57;
const N_PURE: usize = 58;
const N_RES1: usize = 59;
const N_TIME: usize = 60;
const N_FUEL: usize = 64;
const N_MEMORY: usize = 72;
const N_WORK: usize = 80;
const N_EXPIRES: usize = 88;
const N_DIMS: usize = 96;
const N_CAP: usize = 112;
const N_TENANT: usize = 144;
const N_MODEL: usize = 176;
const N_VREF: usize = 208;
const N_DEPS: usize = 240;
const DEP_LEN: usize = 6;
const N_OPERANDS: usize = 288;
const OPERAND_LEN: usize = 40;

/// Static per-node checks (section 4.4 rules 10 to 23) on the raw record.
fn check_node(n: &[u8], h: &[u8]) -> Result<(), Refusal> {
    // Rule 10.
    if all_zero(&n[N_JOB..N_JOB + 16]) || all_zero(&n[N_IDEM..N_IDEM + 16]) || u32_at(n, N_GEN) == 0
    {
        return Err(Refusal::NoJob);
    }
    let dep_count = n[N_DEPS_N] as usize;
    let op_count = n[N_OPS_N] as usize;
    let rank = n[N_RANK] as usize;
    // Rule 11.
    let mut reserved_bad = n[N_RES1] != 0;
    for s in dep_count.min(MAX_DEPS)..MAX_DEPS {
        let at = N_DEPS + s * DEP_LEN;
        reserved_bad |= !all_zero(&n[at..at + DEP_LEN]);
    }
    for s in 0..MAX_OPERANDS {
        let at = N_OPERANDS + s * OPERAND_LEN;
        if s < op_count {
            reserved_bad |= !all_zero(&n[at + 1..at + 4]);
        } else {
            reserved_bad |= !all_zero(&n[at..at + OPERAND_LEN]);
        }
    }
    for d in rank.min(4)..4 {
        reserved_bad |= u32_at(n, N_DIMS + 4 * d) != 0;
    }
    if reserved_bad {
        return Err(Refusal::ReservedNonzero);
    }
    // Rule 12.
    let k = n[N_KIND];
    let op = n[N_OP];
    let op_ok = match k {
        kind::COMPUTE => (1..=6).contains(&op),
        kind::NEURAL => (1..=4).contains(&op),
        _ => false,
    };
    let operand_kinds_ok =
        (0..op_count.min(MAX_OPERANDS)).all(|s| (1..=5).contains(&n[N_OPERANDS + s * OPERAND_LEN]));
    if !op_ok
        || n[N_PROFILE] > profile::SPECIALIST
        || n[N_EFFECT] > effect::EFFECT
        || n[N_VERIFIER] > verifier::JUDGE
        || !(1..=3).contains(&n[N_RETRY])
        || !(1..=8).contains(&n[N_ATTEMPTS])
        || !(1..=2).contains(&n[N_CANCEL])
        || n[N_PRECISION] > 6
        || n[N_SUBSTRATE] == 0
        || n[N_SUBSTRATE] & 0xF8 != 0
        || dep_count > MAX_DEPS
        || op_count > MAX_OPERANDS
        || !(1..=7).contains(&n[N_RTYPE])
        || rank > 4
        || n[N_PURE] > 1
        || !operand_kinds_ok
    {
        return Err(Refusal::BadEnum);
    }
    // Rule 13.
    if n[N_TENANT..N_TENANT + 32] != h[H_TENANT..H_TENANT + 32] {
        return Err(Refusal::CrossTenant);
    }
    // Rule 14.
    if all_zero(&n[N_CAP..N_CAP + 32]) {
        return Err(Refusal::NoCapability);
    }
    // Rule 15.
    if n[N_EFFECT] > h[H_CEILING] {
        return Err(Refusal::UnauthorizedEffect);
    }
    // Rule 16.
    let vk = n[N_VERIFIER];
    let vref_zero = all_zero(&n[N_VREF..N_VREF + 32]);
    let pure = n[N_PURE] == 1;
    if vk == 0
        || (vk != verifier::RECOMPUTE && vref_zero)
        || (vk == verifier::RECOMPUTE && (!vref_zero || !pure))
    {
        return Err(Refusal::NoVerifier);
    }
    // Rule 17.
    if pure && (k == kind::NEURAL || n[N_EFFECT] == effect::EFFECT) {
        return Err(Refusal::Impure);
    }
    // Rule 18.
    let (cap_in, cap_out) = profile_caps(n[N_PROFILE]).unwrap_or((0, 0));
    let tin = u16_at(n, N_IN);
    let tout = u16_at(n, N_OUT);
    let rin = u16_at(n, N_REQ_IN);
    let rout = u16_at(n, N_REQ_OUT);
    let model_zero = all_zero(&n[N_MODEL..N_MODEL + 32]);
    let profile_bad = if k == kind::COMPUTE {
        n[N_PROFILE] != profile::ZERO
            || tin != 0
            || tout != 0
            || rin != 0
            || rout != 0
            || !model_zero
    } else {
        n[N_PROFILE] == profile::ZERO
            || tin == 0
            || tout == 0
            || tin > cap_in
            || tout > cap_out
            || model_zero
    };
    if profile_bad {
        return Err(Refusal::TokenProfile);
    }
    // Rule 19.
    if rin > tin || rout > tout {
        return Err(Refusal::NeedsExpansion);
    }
    // Rule 20.
    if (n[N_RETRY] == retry::NEVER && n[N_ATTEMPTS] > 1)
        || (n[N_EFFECT] == effect::EFFECT && n[N_RETRY] == retry::IDEMPOTENT)
    {
        return Err(Refusal::BadRetry);
    }
    // Rule 21.
    if u32_at(n, N_TIME) == 0
        || u64_at(n, N_FUEL) == 0
        || u64_at(n, N_MEMORY) == 0
        || u64_at(n, N_WORK) == 0
    {
        return Err(Refusal::ZeroCap);
    }
    // Rule 22.
    let exp = u64_at(n, N_EXPIRES);
    if exp == 0 || exp > u64_at(h, H_EXPIRES) {
        return Err(Refusal::BadExpiry);
    }
    // Rule 23.
    for s in 0..op_count {
        let at = N_OPERANDS + s * OPERAND_LEN;
        if u32_at(n, at + 4) == 0 || all_zero(&n[at + 8..at + 40]) {
            return Err(Refusal::MissingOperand);
        }
    }
    Ok(())
}

fn parse_node(n: &[u8]) -> Node {
    let deps = (0..n[N_DEPS_N] as usize)
        .map(|s| {
            let at = N_DEPS + s * DEP_LEN;
            Dep {
                index: u16_at(n, at),
                generation: u32_at(n, at + 2),
            }
        })
        .collect();
    let operands = (0..n[N_OPS_N] as usize)
        .map(|s| {
            let at = N_OPERANDS + s * OPERAND_LEN;
            Operand {
                kind: n[at],
                generation: u32_at(n, at + 4),
                digest: arr(n, at + 8),
            }
        })
        .collect();
    Node {
        job_id: arr(n, N_JOB),
        idempotence_key: arr(n, N_IDEM),
        generation: u32_at(n, N_GEN),
        kind: n[N_KIND],
        op: n[N_OP],
        profile: n[N_PROFILE],
        effect_class: n[N_EFFECT],
        input_tokens: u16_at(n, N_IN),
        output_tokens: u16_at(n, N_OUT),
        required_input_tokens: u16_at(n, N_REQ_IN),
        required_output_tokens: u16_at(n, N_REQ_OUT),
        verifier_kind: n[N_VERIFIER],
        retry_class: n[N_RETRY],
        max_attempts: n[N_ATTEMPTS],
        cancel_mode: n[N_CANCEL],
        precision: n[N_PRECISION],
        substrate_mask: n[N_SUBSTRATE],
        result_type: n[N_RTYPE],
        result_rank: n[N_RANK],
        pure: n[N_PURE] == 1,
        time_ms: u32_at(n, N_TIME),
        fuel: u64_at(n, N_FUEL),
        memory: u64_at(n, N_MEMORY),
        work: u64_at(n, N_WORK),
        expires_at: u64_at(n, N_EXPIRES),
        result_dims: [
            u32_at(n, N_DIMS),
            u32_at(n, N_DIMS + 4),
            u32_at(n, N_DIMS + 8),
            u32_at(n, N_DIMS + 12),
        ],
        capability_ref: arr(n, N_CAP),
        tenant_id: arr(n, N_TENANT),
        model_ref: arr(n, N_MODEL),
        verifier_ref: arr(n, N_VREF),
        deps,
        operands,
    }
}

/// The canonical execution order: Kahn's algorithm taking the lowest-index
/// ready node first. `None` when the graph has a cycle. Dependency indexes
/// must already be in range.
pub fn canonical_order(nodes: &[Node]) -> Option<Vec<usize>> {
    let n = nodes.len();
    let mut indeg: Vec<usize> = nodes.iter().map(|x| x.deps.len()).collect();
    let mut emitted = vec![false; n];
    let mut order = Vec::with_capacity(n);
    while order.len() < n {
        let next = (0..n).find(|&i| !emitted[i] && indeg[i] == 0)?;
        emitted[next] = true;
        order.push(next);
        for (i, node) in nodes.iter().enumerate() {
            for d in &node.deps {
                if d.index as usize == next {
                    indeg[i] -= 1;
                }
            }
        }
    }
    Some(order)
}

/// Decode and check one document in the order of SPEC.md section 4.4, the
/// same order as the C checker, so the same bytes give the same code.
pub fn decode(b: &[u8]) -> Result<Dag, Refusal> {
    if b.len() < HEADER_LEN {
        return Err(Refusal::BadLength);
    }
    if b[H_MAGIC..H_MAGIC + 4] != MAGIC {
        return Err(Refusal::BadMagic);
    }
    if b[H_VERSION] == 0 {
        return Err(Refusal::Downgrade);
    }
    if b[H_VERSION] > VERSION {
        return Err(Refusal::BadVersion);
    }
    let count = u16_at(b, H_COUNT) as usize;
    if count == 0 || count > MAX_NODES {
        return Err(Refusal::BadCount);
    }
    if b.len() != HEADER_LEN + count * NODE_LEN {
        return Err(Refusal::BadLength);
    }
    if !all_zero(&b[H_RES0..H_RES0 + 4]) {
        return Err(Refusal::ReservedNonzero);
    }
    if b[H_CEILING] > effect::EFFECT {
        return Err(Refusal::BadEnum);
    }
    if all_zero(&b[H_OBJECTIVE..H_OBJECTIVE + 32]) {
        return Err(Refusal::NoObjective);
    }
    if all_zero(&b[H_TENANT..H_TENANT + 32]) {
        return Err(Refusal::NoTenant);
    }
    if all_zero(&b[H_SUBJECT..H_SUBJECT + 32]) {
        return Err(Refusal::NoSubject);
    }
    if all_zero(&b[H_APPROVAL..H_APPROVAL + 32]) {
        return Err(Refusal::NoApproval);
    }
    if u32_at(b, H_INCARNATION) == 0 {
        return Err(Refusal::NoObjective);
    }
    let h = &b[..HEADER_LEN];
    let mut nodes = Vec::with_capacity(count);
    for i in 0..count {
        let rec = &b[HEADER_LEN + i * NODE_LEN..HEADER_LEN + (i + 1) * NODE_LEN];
        check_node(rec, h)?;
        nodes.push(parse_node(rec));
    }
    // Rule 24.
    for i in 0..count {
        for j in i + 1..count {
            if nodes[i].job_id == nodes[j].job_id
                || nodes[i].idempotence_key == nodes[j].idempotence_key
            {
                return Err(Refusal::DuplicateJob);
            }
        }
    }
    // Rule 25.
    for (i, node) in nodes.iter().enumerate() {
        if node
            .deps
            .iter()
            .any(|d| d.index as usize == i || d.index as usize >= count)
        {
            return Err(Refusal::MissingDep);
        }
    }
    // Rule 26.
    for node in &nodes {
        if node
            .deps
            .iter()
            .any(|d| d.generation != nodes[d.index as usize].generation)
        {
            return Err(Refusal::StaleGeneration);
        }
    }
    // Rule 27.
    if canonical_order(&nodes).is_none() {
        return Err(Refusal::Cycle);
    }
    // Rule 28.
    let sum = |f: &dyn Fn(&Node) -> u128| nodes.iter().map(f).sum::<u128>();
    let header = Header {
        effect_ceiling: b[H_CEILING],
        objective_id: arr(b, H_OBJECTIVE),
        tenant_id: arr(b, H_TENANT),
        subject_id: arr(b, H_SUBJECT),
        approval_ref: arr(b, H_APPROVAL),
        incarnation: u32_at(b, H_INCARNATION),
        expires_at: u64_at(b, H_EXPIRES),
        budget_time_ms: u64_at(b, H_B_TIME),
        budget_fuel: u64_at(b, H_B_FUEL),
        budget_memory: u64_at(b, H_B_MEMORY),
        budget_work: u64_at(b, H_B_WORK),
        budget_input_tokens: u32_at(b, H_B_IN),
        budget_output_tokens: u32_at(b, H_B_OUT),
    };
    if sum(&|x| x.time_ms as u128) > header.budget_time_ms as u128
        || sum(&|x| x.fuel as u128) > header.budget_fuel as u128
        || sum(&|x| x.work as u128) > header.budget_work as u128
        || sum(&|x| x.input_tokens as u128) > header.budget_input_tokens as u128
        || sum(&|x| x.output_tokens as u128) > header.budget_output_tokens as u128
        || nodes.iter().any(|x| x.memory > header.budget_memory)
    {
        return Err(Refusal::OverBudget);
    }
    Ok(Dag { header, nodes })
}

/// Write one document. Fields are written exactly as given; nothing is
/// checked beyond the slot counts (use [`decode`] to check).
pub fn encode(d: &Dag) -> Result<Vec<u8>, EncodeError> {
    if d.nodes.len() > MAX_NODES {
        return Err(EncodeError::TooManyNodes);
    }
    let mut b = vec![0u8; HEADER_LEN + d.nodes.len() * NODE_LEN];
    let h = &d.header;
    b[H_MAGIC..H_MAGIC + 4].copy_from_slice(&MAGIC);
    b[H_VERSION] = VERSION;
    b[H_CEILING] = h.effect_ceiling;
    b[H_COUNT..H_COUNT + 2].copy_from_slice(&(d.nodes.len() as u16).to_be_bytes());
    b[H_OBJECTIVE..H_OBJECTIVE + 32].copy_from_slice(&h.objective_id);
    b[H_TENANT..H_TENANT + 32].copy_from_slice(&h.tenant_id);
    b[H_SUBJECT..H_SUBJECT + 32].copy_from_slice(&h.subject_id);
    b[H_APPROVAL..H_APPROVAL + 32].copy_from_slice(&h.approval_ref);
    b[H_INCARNATION..H_INCARNATION + 4].copy_from_slice(&h.incarnation.to_be_bytes());
    b[H_EXPIRES..H_EXPIRES + 8].copy_from_slice(&h.expires_at.to_be_bytes());
    b[H_B_TIME..H_B_TIME + 8].copy_from_slice(&h.budget_time_ms.to_be_bytes());
    b[H_B_FUEL..H_B_FUEL + 8].copy_from_slice(&h.budget_fuel.to_be_bytes());
    b[H_B_MEMORY..H_B_MEMORY + 8].copy_from_slice(&h.budget_memory.to_be_bytes());
    b[H_B_WORK..H_B_WORK + 8].copy_from_slice(&h.budget_work.to_be_bytes());
    b[H_B_IN..H_B_IN + 4].copy_from_slice(&h.budget_input_tokens.to_be_bytes());
    b[H_B_OUT..H_B_OUT + 4].copy_from_slice(&h.budget_output_tokens.to_be_bytes());
    for (i, x) in d.nodes.iter().enumerate() {
        if x.deps.len() > MAX_DEPS {
            return Err(EncodeError::TooManyDeps);
        }
        if x.operands.len() > MAX_OPERANDS {
            return Err(EncodeError::TooManyOperands);
        }
        let n = &mut b[HEADER_LEN + i * NODE_LEN..HEADER_LEN + (i + 1) * NODE_LEN];
        n[N_JOB..N_JOB + 16].copy_from_slice(&x.job_id);
        n[N_IDEM..N_IDEM + 16].copy_from_slice(&x.idempotence_key);
        n[N_GEN..N_GEN + 4].copy_from_slice(&x.generation.to_be_bytes());
        n[N_KIND] = x.kind;
        n[N_OP] = x.op;
        n[N_PROFILE] = x.profile;
        n[N_EFFECT] = x.effect_class;
        n[N_IN..N_IN + 2].copy_from_slice(&x.input_tokens.to_be_bytes());
        n[N_OUT..N_OUT + 2].copy_from_slice(&x.output_tokens.to_be_bytes());
        n[N_REQ_IN..N_REQ_IN + 2].copy_from_slice(&x.required_input_tokens.to_be_bytes());
        n[N_REQ_OUT..N_REQ_OUT + 2].copy_from_slice(&x.required_output_tokens.to_be_bytes());
        n[N_VERIFIER] = x.verifier_kind;
        n[N_RETRY] = x.retry_class;
        n[N_ATTEMPTS] = x.max_attempts;
        n[N_CANCEL] = x.cancel_mode;
        n[N_PRECISION] = x.precision;
        n[N_SUBSTRATE] = x.substrate_mask;
        n[N_DEPS_N] = x.deps.len() as u8;
        n[N_OPS_N] = x.operands.len() as u8;
        n[N_RTYPE] = x.result_type;
        n[N_RANK] = x.result_rank;
        n[N_PURE] = x.pure as u8;
        n[N_TIME..N_TIME + 4].copy_from_slice(&x.time_ms.to_be_bytes());
        n[N_FUEL..N_FUEL + 8].copy_from_slice(&x.fuel.to_be_bytes());
        n[N_MEMORY..N_MEMORY + 8].copy_from_slice(&x.memory.to_be_bytes());
        n[N_WORK..N_WORK + 8].copy_from_slice(&x.work.to_be_bytes());
        n[N_EXPIRES..N_EXPIRES + 8].copy_from_slice(&x.expires_at.to_be_bytes());
        for (k, dim) in x.result_dims.iter().enumerate() {
            n[N_DIMS + 4 * k..N_DIMS + 4 * k + 4].copy_from_slice(&dim.to_be_bytes());
        }
        n[N_CAP..N_CAP + 32].copy_from_slice(&x.capability_ref);
        n[N_TENANT..N_TENANT + 32].copy_from_slice(&x.tenant_id);
        n[N_MODEL..N_MODEL + 32].copy_from_slice(&x.model_ref);
        n[N_VREF..N_VREF + 32].copy_from_slice(&x.verifier_ref);
        for (s, dep) in x.deps.iter().enumerate() {
            let at = N_DEPS + s * DEP_LEN;
            n[at..at + 2].copy_from_slice(&dep.index.to_be_bytes());
            n[at + 2..at + 6].copy_from_slice(&dep.generation.to_be_bytes());
        }
        for (s, op) in x.operands.iter().enumerate() {
            let at = N_OPERANDS + s * OPERAND_LEN;
            n[at] = op.kind;
            n[at + 4..at + 8].copy_from_slice(&op.generation.to_be_bytes());
            n[at + 8..at + 40].copy_from_slice(&op.digest);
        }
    }
    Ok(b)
}

/// `dag_digest`: SHA-256 of the document bytes (section 3, rule 4).
pub fn dag_digest(document: &[u8]) -> [u8; 32] {
    Sha256::digest(document).into()
}

fn hex(out: &mut String, bytes: &[u8]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for &x in bytes {
        out.push(H[(x >> 4) as usize] as char);
        out.push(H[(x & 15) as usize] as char);
    }
}

/// The verdict line in the exact format of `mjb_verify FILE` and
/// `vectors/expected.txt`.
pub fn verdict_line(document: &[u8]) -> String {
    match decode(document) {
        Err(r) => format!("refuse {}", r.name()),
        Ok(d) => {
            let mut s = format!(
                "ok nodes={} incarnation={} ceiling={} objective=",
                d.nodes.len(),
                d.header.incarnation,
                d.header.effect_ceiling
            );
            hex(&mut s, &d.header.objective_id);
            s.push_str(" tenant=");
            hex(&mut s, &d.header.tenant_id);
            s.push_str(" digest=");
            hex(&mut s, &dag_digest(document));
            s.push_str(" order=");
            let order = canonical_order(&d.nodes).expect("decode checked acyclic");
            let parts: Vec<String> = order.iter().map(|i| i.to_string()).collect();
            s.push_str(&parts.join(","));
            s
        }
    }
}

/// One MJR1 receipt (section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub outcome: u8,
    pub attempt: u8,
    pub dag_digest: [u8; 32],
    pub job_id: [u8; 16],
    pub idempotence_key: [u8; 16],
    pub generation: u32,
    pub used_time_ms: u32,
    pub used_input_tokens: u16,
    pub used_output_tokens: u16,
    pub used_fuel: u64,
    pub used_memory: u64,
    pub used_work: u64,
    pub input_binding: [u8; 32],
    pub output_digest: [u8; 32],
    pub source_hash: [u8; 32],
    pub model_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub verifier_verdict: [u8; 32],
    pub signer_key: [u8; 33],
    pub signature: [u8; 64],
}

/// Write one receipt.
pub fn encode_receipt(r: &Receipt) -> [u8; RECEIPT_LEN] {
    let mut b = [0u8; RECEIPT_LEN];
    b[0..4].copy_from_slice(&RECEIPT_MAGIC);
    b[4] = VERSION;
    b[5] = r.outcome;
    b[6] = r.attempt;
    b[8..40].copy_from_slice(&r.dag_digest);
    b[40..56].copy_from_slice(&r.job_id);
    b[56..72].copy_from_slice(&r.idempotence_key);
    b[72..76].copy_from_slice(&r.generation.to_be_bytes());
    b[76..80].copy_from_slice(&r.used_time_ms.to_be_bytes());
    b[80..82].copy_from_slice(&r.used_input_tokens.to_be_bytes());
    b[82..84].copy_from_slice(&r.used_output_tokens.to_be_bytes());
    b[88..96].copy_from_slice(&r.used_fuel.to_be_bytes());
    b[96..104].copy_from_slice(&r.used_memory.to_be_bytes());
    b[104..112].copy_from_slice(&r.used_work.to_be_bytes());
    b[112..144].copy_from_slice(&r.input_binding);
    b[144..176].copy_from_slice(&r.output_digest);
    b[176..208].copy_from_slice(&r.source_hash);
    b[208..240].copy_from_slice(&r.model_hash);
    b[240..272].copy_from_slice(&r.policy_hash);
    b[272..304].copy_from_slice(&r.verifier_verdict);
    b[304..337].copy_from_slice(&r.signer_key);
    b[340..404].copy_from_slice(&r.signature);
    b
}

/// Decode one receipt and apply the static rules of section 5.2
/// (`MJB_BAD_RECEIPT`). The signature is not checked here.
pub fn decode_receipt(b: &[u8]) -> Result<Receipt, Refusal> {
    if b.len() != RECEIPT_LEN
        || b[0..4] != RECEIPT_MAGIC
        || b[4] != VERSION
        || b[7] != 0
        || !all_zero(&b[84..88])
        || !all_zero(&b[337..340])
        || !(outcome::COMPLETED..=outcome::UNCERTAIN).contains(&b[5])
        || b[6] == 0
        || (b[304] != 0x02 && b[304] != 0x03)
        || all_zero(&b[176..208])
        || all_zero(&b[240..272])
    {
        return Err(Refusal::BadReceipt);
    }
    let completed = b[5] == outcome::COMPLETED;
    if completed == all_zero(&b[144..176]) || (completed && all_zero(&b[272..304])) {
        return Err(Refusal::BadReceipt);
    }
    Ok(Receipt {
        outcome: b[5],
        attempt: b[6],
        dag_digest: arr(b, 8),
        job_id: arr(b, 40),
        idempotence_key: arr(b, 56),
        generation: u32_at(b, 72),
        used_time_ms: u32_at(b, 76),
        used_input_tokens: u16_at(b, 80),
        used_output_tokens: u16_at(b, 82),
        used_fuel: u64_at(b, 88),
        used_memory: u64_at(b, 96),
        used_work: u64_at(b, 104),
        input_binding: arr(b, 112),
        output_digest: arr(b, 144),
        source_hash: arr(b, 176),
        model_hash: arr(b, 208),
        policy_hash: arr(b, 240),
        verifier_verdict: arr(b, 272),
        signer_key: arr(b, 304),
        signature: arr(b, 340),
    })
}

/// `receipt_digest`: SHA-256 of the signed region (the signature excluded).
pub fn receipt_digest(r: &Receipt) -> [u8; 32] {
    Sha256::digest(&encode_receipt(r)[..RECEIPT_SIGNED_LEN]).into()
}

/// Fill `signer_key` from `key` and sign the receipt.
pub fn sign_receipt(r: &mut Receipt, key: &SigningKey) {
    r.signer_key = p256_compressed_key(key);
    let bytes = encode_receipt(r);
    r.signature = p256_sign_low_s(key, &bytes[..RECEIPT_SIGNED_LEN]);
}

/// The input binding of section 5.1 from dependency receipt digests (in slot
/// order) and the node's operands.
pub fn input_binding(dep_receipt_digests: &[[u8; 32]], operands: &[Operand]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MJR1-BIND");
    for d in dep_receipt_digests {
        h.update(d);
    }
    for op in operands {
        h.update([op.kind]);
        h.update(op.generation.to_be_bytes());
        h.update(op.digest);
    }
    h.finalize().into()
}

/// Derived node state (section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Some dependency is not yet DONE.
    Waiting,
    /// Every dependency is DONE and no terminal receipt exists.
    Ready,
    /// A COMPLETED receipt was applied.
    Done,
    /// A REFUSED receipt was applied.
    Refused,
    /// A CANCELLED receipt was applied, or the objective was cancelled.
    Cancelled,
    /// FAILED or UNCERTAIN on the last allowed attempt.
    Exhausted,
    /// The last attempt is UNCERTAIN and another is allowed after
    /// reconciliation against the effect ledger.
    Uncertain,
    /// A dependency is REFUSED, CANCELLED, EXHAUSTED or BLOCKED.
    Blocked,
}

/// Whether [`DagRun::apply`] changed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    New,
    Replay,
}

#[derive(Debug, Clone, Default)]
struct Slot {
    /// Every receipt applied to this node, in order.
    applied: Vec<[u8; RECEIPT_LEN]>,
    last_outcome: u8,
    last_attempt: u8,
    /// Digest of the COMPLETED receipt.
    done: Option<[u8; 32]>,
    output: Option<[u8; 32]>,
}

/// The receipt ledger of one accepted document (section 5.2).
#[derive(Debug, Clone)]
pub struct DagRun {
    dag: Dag,
    digest: [u8; 32],
    trusted: Vec<[u8; 33]>,
    slots: Vec<Slot>,
    cancelled: bool,
    log: Vec<[u8; RECEIPT_LEN]>,
}

impl DagRun {
    /// Admit a document at the receiver's clock `now` (Unix seconds) with the
    /// receiver's own trusted executor keys. Expired documents are refused.
    pub fn admit(document: &[u8], trusted: Vec<[u8; 33]>, now: u64) -> Result<Self, Refusal> {
        let dag = decode(document)?;
        if dag.header.expires_at < now {
            return Err(Refusal::BadExpiry);
        }
        let n = dag.nodes.len();
        Ok(DagRun {
            dag,
            digest: dag_digest(document),
            trusted,
            slots: vec![Slot::default(); n],
            cancelled: false,
            log: Vec::new(),
        })
    }

    /// Rebuild the ledger after a restart by replaying the stored receipt log.
    pub fn restore(
        document: &[u8],
        trusted: Vec<[u8; 33]>,
        now: u64,
        log: &[[u8; RECEIPT_LEN]],
    ) -> Result<Self, Refusal> {
        let mut run = Self::admit(document, trusted, now)?;
        for r in log {
            run.apply(r)?;
        }
        Ok(run)
    }

    /// The accepted document.
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// The `dag_digest` receipts must name.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Every newly applied receipt in order: what a receiver stores to
    /// survive a restart.
    pub fn log(&self) -> &[[u8; RECEIPT_LEN]] {
        &self.log
    }

    /// The `output_digest` of a DONE node.
    pub fn output(&self, i: usize) -> Option<[u8; 32]> {
        self.slots[i].output
    }

    /// The binding a receipt for node `i` must carry, once every dependency
    /// is DONE.
    pub fn expected_binding(&self, i: usize) -> Option<[u8; 32]> {
        let node = &self.dag.nodes[i];
        let mut deps = Vec::with_capacity(node.deps.len());
        for d in &node.deps {
            deps.push(self.slots[d.index as usize].done?);
        }
        Some(input_binding(&deps, &node.operands))
    }

    /// Cancel the objective: every receipt applied so far stands, every later
    /// receipt is refused, every non-terminal node becomes CANCELLED.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Apply one receipt (section 5.2). A refusal changes nothing.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<Applied, Refusal> {
        let r = decode_receipt(bytes)?;
        if !self.trusted.contains(&r.signer_key)
            || p256_verify_low_s(&r.signer_key, &bytes[..RECEIPT_SIGNED_LEN], &r.signature).is_err()
        {
            return Err(Refusal::ForgedReceipt);
        }
        if r.dag_digest != self.digest {
            return Err(Refusal::WrongDag);
        }
        let i = self
            .dag
            .nodes
            .iter()
            .position(|n| n.job_id == r.job_id)
            .ok_or(Refusal::UnknownJob)?;
        let node = &self.dag.nodes[i];
        if node.idempotence_key != r.idempotence_key {
            return Err(Refusal::UnknownJob);
        }
        if node.generation != r.generation {
            return Err(Refusal::StaleGeneration);
        }
        if node.model_ref != r.model_hash {
            return Err(Refusal::ModelMismatch);
        }
        let slot = &self.slots[i];
        if slot.applied.iter().any(|a| a[..] == bytes[..]) {
            return Ok(Applied::Replay);
        }
        if self.cancelled {
            return Err(Refusal::Cancelled);
        }
        if is_terminal(slot.last_outcome) {
            return Err(Refusal::DoubleCommit);
        }
        if r.attempt != slot.last_attempt.saturating_add(1) || r.attempt > node.max_attempts {
            return Err(Refusal::BadRetry);
        }
        if r.used_time_ms > node.time_ms
            || r.used_input_tokens > node.input_tokens
            || r.used_output_tokens > node.output_tokens
            || r.used_fuel > node.fuel
            || r.used_memory > node.memory
            || r.used_work > node.work
        {
            return Err(Refusal::ReceiptOverBudget);
        }
        match self.expected_binding(i) {
            Some(b) if b != r.input_binding => return Err(Refusal::BindingMismatch),
            None if r.outcome == outcome::COMPLETED => return Err(Refusal::DepNotDone),
            _ => {}
        }
        let mut stored = [0u8; RECEIPT_LEN];
        stored.copy_from_slice(bytes);
        let slot = &mut self.slots[i];
        slot.applied.push(stored);
        slot.last_outcome = r.outcome;
        slot.last_attempt = r.attempt;
        if r.outcome == outcome::COMPLETED {
            slot.done = Some(receipt_digest(&r));
            slot.output = Some(r.output_digest);
        }
        self.log.push(stored);
        Ok(Applied::New)
    }

    /// The derived state of node `i` (section 5.3).
    pub fn state(&self, i: usize) -> NodeState {
        let order = canonical_order(&self.dag.nodes).expect("admitted documents are acyclic");
        let mut states = vec![NodeState::Waiting; self.dag.nodes.len()];
        for &k in &order {
            states[k] = self.own_state(k, &states);
        }
        states[i]
    }

    /// The derived state of every node, by index.
    pub fn states(&self) -> Vec<NodeState> {
        (0..self.dag.nodes.len()).map(|i| self.state(i)).collect()
    }

    fn own_state(&self, k: usize, states: &[NodeState]) -> NodeState {
        let slot = &self.slots[k];
        let node = &self.dag.nodes[k];
        match slot.last_outcome {
            outcome::COMPLETED => return NodeState::Done,
            outcome::REFUSED => return NodeState::Refused,
            outcome::CANCELLED => return NodeState::Cancelled,
            _ => {}
        }
        let out_of_attempts = slot.last_attempt >= node.max_attempts
            && matches!(slot.last_outcome, outcome::FAILED | outcome::UNCERTAIN);
        if out_of_attempts {
            return NodeState::Exhausted;
        }
        if self.cancelled {
            return NodeState::Cancelled;
        }
        let dep_states = node.deps.iter().map(|d| states[d.index as usize]);
        if dep_states.clone().any(|s| {
            matches!(
                s,
                NodeState::Refused
                    | NodeState::Cancelled
                    | NodeState::Exhausted
                    | NodeState::Blocked
            )
        }) {
            return NodeState::Blocked;
        }
        if slot.last_outcome == outcome::UNCERTAIN {
            return NodeState::Uncertain;
        }
        if dep_states.clone().all(|s| s == NodeState::Done) {
            NodeState::Ready
        } else {
            NodeState::Waiting
        }
    }
}

fn is_terminal(o: u8) -> bool {
    matches!(
        o,
        outcome::COMPLETED | outcome::REFUSED | outcome::CANCELLED
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_table_matches_the_issue() {
        assert_eq!(profile_caps(profile::ZERO), Some((0, 0)));
        assert_eq!(profile_caps(profile::MINIMAL), Some((64, 16)));
        assert_eq!(profile_caps(profile::DEFAULT), Some((128, 32)));
        assert_eq!(profile_caps(profile::LARGE), Some((256, 64)));
        assert_eq!(profile_caps(profile::SPECIALIST), Some((512, 128)));
        assert_eq!(profile_caps(5), None);
    }

    #[test]
    fn layout_constants() {
        assert_eq!(N_OPERANDS + MAX_OPERANDS * OPERAND_LEN, NODE_LEN);
        assert_eq!(N_DEPS + MAX_DEPS * DEP_LEN, N_OPERANDS);
        assert_eq!(H_B_OUT + 4, HEADER_LEN);
        assert_eq!(MAX_DOCUMENT, 28864);
    }
}
