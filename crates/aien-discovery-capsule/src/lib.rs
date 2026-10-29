//! The DCP1 family: Discovery Capsule, owner consent, signed retraction,
//! retraction acknowledgement and experience lineage.
//!
//! Spec: `specs/discovery-capsule/SPEC.md` (Draft v0.1, contract 0.1.0, wire
//! version 1). The C reference checker `specs/discovery-capsule/tools/dcp_verify.c`
//! pins the static rules (section 10); [`decode`] gives the same verdict on
//! the same bytes (`tests/vectors.rs`). Signatures and the stateful recipient
//! rules of section 11 live here and in [`recipient`].
//!
//! A capsule never authorizes itself: nothing in this crate turns a capsule
//! into a grant. [`recipient::admit_execution`] needs the recipient's own
//! passing verdict and the recipient's own capability grant.
#![forbid(unsafe_code)]

pub mod recipient;

use aien_provenance::{p256_compressed_key, p256_sign_low_s, p256_verify_low_s};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

/// The only wire version.
pub const VERSION: u8 = 1;
/// Record lengths (SPEC.md section 1).
pub const CAPSULE_LEN: usize = 676;
pub const CONSENT_LEN: usize = 388;
pub const RETRACTION_LEN: usize = 284;
pub const ACK_LEN: usize = 148;
pub const LINEAGE_LEN: usize = 588;

/// `share_scope` values.
pub mod scope {
    pub const PRIVATE: u8 = 0;
    pub const NAMED: u8 = 1;
    pub const COMMUNITY: u8 = 2;
    pub const PUBLIC: u8 = 3;
}
/// `permissions` / `purposes` bits.
pub mod perm {
    pub const DISCOVER: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const REDISTRIBUTE: u8 = 0x04;
    pub const TRAIN: u8 = 0x08;
    pub const ALL: u8 = 0x0F;
}
/// Retraction `scope` bits.
pub mod retract {
    pub const FUTURE_AVAILABILITY: u8 = 0x01;
    pub const RETRIEVAL: u8 = 0x02;
    pub const TRAINING: u8 = 0x04;
    pub const REPUBLICATION: u8 = 0x08;
    pub const ALL: u8 = 0x0F;
}
/// `required_capabilities` bits (a request, never a grant).
pub mod cap {
    pub const CPU_COMPUTE: u32 = 1 << 0;
    pub const GPU_COMPUTE: u32 = 1 << 1;
    pub const CORTEX_READ: u32 = 1 << 2;
    pub const WORLD_READ: u32 = 1 << 3;
    pub const WORLD_EFFECT: u32 = 1 << 4;
    pub const NETWORK: u32 = 1 << 5;
    pub const ALL: u32 = 0x3F;
}
/// `license` registry.
pub mod license {
    pub const APACHE_2_0: u16 = 1;
    pub const MIT: u16 = 2;
    pub const CC_BY_4_0: u16 = 3;
    pub const CC_BY_SA_4_0: u16 = 4;
    pub const CDLA_PERMISSIVE_2_0: u16 = 5;
    pub const OWNER_CONSENT_ONLY: u16 = 6;
}
/// Ack `status` values.
pub mod ack_status {
    pub const ENFORCED: u8 = 1;
    pub const ENFORCED_WITH_RETAINED: u8 = 2;
}

/// A refusal code from SPEC.md section 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadLength,
    BadMagic,
    Downgrade,
    BadVersion,
    ReservedNonzero,
    BadEnum,
    UnknownLicense,
    FalseErasureClaim,
    MissingField,
    BadKey,
    BadValidity,
    Inconsistent,
    ScopeConflict,
    PermissionAmplification,
    NoConsent,
    AncestorCycle,
    Duplicate,
    BadSignature,
    OwnerMismatch,
    Private,
    NotRecipient,
    Expired,
    Stale,
    Revoked,
    NotPermitted,
    Conflict,
    UnknownCustodian,
    SelfAuthorized,
    Unverified,
    CapabilityDenied,
    CrossDataset,
    UnknownParent,
}

impl Refusal {
    /// The code name as written in SPEC.md and printed by the C checker.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::BadLength => "DCP_BAD_LENGTH",
            Refusal::BadMagic => "DCP_BAD_MAGIC",
            Refusal::Downgrade => "DCP_DOWNGRADE",
            Refusal::BadVersion => "DCP_BAD_VERSION",
            Refusal::ReservedNonzero => "DCP_RESERVED_NONZERO",
            Refusal::BadEnum => "DCP_BAD_ENUM",
            Refusal::UnknownLicense => "DCP_UNKNOWN_LICENSE",
            Refusal::FalseErasureClaim => "DCP_FALSE_ERASURE_CLAIM",
            Refusal::MissingField => "DCP_MISSING_FIELD",
            Refusal::BadKey => "DCP_BAD_KEY",
            Refusal::BadValidity => "DCP_BAD_VALIDITY",
            Refusal::Inconsistent => "DCP_INCONSISTENT",
            Refusal::ScopeConflict => "DCP_SCOPE_CONFLICT",
            Refusal::PermissionAmplification => "DCP_PERMISSION_AMPLIFICATION",
            Refusal::NoConsent => "DCP_NO_CONSENT",
            Refusal::AncestorCycle => "DCP_ANCESTOR_CYCLE",
            Refusal::Duplicate => "DCP_DUPLICATE",
            Refusal::BadSignature => "DCP_BAD_SIGNATURE",
            Refusal::OwnerMismatch => "DCP_OWNER_MISMATCH",
            Refusal::Private => "DCP_PRIVATE",
            Refusal::NotRecipient => "DCP_NOT_RECIPIENT",
            Refusal::Expired => "DCP_EXPIRED",
            Refusal::Stale => "DCP_STALE",
            Refusal::Revoked => "DCP_REVOKED",
            Refusal::NotPermitted => "DCP_NOT_PERMITTED",
            Refusal::Conflict => "DCP_CONFLICT",
            Refusal::UnknownCustodian => "DCP_UNKNOWN_CUSTODIAN",
            Refusal::SelfAuthorized => "DCP_SELF_AUTHORIZED",
            Refusal::Unverified => "DCP_UNVERIFIED",
            Refusal::CapabilityDenied => "DCP_CAPABILITY_DENIED",
            Refusal::CrossDataset => "DCP_CROSS_DATASET",
            Refusal::UnknownParent => "DCP_UNKNOWN_PARENT",
        }
    }
}

/// `DiscoveryCapsuleV1` (section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub share_scope: u8,
    pub permissions: u8,
    pub precision: u8,
    pub license: u16,
    pub failure_count: u16,
    pub abi_version: u32,
    pub required_capabilities: u32,
    pub precondition_rank: u8,
    pub precondition_dims: [u32; 4],
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_seq: u64,
    pub meaning_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub compiler_digest: [u8; 32],
    pub executable_digest: [u8; 32],
    pub preconditions_digest: [u8; 32],
    pub verifier_ref: [u8; 32],
    pub evidence_digest: [u8; 32],
    pub failure_cases_digest: [u8; 32],
    pub utility_verdict_ref: [u8; 32],
    pub science_verdict_ref: [u8; 32],
    pub recipient_policy_digest: [u8; 32],
    pub recipient_set_digest: [u8; 32],
    pub consent_ref: [u8; 32],
    pub revocation_head: [u8; 32],
    pub parent_capsule: [u8; 32],
    pub microjob_ref: [u8; 32],
    pub owner_key: [u8; 33],
    pub signature: [u8; 64],
}

/// `OwnerConsentV1` (section 6). `custodians` holds the used slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    pub purposes: u8,
    pub consent_version: u32,
    pub notice_seconds: u32,
    pub issued_at: u64,
    pub retention_end: u64,
    pub provenance_digest: [u8; 32],
    pub recipient_digest: [u8; 32],
    pub fragment_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub custodians: Vec<[u8; 32]>,
    pub owner_key: [u8; 33],
    pub signature: [u8; 64],
}

/// `OwnerRetractionV1` (section 7). `erasure_claim` is always written as 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retraction {
    pub scope: u8,
    pub seq: u64,
    pub effective_at: u64,
    pub target_digest: [u8; 32],
    pub prev_retraction: [u8; 32],
    pub provenance_digest: [u8; 32],
    pub tombstone_digest: [u8; 32],
    pub owner_key: [u8; 33],
    pub signer_key: [u8; 33],
    pub signature: [u8; 64],
}

/// `RetractionAckV1` (section 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub status: u8,
    pub acked_at: u64,
    pub retraction_digest: [u8; 32],
    pub recipient_key: [u8; 33],
    pub signature: [u8; 64],
}

/// `ExperienceLineageV1` (section 9). `parents` and `influenced` hold the
/// used slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lineage {
    pub content_digest: [u8; 32],
    pub dataset_id: [u8; 32],
    pub consent_ref: [u8; 32],
    pub parents: Vec<[u8; 32]>,
    pub influenced: Vec<[u8; 32]>,
    pub owner_key: [u8; 33],
    pub signature: [u8; 64],
}

/// Any record of the family.
#[derive(Debug, Clone, PartialEq, Eq)]
// Records are decoded once and moved into `Verified`; boxing the capsule
// would add a heap allocation per decode for no gain.
#[allow(clippy::large_enum_variant)]
pub enum Record {
    Capsule(Capsule),
    Consent(Consent),
    Retraction(Retraction),
    Ack(Ack),
    Lineage(Lineage),
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
fn z(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}
fn z32(b: &[u8], at: usize) -> bool {
    z(&b[at..at + 32])
}
fn key_ok(b: &[u8], at: usize) -> bool {
    b[at] == 0x02 || b[at] == 0x03
}

/// Length, signing-key offset and signature offset of a record type.
fn layout(magic: &[u8]) -> Option<(usize, usize, usize)> {
    match magic {
        b"DCP1" => Some((CAPSULE_LEN, 576, 612)),
        b"DCC1" => Some((CONSENT_LEN, 288, 324)),
        b"DCR1" => Some((RETRACTION_LEN, 185, 220)),
        b"DCA1" => Some((ACK_LEN, 48, 84)),
        b"DCL1" => Some((LINEAGE_LEN, 488, 524)),
        _ => None,
    }
}

/// Decode and check one record against the static rules of SPEC.md section
/// 10, in the same order as the C checker. Signatures are not checked here
/// (see [`open`]).
pub fn decode(b: &[u8]) -> Result<Record, Refusal> {
    if b.len() < 5 {
        return Err(Refusal::BadLength);
    }
    let (len, _, _) = layout(&b[0..4]).ok_or(Refusal::BadMagic)?;
    if b[4] == 0 {
        return Err(Refusal::Downgrade);
    }
    if b[4] > VERSION {
        return Err(Refusal::BadVersion);
    }
    if b.len() != len {
        return Err(Refusal::BadLength);
    }
    match &b[0..4] {
        b"DCP1" => check_capsule(b).map(Record::Capsule),
        b"DCC1" => check_consent(b).map(Record::Consent),
        b"DCR1" => check_retraction(b).map(Record::Retraction),
        b"DCA1" => check_ack(b).map(Record::Ack),
        _ => check_lineage(b).map(Record::Lineage),
    }
}

fn check_capsule(b: &[u8]) -> Result<Capsule, Refusal> {
    let rank = b[20] as usize;
    let dims_bad = (rank.min(4)..4).any(|d| u32_at(b, 24 + 4 * d) != 0);
    if !z(&b[21..24]) || !z(&b[609..612]) || dims_bad {
        return Err(Refusal::ReservedNonzero);
    }
    let caps = u32_at(b, 16);
    if b[5] > scope::PUBLIC
        || b[6] & !perm::ALL != 0
        || b[7] > 6
        || caps & !cap::ALL != 0
        || rank > 4
    {
        return Err(Refusal::BadEnum);
    }
    let lic = u16_at(b, 8);
    if !(1..=6).contains(&lic) {
        return Err(Refusal::UnknownLicense);
    }
    if u32_at(b, 12) == 0 || (64..288).step_by(32).any(|at| z32(b, at)) || z32(b, 384) {
        return Err(Refusal::MissingField);
    }
    if !key_ok(b, 576) {
        return Err(Refusal::BadKey);
    }
    let (from, until) = (u64_at(b, 40), u64_at(b, 48));
    if from == 0 || until <= from {
        return Err(Refusal::BadValidity);
    }
    if (u16_at(b, 10) != 0) == z32(b, 288) || (u64_at(b, 56) != 0) == z32(b, 480) {
        return Err(Refusal::Inconsistent);
    }
    let (sc, perms) = (b[5], b[6]);
    if (sc == scope::PRIVATE && perms != 0) || ((sc == scope::NAMED) == z32(b, 416)) {
        return Err(Refusal::ScopeConflict);
    }
    if perms & (perm::REDISTRIBUTE | perm::TRAIN) != 0 && perms & perm::READ == 0 {
        return Err(Refusal::PermissionAmplification);
    }
    let needs_consent =
        perms & (perm::READ | perm::REDISTRIBUTE | perm::TRAIN) != 0 || sc != scope::PRIVATE;
    if needs_consent && z32(b, 448) {
        return Err(Refusal::NoConsent);
    }
    Ok(Capsule {
        share_scope: sc,
        permissions: perms,
        precision: b[7],
        license: lic,
        failure_count: u16_at(b, 10),
        abi_version: u32_at(b, 12),
        required_capabilities: caps,
        precondition_rank: b[20],
        precondition_dims: [u32_at(b, 24), u32_at(b, 28), u32_at(b, 32), u32_at(b, 36)],
        valid_from: from,
        expires_at: until,
        revocation_seq: u64_at(b, 56),
        meaning_digest: arr(b, 64),
        source_digest: arr(b, 96),
        compiler_digest: arr(b, 128),
        executable_digest: arr(b, 160),
        preconditions_digest: arr(b, 192),
        verifier_ref: arr(b, 224),
        evidence_digest: arr(b, 256),
        failure_cases_digest: arr(b, 288),
        utility_verdict_ref: arr(b, 320),
        science_verdict_ref: arr(b, 352),
        recipient_policy_digest: arr(b, 384),
        recipient_set_digest: arr(b, 416),
        consent_ref: arr(b, 448),
        revocation_head: arr(b, 480),
        parent_capsule: arr(b, 512),
        microjob_ref: arr(b, 544),
        owner_key: arr(b, 576),
        signature: arr(b, 612),
    })
}

fn check_consent(b: &[u8]) -> Result<Consent, Refusal> {
    let n = b[6] as usize;
    let slots_bad = (n.min(4)..4).any(|s| !z32(b, 160 + 32 * s));
    if b[7] != 0 || !z(&b[321..324]) || slots_bad {
        return Err(Refusal::ReservedNonzero);
    }
    if b[5] == 0 || b[5] & !perm::ALL != 0 || n > 4 {
        return Err(Refusal::BadEnum);
    }
    if u32_at(b, 8) == 0
        || [32, 64, 96, 128].iter().any(|&at| z32(b, at))
        || (0..n).any(|s| z32(b, 160 + 32 * s))
    {
        return Err(Refusal::MissingField);
    }
    if !key_ok(b, 288) {
        return Err(Refusal::BadKey);
    }
    let (issued, until) = (u64_at(b, 16), u64_at(b, 24));
    if issued == 0 || until <= issued {
        return Err(Refusal::BadValidity);
    }
    if b[5] & (perm::REDISTRIBUTE | perm::TRAIN) != 0 && b[5] & perm::READ == 0 {
        return Err(Refusal::PermissionAmplification);
    }
    Ok(Consent {
        purposes: b[5],
        consent_version: u32_at(b, 8),
        notice_seconds: u32_at(b, 12),
        issued_at: issued,
        retention_end: until,
        provenance_digest: arr(b, 32),
        recipient_digest: arr(b, 64),
        fragment_digest: arr(b, 96),
        payload_digest: arr(b, 128),
        custodians: (0..n).map(|s| arr(b, 160 + 32 * s)).collect(),
        owner_key: arr(b, 288),
        signature: arr(b, 324),
    })
}

fn check_retraction(b: &[u8]) -> Result<Retraction, Refusal> {
    if b[7] != 0 || !z(&b[218..220]) {
        return Err(Refusal::ReservedNonzero);
    }
    if b[5] == 0 || b[5] & !retract::ALL != 0 {
        return Err(Refusal::BadEnum);
    }
    if b[6] != 0 {
        return Err(Refusal::FalseErasureClaim);
    }
    let seq = u64_at(b, 8);
    if seq == 0 || z32(b, 24) || z32(b, 88) || z32(b, 120) {
        return Err(Refusal::MissingField);
    }
    if !key_ok(b, 152) || !key_ok(b, 185) {
        return Err(Refusal::BadKey);
    }
    if u64_at(b, 16) == 0 {
        return Err(Refusal::BadValidity);
    }
    if (seq == 1) != z32(b, 56) {
        return Err(Refusal::Inconsistent);
    }
    Ok(Retraction {
        scope: b[5],
        seq,
        effective_at: u64_at(b, 16),
        target_digest: arr(b, 24),
        prev_retraction: arr(b, 56),
        provenance_digest: arr(b, 88),
        tombstone_digest: arr(b, 120),
        owner_key: arr(b, 152),
        signer_key: arr(b, 185),
        signature: arr(b, 220),
    })
}

fn check_ack(b: &[u8]) -> Result<Ack, Refusal> {
    if !z(&b[6..8]) || !z(&b[81..84]) {
        return Err(Refusal::ReservedNonzero);
    }
    if !(1..=2).contains(&b[5]) {
        return Err(Refusal::BadEnum);
    }
    if z32(b, 16) {
        return Err(Refusal::MissingField);
    }
    if !key_ok(b, 48) {
        return Err(Refusal::BadKey);
    }
    if u64_at(b, 8) == 0 {
        return Err(Refusal::BadValidity);
    }
    Ok(Ack {
        status: b[5],
        acked_at: u64_at(b, 8),
        retraction_digest: arr(b, 16),
        recipient_key: arr(b, 48),
        signature: arr(b, 84),
    })
}

fn check_lineage(b: &[u8]) -> Result<Lineage, Refusal> {
    let (np, ni) = (b[5] as usize, b[6] as usize);
    let parents_bad = (np.min(4)..4).any(|s| !z32(b, 104 + 32 * s));
    let infl_bad = (ni.min(8)..8).any(|s| !z32(b, 232 + 32 * s));
    if b[7] != 0 || !z(&b[521..524]) || parents_bad || infl_bad {
        return Err(Refusal::ReservedNonzero);
    }
    if np > 4 || ni > 8 {
        return Err(Refusal::BadEnum);
    }
    if z32(b, 8)
        || z32(b, 40)
        || z32(b, 72)
        || (0..np).any(|s| z32(b, 104 + 32 * s))
        || (0..ni).any(|s| z32(b, 232 + 32 * s))
    {
        return Err(Refusal::MissingField);
    }
    if !key_ok(b, 488) {
        return Err(Refusal::BadKey);
    }
    let parents: Vec<[u8; 32]> = (0..np).map(|s| arr(b, 104 + 32 * s)).collect();
    let content: [u8; 32] = arr(b, 8);
    if parents.contains(&content) {
        return Err(Refusal::AncestorCycle);
    }
    for i in 0..np {
        if parents[i + 1..].contains(&parents[i]) {
            return Err(Refusal::Duplicate);
        }
    }
    Ok(Lineage {
        content_digest: content,
        dataset_id: arr(b, 40),
        consent_ref: arr(b, 72),
        parents,
        influenced: (0..ni).map(|s| arr(b, 232 + 32 * s)).collect(),
        owner_key: arr(b, 488),
        signature: arr(b, 524),
    })
}

fn put32(b: &mut [u8], at: usize, v: &[u8; 32]) {
    b[at..at + 32].copy_from_slice(v);
}

impl Capsule {
    /// Write the record, signature included.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; CAPSULE_LEN];
        b[0..4].copy_from_slice(b"DCP1");
        b[4] = VERSION;
        b[5] = self.share_scope;
        b[6] = self.permissions;
        b[7] = self.precision;
        b[8..10].copy_from_slice(&self.license.to_be_bytes());
        b[10..12].copy_from_slice(&self.failure_count.to_be_bytes());
        b[12..16].copy_from_slice(&self.abi_version.to_be_bytes());
        b[16..20].copy_from_slice(&self.required_capabilities.to_be_bytes());
        b[20] = self.precondition_rank;
        for (d, v) in self.precondition_dims.iter().enumerate() {
            b[24 + 4 * d..28 + 4 * d].copy_from_slice(&v.to_be_bytes());
        }
        b[40..48].copy_from_slice(&self.valid_from.to_be_bytes());
        b[48..56].copy_from_slice(&self.expires_at.to_be_bytes());
        b[56..64].copy_from_slice(&self.revocation_seq.to_be_bytes());
        let digests = [
            &self.meaning_digest,
            &self.source_digest,
            &self.compiler_digest,
            &self.executable_digest,
            &self.preconditions_digest,
            &self.verifier_ref,
            &self.evidence_digest,
            &self.failure_cases_digest,
            &self.utility_verdict_ref,
            &self.science_verdict_ref,
            &self.recipient_policy_digest,
            &self.recipient_set_digest,
            &self.consent_ref,
            &self.revocation_head,
            &self.parent_capsule,
            &self.microjob_ref,
        ];
        for (k, d) in digests.iter().enumerate() {
            put32(&mut b, 64 + 32 * k, d);
        }
        b[576..609].copy_from_slice(&self.owner_key);
        b[612..676].copy_from_slice(&self.signature);
        b
    }

    /// Set `owner_key` from `key` and sign.
    pub fn sign(&mut self, key: &SigningKey) {
        self.owner_key = p256_compressed_key(key);
        self.signature = p256_sign_low_s(key, &self.encode()[..612]);
    }

    /// `record_digest` (signature excluded).
    pub fn digest(&self) -> [u8; 32] {
        record_digest(&self.encode())
    }
}

impl Consent {
    /// Write the record, signature included.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; CONSENT_LEN];
        b[0..4].copy_from_slice(b"DCC1");
        b[4] = VERSION;
        b[5] = self.purposes;
        b[6] = self.custodians.len() as u8;
        b[8..12].copy_from_slice(&self.consent_version.to_be_bytes());
        b[12..16].copy_from_slice(&self.notice_seconds.to_be_bytes());
        b[16..24].copy_from_slice(&self.issued_at.to_be_bytes());
        b[24..32].copy_from_slice(&self.retention_end.to_be_bytes());
        put32(&mut b, 32, &self.provenance_digest);
        put32(&mut b, 64, &self.recipient_digest);
        put32(&mut b, 96, &self.fragment_digest);
        put32(&mut b, 128, &self.payload_digest);
        for (s, c) in self.custodians.iter().take(4).enumerate() {
            put32(&mut b, 160 + 32 * s, c);
        }
        b[288..321].copy_from_slice(&self.owner_key);
        b[324..388].copy_from_slice(&self.signature);
        b
    }

    /// Set `owner_key` from `key` and sign.
    pub fn sign(&mut self, key: &SigningKey) {
        self.owner_key = p256_compressed_key(key);
        self.signature = p256_sign_low_s(key, &self.encode()[..324]);
    }

    /// `record_digest` (signature excluded).
    pub fn digest(&self) -> [u8; 32] {
        record_digest(&self.encode())
    }
}

impl Retraction {
    /// Write the record, signature included (`erasure_claim` is 0).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; RETRACTION_LEN];
        b[0..4].copy_from_slice(b"DCR1");
        b[4] = VERSION;
        b[5] = self.scope;
        b[8..16].copy_from_slice(&self.seq.to_be_bytes());
        b[16..24].copy_from_slice(&self.effective_at.to_be_bytes());
        put32(&mut b, 24, &self.target_digest);
        put32(&mut b, 56, &self.prev_retraction);
        put32(&mut b, 88, &self.provenance_digest);
        put32(&mut b, 120, &self.tombstone_digest);
        b[152..185].copy_from_slice(&self.owner_key);
        b[185..218].copy_from_slice(&self.signer_key);
        b[220..284].copy_from_slice(&self.signature);
        b
    }

    /// Set `signer_key` from `key` and sign (`owner_key` is left as set).
    pub fn sign(&mut self, key: &SigningKey) {
        self.signer_key = p256_compressed_key(key);
        self.signature = p256_sign_low_s(key, &self.encode()[..220]);
    }

    /// `record_digest` (signature excluded).
    pub fn digest(&self) -> [u8; 32] {
        record_digest(&self.encode())
    }
}

impl Ack {
    /// Write the record, signature included.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; ACK_LEN];
        b[0..4].copy_from_slice(b"DCA1");
        b[4] = VERSION;
        b[5] = self.status;
        b[8..16].copy_from_slice(&self.acked_at.to_be_bytes());
        put32(&mut b, 16, &self.retraction_digest);
        b[48..81].copy_from_slice(&self.recipient_key);
        b[84..148].copy_from_slice(&self.signature);
        b
    }

    /// Set `recipient_key` from `key` and sign.
    pub fn sign(&mut self, key: &SigningKey) {
        self.recipient_key = p256_compressed_key(key);
        self.signature = p256_sign_low_s(key, &self.encode()[..84]);
    }
}

impl Lineage {
    /// Write the record, signature included.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; LINEAGE_LEN];
        b[0..4].copy_from_slice(b"DCL1");
        b[4] = VERSION;
        b[5] = self.parents.len() as u8;
        b[6] = self.influenced.len() as u8;
        put32(&mut b, 8, &self.content_digest);
        put32(&mut b, 40, &self.dataset_id);
        put32(&mut b, 72, &self.consent_ref);
        for (s, p) in self.parents.iter().take(4).enumerate() {
            put32(&mut b, 104 + 32 * s, p);
        }
        for (s, p) in self.influenced.iter().take(8).enumerate() {
            put32(&mut b, 232 + 32 * s, p);
        }
        b[488..521].copy_from_slice(&self.owner_key);
        b[524..588].copy_from_slice(&self.signature);
        b
    }

    /// Set `owner_key` from `key` and sign.
    pub fn sign(&mut self, key: &SigningKey) {
        self.owner_key = p256_compressed_key(key);
        self.signature = p256_sign_low_s(key, &self.encode()[..524]);
    }
}

impl Record {
    /// Write the record, signature included.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Record::Capsule(x) => x.encode(),
            Record::Consent(x) => x.encode(),
            Record::Retraction(x) => x.encode(),
            Record::Ack(x) => x.encode(),
            Record::Lineage(x) => x.encode(),
        }
    }
}

/// `record_digest`: SHA-256 of every byte before the signature. `bytes`
/// must be a record of known type and length.
pub fn record_digest(bytes: &[u8]) -> [u8; 32] {
    let (_, _, sig) = layout(&bytes[0..4]).expect("record of a known type");
    Sha256::digest(&bytes[..sig]).into()
}

/// A record whose static rules and signature both passed. Only [`open`]
/// makes one, so a recipient rule can never be fed unchecked fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T> {
    inner: T,
    digest: [u8; 32],
}

impl<T> Verified<T> {
    /// The checked record.
    pub fn get(&self) -> &T {
        &self.inner
    }
    /// Its `record_digest`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Check one record's static rules and its signature under the signing key
/// the record names (owner, signer or recipient key).
pub fn open(bytes: &[u8]) -> Result<Verified<Record>, Refusal> {
    let record = decode(bytes)?;
    let (_, key_at, sig_at) = layout(&bytes[0..4]).expect("decode checked the magic");
    let key: [u8; 33] = arr(bytes, key_at);
    let sig: [u8; 64] = arr(bytes, sig_at);
    p256_verify_low_s(&key, &bytes[..sig_at], &sig).map_err(|_| Refusal::BadSignature)?;
    Ok(Verified {
        inner: record,
        digest: record_digest(bytes),
    })
}

macro_rules! open_as {
    ($name:ident, $variant:ident, $ty:ty) => {
        /// [`open`] for one record type; another type is `DCP_BAD_MAGIC`.
        pub fn $name(bytes: &[u8]) -> Result<Verified<$ty>, Refusal> {
            let v = open(bytes)?;
            match v.inner {
                Record::$variant(x) => Ok(Verified {
                    inner: x,
                    digest: v.digest,
                }),
                _ => Err(Refusal::BadMagic),
            }
        }
    };
}
open_as!(open_capsule, Capsule, Capsule);
open_as!(open_consent, Consent, Consent);
open_as!(open_retraction, Retraction, Retraction);
open_as!(open_ack, Ack, Ack);
open_as!(open_lineage, Lineage, Lineage);

/// `recipient_set_digest` of a NAMED capsule: keys sorted bytewise, no
/// duplicates (SPEC.md section 9).
pub fn recipients_digest(keys: &[[u8; 33]]) -> [u8; 32] {
    let mut sorted = keys.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut h = Sha256::new();
    h.update(b"DCP1-RECIPIENTS");
    for k in &sorted {
        h.update(k);
    }
    h.finalize().into()
}

/// SHA-256 of a key, the form a consent declares custodians in.
pub fn key_digest(key: &[u8; 33]) -> [u8; 32] {
    Sha256::digest(key).into()
}

fn hex(out: &mut String, bytes: &[u8]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for &x in bytes {
        out.push(H[(x >> 4) as usize] as char);
        out.push(H[(x & 15) as usize] as char);
    }
}

/// The verdict line in the exact format of `dcp_verify FILE` and
/// `vectors/expected.txt`: `ok type=MAGIC digest=H64 key=H66` (the signing
/// key) or `refuse CODE`.
pub fn verdict_line(bytes: &[u8]) -> String {
    match decode(bytes) {
        Err(r) => format!("refuse {}", r.name()),
        Ok(_) => {
            let (_, key_at, _) = layout(&bytes[0..4]).expect("decoded");
            let mut s = format!(
                "ok type={} digest=",
                std::str::from_utf8(&bytes[0..4]).unwrap()
            );
            hex(&mut s, &record_digest(bytes));
            s.push_str(" key=");
            hex(&mut s, &bytes[key_at..key_at + 33]);
            s
        }
    }
}
