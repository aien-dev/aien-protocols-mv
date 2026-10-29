//! Stateful recipient rules of SPEC.md section 11: the owner's retraction
//! chain, use checks for serving / training / republication, execution
//! admission, honest retraction delivery status, and experience lineage.
//!
//! Every function takes [`Verified`] records, so static rules and signatures
//! have always been checked first. A refusal changes no state.

use std::collections::HashMap;

use crate::{
    key_digest, perm, recipients_digest, retract, scope, Ack, Capsule, Consent, Lineage, Refusal,
    Retraction, Verified,
};

/// Whether an apply changed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    New,
    Replay,
}

/// One owner's retraction chain as one node knows it.
#[derive(Debug, Clone)]
pub struct OwnerChain {
    owner: [u8; 33],
    custodians: Vec<[u8; 32]>,
    entries: Vec<(Retraction, [u8; 32])>,
}

impl OwnerChain {
    /// An empty chain for `consent`'s owner, with the custodians that consent
    /// declares (and no others).
    pub fn new(consent: &Verified<Consent>) -> Self {
        OwnerChain {
            owner: consent.get().owner_key,
            custodians: consent.get().custodians.clone(),
            entries: Vec::new(),
        }
    }

    /// The owner whose chain this is.
    pub fn owner(&self) -> [u8; 33] {
        self.owner
    }

    /// Sequence of the newest retraction, 0 when none.
    pub fn head_seq(&self) -> u64 {
        self.entries.len() as u64
    }

    /// `record_digest` of the retraction at `seq` (1-based).
    pub fn digest_at(&self, seq: u64) -> Option<[u8; 32]> {
        if seq == 0 {
            return None;
        }
        self.entries.get(seq as usize - 1).map(|(_, d)| *d)
    }

    /// Append one retraction. Concurrent conflicting operations, gaps and a
    /// wrong `prev_retraction` fail closed (`DCP_CONFLICT`).
    pub fn apply(&mut self, r: &Verified<Retraction>) -> Result<Applied, Refusal> {
        let x = r.get();
        if x.owner_key != self.owner {
            return Err(Refusal::OwnerMismatch);
        }
        if x.signer_key != self.owner && !self.custodians.contains(&key_digest(&x.signer_key)) {
            return Err(Refusal::UnknownCustodian);
        }
        let head = self.head_seq();
        if x.seq <= head {
            return if self.digest_at(x.seq) == Some(r.digest()) {
                Ok(Applied::Replay)
            } else {
                Err(Refusal::Conflict)
            };
        }
        let prev_ok = if x.seq == 1 {
            true
        } else {
            self.digest_at(head) == Some(x.prev_retraction)
        };
        if x.seq != head + 1 || !prev_ok {
            return Err(Refusal::Conflict);
        }
        self.entries.push((x.clone(), r.digest()));
        Ok(Applied::New)
    }

    /// Whether a retraction in effect at `now` targets `target` with any of
    /// `scope_bits`.
    pub fn retracts(&self, target: &[u8; 32], scope_bits: u8, now: u64) -> bool {
        self.entries.iter().any(|(r, _)| {
            &r.target_digest == target && r.scope & scope_bits != 0 && r.effective_at <= now
        })
    }
}

/// The use a recipient asks to make of a capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Use {
    /// Retrieve and read.
    Serve,
    /// Make it training-eligible.
    Train,
    /// Pass it on.
    Republish,
}

impl Use {
    fn permission(self) -> u8 {
        match self {
            Use::Serve => perm::READ,
            Use::Train => perm::TRAIN,
            Use::Republish => perm::REDISTRIBUTE,
        }
    }
    fn retraction_scope(self) -> u8 {
        match self {
            Use::Serve => retract::FUTURE_AVAILABILITY | retract::RETRIEVAL,
            Use::Train => retract::TRAINING,
            Use::Republish => retract::REPUBLICATION,
        }
    }
}

/// What the recipient knows when it asks.
#[derive(Debug, Clone)]
pub struct UseRequest<'a> {
    pub use_: Use,
    pub requester: [u8; 33],
    /// The full NAMED recipient list, when the capsule is NAMED.
    pub named_recipients: &'a [[u8; 33]],
    pub now: u64,
    /// The newest `consent_version` this node knows for the same fragment.
    pub newest_consent_version: u32,
    /// The parent capsule, when `parent_capsule` is not zero.
    pub parent: Option<&'a Verified<Capsule>>,
}

/// Check one use of a capsule against its consent and the owner's chain
/// (SPEC.md section 11). `Ok` means "this use is not refused by the capsule
/// contract"; it is not an authorization for any effect.
pub fn check_use(
    capsule: &Verified<Capsule>,
    consent: Option<&Verified<Consent>>,
    chain: &OwnerChain,
    req: &UseRequest<'_>,
) -> Result<(), Refusal> {
    let c = capsule.get();
    if chain.owner() != c.owner_key || consent.is_some_and(|k| k.get().owner_key != c.owner_key) {
        return Err(Refusal::OwnerMismatch);
    }
    if c.share_scope == scope::PRIVATE && req.requester != c.owner_key {
        return Err(Refusal::Private);
    }
    let needs_consent = c.permissions & (perm::READ | perm::REDISTRIBUTE | perm::TRAIN) != 0
        || c.share_scope != scope::PRIVATE;
    if needs_consent {
        match consent {
            Some(k)
                if k.digest() == c.consent_ref && k.get().fragment_digest == c.meaning_digest => {}
            _ => return Err(Refusal::NoConsent),
        }
    }
    if let Some(k) = consent {
        if c.permissions & !k.get().purposes != 0 {
            return Err(Refusal::PermissionAmplification);
        }
    }
    if c.parent_capsule != [0; 32] {
        match req.parent {
            Some(p) if p.digest() == c.parent_capsule => {
                if c.permissions & !p.get().permissions != 0 {
                    return Err(Refusal::PermissionAmplification);
                }
            }
            _ => return Err(Refusal::UnknownParent),
        }
    }
    if req.requester != c.owner_key && c.permissions & req.use_.permission() == 0 {
        return Err(Refusal::NotPermitted);
    }
    if c.share_scope == scope::NAMED
        && req.requester != c.owner_key
        && (recipients_digest(req.named_recipients) != c.recipient_set_digest
            || !req.named_recipients.contains(&req.requester))
    {
        return Err(Refusal::NotRecipient);
    }
    if req.now < c.valid_from
        || req.now > c.expires_at
        || consent.is_some_and(|k| req.now > k.get().retention_end)
    {
        return Err(Refusal::Expired);
    }
    if c.revocation_seq > chain.head_seq()
        || consent.is_some_and(|k| req.newest_consent_version > k.get().consent_version)
    {
        return Err(Refusal::Stale);
    }
    if c.revocation_seq > 0 && chain.digest_at(c.revocation_seq) != Some(c.revocation_head) {
        return Err(Refusal::Conflict);
    }
    let bits = req.use_.retraction_scope();
    if chain.retracts(&capsule.digest(), bits, req.now)
        || chain.retracts(&c.meaning_digest, bits, req.now)
    {
        return Err(Refusal::Revoked);
    }
    Ok(())
}

/// A verdict from the recipient's own independent verifier, run on the
/// recipient's platform. Local to the recipient; not a wire record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientVerdict {
    pub capsule_digest: [u8; 32],
    pub platform_digest: [u8; 32],
    pub verifier_key: [u8; 33],
    pub passed: bool,
}

/// The result of [`admit_execution`]: which capsule may run, on which
/// platform, within which requested capabilities. Effects still need AEGIS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionAdmission {
    pub capsule_digest: [u8; 32],
    pub platform_digest: [u8; 32],
    pub capabilities: u32,
}

/// Admit a capsule for execution on `platform_digest`: only with a passing
/// verdict from a verifier that is not the owner, for this exact capsule and
/// platform, and only within `granted` capabilities.
pub fn admit_execution(
    capsule: &Verified<Capsule>,
    verdict: &RecipientVerdict,
    platform_digest: [u8; 32],
    granted: u32,
) -> Result<ExecutionAdmission, Refusal> {
    let c = capsule.get();
    if verdict.verifier_key == c.owner_key {
        return Err(Refusal::SelfAuthorized);
    }
    if !verdict.passed
        || verdict.capsule_digest != capsule.digest()
        || verdict.platform_digest != platform_digest
    {
        return Err(Refusal::Unverified);
    }
    if c.required_capabilities & !granted != 0 {
        return Err(Refusal::CapabilityDenied);
    }
    Ok(ExecutionAdmission {
        capsule_digest: capsule.digest(),
        platform_digest,
        capabilities: c.required_capabilities,
    })
}

/// Delivery status of one retraction at one recipient. There is no "erased".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Pending,
    Acknowledged { status: u8, acked_at: u64 },
    Unreachable,
}

/// The owner-side view of one retraction's propagation (section 11.1).
#[derive(Debug, Clone)]
pub struct RetractionTracker {
    retraction: [u8; 32],
    recipients: Vec<([u8; 33], Delivery, Option<[u8; 32]>)>,
}

impl RetractionTracker {
    /// Track `retraction` as sent to `recipients`; every one starts PENDING.
    pub fn new(retraction: &Verified<Retraction>, recipients: &[[u8; 33]]) -> Self {
        RetractionTracker {
            retraction: retraction.digest(),
            recipients: recipients
                .iter()
                .map(|k| (*k, Delivery::Pending, None))
                .collect(),
        }
    }

    /// Record one signed acknowledgement.
    pub fn apply_ack(&mut self, ack: &Verified<Ack>) -> Result<Applied, Refusal> {
        let a = ack.get();
        if a.retraction_digest != self.retraction {
            return Err(Refusal::Conflict);
        }
        let slot = self
            .recipients
            .iter_mut()
            .find(|(k, _, _)| *k == a.recipient_key)
            .ok_or(Refusal::NotRecipient)?;
        match slot.2 {
            Some(d) if d == ack.digest() => Ok(Applied::Replay),
            Some(_) => Err(Refusal::Conflict),
            None => {
                slot.1 = Delivery::Acknowledged {
                    status: a.status,
                    acked_at: a.acked_at,
                };
                slot.2 = Some(ack.digest());
                Ok(Applied::New)
            }
        }
    }

    /// Mark a recipient that cannot be reached; it is never shown as
    /// acknowledged.
    pub fn mark_unreachable(&mut self, key: &[u8; 33]) -> Result<(), Refusal> {
        let slot = self
            .recipients
            .iter_mut()
            .find(|(k, _, _)| k == key)
            .ok_or(Refusal::NotRecipient)?;
        if slot.2.is_none() {
            slot.1 = Delivery::Unreachable;
        }
        Ok(())
    }

    /// Delivery status of one recipient.
    pub fn status(&self, key: &[u8; 33]) -> Option<Delivery> {
        self.recipients
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, d, _)| *d)
    }

    /// Recipients still PENDING.
    pub fn pending(&self) -> Vec<[u8; 33]> {
        self.filter(|d| d == Delivery::Pending)
    }

    /// Recipients that acknowledged but retain copies or trained descendants.
    pub fn retained(&self) -> Vec<[u8; 33]> {
        self.filter(|d| {
            matches!(
                d,
                Delivery::Acknowledged {
                    status: crate::ack_status::ENFORCED_WITH_RETAINED,
                    ..
                }
            )
        })
    }

    /// True only when every recipient acknowledged. Even then this says
    /// "future use stopped at compliant recipients", never "erased".
    pub fn all_acknowledged(&self) -> bool {
        self.recipients
            .iter()
            .all(|(_, d, _)| matches!(d, Delivery::Acknowledged { .. }))
    }

    fn filter(&self, f: impl Fn(Delivery) -> bool) -> Vec<[u8; 33]> {
        self.recipients
            .iter()
            .filter(|(_, d, _)| f(*d))
            .map(|(k, _, _)| *k)
            .collect()
    }
}

/// Experience lineage known to one node, keyed by `content_digest`.
#[derive(Debug, Clone, Default)]
pub struct LineageIndex {
    records: HashMap<[u8; 32], (Lineage, [u8; 32])>,
}

impl LineageIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one record. A second, different record for one content is
    /// `DCP_DUPLICATE`; a known parent from another dataset is
    /// `DCP_CROSS_DATASET`; a parent chain that leads back here is
    /// `DCP_ANCESTOR_CYCLE`. Unknown parents are allowed here (offline sync)
    /// and refused when ancestry is needed.
    pub fn add(&mut self, l: &Verified<Lineage>) -> Result<Applied, Refusal> {
        let x = l.get();
        if let Some((_, d)) = self.records.get(&x.content_digest) {
            return if *d == l.digest() {
                Ok(Applied::Replay)
            } else {
                Err(Refusal::Duplicate)
            };
        }
        for p in &x.parents {
            if let Some((parent, _)) = self.records.get(p) {
                if parent.dataset_id != x.dataset_id {
                    return Err(Refusal::CrossDataset);
                }
            }
        }
        let mut stack: Vec<[u8; 32]> = x.parents.clone();
        let mut seen: Vec<[u8; 32]> = Vec::new();
        while let Some(c) = stack.pop() {
            if c == x.content_digest {
                return Err(Refusal::AncestorCycle);
            }
            if seen.contains(&c) {
                continue;
            }
            seen.push(c);
            if let Some((r, _)) = self.records.get(&c) {
                stack.extend(r.parents.iter().copied());
            }
        }
        self.records
            .insert(x.content_digest, (x.clone(), l.digest()));
        Ok(Applied::New)
    }

    /// `content` and all its ancestors. Every ancestor must be held.
    pub fn ancestry(&self, content: &[u8; 32]) -> Result<Vec<[u8; 32]>, Refusal> {
        let mut out: Vec<[u8; 32]> = Vec::new();
        let mut stack = vec![*content];
        while let Some(c) = stack.pop() {
            if out.contains(&c) {
                continue;
            }
            let (r, _) = self.records.get(&c).ok_or(Refusal::UnknownParent)?;
            out.push(c);
            stack.extend(r.parents.iter().copied());
        }
        Ok(out)
    }

    /// Whether `content` may be used for training: every ancestor held, in
    /// one dataset, and none retracted for TRAINING in its owner's chain.
    pub fn training_eligible(
        &self,
        content: &[u8; 32],
        chains: &[&OwnerChain],
        now: u64,
    ) -> Result<(), Refusal> {
        let all = self.ancestry(content)?;
        let dataset = self.records[content].0.dataset_id;
        for c in &all {
            let (r, _) = &self.records[c];
            if r.dataset_id != dataset {
                return Err(Refusal::CrossDataset);
            }
            let chain = chains
                .iter()
                .find(|ch| ch.owner() == r.owner_key)
                .ok_or(Refusal::Stale)?;
            if chain.retracts(c, retract::TRAINING, now) {
                return Err(Refusal::Revoked);
            }
        }
        Ok(())
    }

    /// The checkpoints and capsules influenced by `target` or any of its
    /// descendants: what must be marked affected after a retraction.
    pub fn affected(&self, target: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut hit: Vec<[u8; 32]> = vec![*target];
        let mut grew = true;
        while grew {
            grew = false;
            for (c, (r, _)) in &self.records {
                if !hit.contains(c) && r.parents.iter().any(|p| hit.contains(p)) {
                    hit.push(*c);
                    grew = true;
                }
            }
        }
        let mut out: Vec<[u8; 32]> = Vec::new();
        for c in &hit {
            if let Some((r, _)) = self.records.get(c) {
                for i in &r.influenced {
                    if !out.contains(i) {
                        out.push(*i);
                    }
                }
            }
        }
        out.sort();
        out
    }
}
