//! Recipient rules of SPEC.md section 11 and the synthetic two-owner
//! lifecycle of aien-protocols-mv#51: publish, recipient audit, acknowledged
//! revocation, refused retrieval and training after it, an offline recipient
//! that stays PENDING, and lineage withdrawal. All keys are TEST keys.

use aien_discovery_capsule::recipient::*;
use aien_discovery_capsule::*;
use aien_provenance::p256_compressed_key;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

const NOW: u64 = 1_850_000_000;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn pk(seed: u8) -> [u8; 33] {
    p256_compressed_key(&sk(seed))
}
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn d(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, x) in out.iter_mut().enumerate() {
        *x = seed.wrapping_add((7 * i) as u8);
    }
    out
}

const OWNER_A: u8 = 0xA0;
const OWNER_B: u8 = 0xB0;
const R1: u8 = 0x11;
const R2: u8 = 0x12;
const R3: u8 = 0x13;
const CUSTODIAN: u8 = 0xC0;
const R1_VERIFIER: u8 = 0x1F;

/// The private trace a capsule is about. Its bytes must never appear in any
/// record; only its digest does.
const PRIVATE_TRACE: &[u8] =
    b"PRIVATE-TRACE: greenhouse owner diary, heater fault at 03:12, BP 142/91";

fn consent(owner: u8, meaning: [u8; 32], purposes: u8, custodians: &[u8], version: u32) -> Vec<u8> {
    let mut c = Consent {
        purposes,
        consent_version: version,
        notice_seconds: 86_400,
        issued_at: NOW - 1000,
        retention_end: NOW + 10_000_000,
        provenance_digest: d(0x61),
        recipient_digest: d(0x62),
        fragment_digest: meaning,
        payload_digest: sha(PRIVATE_TRACE),
        custodians: custodians.iter().map(|&s| key_digest(&pk(s))).collect(),
        owner_key: [0; 33],
        signature: [0; 64],
    };
    c.sign(&sk(owner));
    c.encode()
}

fn capsule_base(meaning: [u8; 32], consent_ref: [u8; 32]) -> Capsule {
    Capsule {
        share_scope: scope::NAMED,
        permissions: perm::DISCOVER | perm::READ | perm::TRAIN,
        precision: 0,
        license: license::APACHE_2_0,
        failure_count: 1,
        abi_version: 1,
        required_capabilities: cap::CPU_COMPUTE | cap::CORTEX_READ,
        precondition_rank: 1,
        precondition_dims: [6, 0, 0, 0],
        valid_from: NOW - 500,
        expires_at: NOW + 5_000_000,
        revocation_seq: 0,
        meaning_digest: meaning,
        source_digest: d(0x21),
        compiler_digest: d(0x22),
        executable_digest: d(0x23),
        preconditions_digest: d(0x24),
        verifier_ref: d(0x25),
        evidence_digest: d(0x26),
        failure_cases_digest: d(0x27),
        utility_verdict_ref: [0; 32],
        science_verdict_ref: [0; 32],
        recipient_policy_digest: d(0x28),
        recipient_set_digest: recipients_digest(&[pk(R1), pk(R2)]),
        consent_ref,
        revocation_head: [0; 32],
        parent_capsule: [0; 32],
        microjob_ref: d(0x29),
        owner_key: [0; 33],
        signature: [0; 64],
    }
}

fn signed_capsule(mut c: Capsule, owner: u8) -> Vec<u8> {
    c.sign(&sk(owner));
    c.encode()
}

fn retraction(
    owner: u8,
    signer: u8,
    seq: u64,
    prev: [u8; 32],
    target: [u8; 32],
    sc: u8,
) -> Vec<u8> {
    let mut r = Retraction {
        scope: sc,
        seq,
        effective_at: NOW,
        target_digest: target,
        prev_retraction: prev,
        provenance_digest: d(0x73),
        tombstone_digest: d(0x74),
        owner_key: pk(owner),
        signer_key: [0; 33],
        signature: [0; 64],
    };
    r.sign(&sk(signer));
    r.encode()
}

fn ack(recipient: u8, retraction_digest: [u8; 32], status: u8) -> Vec<u8> {
    let mut a = Ack {
        status,
        acked_at: NOW + 60,
        retraction_digest,
        recipient_key: [0; 33],
        signature: [0; 64],
    };
    a.sign(&sk(recipient));
    a.encode()
}

fn req(use_: Use, requester: u8, named: &[[u8; 33]]) -> UseRequest<'_> {
    UseRequest {
        use_,
        requester: pk(requester),
        named_recipients: named,
        now: NOW + 100,
        newest_consent_version: 1,
        parent: None,
    }
}

struct World {
    meaning_a: [u8; 32],
    consent_a: Verified<Consent>,
    capsule_a: Verified<Capsule>,
    consent_b: Verified<Consent>,
    capsule_b: Verified<Capsule>,
    named: Vec<[u8; 33]>,
}

fn world() -> World {
    let meaning_a = sha(b"om: claim mean_milli(readings) is exact for 6 sensors");
    let consent_a = open_consent(&consent(
        OWNER_A,
        meaning_a,
        perm::DISCOVER | perm::READ | perm::TRAIN,
        &[CUSTODIAN],
        1,
    ))
    .unwrap();
    let capsule_a = open_capsule(&signed_capsule(
        capsule_base(meaning_a, consent_a.digest()),
        OWNER_A,
    ))
    .unwrap();
    let meaning_b = sha(b"om: procedure heater_duty_cycle(limit)");
    let consent_b = open_consent(&consent(
        OWNER_B,
        meaning_b,
        perm::DISCOVER | perm::READ,
        &[],
        1,
    ))
    .unwrap();
    let mut cb = capsule_base(meaning_b, consent_b.digest());
    cb.share_scope = scope::PUBLIC;
    cb.permissions = perm::DISCOVER | perm::READ;
    cb.recipient_set_digest = [0; 32];
    let capsule_b = open_capsule(&signed_capsule(cb, OWNER_B)).unwrap();
    World {
        meaning_a,
        consent_a,
        capsule_a,
        consent_b,
        capsule_b,
        named: vec![pk(R2), pk(R1)],
    }
}

#[test]
fn two_owner_publish_audit_revoke_lifecycle() {
    let w = world();
    let mut chain_a_r1 = OwnerChain::new(&w.consent_a);
    let chain_b_r1 = OwnerChain::new(&w.consent_b);
    let chain_a_r2 = OwnerChain::new(&w.consent_a);

    // Publish and recipient audit.
    let serve = req(Use::Serve, R1, &w.named);
    check_use(&w.capsule_a, Some(&w.consent_a), &chain_a_r1, &serve).unwrap();
    check_use(
        &w.capsule_a,
        Some(&w.consent_a),
        &chain_a_r1,
        &req(Use::Train, R1, &w.named),
    )
    .unwrap();
    assert_eq!(
        check_use(
            &w.capsule_a,
            Some(&w.consent_a),
            &chain_a_r1,
            &req(Use::Republish, R1, &w.named)
        ),
        Err(Refusal::NotPermitted)
    );
    assert_eq!(
        check_use(
            &w.capsule_a,
            Some(&w.consent_a),
            &chain_a_r1,
            &req(Use::Serve, R3, &w.named)
        ),
        Err(Refusal::NotRecipient)
    );
    check_use(
        &w.capsule_b,
        Some(&w.consent_b),
        &chain_b_r1,
        &req(Use::Serve, R3, &[]),
    )
    .unwrap();

    // R1 runs its own verifier on its own platform before any execution.
    let platform = d(0xF1);
    let verdict = RecipientVerdict {
        capsule_digest: w.capsule_a.digest(),
        platform_digest: platform,
        verifier_key: pk(R1_VERIFIER),
        passed: true,
    };
    let granted = cap::CPU_COMPUTE | cap::CORTEX_READ;
    let adm = admit_execution(&w.capsule_a, &verdict, platform, granted).unwrap();
    assert_eq!(adm.capabilities, granted);

    // Revocation by owner A, sent to R1 and R2.
    let r1_bytes = retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        w.capsule_a.digest(),
        retract::RETRIEVAL | retract::TRAINING,
    );
    let r1 = open_retraction(&r1_bytes).unwrap();
    let mut tracker = RetractionTracker::new(&r1, &[pk(R1), pk(R2)]);
    assert_eq!(chain_a_r1.apply(&r1), Ok(Applied::New));
    assert_eq!(chain_a_r1.apply(&r1), Ok(Applied::Replay));
    let a1 = open_ack(&ack(R1, r1.digest(), ack_status::ENFORCED)).unwrap();
    assert_eq!(tracker.apply_ack(&a1), Ok(Applied::New));
    assert_eq!(tracker.apply_ack(&a1), Ok(Applied::Replay));

    // Subsequent retrieval and training at R1 refuse; owner B is unaffected.
    assert_eq!(
        check_use(&w.capsule_a, Some(&w.consent_a), &chain_a_r1, &serve),
        Err(Refusal::Revoked)
    );
    assert_eq!(
        check_use(
            &w.capsule_a,
            Some(&w.consent_a),
            &chain_a_r1,
            &req(Use::Train, R1, &w.named)
        ),
        Err(Refusal::Revoked)
    );
    check_use(
        &w.capsule_b,
        Some(&w.consent_b),
        &chain_b_r1,
        &req(Use::Serve, R1, &[]),
    )
    .unwrap();

    // R2 is offline: it is PENDING, never shown as acknowledged or erased.
    assert_eq!(tracker.status(&pk(R2)), Some(Delivery::Pending));
    assert_eq!(tracker.pending(), vec![pk(R2)]);
    assert!(!tracker.all_acknowledged());
    tracker.mark_unreachable(&pk(R2)).unwrap();
    assert_eq!(tracker.status(&pk(R2)), Some(Delivery::Unreachable));
    assert!(!tracker.all_acknowledged());
    // An unreachable acknowledged recipient keeps its ack.
    tracker.mark_unreachable(&pk(R1)).unwrap();
    assert!(matches!(
        tracker.status(&pk(R1)),
        Some(Delivery::Acknowledged {
            status: ack_status::ENFORCED,
            ..
        })
    ));

    // A new capsule revision signed after the retraction: R1 (synced) may
    // serve it; R2 (behind) must sync first.
    let meaning_v2 = sha(b"om: claim mean_milli(readings) is exact for 6 sensors, v2");
    let consent_v2 = open_consent(&consent(
        OWNER_A,
        meaning_v2,
        perm::DISCOVER | perm::READ | perm::TRAIN,
        &[CUSTODIAN],
        1,
    ))
    .unwrap();
    let mut c2 = capsule_base(meaning_v2, consent_v2.digest());
    c2.revocation_seq = 1;
    c2.revocation_head = r1.digest();
    let capsule_v2 = open_capsule(&signed_capsule(c2, OWNER_A)).unwrap();
    check_use(&capsule_v2, Some(&consent_v2), &chain_a_r1, &serve).unwrap();
    assert_eq!(
        check_use(
            &capsule_v2,
            Some(&consent_v2),
            &chain_a_r2,
            &req(Use::Serve, R2, &w.named)
        ),
        Err(Refusal::Stale)
    );
}

#[test]
fn retained_copies_are_reported_not_hidden() {
    let w = world();
    let r = open_retraction(&retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        w.capsule_a.digest(),
        retract::TRAINING,
    ))
    .unwrap();
    let mut tracker = RetractionTracker::new(&r, &[pk(R1), pk(R2)]);
    let a = open_ack(&ack(R1, r.digest(), ack_status::ENFORCED_WITH_RETAINED)).unwrap();
    tracker.apply_ack(&a).unwrap();
    assert_eq!(tracker.retained(), vec![pk(R1)]);
    // A different second ack from the same recipient fails closed.
    let other = open_ack(&ack(R1, r.digest(), ack_status::ENFORCED)).unwrap();
    assert_eq!(tracker.apply_ack(&other), Err(Refusal::Conflict));
    // An ack from a key the retraction was not sent to.
    let stranger = open_ack(&ack(R3, r.digest(), ack_status::ENFORCED)).unwrap();
    assert_eq!(tracker.apply_ack(&stranger), Err(Refusal::NotRecipient));
    // An ack for another retraction.
    let wrong = open_ack(&ack(R2, d(0x99), ack_status::ENFORCED)).unwrap();
    assert_eq!(tracker.apply_ack(&wrong), Err(Refusal::Conflict));
    // A forged ack.
    let mut bytes = ack(R2, r.digest(), ack_status::ENFORCED);
    bytes[9] ^= 1;
    assert_eq!(open_ack(&bytes).err(), Some(Refusal::BadSignature));
}

#[test]
fn retraction_chain_fails_closed() {
    let w = world();
    let mut chain = OwnerChain::new(&w.consent_a);
    let target = w.capsule_a.digest();
    let first = open_retraction(&retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        target,
        retract::RETRIEVAL,
    ))
    .unwrap();
    chain.apply(&first).unwrap();
    // Concurrent conflicting operation: another seq 1.
    let other1 = open_retraction(&retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        target,
        retract::TRAINING,
    ))
    .unwrap();
    assert_eq!(chain.apply(&other1), Err(Refusal::Conflict));
    // Gap.
    let gap = open_retraction(&retraction(
        OWNER_A,
        OWNER_A,
        3,
        first.digest(),
        target,
        retract::TRAINING,
    ))
    .unwrap();
    assert_eq!(chain.apply(&gap), Err(Refusal::Conflict));
    // Wrong previous head.
    let fork = open_retraction(&retraction(
        OWNER_A,
        OWNER_A,
        2,
        d(0x55),
        target,
        retract::TRAINING,
    ))
    .unwrap();
    assert_eq!(chain.apply(&fork), Err(Refusal::Conflict));
    // A key that is neither the owner nor a declared custodian.
    let rogue = open_retraction(&retraction(
        OWNER_A,
        R3,
        2,
        first.digest(),
        target,
        retract::TRAINING,
    ))
    .unwrap();
    assert_eq!(chain.apply(&rogue), Err(Refusal::UnknownCustodian));
    // The declared custodian may continue the chain.
    let by_custodian = open_retraction(&retraction(
        OWNER_A,
        CUSTODIAN,
        2,
        first.digest(),
        target,
        retract::TRAINING,
    ))
    .unwrap();
    assert_eq!(chain.apply(&by_custodian), Ok(Applied::New));
    assert_eq!(chain.head_seq(), 2);
    // Another owner's retraction does not enter this chain.
    let foreign = open_retraction(&retraction(
        OWNER_B,
        OWNER_B,
        3,
        by_custodian.digest(),
        target,
        1,
    ))
    .unwrap();
    assert_eq!(chain.apply(&foreign), Err(Refusal::OwnerMismatch));
    // A capsule whose revocation head disagrees with the chain is a fork.
    let mut c = capsule_base(w.meaning_a, w.consent_a.digest());
    c.revocation_seq = 1;
    c.revocation_head = d(0x44);
    let forked = open_capsule(&signed_capsule(c, OWNER_A)).unwrap();
    assert_eq!(
        check_use(
            &forked,
            Some(&w.consent_a),
            &chain,
            &req(Use::Serve, R1, &w.named)
        ),
        Err(Refusal::Conflict)
    );
}

#[test]
fn erasure_claims_are_refused() {
    let w = world();
    let mut bytes = retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        w.capsule_a.digest(),
        retract::ALL,
    );
    bytes[6] = 1;
    assert_eq!(decode(&bytes).err(), Some(Refusal::FalseErasureClaim));
}

#[test]
fn edited_capsules_and_consents_fail_signature() {
    let w = world();
    let mut bytes = w.capsule_a.get().encode();
    bytes[16 + 3] |= cap::GPU_COMPUTE as u8; // quietly ask for the GPU
    assert_eq!(open_capsule(&bytes).err(), Some(Refusal::BadSignature));
    let mut bytes = w.consent_a.get().encode();
    bytes[5] |= perm::REDISTRIBUTE;
    assert_eq!(open_consent(&bytes).err(), Some(Refusal::BadSignature));
    // Re-signed by someone else: the owner key no longer matches the chain.
    let mut stolen = w.capsule_a.get().clone();
    stolen.sign(&sk(R3));
    let stolen = open_capsule(&stolen.encode()).unwrap();
    let chain = OwnerChain::new(&w.consent_a);
    assert_eq!(
        check_use(
            &stolen,
            Some(&w.consent_a),
            &chain,
            &req(Use::Serve, R1, &w.named)
        ),
        Err(Refusal::OwnerMismatch)
    );
}

#[test]
fn capsule_never_authorizes_itself() {
    let w = world();
    let platform = d(0xF1);
    let granted = cap::ALL;
    let mut v = RecipientVerdict {
        capsule_digest: w.capsule_a.digest(),
        platform_digest: platform,
        verifier_key: pk(OWNER_A),
        passed: true,
    };
    assert_eq!(
        admit_execution(&w.capsule_a, &v, platform, granted),
        Err(Refusal::SelfAuthorized)
    );
    v.verifier_key = pk(R1_VERIFIER);
    v.passed = false;
    assert_eq!(
        admit_execution(&w.capsule_a, &v, platform, granted),
        Err(Refusal::Unverified)
    );
    v.passed = true;
    assert_eq!(
        admit_execution(&w.capsule_a, &v, d(0xF2), granted),
        Err(Refusal::Unverified)
    );
    v.capsule_digest = w.capsule_b.digest();
    assert_eq!(
        admit_execution(&w.capsule_a, &v, platform, granted),
        Err(Refusal::Unverified)
    );
    v.capsule_digest = w.capsule_a.digest();
    assert_eq!(
        admit_execution(&w.capsule_a, &v, platform, cap::CPU_COMPUTE),
        Err(Refusal::CapabilityDenied)
    );
}

#[test]
fn permission_amplification_is_refused() {
    let w = world();
    // The consent allows READ only; the capsule claims TRAIN as well.
    let narrow = open_consent(&consent(OWNER_A, w.meaning_a, perm::READ, &[], 1)).unwrap();
    let wide = open_capsule(&signed_capsule(
        capsule_base(w.meaning_a, narrow.digest()),
        OWNER_A,
    ))
    .unwrap();
    let chain = OwnerChain::new(&narrow);
    assert_eq!(
        check_use(&wide, Some(&narrow), &chain, &req(Use::Serve, R1, &w.named)),
        Err(Refusal::PermissionAmplification)
    );
    // A derived capsule may not be wider than its parent.
    let mut parent = capsule_base(w.meaning_a, w.consent_a.digest());
    parent.permissions = perm::DISCOVER | perm::READ;
    let parent = open_capsule(&signed_capsule(parent, OWNER_A)).unwrap();
    let mut child = capsule_base(w.meaning_a, w.consent_a.digest());
    child.parent_capsule = parent.digest();
    let child = open_capsule(&signed_capsule(child, OWNER_A)).unwrap();
    let chain = OwnerChain::new(&w.consent_a);
    let mut r = req(Use::Serve, R1, &w.named);
    assert_eq!(
        check_use(&child, Some(&w.consent_a), &chain, &r),
        Err(Refusal::UnknownParent)
    );
    r.parent = Some(&parent);
    assert_eq!(
        check_use(&child, Some(&w.consent_a), &chain, &r),
        Err(Refusal::PermissionAmplification)
    );
}

#[test]
fn consent_binding_scope_time_and_staleness() {
    let w = world();
    let chain = OwnerChain::new(&w.consent_a);
    let r = req(Use::Serve, R1, &w.named);
    // Missing or wrong consent.
    assert_eq!(
        check_use(&w.capsule_a, None, &chain, &r),
        Err(Refusal::NoConsent)
    );
    let other = open_consent(&consent(OWNER_A, d(0x01), perm::ALL, &[], 1)).unwrap();
    assert_eq!(
        check_use(&w.capsule_a, Some(&other), &chain, &r),
        Err(Refusal::NoConsent)
    );
    // Consent from another owner.
    assert_eq!(
        check_use(&w.capsule_a, Some(&w.consent_b), &chain, &r),
        Err(Refusal::OwnerMismatch)
    );
    // Expired capsule.
    let mut late = r.clone();
    late.now = w.capsule_a.get().expires_at + 1;
    assert_eq!(
        check_use(&w.capsule_a, Some(&w.consent_a), &chain, &late),
        Err(Refusal::Expired)
    );
    // A newer consent version for the fragment is known.
    let mut newer = r.clone();
    newer.newest_consent_version = 2;
    assert_eq!(
        check_use(&w.capsule_a, Some(&w.consent_a), &chain, &newer),
        Err(Refusal::Stale)
    );
    // Named list that does not match the digest the capsule binds.
    let wrong_list = vec![pk(R1), pk(R3)];
    assert_eq!(
        check_use(
            &w.capsule_a,
            Some(&w.consent_a),
            &chain,
            &req(Use::Serve, R1, &wrong_list)
        ),
        Err(Refusal::NotRecipient)
    );
}

#[test]
fn private_is_the_default_and_stays_with_the_owner() {
    let w = world();
    let mut c = capsule_base(w.meaning_a, [0; 32]);
    c.share_scope = scope::PRIVATE;
    c.permissions = 0;
    c.recipient_set_digest = [0; 32];
    let private = open_capsule(&signed_capsule(c, OWNER_A)).unwrap();
    let chain = OwnerChain::new(&w.consent_a);
    assert_eq!(
        check_use(&private, None, &chain, &req(Use::Serve, R1, &[])),
        Err(Refusal::Private)
    );
    check_use(&private, None, &chain, &req(Use::Serve, OWNER_A, &[])).unwrap();
}

#[test]
fn unknown_license_scope_and_versions_fail_closed() {
    let w = world();
    let mut bytes = w.capsule_a.get().encode();
    bytes[9] = 9;
    assert_eq!(decode(&bytes).err(), Some(Refusal::UnknownLicense));
    let mut bytes = w.capsule_a.get().encode();
    bytes[5] = 7;
    assert_eq!(decode(&bytes).err(), Some(Refusal::BadEnum));
    let mut bytes = w.capsule_a.get().encode();
    bytes[4] = 2;
    assert_eq!(decode(&bytes).err(), Some(Refusal::BadVersion));
    assert_eq!(decode(&bytes[..600]).err(), Some(Refusal::BadVersion));
    bytes[4] = 1;
    assert_eq!(decode(&bytes[..600]).err(), Some(Refusal::BadLength));
}

#[test]
fn private_bytes_never_appear_in_records() {
    let w = world();
    let r = retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        w.capsule_a.digest(),
        retract::ALL,
    );
    let a = ack(R1, sha(&r), ack_status::ENFORCED);
    let records = [
        w.capsule_a.get().encode(),
        w.consent_a.get().encode(),
        r,
        a,
        lineage(OWNER_A, sha(PRIVATE_TRACE), d(0xD1), &[], &[]),
    ];
    for rec in &records {
        assert!(
            !rec.windows(PRIVATE_TRACE.len())
                .any(|win| win == PRIVATE_TRACE),
            "private trace bytes leaked into a record"
        );
        assert!(!rec.windows(6).any(|win| win == b"142/91"));
    }
    assert_eq!(w.consent_a.get().payload_digest, sha(PRIVATE_TRACE));
}

fn lineage(
    owner: u8,
    content: [u8; 32],
    dataset: [u8; 32],
    parents: &[[u8; 32]],
    influenced: &[[u8; 32]],
) -> Vec<u8> {
    let mut l = Lineage {
        content_digest: content,
        dataset_id: dataset,
        consent_ref: d(0xCC),
        parents: parents.to_vec(),
        influenced: influenced.to_vec(),
        owner_key: [0; 33],
        signature: [0; 64],
    };
    l.sign(&sk(owner));
    l.encode()
}

#[test]
fn lineage_withdrawal_blocks_training_and_marks_descendants() {
    let w = world();
    let ds = d(0xD1);
    let (e1, e2, e3, e4) = (sha(b"exp-1"), sha(b"exp-2"), sha(b"exp-3"), sha(b"exp-4"));
    let (ckpt_x, capsule_y, ckpt_z) = (d(0xE1), d(0xE2), d(0xE3));
    let mut idx = LineageIndex::new();
    for bytes in [
        lineage(OWNER_A, e1, ds, &[], &[]),
        lineage(OWNER_A, e2, ds, &[e1], &[ckpt_z]),
        lineage(OWNER_A, e3, ds, &[e2], &[ckpt_x]),
        lineage(OWNER_A, e4, ds, &[e1], &[capsule_y]),
    ] {
        assert_eq!(idx.add(&open_lineage(&bytes).unwrap()), Ok(Applied::New));
    }
    let mut chain = OwnerChain::new(&w.consent_a);
    idx.training_eligible(&e3, &[&chain], NOW).unwrap();

    // The owner withdraws experience e1 from training.
    let r = open_retraction(&retraction(
        OWNER_A,
        OWNER_A,
        1,
        [0; 32],
        e1,
        retract::TRAINING,
    ))
    .unwrap();
    chain.apply(&r).unwrap();
    assert_eq!(
        idx.training_eligible(&e3, &[&chain], NOW),
        Err(Refusal::Revoked)
    );
    assert_eq!(
        idx.training_eligible(&e1, &[&chain], NOW),
        Err(Refusal::Revoked)
    );
    // Every checkpoint and capsule influenced downstream is marked affected.
    let mut want = vec![ckpt_x, capsule_y, ckpt_z];
    want.sort();
    assert_eq!(idx.affected(&e1), want);
    assert_eq!(idx.affected(&e3), vec![ckpt_x]);
    // No owner chain known for an ancestor: fail closed.
    assert_eq!(idx.training_eligible(&e3, &[], NOW), Err(Refusal::Stale));
}

#[test]
fn lineage_duplicate_cross_dataset_cycle_and_unknown_parent() {
    let ds = d(0xD1);
    let (e1, e2) = (sha(b"exp-1"), sha(b"exp-2"));
    let mut idx = LineageIndex::new();
    let first = lineage(OWNER_A, e1, ds, &[], &[]);
    idx.add(&open_lineage(&first).unwrap()).unwrap();
    assert_eq!(idx.add(&open_lineage(&first).unwrap()), Ok(Applied::Replay));
    let dup = lineage(OWNER_A, e1, ds, &[], &[d(0xE9)]);
    assert_eq!(
        idx.add(&open_lineage(&dup).unwrap()),
        Err(Refusal::Duplicate)
    );
    // Injection from another dataset.
    let inject = lineage(OWNER_A, e2, d(0xD2), &[e1], &[]);
    assert_eq!(
        idx.add(&open_lineage(&inject).unwrap()),
        Err(Refusal::CrossDataset)
    );
    // Ancestor cycle across records: a -> b (unknown yet), then b -> a.
    let (a, b) = (sha(b"exp-a"), sha(b"exp-b"));
    idx.add(&open_lineage(&lineage(OWNER_A, a, ds, &[b], &[])).unwrap())
        .unwrap();
    assert_eq!(
        idx.add(&open_lineage(&lineage(OWNER_A, b, ds, &[a], &[])).unwrap()),
        Err(Refusal::AncestorCycle)
    );
    // `a` names a parent this node does not hold.
    let w = world();
    let chain = OwnerChain::new(&w.consent_a);
    assert_eq!(
        idx.training_eligible(&a, &[&chain], NOW),
        Err(Refusal::UnknownParent)
    );
}
