//! Receipt ledger (SPEC.md section 5) and the offline sample of
//! aien-protocols-mv#50: an 11-node DAG with a long objective, independent
//! numeric nodes, two neural route nodes, a refused node with a blocked
//! dependent, an interrupt and restart, and a checked aggregate answer.
//!
//! COMPUTE nodes are executed for real here (integer arithmetic over operand
//! bytes fetched by digest). NEURAL node outputs are fixed fixture bytes: no
//! model runs in this test, and none is claimed.

use std::collections::HashMap;

use aien_microjob::*;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = 2_000_000_000;

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn fill<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, x) in out.iter_mut().enumerate() {
        *x = seed.wrapping_add((7 * i) as u8);
    }
    out
}

fn id16(seed: u8, i: usize) -> [u8; 16] {
    let mut out: [u8; 16] = fill(seed);
    out[14..].copy_from_slice(&(i as u16 + 1).to_be_bytes());
    out
}

fn tenant() -> [u8; 32] {
    fill(0x7E)
}

fn header(ceiling: u8, objective_id: [u8; 32]) -> Header {
    Header {
        effect_ceiling: ceiling,
        objective_id,
        tenant_id: tenant(),
        subject_id: fill(0x5B),
        approval_ref: fill(0xA9),
        incarnation: 1,
        expires_at: EXPIRES,
        budget_time_ms: 100_000,
        budget_fuel: 1_000_000,
        budget_memory: 1 << 30,
        budget_work: 1_000_000,
        budget_input_tokens: 4096,
        budget_output_tokens: 1024,
    }
}

fn compute_node(i: usize, op: u8) -> Node {
    Node {
        job_id: id16(0x4A, i),
        idempotence_key: id16(0x1D, i),
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
        retry_class: retry::IDEMPOTENT,
        max_attempts: 3,
        cancel_mode: cancel::DISCARD,
        precision: 0,
        substrate_mask: 1,
        result_type: 2,
        result_rank: 0,
        pure: true,
        time_ms: 100,
        fuel: 1000,
        memory: 1 << 20,
        work: 1000,
        expires_at: EXPIRES - 1,
        result_dims: [0; 4],
        capability_ref: fill(0xCA),
        tenant_id: tenant(),
        model_ref: [0; 32],
        verifier_ref: [0; 32],
        deps: Vec::new(),
        operands: Vec::new(),
    }
}

fn neural_node(i: usize, op: u8, prof: u8, caps: (u16, u16), required: (u16, u16)) -> Node {
    Node {
        kind: kind::NEURAL,
        op,
        profile: prof,
        effect_class: effect::NONE,
        input_tokens: caps.0,
        output_tokens: caps.1,
        required_input_tokens: required.0,
        required_output_tokens: required.1,
        verifier_kind: verifier::CHECKER,
        verifier_ref: fill(0x5E),
        max_attempts: 2,
        precision: 2,
        substrate_mask: 3,
        result_type: 6,
        pure: false,
        model_ref: fill(0x3D),
        ..compute_node(i, 1)
    }
}

fn with_deps(mut n: Node, nodes: &[Node], deps: &[usize]) -> Node {
    n.deps = deps
        .iter()
        .map(|&d| Dep {
            index: d as u16,
            generation: nodes[d].generation,
        })
        .collect();
    n
}

fn content(store: &mut HashMap<[u8; 32], Vec<u8>>, bytes: &[u8]) -> Operand {
    let digest = sha(bytes);
    store.insert(digest, bytes.to_vec());
    Operand {
        kind: operand::CONTENT,
        generation: 1,
        digest,
    }
}

fn executor_key() -> SigningKey {
    // TEST key only: a fixed scalar so receipts are reproducible.
    SigningKey::from_slice(&[0x42u8; 32]).unwrap()
}

fn trusted() -> Vec<[u8; 33]> {
    vec![aien_provenance::p256_compressed_key(&executor_key())]
}

/// A receipt for node `i` of `run` with the binding the ledger expects (or a
/// zero binding when dependencies are not all DONE).
fn receipt(run: &DagRun, i: usize, outcome_code: u8, attempt: u8, output: &[u8]) -> Receipt {
    let node = &run.dag().nodes[i];
    let completed = outcome_code == outcome::COMPLETED;
    Receipt {
        outcome: outcome_code,
        attempt,
        dag_digest: run.digest(),
        job_id: node.job_id,
        idempotence_key: node.idempotence_key,
        generation: node.generation,
        used_time_ms: node.time_ms / 2,
        used_input_tokens: node.input_tokens / 2,
        used_output_tokens: node.output_tokens / 2,
        used_fuel: node.fuel / 2,
        used_memory: node.memory / 2,
        used_work: node.work / 2,
        input_binding: run.expected_binding(i).unwrap_or([0; 32]),
        output_digest: if completed { sha(output) } else { [0; 32] },
        source_hash: fill(0x50),
        model_hash: node.model_ref,
        policy_hash: fill(0x60),
        verifier_verdict: if completed { fill(0x70) } else { [0; 32] },
        signer_key: [0; 33],
        signature: [0; 64],
    }
}

fn signed(mut r: Receipt) -> [u8; RECEIPT_LEN] {
    sign_receipt(&mut r, &executor_key());
    encode_receipt(&r)
}

fn parse_list(b: &[u8]) -> Vec<i64> {
    std::str::from_utf8(b)
        .unwrap()
        .split(',')
        .map(|x| x.trim().parse().unwrap())
        .collect()
}

fn int_bytes(v: i64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn int_of(b: &[u8]) -> i64 {
    i64::from_be_bytes(b.try_into().unwrap())
}

struct Sample {
    document: Vec<u8>,
    store: HashMap<[u8; 32], Vec<u8>>,
    readings_a: Vec<u8>,
    readings_b: Vec<u8>,
}

/// The 11-node offline sample. The objective text is long; every node stays
/// inside its small per-node contract.
fn sample() -> Sample {
    let mut objective = String::from("AIEN_E2E_OBJECTIVE_V1\n");
    for k in 0..40 {
        objective.push_str(&format!(
            "Step {k}: read the six greenhouse temperature sensors from the two typed content records, \
             compute their exact mean in milli-degrees, compare it to the agreed threshold, route the \
             request to the thermal skill and report in the brief style. "
        ));
    }
    assert!(objective.len() > 8000, "the objective is long");
    let objective_id = sha(objective.as_bytes());

    let mut store = HashMap::new();
    let readings_a = b"21,23,22".to_vec();
    let readings_b = b"25,24,26".to_vec();
    let op_a = content(&mut store, &readings_a);
    let op_b = content(&mut store, &readings_b);
    let op_count = content(&mut store, b"6");
    let op_threshold = content(&mut store, b"23000");
    let op_request = content(&mut store, b"Is the greenhouse too warm?");
    let cortex = Operand {
        kind: operand::CORTEX_STATE,
        generation: 3,
        digest: fill(0xC0),
    };

    let mut nodes: Vec<Node> = Vec::new();
    let mut n0 = compute_node(0, compute_op::ARITH);
    n0.operands = vec![op_a];
    nodes.push(n0);
    let mut n1 = compute_node(1, compute_op::ARITH);
    n1.operands = vec![op_b];
    nodes.push(n1);
    let n2 = with_deps(compute_node(2, compute_op::REDUCE), &nodes, &[0, 1]);
    nodes.push(n2);
    let mut n3 = with_deps(compute_node(3, compute_op::ARITH), &nodes, &[2]);
    n3.operands = vec![op_count];
    nodes.push(n3);
    let mut n4 = with_deps(compute_node(4, compute_op::COMPARE), &nodes, &[3]);
    n4.operands = vec![op_threshold];
    n4.result_type = 5;
    nodes.push(n4);
    let mut n5 = neural_node(5, neural_op::ROUTE, profile::MINIMAL, (64, 16), (12, 4));
    n5.operands = vec![op_request];
    nodes.push(n5);
    let mut n6 = neural_node(6, neural_op::ROUTE, profile::DEFAULT, (128, 32), (90, 4));
    n6.operands = vec![cortex];
    nodes.push(n6);
    let mut n7 = with_deps(compute_node(7, compute_op::VERIFY), &nodes, &[3]);
    n7.operands = vec![op_a, op_b];
    n7.verifier_kind = verifier::CHECKER;
    n7.verifier_ref = fill(0x77);
    n7.result_type = 5;
    nodes.push(n7);
    let n8 = with_deps(
        neural_node(
            8,
            neural_op::SUMMARIZE,
            profile::LARGE,
            (256, 64),
            (200, 60),
        ),
        &nodes,
        &[4, 5, 6],
    );
    nodes.push(n8);
    let n9 = with_deps(compute_node(9, compute_op::COMPILE), &nodes, &[8]);
    nodes.push(n9);
    let mut n10 = with_deps(compute_node(10, compute_op::ARITH), &nodes, &[4, 7]);
    n10.result_type = 1;
    nodes.push(n10);

    let dag = Dag {
        header: header(effect::COMPUTE, objective_id),
        nodes,
    };
    Sample {
        document: encode(&dag).unwrap(),
        store,
        readings_a,
        readings_b,
    }
}

/// Run a COMPUTE node for real: fetch operands by digest (refuse when one is
/// missing) and dependency outputs by digest.
fn run_compute(
    run: &DagRun,
    i: usize,
    store: &HashMap<[u8; 32], Vec<u8>>,
    outputs: &HashMap<[u8; 32], Vec<u8>>,
) -> Option<Vec<u8>> {
    let node = &run.dag().nodes[i];
    let ops: Option<Vec<&Vec<u8>>> = node.operands.iter().map(|o| store.get(&o.digest)).collect();
    let ops = ops?;
    let deps: Vec<&Vec<u8>> = node
        .deps
        .iter()
        .map(|d| &outputs[&run.output(d.index as usize).unwrap()])
        .collect();
    Some(match i {
        0 | 1 => int_bytes(parse_list(ops[0]).iter().sum()),
        2 => int_bytes(int_of(deps[0]) + int_of(deps[1])),
        3 => {
            let count: i64 = std::str::from_utf8(ops[0]).unwrap().parse().unwrap();
            int_bytes(int_of(deps[0]) * 1000 / count)
        }
        4 => {
            let threshold: i64 = std::str::from_utf8(ops[0]).unwrap().parse().unwrap();
            vec![(int_of(deps[0]) > threshold) as u8]
        }
        7 => {
            // Independent check: recompute the mean from the raw readings.
            let all: Vec<i64> = parse_list(ops[0])
                .into_iter()
                .chain(parse_list(ops[1]))
                .collect();
            let mean = all.iter().sum::<i64>() * 1000 / all.len() as i64;
            vec![(mean == int_of(deps[0])) as u8]
        }
        10 => {
            assert_eq!(deps[1], &vec![1u8], "the independent check passed");
            let mean = int_of(&outputs[&run.output(3).unwrap()]);
            format!("mean_milli={mean};exceeds={}", deps[0][0]).into_bytes()
        }
        _ => return None,
    })
}

fn execute(
    run: &mut DagRun,
    i: usize,
    store: &HashMap<[u8; 32], Vec<u8>>,
    outputs: &mut HashMap<[u8; 32], Vec<u8>>,
) -> [u8; RECEIPT_LEN] {
    assert_eq!(run.state(i), NodeState::Ready, "node {i} must be ready");
    let out = run_compute(run, i, store, outputs).expect("operands present");
    let bytes = signed(receipt(run, i, outcome::COMPLETED, 1, &out));
    assert_eq!(run.apply(&bytes), Ok(Applied::New), "node {i}");
    outputs.insert(sha(&out), out);
    bytes
}

#[test]
fn offline_sample_eleven_nodes_with_restart_and_checked_answer() {
    let s = sample();
    let mut outputs = HashMap::new();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).expect("sample admitted");
    assert_eq!(run.dag().nodes.len(), 11);
    assert_eq!(
        canonical_order(&run.dag().nodes).unwrap(),
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    assert_eq!(run.state(0), NodeState::Ready);
    assert_eq!(run.state(5), NodeState::Ready);
    assert_eq!(run.state(2), NodeState::Waiting);

    let mut stored = Vec::new();
    for i in [0, 1, 2, 3, 4] {
        stored.push(execute(&mut run, i, &s.store, &mut outputs));
    }

    // Interrupt: the receiver loses its memory and replays its stored log.
    let log = run.log().to_vec();
    assert_eq!(log.len(), 5);
    drop(run);
    let mut run = DagRun::restore(&s.document, trusted(), NOW, &log).expect("restore");
    for (i, st) in run.states().iter().enumerate() {
        let want = match i {
            0..=4 => NodeState::Done,
            5 | 6 => NodeState::Ready,
            7 => NodeState::Ready,
            _ => NodeState::Waiting,
        };
        assert_eq!(*st, want, "node {i} after restart");
    }
    // Resume: the executor re-sends a receipt it is unsure arrived.
    assert_eq!(run.apply(&stored[2]), Ok(Applied::Replay));
    // A second, different commit of a finished node is refused.
    let mut other = receipt(&run, 2, outcome::COMPLETED, 1, &int_bytes(999));
    other.input_binding = run.expected_binding(2).unwrap();
    assert_eq!(run.apply(&signed(other)), Err(Refusal::DoubleCommit));

    // Two neural route nodes: fixture outputs, no model runs here.
    for (i, text) in [(5usize, &b"skill:thermal"[..]), (6, &b"style:brief"[..])] {
        let r = signed(receipt(&run, i, outcome::COMPLETED, 1, text));
        assert_eq!(run.apply(&r), Ok(Applied::New));
        outputs.insert(sha(text), text.to_vec());
    }
    execute(&mut run, 7, &s.store, &mut outputs);

    // Node 8 is refused by its executor; node 9 is then blocked.
    assert_eq!(run.state(8), NodeState::Ready);
    let refused = signed(receipt(&run, 8, outcome::REFUSED, 1, b""));
    assert_eq!(run.apply(&refused), Ok(Applied::New));
    assert_eq!(run.state(8), NodeState::Refused);
    assert_eq!(run.state(9), NodeState::Blocked);
    let early = signed(receipt(&run, 9, outcome::COMPLETED, 1, b"x"));
    assert_eq!(run.apply(&early), Err(Refusal::DepNotDone));

    execute(&mut run, 10, &s.store, &mut outputs);

    // The aggregate answer, checked against an independent computation.
    let answer = &outputs[&run.output(10).unwrap()];
    let all: Vec<i64> = parse_list(&s.readings_a)
        .into_iter()
        .chain(parse_list(&s.readings_b))
        .collect();
    let mean_milli = all.iter().sum::<i64>() * 1000 / all.len() as i64;
    let expected = format!(
        "mean_milli={mean_milli};exceeds={}",
        (mean_milli > 23000) as u8
    );
    assert_eq!(answer, expected.as_bytes());
    assert_eq!(expected, "mean_milli=23500;exceeds=1");

    let states = run.states();
    assert_eq!(
        states,
        vec![
            NodeState::Done,
            NodeState::Done,
            NodeState::Done,
            NodeState::Done,
            NodeState::Done,
            NodeState::Done,
            NodeState::Done,
            NodeState::Done,
            NodeState::Refused,
            NodeState::Blocked,
            NodeState::Done,
        ]
    );
    // Every input was available by digest.
    for n in &run.dag().nodes {
        for o in &n.operands {
            if o.kind == operand::CONTENT {
                assert!(s.store.contains_key(&o.digest));
            }
        }
    }
}

#[test]
fn pure_nodes_recompute_deterministically() {
    let s = sample();
    let mut outputs = HashMap::new();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    execute(&mut run, 0, &s.store, &mut outputs);
    let again = run_compute(&run, 0, &s.store, &outputs).unwrap();
    assert!(run.dag().nodes[0].pure);
    assert_eq!(Some(sha(&again)), run.output(0));
}

#[test]
fn missing_operand_is_refused_not_truncated() {
    let mut s = sample();
    let digest = sha(b"21,23,22");
    s.store.remove(&digest);
    let run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    assert!(run_compute(&run, 0, &s.store, &HashMap::new()).is_none());
}

#[test]
fn replaced_or_missing_operand_breaks_the_binding() {
    let s = sample();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    let node = run.dag().nodes[0].clone();
    // Replaced operand: computed from other bytes than the declared digest.
    let mut swapped = node.operands.clone();
    swapped[0].digest = sha(b"99,99,99");
    let mut r = receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(297));
    r.input_binding = input_binding(&[], &swapped);
    assert_eq!(run.apply(&signed(r)), Err(Refusal::BindingMismatch));
    // Missing operand: binding computed without it.
    let mut r = receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(0));
    r.input_binding = input_binding(&[], &[]);
    assert_eq!(run.apply(&signed(r)), Err(Refusal::BindingMismatch));
    // The honest receipt still applies: refusals changed nothing.
    let ok = signed(receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(66)));
    assert_eq!(run.apply(&ok), Ok(Applied::New));
}

#[test]
fn forged_receipts_are_refused() {
    let s = sample();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    // Signed by a key the receiver does not trust.
    let mut r = receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(66));
    sign_receipt(&mut r, &SigningKey::from_slice(&[0x13u8; 32]).unwrap());
    assert_eq!(run.apply(&encode_receipt(&r)), Err(Refusal::ForgedReceipt));
    // Trusted signer, then one signed byte changed.
    let mut bytes = signed(receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(66)));
    bytes[150] ^= 1;
    assert_eq!(run.apply(&bytes), Err(Refusal::ForgedReceipt));
    // Signature bytes changed.
    let mut bytes = signed(receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(66)));
    bytes[RECEIPT_LEN - 1] ^= 1;
    assert_eq!(run.apply(&bytes), Err(Refusal::ForgedReceipt));
}

#[test]
fn receipt_binding_rules() {
    let s = sample();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    let base = receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(66));

    let mut r = base.clone();
    r.dag_digest = [9; 32];
    assert_eq!(run.apply(&signed(r)), Err(Refusal::WrongDag));

    let mut r = base.clone();
    r.job_id = [3; 16];
    assert_eq!(run.apply(&signed(r)), Err(Refusal::UnknownJob));

    let mut r = base.clone();
    r.idempotence_key = [3; 16];
    assert_eq!(run.apply(&signed(r)), Err(Refusal::UnknownJob));

    let mut r = base.clone();
    r.generation = 2;
    assert_eq!(run.apply(&signed(r)), Err(Refusal::StaleGeneration));

    let mut r = base.clone();
    r.model_hash = fill(0x3D);
    assert_eq!(run.apply(&signed(r)), Err(Refusal::ModelMismatch));

    // Time and word (token) budget overruns.
    let mut r = base.clone();
    r.used_time_ms = run.dag().nodes[0].time_ms + 1;
    assert_eq!(run.apply(&signed(r)), Err(Refusal::ReceiptOverBudget));
    let mut r = receipt(&run, 5, outcome::COMPLETED, 1, b"skill:thermal");
    r.used_output_tokens = 17;
    assert_eq!(run.apply(&signed(r)), Err(Refusal::ReceiptOverBudget));

    // Dependencies first.
    let r = receipt(&run, 2, outcome::COMPLETED, 1, &int_bytes(141));
    assert_eq!(run.apply(&signed(r)), Err(Refusal::DepNotDone));

    // Static receipt rules and unknown receipt version.
    let mut bytes = signed(base.clone());
    bytes[4] = 2;
    assert_eq!(run.apply(&bytes), Err(Refusal::BadReceipt));
    let mut r = base.clone();
    r.output_digest = [0; 32];
    assert_eq!(run.apply(&signed(r)), Err(Refusal::BadReceipt));
    let mut r = base.clone();
    r.verifier_verdict = [0; 32];
    assert_eq!(run.apply(&signed(r)), Err(Refusal::BadReceipt));
    assert_eq!(run.apply(&[0u8; 10]), Err(Refusal::BadReceipt));

    // A proposal is not a receipt: nothing above changed state.
    assert!(run.log().is_empty());
    assert_eq!(run.apply(&signed(base)), Ok(Applied::New));
}

#[test]
fn retry_and_exhaustion() {
    let s = sample();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    // Node 0: IDEMPOTENT, 3 attempts.
    let f1 = signed(receipt(&run, 0, outcome::FAILED, 1, b""));
    assert_eq!(run.apply(&f1), Ok(Applied::New));
    assert_eq!(run.state(0), NodeState::Ready);
    let mut again = receipt(&run, 0, outcome::FAILED, 1, b"");
    again.used_work = 1;
    assert_eq!(run.apply(&signed(again)), Err(Refusal::BadRetry));
    let skip = signed(receipt(&run, 0, outcome::FAILED, 3, b""));
    assert_eq!(run.apply(&skip), Err(Refusal::BadRetry));
    let f2 = signed(receipt(&run, 0, outcome::FAILED, 2, b""));
    let f3 = signed(receipt(&run, 0, outcome::FAILED, 3, b""));
    assert_eq!(run.apply(&f2), Ok(Applied::New));
    assert_eq!(run.apply(&f3), Ok(Applied::New));
    assert_eq!(run.state(0), NodeState::Exhausted);
    assert_eq!(run.state(2), NodeState::Blocked);
    let f4 = signed(receipt(&run, 0, outcome::FAILED, 4, b""));
    assert_eq!(run.apply(&f4), Err(Refusal::BadRetry));
}

fn effect_doc(retry_class: u8, attempts: u8) -> Vec<u8> {
    let mut n = compute_node(0, compute_op::ARITH);
    n.effect_class = effect::EFFECT;
    n.pure = false;
    n.verifier_kind = verifier::JUDGE;
    n.verifier_ref = fill(0x99);
    n.retry_class = retry_class;
    n.max_attempts = attempts;
    n.cancel_mode = cancel::CHECKPOINT;
    n.operands = vec![Operand {
        kind: operand::WORLD_STATE,
        generation: 1,
        digest: fill(0xE0),
    }];
    encode(&Dag {
        header: header(effect::EFFECT, fill(0x0B)),
        nodes: vec![n],
    })
    .unwrap()
}

#[test]
fn uncertain_effect_needs_reconcile_first_and_never_blind_retry() {
    let doc = effect_doc(retry::RECONCILE_FIRST, 2);
    let mut run = DagRun::admit(&doc, trusted(), NOW).unwrap();
    let u = signed(receipt(&run, 0, outcome::UNCERTAIN, 1, b""));
    assert_eq!(run.apply(&u), Ok(Applied::New));
    assert_eq!(run.state(0), NodeState::Uncertain);
    let done = signed(receipt(&run, 0, outcome::COMPLETED, 2, b"written"));
    assert_eq!(run.apply(&done), Ok(Applied::New));
    assert_eq!(run.state(0), NodeState::Done);

    // NEVER: one attempt only; an UNCERTAIN outcome is final.
    let doc = effect_doc(retry::NEVER, 1);
    let mut run = DagRun::admit(&doc, trusted(), NOW).unwrap();
    let u = signed(receipt(&run, 0, outcome::UNCERTAIN, 1, b""));
    assert_eq!(run.apply(&u), Ok(Applied::New));
    assert_eq!(run.state(0), NodeState::Exhausted);
    let retry = signed(receipt(&run, 0, outcome::COMPLETED, 2, b"written"));
    assert_eq!(run.apply(&retry), Err(Refusal::BadRetry));

    // An EFFECT node may never be IDEMPOTENT.
    assert_eq!(
        decode(&effect_doc(retry::IDEMPOTENT, 2)),
        Err(Refusal::BadRetry)
    );
}

#[test]
fn cancel_is_atomic_with_receipts() {
    let s = sample();
    let mut outputs = HashMap::new();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    let r0 = execute(&mut run, 0, &s.store, &mut outputs);
    run.cancel();
    let log = run.log().to_vec();
    drop(run);
    let mut run = DagRun::restore(&s.document, trusted(), NOW, &log).expect("cancel restore");
    let late = signed(receipt(&run, 1, outcome::COMPLETED, 1, &int_bytes(75)));
    assert_eq!(run.apply(&late), Err(Refusal::Cancelled));
    assert_eq!(run.apply(&r0), Ok(Applied::Replay));
    assert_eq!(run.state(0), NodeState::Done);
    assert_eq!(run.state(1), NodeState::Cancelled);
    assert_eq!(run.state(10), NodeState::Cancelled);
    run.cancel();
    assert_eq!(run.log(), log);
}

#[test]
fn restore_preserves_empty_cancellation_and_event_order() {
    let s = sample();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    let fresh = signed(receipt(&run, 0, outcome::COMPLETED, 1, &int_bytes(75)));
    run.cancel();
    run.cancel();
    assert_eq!(run.log(), &[LedgerEvent::Cancelled]);
    let mut restored = DagRun::restore(&s.document, trusted(), NOW, run.log()).unwrap();
    assert!(restored.states().iter().all(|s| *s == NodeState::Cancelled));
    assert_eq!(restored.apply(&fresh), Err(Refusal::Cancelled));
    let invalid = [LedgerEvent::Cancelled, LedgerEvent::Receipt(fresh)];
    assert_eq!(
        DagRun::restore(&s.document, trusted(), NOW, &invalid).unwrap_err(),
        Refusal::Cancelled
    );

    // The same fresh receipt is valid before, but not after, cancellation.
    let ordered = [LedgerEvent::Receipt(fresh), LedgerEvent::Cancelled];
    let mut restored = DagRun::restore(&s.document, trusted(), NOW, &ordered).unwrap();
    assert_eq!(restored.state(0), NodeState::Done);
    assert_eq!(restored.apply(&fresh), Ok(Applied::Replay));
    assert_eq!(restored.log(), ordered);

    // Existing duplicate receipt normalization remains idempotent.
    let redundant = [
        LedgerEvent::Receipt(fresh),
        LedgerEvent::Cancelled,
        LedgerEvent::Receipt(fresh),
        LedgerEvent::Cancelled,
    ];
    let restored = DagRun::restore(&s.document, trusted(), NOW, &redundant).unwrap();
    assert_eq!(restored.log(), ordered);
    let mut forged = fresh;
    forged[RECEIPT_SIGNED_LEN] ^= 1;
    assert_eq!(
        DagRun::restore(
            &s.document,
            trusted(),
            NOW,
            &[LedgerEvent::Cancelled, LedgerEvent::Receipt(forged)]
        )
        .unwrap_err(),
        Refusal::ForgedReceipt
    );
}

#[test]
fn admission_checks_each_node_expiry() {
    let s = sample();
    let mut dag = decode(&s.document).unwrap();
    dag.nodes[0].expires_at = NOW - 1;
    assert_eq!(
        DagRun::admit(&encode(&dag).unwrap(), trusted(), NOW).unwrap_err(),
        Refusal::BadExpiry
    );
    dag.nodes[0].expires_at = NOW;
    DagRun::admit(&encode(&dag).unwrap(), trusted(), NOW).unwrap();
}

#[test]
fn effects_are_never_wider_than_the_approval() {
    let mut doc = effect_doc(retry::RECONCILE_FIRST, 2);
    doc[5] = effect::COMPUTE; // the approval covers COMPUTE only
    assert_eq!(decode(&doc), Err(Refusal::UnauthorizedEffect));
}

#[test]
fn cross_tenant_node_is_refused() {
    let s = sample();
    let mut dag = decode(&s.document).unwrap();
    dag.nodes[6].tenant_id = fill(0x11);
    assert_eq!(decode(&encode(&dag).unwrap()), Err(Refusal::CrossTenant));
}

#[test]
fn minimal_profile_refuses_instead_of_truncating_then_expands() {
    let mut store = HashMap::new();
    let request = "Summarise the effect of the three failed greenhouse heater runs on the next \
                   planting window, keeping every sensor id and timestamp exact.";
    let op = content(&mut store, request.as_bytes());
    // The planner measured 90 essential input tokens: 64/16 cannot hold them.
    let mut n = neural_node(0, neural_op::EXTRACT, profile::MINIMAL, (64, 16), (90, 12));
    n.operands = vec![op];
    let mut dag = Dag {
        header: header(effect::NONE, fill(0x0B)),
        nodes: vec![n],
    };
    assert_eq!(decode(&encode(&dag).unwrap()), Err(Refusal::NeedsExpansion));
    // Explicit expansion to the DEFAULT profile, nothing trimmed.
    dag.nodes[0].profile = profile::DEFAULT;
    dag.nodes[0].input_tokens = 128;
    dag.nodes[0].output_tokens = 32;
    let accepted = decode(&encode(&dag).unwrap()).unwrap();
    assert_eq!(accepted.nodes[0].required_input_tokens, 90);
    assert_eq!(
        accepted.nodes[0].operands[0].digest,
        sha(request.as_bytes())
    );
}

#[test]
fn dependency_version_invalidation() {
    let s = sample();
    let mut outputs = HashMap::new();
    let mut run = DagRun::admit(&s.document, trusted(), NOW).unwrap();
    let r0 = execute(&mut run, 0, &s.store, &mut outputs);

    // Node 0's input changes: it takes generation 2. A dependent still naming
    // generation 1 is stale.
    let mut dag = decode(&s.document).unwrap();
    dag.nodes[0].generation = 2;
    assert_eq!(
        decode(&encode(&dag).unwrap()),
        Err(Refusal::StaleGeneration)
    );
    // Re-plan: the dependent names the new generation; new document digest.
    dag.nodes[2].deps[0].generation = 2;
    dag.header.incarnation = 2;
    let doc2 = encode(&dag).unwrap();
    let mut run2 = DagRun::admit(&doc2, trusted(), NOW).unwrap();
    assert_ne!(run2.digest(), run.digest());
    assert_eq!(run2.apply(&r0), Err(Refusal::WrongDag));
}

#[test]
fn unknown_versions_and_expired_documents() {
    let s = sample();
    let mut doc = s.document.clone();
    doc[4] = 2;
    assert_eq!(decode(&doc), Err(Refusal::BadVersion));
    doc[4] = 0;
    assert_eq!(decode(&doc), Err(Refusal::Downgrade));
    assert_eq!(
        DagRun::admit(&s.document, trusted(), EXPIRES + 1).err(),
        Some(Refusal::BadExpiry)
    );
}

#[test]
fn cycles_are_refused() {
    let s = sample();
    let mut dag = decode(&s.document).unwrap();
    dag.nodes[0].deps = vec![Dep {
        index: 10,
        generation: 1,
    }];
    assert_eq!(decode(&encode(&dag).unwrap()), Err(Refusal::Cycle));
}

#[test]
fn verifier_is_required() {
    let s = sample();
    let mut dag = decode(&s.document).unwrap();
    dag.nodes[5].verifier_kind = 0;
    assert_eq!(decode(&encode(&dag).unwrap()), Err(Refusal::NoVerifier));
}

#[test]
fn over_budget_documents_are_refused() {
    let s = sample();
    let mut dag = decode(&s.document).unwrap();
    dag.header.budget_time_ms = 11 * 100 - 1;
    assert_eq!(decode(&encode(&dag).unwrap()), Err(Refusal::OverBudget));
}
