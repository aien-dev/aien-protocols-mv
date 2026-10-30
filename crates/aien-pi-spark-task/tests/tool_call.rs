//! Tool-call tasks (SPEC.md section 11) against the shared vectors.
//!
//! Reads the same files the C reference checker reads, byte for byte:
//! `vectors/interplane-tool-request.json` (the INTERPLANE canonical request),
//! `vectors/ok-tool-call-request.pst`, and every recorded session in
//! `vectors/sessions/expected.txt` whose name contains `tool`. For each
//! session the Rust reader must print the same verdict line as
//! `pst_verify --session`.
//!
//! Scope: this reader checks the single-message rules ([`decode`]) and the
//! tool-call rules ([`TaskBody`]). The other session rules of section 10
//! (side, subject, ordinals, context, the order table) are checked by the C
//! checker only; the tool vectors are built so that none of them decides the
//! verdict.

use std::collections::HashMap;
use std::path::PathBuf;

use aien_pi_spark_task::{
    decode, payload_digest, Refusal, TaskBody, ToolCallHead, TYPE_TOOL_CALL_CHUNK,
};

/// The digest interplane-core printed for the carried request at
/// aien-dev/interplane-mv 83df0f074b2c572473cd535c89f767df48933f4a.
const INTERPLANE_DIGEST: &str =
    "sha256:78dbef7ee689b20ad9ae530fd7fa8417fb671778667b27f910484156776990d6";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/pi-spark-task/vectors")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(vectors_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn the_head_names_the_carried_interplane_request() {
    let canonical = read("interplane-tool-request.json");
    let bytes = read("ok-tool-call-request.pst");
    let msg = decode(&bytes).expect("ok-tool-call-request.pst is accepted");
    let head = ToolCallHead::parse(msg.payload).expect("a 36-byte head");
    assert_eq!(head.interplane_digest_string(), INTERPLANE_DIGEST);
    assert_eq!(payload_digest(&canonical), head.interplane_digest);
    assert_eq!(head.canonical_len as usize, canonical.len());
}

/// One recorded session (section 10.4 container), checked for the
/// single-message and tool-call rules. Also returns the canonical bytes of
/// every tool call that completed.
fn tool_session(b: &[u8]) -> (String, Vec<Vec<u8>>) {
    let mut tasks: HashMap<[u8; 16], TaskBody> = HashMap::new();
    let mut done = Vec::new();
    assert_eq!(&b[..4], b"PSS1", "recording magic");
    let mut o = 4;
    let mut step = 0usize;
    let refuse = |r: Refusal, step: usize| format!("refuse {} step={step}", r.code());
    while o < b.len() {
        step += 1;
        let side = b[o];
        let len = usize::from(u16::from_be_bytes([b[o + 1], b[o + 2]]));
        let rec = &b[o + 3..o + 3 + len];
        o += 3 + len;
        let msg = match decode(rec) {
            Ok(m) => m,
            Err(r) => return (refuse(r, step), done),
        };
        let id = msg.header.task_id;
        if let Some(body) = TaskBody::open(&msg) {
            match body {
                Ok(body) => {
                    tasks.entry(id).or_insert(body);
                }
                Err(r) => return (refuse(r, step), done),
            }
            continue;
        }
        let Some(task) = tasks.get_mut(&id) else {
            panic!("step {step}: a tool vector names an unknown task");
        };
        if msg.header.msg_type == TYPE_TOOL_CALL_CHUNK {
            match task.chunk(msg.payload) {
                Ok(true) => {
                    if let TaskBody::ToolCall(call) = task {
                        done.push(call.canonical_bytes().expect("verified").to_vec());
                    }
                }
                Ok(false) => {}
                Err(r) => return (refuse(r, step), done),
            }
        } else if side == 2 {
            if let Err(r) = task.check_spark(msg.header.msg_type) {
                return (refuse(r, step), done);
            }
        }
    }
    (format!("ok steps={step} tasks={}", tasks.len()), done)
}

#[test]
fn every_tool_session_matches_the_c_checker() {
    let canonical = read("interplane-tool-request.json");
    let list = String::from_utf8(read("sessions/expected.txt")).expect("utf-8");
    let mut checked = 0usize;
    let mut carried = 0usize;
    let mut failures = Vec::new();
    for line in list.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, want) = line.split_once(' ').expect("file name and verdict");
        if !name.contains("tool") {
            continue;
        }
        let (got, done) = tool_session(&read(&format!("sessions/{name}")));
        if got != want {
            failures.push(format!("{name}\n  expected: {want}\n  got:      {got}"));
        }
        for bytes in done {
            // Carried unchanged: the joined chunks are the INTERPLANE bytes.
            if bytes != canonical {
                failures.push(format!(
                    "{name}: joined bytes differ from the INTERPLANE request"
                ));
            }
            carried += 1;
        }
        checked += 1;
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} tool sessions differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked >= 9,
        "expected at least 9 tool sessions, found {checked}"
    );
    assert!(carried >= 1, "no tool session carried the whole request");
}
