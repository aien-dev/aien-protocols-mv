//! Writes the INTERPLANE canonical tool request carried by the PST1 tool-call
//! vectors (specs/pi-spark-task/SPEC.md section 11) and prints its digest.
//!
//! The request is built as a JSON value, checked to parse as an INTERPLANE
//! `tool_request` payload, and written as interplane-core's RFC 8785 canonical
//! bytes. It is longer than one PST1 payload (800 bytes) on purpose, so the
//! vectors need three chunks.
use std::process::ExitCode;

use interplane_core::{canonicalize, digest_bytes, Payload};
use serde_json::{json, Value};

fn request() -> Value {
    let text = "Find every receipt from the last week that mentions the garden \
        hose, the rain barrel or the drip line. Summarise each one in a single \
        plain sentence: what was bought, where, and for how much. Leave out card \
        numbers and addresses. If two receipts look like the same purchase, say \
        so instead of counting it twice.\n";
    json!({
        "kind": "tool_request",
        "request_id": "pst1-c6-vector-1",
        "tool": {"namespace": "aien.receipts", "name": "search"},
        "arguments": {
            "query": "garden hose OR rain barrel OR drip line",
            "since_days": 7,
            "limit": 25,
            "fields": ["merchant", "date", "total", "items"],
            "redact": ["card_number", "address"],
            "instructions": text.repeat(4),
            "locale": "en-GB",
            "currency_hint": "\u{a3}",
            "note": "caf\u{e9} \u{2615} \u{1f327}"
        },
        "provenance": {
            "dialect": "openai",
            "parser_version": "1.0.0",
            "model": "pi-local-router",
            "source_turn": 7,
            "source_call_id": "call_pst1_c6"
        }
    })
}

fn main() -> ExitCode {
    let Some(out) = std::env::args().nth(1) else {
        eprintln!("usage: pst1-interplane-request OUT");
        return ExitCode::from(2);
    };
    let v = request();
    if !matches!(Payload::from_value(&v), Ok(Payload::ToolRequest(_))) {
        eprintln!("not an INTERPLANE tool_request");
        return ExitCode::from(1);
    }
    let canon = canonicalize(&v);
    let again: Value = serde_json::from_str(&canon).expect("canonical text parses");
    assert_eq!(canonicalize(&again), canon, "canonical form is stable");
    if let Err(e) = std::fs::write(&out, canon.as_bytes()) {
        eprintln!("cannot write {out}: {e}");
        return ExitCode::from(2);
    }
    println!(
        "bytes={} digest={}",
        canon.len(),
        digest_bytes(canon.as_bytes())
    );
    ExitCode::SUCCESS
}
