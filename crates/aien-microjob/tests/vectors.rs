//! Walks `specs/microjob/vectors/expected.txt` and requires the Rust reader to
//! print the same verdict line as the C reference checker
//! (`tools/mjb_verify.c`) for every file, and to write every accepted document
//! back out as the identical bytes.

use std::path::PathBuf;

use aien_microjob::{decode, encode, verdict_line};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/microjob/vectors")
}

#[test]
fn every_expected_line_matches_the_c_checker() {
    let dir = vectors_dir();
    let list = std::fs::read_to_string(dir.join("expected.txt")).expect("read expected.txt");
    let mut checked = 0usize;
    let mut accepted = 0usize;
    let mut failures = Vec::new();
    for line in list.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, want) = line
            .split_once(' ')
            .expect("line has a file name and a verdict");
        let bytes = std::fs::read(dir.join(name)).expect("read vector");
        let got = verdict_line(&bytes);
        if got != want {
            failures.push(format!("{name}\n  expected: {want}\n  got:      {got}"));
        }
        if let Ok(dag) = decode(&bytes) {
            let again = encode(&dag).expect("re-encode accepted document");
            if again != bytes {
                failures.push(format!("{name}: round trip gave different bytes"));
            }
            accepted += 1;
        }
        checked += 1;
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} vectors differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked >= 100,
        "expected at least 100 vectors, found {checked}"
    );
    assert!(
        accepted >= 8,
        "expected at least 8 accepted vectors, found {accepted}"
    );
}
