//! Print the `matmul_u32` payload (hex) and the Rust worker kernel's output
//! digest for `M K N SEED`, one line: `<payload-hex> <digest-hex>`. Used by
//! `specs/aienet/jobpath/parity.sh` against the Omega recompute.
use aien_microjob::aienet0::{matmul_u32_digest, to_hex, MatmulU32};

fn main() {
    let a: Vec<u64> = std::env::args()
        .skip(1)
        .map(|s| s.parse().expect("M K N SEED are integers"))
        .collect();
    assert_eq!(a.len(), 4, "usage: an0_digest M K N SEED");
    let j = MatmulU32 {
        m: a[0] as u16,
        k: a[1] as u16,
        n: a[2] as u16,
        seed: a[3],
    };
    println!("{} {}", to_hex(&j.encode()), to_hex(&matmul_u32_digest(&j)));
}
