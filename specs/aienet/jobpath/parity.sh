#!/usr/bin/env bash
# Parity: the Omega recompute (Spark verifier) against the Rust worker kernel
# (aien-microjob aienet0::matmul_u32_digest, i-k-j order) on fixed shapes,
# then the .om refusal exits. Usage: parity.sh RECOMPUTE_BIN
# Exit 0 only for parity, 1 for a behavioral mismatch, 2 for invalid setup/output.
set -e -u -o pipefail
bin=${1:?usage: parity.sh RECOMPUTE_BIN}
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
invalid() { echo "PARITY INVALID: $*" >&2; exit 2; }
for tool in cargo xxd; do
  command -v "$tool" >/dev/null || invalid "missing $tool"
done
[ -x "$bin" ] || invalid "recompute is not executable"
target=${CARGO_TARGET_DIR:-$root/target}
cargo build -q -p aien-microjob --example an0_digest --target-dir "$target" || invalid 'Rust oracle build failed'
ex=$target/debug/examples/an0_digest
[ -x "$ex" ] || invalid 'Rust oracle is not executable'
fail=0
while read -r m k n seed; do
  oracle=$("$ex" "$m" "$k" "$n" "$seed") || invalid 'Rust oracle failed'
  [[ $oracle =~ ^[0-9a-f]{30}\ [0-9a-f]{64}$ ]] || invalid 'malformed Rust oracle output'
  read -r payload want <<< "$oracle"
  got=$(printf '%s' "$payload" | xxd -r -p | "$bin") || invalid 'recompute failed'
  [[ $got =~ ^[0-9a-f]{64}$ ]] || invalid 'malformed recompute output'
  if [ "$got" = "$want" ]; then
    echo "MATCH $m $k $n $seed $got"
  else
    echo "MISMATCH $m $k $n $seed rust=$want om=$got"; fail=1
  fi
done <<'EOF'
1 1 1 0
7 5 3 2716205057
3 8 1 18446744073709551615
16 9 31 42
64 64 64 1311768467463790320
1 256 1 7
256 1 256 7
256 256 256 2716205057
EOF
# Refusals: payload kind 2 -> 3, a zero dimension -> 4, m=257 -> 4, short -> 2.
check() {
  local hex=$1 want=$2 rc
  if printf '%s' "$hex" | xxd -r -p | "$bin" >/dev/null 2>&1; then rc=0; else rc=$?; fi
  if [ "$rc" = "$want" ]; then echo "REFUSE_OK exit=$rc payload=$hex"; else echo "REFUSE_BAD want=$want got=$rc payload=$hex"; fail=1; fi
}
check 020001000100010000000000000001 3
check 010000000100010000000000000001 4
check 010101000100010000000000000001 4
check 0100010001000100000000000000 2
exit "$fail"
