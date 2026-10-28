#!/usr/bin/env bash
# Parity: the Omega recompute (Spark verifier) against the Rust worker kernel
# (aien-microjob aienet0::matmul_u32_digest, i-k-j order) on fixed shapes,
# then the .om refusal exits. Usage: parity.sh RECOMPUTE_BIN
# Exit 0 only when every digest matches and every refusal exit is exact.
set -u -o pipefail
bin=${1:?usage: parity.sh RECOMPUTE_BIN}
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
cargo build -q -p aien-microjob --example an0_digest
ex=$root/target/debug/examples/an0_digest
fail=0
while read -r m k n seed; do
  read -r payload want < <("$ex" "$m" "$k" "$n" "$seed")
  got=$(printf '%s' "$payload" | xxd -r -p | "$bin")
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
  printf '%s' "$hex" | xxd -r -p | "$bin" >/dev/null 2>&1; rc=$?
  if [ "$rc" = "$want" ]; then echo "REFUSE_OK exit=$rc payload=$hex"; else echo "REFUSE_BAD want=$want got=$rc payload=$hex"; fail=1; fi
}
check 020001000100010000000000000001 3
check 010000000100010000000000000001 4
check 010101000100010000000000000001 4
check 0100010001000100000000000000 2
exit $fail
