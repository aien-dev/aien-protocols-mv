#!/usr/bin/env bash
# Deterministic fault injection for the parity/mutant runners, not kernel parity.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/specs/aienet/jobpath" "$scratch/tools" "$scratch/target/debug/examples"
cp "$here/parity.sh" "$here/mutants.sh" "$scratch/specs/aienet/jobpath/"
cat > "$scratch/tools/cargo" <<'EOF'
#!/bin/sh
exit "${FIXTURE_CARGO_RC:-0}"
EOF
cat > "$scratch/target/debug/examples/an0_digest" <<'EOF'
#!/bin/bash
case ${FIXTURE_ORACLE:-valid} in
  empty) exit 0 ;;
  fail) exit 101 ;;
  invalid) echo 'not hex'; exit 0 ;;
esac
printf '010001000100010000000000000000 %064d\n' 0
case ${FIXTURE_ORACLE:-valid} in
  extra) echo extra ;;
esac
EOF
cat > "$scratch/recompute" <<'EOF'
#!/bin/bash
hex=$(xxd -p -c 256)
case "$hex" in
  020001000100010000000000000001) exit 3 ;;
  010000000100010000000000000001|010101000100010000000000000001) exit 4 ;;
  0100010001000100000000000000) exit 2 ;;
esac
case ${FIXTURE_RECOMPUTE:-valid} in
  empty) exit 0 ;;
  fail) exit 1 ;;
  invalid) echo bad; exit 0 ;;
  mismatch) printf '%064d\n' 1; exit 0 ;;
esac
printf '%064d\n' 0
EOF
chmod +x "$scratch/tools/cargo" "$scratch/recompute" "$scratch/target/debug/examples/an0_digest"
export CARGO_TARGET_DIR=$scratch/target
export PATH=$scratch/tools:$PATH
parity=$scratch/specs/aienet/jobpath/parity.sh
expect() {
  local name=$1 want=$2 rc
  shift 2
  if "$@" >"$scratch/$name.log" 2>&1; then rc=0; else rc=$?; fi
  if [ "$rc" != "$want" ]; then
    cat "$scratch/$name.log"
    echo "FAIL $name expected=$want observed=$rc"; exit 1
  fi
  echo "PASS $name exit=$rc"
}
expect fixture-baseline 0 bash "$parity" "$scratch/recompute"
expect cargo-failure 2 env FIXTURE_CARGO_RC=101 bash "$parity" "$scratch/recompute"
if grep -q '^MATCH' "$scratch/cargo-failure.log"; then echo 'FAIL cargo-failure matched stale output'; exit 1; fi
for mode in empty fail invalid extra; do
  expect "oracle-$mode" 2 env FIXTURE_ORACLE=$mode bash "$parity" "$scratch/recompute"
done
for mode in empty fail invalid; do
  expect "recompute-$mode" 2 env FIXTURE_RECOMPUTE=$mode bash "$parity" "$scratch/recompute"
done
expect digest-mismatch 1 env FIXTURE_RECOMPUTE=mismatch bash "$parity" "$scratch/recompute"
expect missing-recompute 2 bash "$parity" "$scratch/absent"
expect missing-omc 2 env -u OMEGA_OMC -u OMEGA_MV bash "$scratch/specs/aienet/jobpath/mutants.sh"
grep -q '^OM-MUTANTS NOT_RUN:' "$scratch/missing-omc.log"
# Hide a prerequisite without relying on what the host has installed.
mkdir "$scratch/limited"
ln -s "$(command -v dirname)" "$scratch/limited/dirname"
expect missing-cargo 2 env PATH="$scratch/limited" /bin/bash "$parity" "$scratch/recompute"
ln -s "$scratch/tools/cargo" "$scratch/limited/cargo"
expect missing-xxd 2 env PATH="$scratch/limited" /bin/bash "$parity" "$scratch/recompute"
echo 'HARNESS PASS'
