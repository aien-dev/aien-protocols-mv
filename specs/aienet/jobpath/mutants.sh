#!/usr/bin/env bash
# Guard mutants for the Aienet-0 job path profile. Each `AN0-GUARD <name>`
# statement in crates/aien-microjob/src/aienet0.rs is removed (or, for
# executor-pin, made to trust the receipt's own signer) in a scratch copy of
# the crate, and the unit tests must then FAIL. A mutant that still passes
# means the guard is not tested. Two Omega mutants of the recompute must make
# parity.sh fail. Usage: mutants.sh [OMC] ; exit 0 only when every mutant is
# killed.
set -u -o pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
scratch=$(mktemp -d /tmp/an0-mutants.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$root/target/mutants}
src=crates/aien-microjob/src/aienet0.rs
cp -a "$root/Cargo.toml" "$root/Cargo.lock" "$root/crates" "$scratch/"
pristine=$(cat "$root/$src")
killed=0; survived=0

run_tests() {
  (cd "$scratch" && cargo test -q -p aien-microjob --lib aienet0 >/dev/null 2>&1)
}

printf '%s\n' "$pristine" > "$scratch/$src"
if ! run_tests; then echo "BASELINE FAIL: unmutated tests do not pass"; exit 2; fi
echo "BASELINE PASS"

names=$(grep -o 'AN0-GUARD [a-z-]*' "$root/$src" | awk '{print $2}')
for name in $names; do
  if [ "$name" = executor-pin ]; then
    printf '%s\n' "$pristine" | sed "s|let trusted = vec!\[pinned_executor\]; // AN0-GUARD executor-pin|let trusted = vec![decode_receipt(receipt)?.signer_key];|" > "$scratch/$src"
  else
    # Drop the whole tagged statement: one line, or (as rustfmt wraps it) the
    # lines from an opening `guard(` through the tagged `)?;`.
    printf '%s\n' "$pristine" | awk -v tag="AN0-GUARD $name" '
      buf != "" { buf = buf "\n" $0; if ($0 ~ /^[[:space:]]*\)\?;/) { if (index($0, tag) == 0) print buf; buf = "" } ; next }
      /^[[:space:]]*guard\($/ { buf = $0; next }
      index($0, "// " tag) && $0 ~ (tag "$") { next }
      { print }' > "$scratch/$src"
  fi
  if cmp -s "$root/$src" "$scratch/$src"; then echo "MUTANT $name NOT APPLIED"; exit 2; fi
  if ! (cd "$scratch" && cargo test -q -p aien-microjob --lib --no-run >/dev/null 2>&1); then
    echo "MUTANT $name BUILD-FAILED (not counted)"; exit 2
  fi
  if run_tests; then echo "MUTANT $name SURVIVED"; survived=$((survived + 1)); else echo "MUTANT $name KILLED"; killed=$((killed + 1)); fi
done

# Omega recompute mutants: a changed splitmix constant and a dropped
# accumulate. Built with the same pinned build.sh; parity.sh must fail.
omc=${1:-${OMEGA_OMC:-}}
if [ -n "$omc" ]; then
  om=$here/matmul_u32_recompute.om
  for spec in 'splitmix-constant|s/0xbf58476d1ce4e5b9/0xbf58476d1ce4e5b8/' 'drop-accumulate|s/^acc = add acc mul x get b q$/acc = mul x get b q/'; do
    name=${spec%%|*}; expr=${spec#*|}
    mkdir -p "$scratch/om-$name"
    cp "$here/build.sh" "$here/pins.txt" "$scratch/om-$name/"
    sed "$expr" "$om" > "$scratch/om-$name/matmul_u32_recompute.om"
    if cmp -s "$om" "$scratch/om-$name/matmul_u32_recompute.om"; then echo "OM-MUTANT $name NOT APPLIED"; exit 2; fi
    if ! OMEGA_OMC=$omc OMEGA_MV=${OMEGA_MV:?set OMEGA_MV} "$scratch/om-$name/build.sh" "$scratch/om-$name/bin" >/dev/null 2>&1; then
      echo "OM-MUTANT $name BUILD-FAILED (not counted)"; exit 2
    fi
    if "$here/parity.sh" "$scratch/om-$name/bin" >/dev/null 2>&1; then echo "OM-MUTANT $name SURVIVED"; survived=$((survived + 1)); else echo "OM-MUTANT $name KILLED"; killed=$((killed + 1)); fi
  done
fi
echo "killed=$killed survived=$survived"
[ "$survived" = 0 ]
