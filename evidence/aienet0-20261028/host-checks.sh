#!/usr/bin/env bash
# Host-only checks behind the Aienet-0 job path evidence (HOST_TESTED, Spark).
# usage: host-checks.sh OMC OMEGA_MV OH_TREE CORE_TREE
#   OMC        pinned omc (sha256 2c82480596bbdc50cda9626866209ef662d5834f278f839ff4ce0250c495029f)
#   OMEGA_MV   omega-mv checkout holding the pinned OM-2 SHA-256 unit
#   OH_TREE    open-humanity checkout at feat/aienet0-mjb1-carrier
#   CORE_TREE  aien-sovereign-core-mv checkout holding ref pr662 (Core PR #662)
# Writes build/parity/mutants/xcheck logs next to this script. Exit 0 only
# when every step passes.
set -u -o pipefail
omc=${1:?} mv=${2:?} oh=${3:?} core=${4:?}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
jp=$root/specs/aienet/jobpath
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
step() { # NAME CMD... : run, log to NAME.log, record rc
  local name=$1
  shift
  { echo "\$ $*"; "$@"; } >"$here/$name.log" 2>&1
  local rc=$?
  echo "$name rc=$rc" | tee -a "$here/host-checks.rc"
  [[ $rc == 0 ]] || fail=1
}
: >"$here/host-checks.rc"
bin=$work/matmul_u32_recompute
step build env OMEGA_OMC="$omc" OMEGA_MV="$mv" "$jp/build.sh" "$bin"
sha256sum "$bin" | sed "s|$work/||" >"$here/recompute.sha256"
step parity "$jp/parity.sh" "$bin"
step mutants-protocols env OMEGA_MV="$mv" "$jp/mutants.sh" "$omc"
step mutants-open-humanity "$oh/scripts/aienet0/mutants.sh" "$work/oh-mutants"
mkdir -p "$here/mutants-open-humanity"
cp "$work"/oh-mutants/*.diff "$here/mutants-open-humanity/"
for d in "$work"/oh-mutants/*.controls; do
  [[ -f $d/summary.tsv ]] && cp "$d/summary.tsv" "$here/mutants-open-humanity/$(basename "$d").summary.tsv"
done

# Three-way agreement: Core #662 task.rs (oracle and run) vs the Rust worker
# kernel (aien-microjob) vs the Omega recompute, on the same payloads.
mkdir -p "$work/x/src"
cp "$here/xcheck662/Cargo.toml" "$work/x/"
cp "$here/xcheck662/main.rs" "$work/x/src/"
git -C "$core" show pr662:crates/aien-hetjob/src/task.rs >"$work/x/src/task.rs"
{
  echo "core pr662 $(git -C "$core" rev-parse pr662)"
  echo "task.rs sha256 $(sha256sum <"$work/x/src/task.rs" | cut -c1-64)"
} >"$here/xcheck662.pins"
(cd "$root" && cargo build -q -p aien-microjob --example an0_digest)
ex=$root/target/debug/examples/an0_digest
xcheck() {
  (cd "$work/x" && cargo build -q --release) || return 1
  local agree=0 bad=0
  while read -r m k n seed; do
    read -r payload rust < <("$ex" "$m" "$k" "$n" "$seed")
    om=$(printf '%s' "$payload" | xxd -r -p | "$bin" | tr -d '\n')
    core=$(echo "$payload" | "$work/x/target/release/xcheck662")
    if [[ $rust == "$om" && $om == "$core" ]]; then v=AGREE; agree=$((agree + 1)); else v=DISAGREE; bad=$((bad + 1)); fi
    echo "$m $k $n $seed core662=$core rust=$rust omega=$om $v"
  done <<'EOF'
1 1 1 0
2 3 4 7
64 64 64 1311768467463790320
64 64 64 2716205057
128 64 32 99
256 256 256 2716205057
EOF
  echo "agree=$agree disagree=$bad"
  [[ $bad == 0 ]]
}
step xcheck662 xcheck
exit $fail
