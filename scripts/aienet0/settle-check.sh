#!/usr/bin/env bash
# HOST_TESTED adapter controls. OpenSSL keys, fault wrappers and carrier binaries
# are verification oracles, not production ledger/signing implementations.
# Usage: existing carrier env + LEDGER + CARRIER_SOURCE_SHA + CARRIER_PROTOCOLS_SHA
#        bash settle-check.sh FRESH_EVIDENCE_DIR
# SETTLE_DRIVER may select a frozen before specimen or a guard mutant.
set -u
here=$(cd "$(dirname "$0")" && pwd)
E=${1:?set a fresh evidence directory}
for v in RUN SERVE LISTEN CONNECT KEYS PINS RECOMPUTE RECOMPUTE_SHA256 WKEYS WPINS LEDGER CARRIER_SOURCE_SHA CARRIER_PROTOCOLS_SHA; do
  eval "value=\${$v:-}"
  [ -n "$value" ] || { echo "set $v" >&2; exit 2; }
done
[ ! -e "$E" ] || { echo "$E exists; use fresh evidence" >&2; exit 2; }
umask 077
mkdir -p "$E"
b=$(mktemp -d)
keys=$(mktemp -d /dev/shm/aienet0-adapter-keys.XXXXXX)
trap 'rm -rf "$b" "$keys"' EXIT
REAL_LEDGER=$LEDGER
REAL_RUN=$RUN
driver=${SETTLE_DRIVER:-$here/settle-run.sh}
export REAL_LEDGER REAL_RUN
for role in issuer verifier; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$keys/$role" || exit 2
done
pubhex() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | od -An -v -tx1 | tr -d ' \n' | cut -c53-; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
identity() { printf '%s' "$1" | xxd -r -p | sha256sum | cut -d' ' -f1; }
ISSUER_KEY=$keys/issuer
VERIFIER_KEY=$keys/verifier
AUTHORITY=$E/authority
QUOTE=$E/quote
printf '%s' 'quote tur-ledger-2 requester provider verifier 40 27 3 10' > "$QUOTE"
"$REAL_RUN" keys --keys "$KEYS" > "$E/carrier-identities.out" || exit 2
owner=$(awk '$1 == "submitter.p256" {print $2}' "$E/carrier-identities.out")
vnode=$(awk '$1 == "verifier.p256" {print $2}' "$E/carrier-identities.out")
pnode=$(cat "$PINS/volunteer.ed25519")
zero=$(printf '0%.0s' $(seq 64))
printf 'genesis tur-ledger-2 %s %s %s %s requester provider verifier %s %s %s' "$zero" "$(pubhex "$ISSUER_KEY")" "$(pubhex "$VERIFIER_KEY")" "$(sha "$QUOTE")" "$(identity "$owner")" "$(identity "$pnode")" "$(identity "$vnode")" > "$AUTHORITY"
export ISSUER_KEY VERIFIER_KEY AUTHORITY QUOTE
{
  printf 'HOST_TESTED adapter failure controls\ncarrier-source %s\ncarrier-protocols %s\n' "$CARRIER_SOURCE_SHA" "$CARRIER_PROTOCOLS_SHA"
  sha256sum "$REAL_LEDGER" "$REAL_RUN" "$SERVE" "$RECOMPUTE" "$driver" "$0"
  openssl version
} > "$E/pins.txt"
cat > "$b/ledger" <<'WRAPPER'
#!/usr/bin/env bash
set -u
op=${3:-}
if [ "${FAULT_KIND:-}" = blocked ] && { [ "$op" = settle ] || [ "$op" = refund ]; }; then exit 3; fi
if [ "$op" = "${FAULT_OP:-}" ]; then
  case ${FAULT_KIND:-} in
    before) exit 3 ;;
    after) "$REAL_LEDGER" "$@"; r=$?; [ "$r" = 0 ] && exit 3; exit "$r" ;;
  esac
fi
exec "$REAL_LEDGER" "$@"
WRAPPER
cat > "$b/run" <<'WRAPPER'
#!/usr/bin/env bash
set -u
if [ "${1:-}" != run ]; then exec "$REAL_RUN" "$@"; fi
"$REAL_RUN" "$@" > "$FORGED_STDOUT_CAPTURE"; r=$?
while IFS= read -r line; do
  case $line in
    'VERIFIED '*)
      read -r word dag receipt rest <<< "$line"
      false=$(printf '0%.0s' $(seq 64)); [ "$receipt" = "$false" ] && false=$(printf '1%.0s' $(seq 64))
      printf 'VERIFIED %s %s\n' "$dag" "$false" ;;
    *) printf '%s\n' "$line" ;;
  esac
done < "$FORGED_STDOUT_CAPTURE"
exit "$r"
WRAPPER
chmod 700 "$b/ledger" "$b/run"
f=0
ok() { echo "PASS $1"; }
no() { echo "FAIL $1: $2"; f=$((f + 1)); }
manual_refund() { # Test cleanup after the failure-state evidence has been captured.
  local d=$1 job=$2 message=$d/manual-refund.authorization sig
  { cat "$d/journal/authority"; printf '\nrefund %s\n%s\n' "$job" "$(sha "$d/reserve.authorization")"; } > "$message"
  openssl dgst -sha256 -sign "$ISSUER_KEY" -out "$d/manual-refund.issuer.der" "$message" || return 1
  sig=$(od -An -v -tx1 "$d/manual-refund.issuer.der" | tr -d ' \n')
  "$REAL_LEDGER" --journal "$d/journal" refund "$job" "$sig" > "$d/manual-refund.out" 2>&1 || return 1
  "$REAL_LEDGER" --journal "$d/journal" audit > "$d/audit-after-manual-refund.out" 2>&1 || return 1
  grep -q ' open 0 ' "$d/audit-after-manual-refund.out"
}
case_run() { # case, mode, fault-op, fault-kind, expected driver exit, final phase, recovery marker
  local name=$1 mode=$2 op=$3 fault=$4 expected_rc=$5 phase=$6 marker=$7 d=$E/$1/$2 rr ar job actual summary
  mkdir -p "$E/$name"
  local run=$REAL_RUN ledger=$REAL_LEDGER
  [ "$op" = stdout ] && run=$b/run
  [ -n "$fault" ] && ledger=$b/ledger
  RUN=$run LEDGER=$ledger WSTATE=$E/$name/worker-state FAULT_OP=$op FAULT_KIND=$fault FORGED_STDOUT_CAPTURE=$E/$name/real-run.out \
    bash "$driver" "$E/$name" "$mode" > "$E/$name/adapter.out" 2>&1; rr=$?
  "$REAL_LEDGER" --journal "$d/journal" audit > "$d/audit-control.out" 2>&1; ar=$?
  summary=$(cat "$d/audit-control.out")
  case $phase in
    none) actual=' jobs 0 open 0 settled 0 refunded 0 ' ;;
    reserved) actual=' jobs 1 open 1 settled 0 refunded 0 ' ;;
    settled) actual=' jobs 1 open 0 settled 1 refunded 0 ' ;;
    refunded) actual=' jobs 1 open 0 settled 0 refunded 1 ' ;;
  esac
  if [ "$rr" = "$expected_rc" ] && [ "$ar" = 0 ] && [[ "$summary" = *"$actual"* ]] && { [ -z "$marker" ] || grep -q "$marker" "$E/$name/adapter.out"; }; then
    ok "$name (driver $rr, $phase, native audit 0)"
  else no "$name" "driver $rr wanted $expected_rc; audit $ar '$summary'; marker '$marker'"; fi
  if [[ "$summary" = *' open 1 '* ]]; then
    job=$(awk '$1 == "BUNDLE" {print $2}' "$d/bundle.out")
    if manual_refund "$d" "$job"; then ok "$name.operator-refund-after-fault-cleared"; else no "$name.operator-refund-after-fault-cleared" "could not close test escrow"; fi
  fi
  (cd "$d" && sha256sum journal/authority journal/journal *.authorization *.der out/*) > "$d/CONTROL-SHA256SUMS"
}
case_run honest honest '' '' 0 settled ''
case_run forged-receipt tampered-receipt '' '' 0 refunded ''
case_run forged-attestation tampered-attestation '' '' 0 refunded ''
case_run false-verified-stdout honest stdout '' 1 refunded ''
case_run reserve-before-write honest reserve before 1 none 'RECOVERY no-reservation JOB'
case_run reserve-lost-response honest reserve after 1 refunded 'RECOVERY closed JOB'
case_run settle-before-write honest settle before 1 refunded 'RECOVERY closed JOB'
case_run settle-lost-response honest settle after 1 settled 'RECOVERY closed JOB'
case_run persistent-write-failure honest '' blocked 1 reserved 'RECOVERY REQUIRED JOB'
if [ "$f" = 0 ] && [ "${ADAPTER_MUTANTS:-1}" = 1 ] && [ -z "${SETTLE_DRIVER:-}" ]; then
  mkdir "$E/mutants"
  sed '/^trap reconcile_exit EXIT$/d' "$driver" > "$b/no-reconciliation.sh"
  sed '/^  if \[ "\$check_rc" = 0 \].*then authorized=yes; fi$/c\  authorized=yes' "$driver" > "$b/no-artifact-admission.sh"
  for mutant in no-reconciliation no-artifact-admission; do
    if cmp -s "$driver" "$b/$mutant.sh"; then no "mutant.$mutant" 'guard replacement did not match'; continue; fi
    ADAPTER_MUTANTS=0 SETTLE_DRIVER=$b/$mutant.sh bash "$0" "$E/mutants/$mutant" > "$E/mutants/$mutant.out" 2>&1
    mr=$?
    # A nonzero setup/build/network error is not a killed mutant: demand the
    # actual signed native settlement/refund assertion and an honest-path pass.
    if [ "$mr" != 1 ] || ! grep -q '^PASS honest (driver 0, settled, native audit 0)' "$E/mutants/$mutant.out"; then
      no "mutant.$mutant" "infrastructure or honest-path failure (exit $mr)"
    elif [ "$mutant" = no-reconciliation ] && grep -q '^FAIL settle-before-write:.*jobs 1 open 1 settled 0 refunded 0' "$E/mutants/$mutant.out"; then
      ok "mutant.$mutant killed (open native escrow after failed settlement)"
    elif [ "$mutant" = no-artifact-admission ] && grep -q '^FAIL forged-attestation:.*jobs 1 open 0 settled 1 refunded 0' "$E/mutants/$mutant.out" && grep -q '^FAIL false-verified-stdout:.*jobs 1 open 0 settled 1 refunded 0' "$E/mutants/$mutant.out"; then
      ok "mutant.$mutant killed (invalid artifacts/stdout paid)"
    else no "mutant.$mutant" 'required guard-specific negative assertion did not fail'; fi
  done
fi
printf 'ADAPTER controls failures=%s\n' "$f"
(cd "$E" && sha256sum authority quote pins.txt carrier-identities.out */adapter.out */*/CONTROL-SHA256SUMS) > "$E/CONTROL-SHA256SUMS"
if [ -d "$E/mutants" ]; then
  (cd "$E" && sha256sum mutants/*.out mutants/*/CONTROL-SHA256SUMS) >> "$E/CONTROL-SHA256SUMS"
fi
[ "$f" = 0 ]
