#!/bin/sh
# Build the Spark's matmul_u32 recompute: the pinned OM-2 SHA-256 unit of omega-mv followed by
# matmul_u32_recompute.om, compiled by the pinned seed-born omc. Exit 3 NOT_RUN when a pin differs.
#   OMEGA_OMC   omc binary (sha256 pinned below)
#   OMEGA_MV    an omega-mv checkout holding om/sha256/sha256-om2.om (sha256 pinned below)
#   $1          output path (default ./matmul_u32_recompute)
set -eu
OMC_PIN=2c82480596bbdc50cda9626866209ef662d5834f278f839ff4ce0250c495029f
SHA_UNIT_PIN=$(sed -n 's/^SHA_UNIT_PIN=//p' "$(dirname "$0")/pins.txt")
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-./matmul_u32_recompute}
[ -n "${OMEGA_OMC:-}" ] && [ -n "${OMEGA_MV:-}" ] || { echo "NOT_RUN: set OMEGA_OMC and OMEGA_MV"; exit 3; }
[ "$(sha256sum < "$OMEGA_OMC" | cut -c1-64)" = "$OMC_PIN" ] || { echo "NOT_RUN: omc is not the pinned compiler"; exit 3; }
UNIT="$OMEGA_MV/om/sha256/sha256-om2.om"
[ "$(sha256sum < "$UNIT" | cut -c1-64)" = "$SHA_UNIT_PIN" ] || { echo "NOT_RUN: $UNIT is not the pinned SHA-256 unit"; exit 3; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# Program mode has no exported entries (omc error 9 on `export fn`), so the unit's four `export fn`
# lines lose the word `export` and nothing else; every other byte of the unit is used as pinned.
sed 's/^export fn /fn /' "$UNIT" > "$T/unit.om"
[ "$(grep -c '^export fn ' "$UNIT")" = 4 ] && ! grep -q '^export fn ' "$T/unit.om" || { echo "FAIL: unexpected SHA-256 unit shape"; exit 1; }
cat "$T/unit.om" "$HERE/matmul_u32_recompute.om" > "$T/src.om"
"$OMEGA_OMC" < "$T/src.om" > "$T/bin"
chmod +x "$T/bin"
mv "$T/bin" "$OUT"
echo "built $OUT sha256=$(sha256sum < "$OUT" | cut -c1-64) src=$(sha256sum < "$T/src.om" | cut -c1-64)"
