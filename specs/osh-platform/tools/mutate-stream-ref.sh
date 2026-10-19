#!/bin/bash
# mutate-stream-ref.sh: show that every check in osh_sv_ref.c is exercised by the stream and task vectors.
# Builds one model per check with that check disabled (-DSV_MUTANT=K, the order of `enum mut`) and
# requires the corpus to report at least one mismatch. A mutant the vectors do not notice is a SURVIVOR
# and fails this script.
#
# Usage: mutate-stream-ref.sh [CC]
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
vec="$here/../vectors"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
names=$(sed -n '/MUT_WRITE_RIGHT = 1/,/MUT_LAST/p' "$here/osh_sv_ref.c" | tr -d ' \n' | sed 's/MUT_WRITE_RIGHT=1/MUT_WRITE_RIGHT/; s/,MUT_LAST.*//' | tr ',' ' ')
test -n "$names" || { echo "cannot read the check list" >&2; exit 2; }
k=0 killed=0 survived=0
for name in $names; do
    k=$((k + 1))
    "$CC" -std=c99 -O1 -w -DSV_MUTANT=$k -o "$tmp/m$k" "$here/osh_sv_ref.c"
    if "$tmp/m$k" --corpus "$vec" >"$tmp/out$k" 2>&1; then
        echo "SURVIVOR $k $name"
        survived=$((survived + 1))
    else
        echo "killed $k $name: $(grep -c -E 'MISMATCH|VECTOR_ERROR' "$tmp/out$k") line(s) differ"
        killed=$((killed + 1))
    fi
done
echo "OSHSV1_MUTANTS total=$k killed=$killed survived=$survived"
test "$survived" -eq 0 && test "$k" -gt 0
