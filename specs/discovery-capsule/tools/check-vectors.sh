#!/bin/bash
# check-vectors.sh: build the DCP1 reference checker and check the vectors.
#
# Usage: check-vectors.sh [CC]        (default CC: cc)
#
# 1. Builds tools/dcp_verify.c with warnings as errors (C99, libc only).
# 2. Regenerates the vectors into a scratch directory (dcp_verify
#    --make-vectors) and requires them byte-identical to vectors/, so a stale
#    or hand-edited vector fails here.
# 3. Runs every vectors/expected.txt line (and re-encodes every accepted
#    message, which must give the same bytes), plus an ASan/UBSan build when
#    the compiler supports it.
# 4. Runs tools/mutate-verifier.sh: every check must be caught by a vector.
# Host-only check: no hardware. Shell and C only. Found by the PROTO-C-VECTORS
# gate (tests/gates/run.sh c-vectors) because its name matches check-*.sh.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
vec="$here/../vectors"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -pedantic -o "$tmp/dcp_verify" "$here/dcp_verify.c"

mkdir -p "$tmp/regen"
"$tmp/dcp_verify" --make-vectors "$tmp/regen"
ignore="-x .crumb -x .crumb.local -x .gitattributes"
if ! diff -r $ignore "$vec" "$tmp/regen" >/dev/null; then
    echo "DCP1_VECTORS_STALE: vectors/ differs from dcp_verify --make-vectors output" >&2
    diff -rq $ignore "$vec" "$tmp/regen" >&2 || true
    exit 1
fi
echo "DCP1_VECTORS_REGEN identical"

"$tmp/dcp_verify" --corpus "$vec"

if "$CC" -std=c99 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
        -o "$tmp/dcp_verify_san" "$here/dcp_verify.c" 2>/dev/null; then
    "$tmp/dcp_verify_san" --corpus "$vec" | sed 's/^DCP1_CONFORMANCE impl=c/DCP1_CONFORMANCE impl=c-asan-ubsan/'
    test "${PIPESTATUS[0]}" -eq 0
else
    echo "DCP1_SANITIZER NOT_RUN (compiler lacks -fsanitize=address,undefined)"
fi

bash "$here/mutate-verifier.sh" "$CC"
echo "DCP1_VECTORS_PASS"
