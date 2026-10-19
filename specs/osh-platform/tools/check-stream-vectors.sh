#!/bin/bash
# check-stream-vectors.sh: check the OSH stream and task vectors (vectors/s*.vec, vectors/t*.vec) against the
# reference model, and guard the shell-core corpus next to them.
#
# Usage: check-stream-vectors.sh [CC]        (default CC: cc)
#
# 1. Lints every s*.vec / t*.vec header (case, kind, exec, domain, needs; file name ends in _<case>.vec;
#    case names unique).
# 2. Builds tools/osh_sv_ref.c with warnings as errors (C99, libc only) and runs the corpus; every vector must
#    PASS. Then the same with ASan/UBSan when the compiler supports it.
# 3. Runs tools/mutate-stream-ref.sh: every check of the model must be caught by a vector.
# 4. Regenerates the shell-core inputs (tools/make-vectors.sh) into a scratch directory and requires them
#    byte-identical to vectors/v*.in and v*.env, so the stream corpus never disturbs the existing format.
# Host-only check of the corpus: it is not evidence about any adapter and qualifies no hardware. Shell and C
# only. Found by the PROTO-C-VECTORS gate (tests/gates/run.sh c-vectors) because its name matches check-*.sh.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
vec="$here/../vectors"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1. header lint
bad=0
n=0
for f in "$vec"/s*.vec "$vec"/t*.vec; do
    [ -e "$f" ] || continue
    n=$((n + 1))
    b=$(basename "$f" .vec)
    c=$(sed -n 's/^case \([a-z0-9_]*\)$/\1/p' "$f" | head -n 1)
    for key in case kind exec domain needs; do
        grep -q "^$key " "$f" || { echo "OSHSV1_LINT $b: missing '$key' line" >&2; bad=1; }
    done
    grep -q -E '^kind (positive|negative)$' "$f" || { echo "OSHSV1_LINT $b: kind must be positive or negative" >&2; bad=1; }
    grep -q -E '^exec (host-logic|native-qemu)$' "$f" || { echo "OSHSV1_LINT $b: exec must be host-logic or native-qemu" >&2; bad=1; }
    grep -q -E '^domain (1|2|any)$' "$f" || { echo "OSHSV1_LINT $b: domain must be 1, 2 or any" >&2; bad=1; }
    case "$b" in
        [st][0-9][0-9][0-9]_"$c") ;;
        *) echo "OSHSV1_LINT $b: file name must be sNNN_<case> or tNNN_<case>" >&2; bad=1 ;;
    esac
    echo "$c" >>"$tmp/cases"
done
test "$n" -gt 0 || { echo "OSHSV1_LINT no stream or task vectors found" >&2; exit 1; }
dups=$(sort "$tmp/cases" | uniq -d)
test -z "$dups" || { echo "OSHSV1_LINT duplicate case names: $dups" >&2; bad=1; }
test "$bad" -eq 0 || exit 1
echo "OSHSV1_LINT ok vectors=$n"

# 2. reference model, plain and sanitized
corpus=$(git -C "$here" rev-parse HEAD 2>/dev/null || echo unpinned)
tc=$("$CC" --version 2>/dev/null | head -n 1 | tr ' ' '_')
"$CC" -std=c99 -O2 -Wall -Wextra -Werror -pedantic -o "$tmp/ref" "$here/osh_sv_ref.c"
"$tmp/ref" --corpus "$vec" --pin "corpus=$corpus" --pin "toolchain=$tc"
if "$CC" -std=c99 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
        -o "$tmp/ref_san" "$here/osh_sv_ref.c" 2>/dev/null; then
    "$tmp/ref_san" --corpus "$vec" | sed 's/impl=reference-model/impl=reference-model-asan-ubsan/' | grep -v '^PASS '
    test "${PIPESTATUS[0]}" -eq 0
else
    echo "OSHSV1_SANITIZER NOT_RUN (compiler lacks -fsanitize=address,undefined)"
fi

# 3. every check has teeth
bash "$here/mutate-stream-ref.sh" "$CC"

# 4. the shell-core corpus is untouched
mkdir -p "$tmp/core"
bash "$here/make-vectors.sh" "$tmp/core"
for f in "$tmp"/core/v*; do
    cmp -s "$f" "$vec/$(basename "$f")" || { echo "OSHSV1_CORE_STALE $(basename "$f") differs from make-vectors.sh" >&2; exit 1; }
done
for f in "$vec"/v*.in "$vec"/v*.env; do
    [ -e "$tmp/core/$(basename "$f")" ] || { echo "OSHSV1_CORE_STALE $(basename "$f") is not generated" >&2; exit 1; }
done
echo "OSHSV1_CORE_REGEN identical"
echo "OSHSV1_VECTORS_PASS"
