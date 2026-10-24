/* mjb_verify.c: reference checker for MJB1, the typed bounded microjob DAG.
 * Spec: ../SPEC.md (Draft v0.1, contract 0.1.0, wire version 1).
 *
 * Self-contained C99: its own SHA-256 (FIPS 180-4), libc only, no heap
 * (static buffers), no clock. mjb_check() is a pure function of one
 * read-only buffer. It pins the static document rules of SPEC.md section 4.4
 * with vectors; it is not linked into any runtime. Receipt rules (section 5)
 * are stateful and live in the Rust ledger (crates/aien-microjob).
 *
 * Usage:
 *   mjb_verify FILE                print one verdict line
 *   mjb_verify --corpus DIR        check every DIR/expected.txt line, print
 *                                  MJB1_CONFORMANCE impl=c pass=N fail=M
 *   mjb_verify --make-vectors DIR  write the vector files and DIR/expected.txt
 *
 * Verdict line (the format expected.txt pins):
 *   ok nodes=N incarnation=I ceiling=C objective=H64 tenant=H64 digest=H64
 *      order=i,j,...              (one line; canonical Kahn order, lowest index first)
 *   refuse CODE                    (CODE is a name from SPEC.md section 6)
 *
 * Exit status: 0 on accept / all corpus lines agree, 1 otherwise, 2 on usage
 * or I/O error.
 *
 * Mutation hooks: building with -DMJB_MUTANT=K disables check K (the CHK_*
 * numbers below). tools/mutate-verifier.sh builds every mutant and requires
 * the vectors to fail each one, which shows every check is exercised.
 */
#define _POSIX_C_SOURCE 200809L /* open, fdopen, close under -std=c99 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef MJB_MUTANT
#define MJB_MUTANT 0
#endif
#define CHECK(k) (MJB_MUTANT != (k))

enum {
    CHK_MIN_LEN = 1, CHK_MAGIC, CHK_DOWNGRADE, CHK_VERSION, CHK_COUNT, CHK_EXACT_LEN,
    CHK_RES0, CHK_CEILING, CHK_OBJECTIVE, CHK_TENANT, CHK_SUBJECT, CHK_APPROVAL,
    CHK_INCARNATION, CHK_JOB, CHK_IDEM, CHK_GEN, CHK_RES1, CHK_DEP_SLOTS,
    CHK_OPERAND_SLOTS, CHK_OPERAND_PAD, CHK_DIMS, CHK_E_KIND_OP, CHK_E_PROFILE,
    CHK_E_EFFECT, CHK_E_VERIFIER, CHK_E_RETRY, CHK_E_ATTEMPTS, CHK_E_CANCEL,
    CHK_E_PRECISION, CHK_E_SUBSTRATE, CHK_E_DEPN, CHK_E_OPN, CHK_E_RTYPE, CHK_E_RANK,
    CHK_E_PURE, CHK_E_OPKIND, CHK_TENANT_MATCH, CHK_CAPABILITY, CHK_EFFECT_CEIL,
    CHK_VERIFIER_ZERO, CHK_VERIFIER_REF, CHK_RECOMPUTE_REF, CHK_RECOMPUTE_PURE,
    CHK_IMPURE_NEURAL, CHK_IMPURE_EFFECT, CHK_COMPUTE_TOKENS, CHK_NEURAL_TOKENS,
    CHK_EXPANSION, CHK_RETRY_NEVER, CHK_RETRY_EFFECT, CHK_ZERO_CAP, CHK_NODE_EXPIRY,
    CHK_OPERAND_MISSING, CHK_DUP, CHK_DEP_RANGE, CHK_STALE, CHK_CYCLE, CHK_BUDGET,
    CHK_LAST
};

/* ---- refusal codes (spec section 6, document part) ------------------------ */
enum {
    MJB_OK = 0, MJB_BAD_LENGTH, MJB_BAD_MAGIC, MJB_DOWNGRADE, MJB_BAD_VERSION,
    MJB_BAD_COUNT, MJB_RESERVED_NONZERO, MJB_BAD_ENUM, MJB_NO_OBJECTIVE, MJB_NO_TENANT,
    MJB_NO_SUBJECT, MJB_NO_APPROVAL, MJB_BAD_EXPIRY, MJB_NO_JOB, MJB_CROSS_TENANT,
    MJB_NO_CAPABILITY, MJB_UNAUTHORIZED_EFFECT, MJB_NO_VERIFIER, MJB_IMPURE,
    MJB_TOKEN_PROFILE, MJB_NEEDS_EXPANSION, MJB_BAD_RETRY, MJB_ZERO_CAP,
    MJB_MISSING_OPERAND, MJB_DUPLICATE_JOB, MJB_MISSING_DEP, MJB_STALE_GENERATION,
    MJB_CYCLE, MJB_OVER_BUDGET, MJB_CODE_COUNT
};
static const char *const code_names[MJB_CODE_COUNT] = {
    "OK", "MJB_BAD_LENGTH", "MJB_BAD_MAGIC", "MJB_DOWNGRADE", "MJB_BAD_VERSION",
    "MJB_BAD_COUNT", "MJB_RESERVED_NONZERO", "MJB_BAD_ENUM", "MJB_NO_OBJECTIVE",
    "MJB_NO_TENANT", "MJB_NO_SUBJECT", "MJB_NO_APPROVAL", "MJB_BAD_EXPIRY", "MJB_NO_JOB",
    "MJB_CROSS_TENANT", "MJB_NO_CAPABILITY", "MJB_UNAUTHORIZED_EFFECT", "MJB_NO_VERIFIER",
    "MJB_IMPURE", "MJB_TOKEN_PROFILE", "MJB_NEEDS_EXPANSION", "MJB_BAD_RETRY",
    "MJB_ZERO_CAP", "MJB_MISSING_OPERAND", "MJB_DUPLICATE_JOB", "MJB_MISSING_DEP",
    "MJB_STALE_GENERATION", "MJB_CYCLE", "MJB_OVER_BUDGET"
};

/* ---- SHA-256 ------------------------------------------------------------ */
typedef struct { uint32_t h[8]; uint64_t n; uint8_t b[64]; uint32_t used; } sha256;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

static void sha_block(sha256 *s, const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void sha_init(sha256 *s) {
    static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(s->h, iv, sizeof iv); s->n = 0; s->used = 0;
}
static void sha_update(sha256 *s, const void *data, size_t len) {
    const uint8_t *p = data;
    s->n += len;
    while (len) {
        uint32_t k = 64 - s->used;
        if (k > len) k = (uint32_t)len;
        memcpy(s->b + s->used, p, k);
        s->used += k; p += k; len -= k;
        if (s->used == 64) { sha_block(s, s->b); s->used = 0; }
    }
}
static void sha_final(sha256 *s, uint8_t out[32]) {
    uint64_t bits = s->n * 8;
    uint8_t pad = 0x80, z = 0, l[8];
    sha_update(s, &pad, 1);
    while (s->used != 56) sha_update(s, &z, 1);
    for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, l, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i] = (uint8_t)(s->h[i] >> 24); out[4*i+1] = (uint8_t)(s->h[i] >> 16);
        out[4*i+2] = (uint8_t)(s->h[i] >> 8); out[4*i+3] = (uint8_t)s->h[i];
    }
}
static void sha_once(const void *p, size_t n, uint8_t out[32]) {
    sha256 s; sha_init(&s); sha_update(&s, p, n); sha_final(&s, out);
}

/* ---- big-endian helpers -------------------------------------------------- */
static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t g64(const uint8_t *p) { return (uint64_t)g32(p) << 32 | g32(p + 4); }
static void p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void p32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void p64(uint8_t *p, uint64_t v) { p32(p, (uint32_t)(v >> 32)); p32(p + 4, (uint32_t)v); }
static int all_zero(const uint8_t *p, size_t n) { while (n--) if (*p++) return 0; return 1; }

/* ---- the format (spec section 4) ------------------------------------------ */
#define HDR     192u
#define NODE    448u
#define MAXN    64u
#define MAXDEP  8u
#define MAXOPS  4u
#define DEPLEN  6u
#define OPLEN   40u
#define MAXDOC  (HDR + MAXN * NODE)

#define H_VERSION 4
#define H_CEILING 5
#define H_COUNT 6
#define H_OBJECTIVE 8
#define H_TENANT 40
#define H_SUBJECT 72
#define H_APPROVAL 104
#define H_INCARNATION 136
#define H_RES0 140
#define H_EXPIRES 144
#define H_B_TIME 152
#define H_B_FUEL 160
#define H_B_MEMORY 168
#define H_B_WORK 176
#define H_B_IN 184
#define H_B_OUT 188

#define N_JOB 0
#define N_IDEM 16
#define N_GEN 32
#define N_KIND 36
#define N_OP 37
#define N_PROFILE 38
#define N_EFFECT 39
#define N_IN 40
#define N_OUT 42
#define N_REQ_IN 44
#define N_REQ_OUT 46
#define N_VERIFIER 48
#define N_RETRY 49
#define N_ATTEMPTS 50
#define N_CANCEL 51
#define N_PRECISION 52
#define N_SUBSTRATE 53
#define N_DEPS_N 54
#define N_OPS_N 55
#define N_RTYPE 56
#define N_RANK 57
#define N_PURE 58
#define N_RES1 59
#define N_TIME 60
#define N_FUEL 64
#define N_MEMORY 72
#define N_WORK 80
#define N_EXPIRES 88
#define N_DIMS 96
#define N_CAP 112
#define N_TENANT 144
#define N_MODEL 176
#define N_VREF 208
#define N_DEPS 240
#define N_OPERANDS 288

static const uint16_t cap_in[5] = { 0, 64, 128, 256, 512 };
static const uint16_t cap_out[5] = { 0, 16, 32, 64, 128 };

/* Rules 10 to 23 for one node record. Loops are clamped to the slot counts so
 * that every mutant stays memory-safe. */
static int check_node(const uint8_t *n, const uint8_t *h) {
    unsigned depn = n[N_DEPS_N], opn = n[N_OPS_N], rank = n[N_RANK];
    unsigned dlim = depn < MAXDEP ? depn : MAXDEP, olim = opn < MAXOPS ? opn : MAXOPS;
    unsigned k = n[N_KIND], op = n[N_OP], prof = n[N_PROFILE], vk = n[N_VERIFIER], s;
    unsigned pidx = prof <= 4 ? prof : 0;
    int pure = n[N_PURE] == 1, vz = all_zero(n + N_VREF, 32), mz = all_zero(n + N_MODEL, 32);
    uint16_t tin = g16(n + N_IN), tout = g16(n + N_OUT), rin = g16(n + N_REQ_IN), rout = g16(n + N_REQ_OUT);
    uint64_t exp = g64(n + N_EXPIRES);

    if (CHECK(CHK_JOB) && all_zero(n + N_JOB, 16)) return MJB_NO_JOB;
    if (CHECK(CHK_IDEM) && all_zero(n + N_IDEM, 16)) return MJB_NO_JOB;
    if (CHECK(CHK_GEN) && g32(n + N_GEN) == 0) return MJB_NO_JOB;

    if (CHECK(CHK_RES1) && n[N_RES1]) return MJB_RESERVED_NONZERO;
    if (CHECK(CHK_DEP_SLOTS))
        for (s = dlim; s < MAXDEP; s++) if (!all_zero(n + N_DEPS + DEPLEN * s, DEPLEN)) return MJB_RESERVED_NONZERO;
    if (CHECK(CHK_OPERAND_SLOTS))
        for (s = olim; s < MAXOPS; s++) if (!all_zero(n + N_OPERANDS + OPLEN * s, OPLEN)) return MJB_RESERVED_NONZERO;
    if (CHECK(CHK_OPERAND_PAD))
        for (s = 0; s < olim; s++) if (!all_zero(n + N_OPERANDS + OPLEN * s + 1, 3)) return MJB_RESERVED_NONZERO;
    if (CHECK(CHK_DIMS))
        for (s = rank < 4 ? rank : 4; s < 4; s++) if (g32(n + N_DIMS + 4 * s)) return MJB_RESERVED_NONZERO;

    if (CHECK(CHK_E_KIND_OP) && !((k == 1 && op >= 1 && op <= 6) || (k == 2 && op >= 1 && op <= 4))) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_PROFILE) && prof > 4) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_EFFECT) && n[N_EFFECT] > 2) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_VERIFIER) && vk > 3) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_RETRY) && (n[N_RETRY] < 1 || n[N_RETRY] > 3)) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_ATTEMPTS) && (n[N_ATTEMPTS] < 1 || n[N_ATTEMPTS] > 8)) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_CANCEL) && (n[N_CANCEL] < 1 || n[N_CANCEL] > 2)) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_PRECISION) && n[N_PRECISION] > 6) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_SUBSTRATE) && (n[N_SUBSTRATE] == 0 || (n[N_SUBSTRATE] & 0xF8))) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_DEPN) && depn > MAXDEP) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_OPN) && opn > MAXOPS) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_RTYPE) && (n[N_RTYPE] < 1 || n[N_RTYPE] > 7)) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_RANK) && rank > 4) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_PURE) && n[N_PURE] > 1) return MJB_BAD_ENUM;
    if (CHECK(CHK_E_OPKIND))
        for (s = 0; s < olim; s++) {
            uint8_t ok = n[N_OPERANDS + OPLEN * s];
            if (ok < 1 || ok > 5) return MJB_BAD_ENUM;
        }

    if (CHECK(CHK_TENANT_MATCH) && memcmp(n + N_TENANT, h + H_TENANT, 32) != 0) return MJB_CROSS_TENANT;
    if (CHECK(CHK_CAPABILITY) && all_zero(n + N_CAP, 32)) return MJB_NO_CAPABILITY;
    if (CHECK(CHK_EFFECT_CEIL) && n[N_EFFECT] > h[H_CEILING]) return MJB_UNAUTHORIZED_EFFECT;

    if (CHECK(CHK_VERIFIER_ZERO) && vk == 0) return MJB_NO_VERIFIER;
    if (CHECK(CHK_VERIFIER_REF) && vk != 1 && vz) return MJB_NO_VERIFIER;
    if (CHECK(CHK_RECOMPUTE_REF) && vk == 1 && !vz) return MJB_NO_VERIFIER;
    if (CHECK(CHK_RECOMPUTE_PURE) && vk == 1 && !pure) return MJB_NO_VERIFIER;

    if (CHECK(CHK_IMPURE_NEURAL) && pure && k == 2) return MJB_IMPURE;
    if (CHECK(CHK_IMPURE_EFFECT) && pure && n[N_EFFECT] == 2) return MJB_IMPURE;

    if (k == 1) {
        if (CHECK(CHK_COMPUTE_TOKENS) && (prof != 0 || tin || tout || rin || rout || !mz)) return MJB_TOKEN_PROFILE;
    } else {
        if (CHECK(CHK_NEURAL_TOKENS) && (prof == 0 || tin == 0 || tout == 0 || tin > cap_in[pidx] || tout > cap_out[pidx] || mz))
            return MJB_TOKEN_PROFILE;
    }
    if (CHECK(CHK_EXPANSION) && (rin > tin || rout > tout)) return MJB_NEEDS_EXPANSION;

    if (CHECK(CHK_RETRY_NEVER) && n[N_RETRY] == 1 && n[N_ATTEMPTS] > 1) return MJB_BAD_RETRY;
    if (CHECK(CHK_RETRY_EFFECT) && n[N_EFFECT] == 2 && n[N_RETRY] == 2) return MJB_BAD_RETRY;

    if (CHECK(CHK_ZERO_CAP) && (g32(n + N_TIME) == 0 || g64(n + N_FUEL) == 0 || g64(n + N_MEMORY) == 0 || g64(n + N_WORK) == 0))
        return MJB_ZERO_CAP;
    if (CHECK(CHK_NODE_EXPIRY) && (exp == 0 || exp > g64(h + H_EXPIRES))) return MJB_BAD_EXPIRY;
    if (CHECK(CHK_OPERAND_MISSING))
        for (s = 0; s < olim; s++) {
            const uint8_t *o = n + N_OPERANDS + OPLEN * s;
            if (g32(o + 4) == 0 || all_zero(o + 8, 32)) return MJB_MISSING_OPERAND;
        }
    return MJB_OK;
}

/* Exact sum: *over is set when the total does not fit in 64 bits. */
static uint64_t add_exact(uint64_t a, uint64_t b, int *over) {
    if (a > UINT64_MAX - b) *over = 1;
    return a + b;
}

/* Kahn's algorithm, lowest index first. Returns the number of nodes emitted. */
static unsigned kahn(const uint8_t *b, unsigned count, unsigned *order) {
    unsigned indeg[MAXN], emitted[MAXN] = { 0 }, done = 0, i, s;
    for (i = 0; i < count; i++) {
        unsigned d = b[HDR + NODE * i + N_DEPS_N];
        indeg[i] = d < MAXDEP ? d : MAXDEP;
    }
    while (done < count) {
        unsigned next = count;
        for (i = 0; i < count; i++) if (!emitted[i] && indeg[i] == 0) { next = i; break; }
        if (next == count) break;
        emitted[next] = 1;
        order[done++] = next;
        for (i = 0; i < count; i++) {
            const uint8_t *n = b + HDR + NODE * i;
            unsigned d = n[N_DEPS_N] < MAXDEP ? n[N_DEPS_N] : MAXDEP;
            for (s = 0; s < d; s++) if (g16(n + N_DEPS + DEPLEN * s) == next) indeg[i]--;
        }
    }
    return done;
}

static int mjb_check(const uint8_t *b, size_t len, unsigned *order, unsigned *count_out) {
    unsigned count, i, j, s;
    int rc, over = 0;
    uint64_t t = 0, fu = 0, wk = 0, ti = 0, to = 0;
    *count_out = 0;
    if (CHECK(CHK_MIN_LEN) && len < HDR) return MJB_BAD_LENGTH;
    if (CHECK(CHK_MAGIC) && memcmp(b, "MJB1", 4) != 0) return MJB_BAD_MAGIC;
    if (CHECK(CHK_DOWNGRADE) && b[H_VERSION] == 0) return MJB_DOWNGRADE;
    if (CHECK(CHK_VERSION) && b[H_VERSION] > 1) return MJB_BAD_VERSION;
    count = g16(b + H_COUNT);
    if (CHECK(CHK_COUNT) && (count == 0 || count > MAXN)) return MJB_BAD_COUNT;
    if (CHECK(CHK_EXACT_LEN) && len != HDR + (size_t)count * NODE) return MJB_BAD_LENGTH;
    if (count > MAXN) return MJB_BAD_COUNT; /* array bound for mutants, not a rule of its own */
    if (CHECK(CHK_RES0) && !all_zero(b + H_RES0, 4)) return MJB_RESERVED_NONZERO;
    if (CHECK(CHK_CEILING) && b[H_CEILING] > 2) return MJB_BAD_ENUM;
    if (CHECK(CHK_OBJECTIVE) && all_zero(b + H_OBJECTIVE, 32)) return MJB_NO_OBJECTIVE;
    if (CHECK(CHK_TENANT) && all_zero(b + H_TENANT, 32)) return MJB_NO_TENANT;
    if (CHECK(CHK_SUBJECT) && all_zero(b + H_SUBJECT, 32)) return MJB_NO_SUBJECT;
    if (CHECK(CHK_APPROVAL) && all_zero(b + H_APPROVAL, 32)) return MJB_NO_APPROVAL;
    if (CHECK(CHK_INCARNATION) && g32(b + H_INCARNATION) == 0) return MJB_NO_OBJECTIVE;
    /* A header expires_at of 0 needs no rule of its own: every node then fails
     * rule 22 (node expiry above the header), with the same code. */

    for (i = 0; i < count; i++)
        if ((rc = check_node(b + HDR + NODE * i, b)) != MJB_OK) return rc;

    if (CHECK(CHK_DUP))
        for (i = 0; i < count; i++)
            for (j = i + 1; j < count; j++) {
                const uint8_t *x = b + HDR + NODE * i, *y = b + HDR + NODE * j;
                if (!memcmp(x + N_JOB, y + N_JOB, 16) || !memcmp(x + N_IDEM, y + N_IDEM, 16)) return MJB_DUPLICATE_JOB;
            }
    if (CHECK(CHK_DEP_RANGE))
        for (i = 0; i < count; i++) {
            const uint8_t *n = b + HDR + NODE * i;
            unsigned d = n[N_DEPS_N] < MAXDEP ? n[N_DEPS_N] : MAXDEP;
            for (s = 0; s < d; s++) {
                unsigned idx = g16(n + N_DEPS + DEPLEN * s);
                if (idx == i || idx >= count) return MJB_MISSING_DEP;
            }
        }
    if (CHECK(CHK_STALE))
        for (i = 0; i < count; i++) {
            const uint8_t *n = b + HDR + NODE * i;
            unsigned d = n[N_DEPS_N] < MAXDEP ? n[N_DEPS_N] : MAXDEP;
            for (s = 0; s < d; s++) {
                unsigned idx = g16(n + N_DEPS + DEPLEN * s);
                if (idx < count && g32(n + N_DEPS + DEPLEN * s + 2) != g32(b + HDR + NODE * idx + N_GEN))
                    return MJB_STALE_GENERATION;
            }
        }
    if (CHECK(CHK_CYCLE) && kahn(b, count, order) != count) return MJB_CYCLE;
    if (CHECK(CHK_BUDGET)) {
        for (i = 0; i < count; i++) {
            const uint8_t *n = b + HDR + NODE * i;
            t = add_exact(t, g32(n + N_TIME), &over);
            fu = add_exact(fu, g64(n + N_FUEL), &over);
            wk = add_exact(wk, g64(n + N_WORK), &over);
            ti += g16(n + N_IN);
            to += g16(n + N_OUT);
            if (g64(n + N_MEMORY) > g64(b + H_B_MEMORY)) over = 1;
        }
        if (over || t > g64(b + H_B_TIME) || fu > g64(b + H_B_FUEL) || wk > g64(b + H_B_WORK)
            || ti > g32(b + H_B_IN) || to > g32(b + H_B_OUT))
            return MJB_OVER_BUDGET;
    }
    kahn(b, count, order);
    *count_out = count;
    return MJB_OK;
}

static void hex(char *out, const uint8_t *p, size_t n) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[p[i] >> 4]; out[2*i+1] = H[p[i] & 15]; }
    out[2*n] = 0;
}

static void ok_line(const uint8_t *b, size_t len, const char *order, char *line, size_t cap) {
    char obj[65], ten[65], dig[65];
    uint8_t d[32];
    sha_once(b, len, d);
    hex(obj, b + H_OBJECTIVE, 32);
    hex(ten, b + H_TENANT, 32);
    hex(dig, d, 32);
    snprintf(line, cap, "ok nodes=%u incarnation=%lu ceiling=%u objective=%s tenant=%s digest=%s order=%s",
             (unsigned)g16(b + H_COUNT), (unsigned long)g32(b + H_INCARNATION), (unsigned)b[H_CEILING], obj, ten, dig, order);
}

static void order_text(const unsigned *order, unsigned count, char *out, size_t cap) {
    size_t at = 0;
    out[0] = 0;
    for (unsigned i = 0; i < count && at + 8 < cap; i++)
        at += (size_t)snprintf(out + at, cap - at, i ? ",%u" : "%u", order[i]);
}

static void verdict_line(const uint8_t *b, size_t len, char *line, size_t cap) {
    unsigned order[MAXN], count;
    char ord[512];
    int code = mjb_check(b, len, order, &count);
    if (code != MJB_OK) { snprintf(line, cap, "refuse %s", code_names[code]); return; }
    order_text(order, count, ord, sizeof ord);
    ok_line(b, len, ord, line, cap);
}

/* ---- file I/O (outside the checker) ---------------------------------------- */
#define FILE_CAP 65536u
static uint8_t file_buf[FILE_CAP];

/* Reads the whole file into file_buf (zeroed first). Returns 0, or -1 on I/O
 * error or a file larger than FILE_CAP (no vector is that large). */
static int slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    size_t k;
    memset(file_buf, 0, sizeof file_buf);
    if (!f) return -1;
    k = fread(file_buf, 1, FILE_CAP, f);
    if (k == FILE_CAP && fgetc(f) != EOF) { fclose(f); return -1; }
    fclose(f);
    *n = k;
    return 0;
}

static void rstrip(char *s) { size_t n = strlen(s); while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = 0; }
static int plain_name(const char *s) { return s[0] && s[0] != '.' && !strchr(s, '/'); }

static FILE *create_file(const char *path, const char *mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    FILE *f;
    if (fd < 0) return NULL;
    if (!(f = fdopen(fd, mode))) close(fd);
    return f;
}

static int corpus(const char *dir) {
    char path[4096], line[1024], got[1024];
    unsigned pass = 0, fail = 0;
    size_t n;
    FILE *f;
    snprintf(path, sizeof path, "%s/expected.txt", dir);
    if (!(f = fopen(path, "r"))) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *sp;
        rstrip(line);
        if (!line[0] || line[0] == '#') continue;
        if (!(sp = strchr(line, ' '))) { fprintf(stderr, "bad line: %s\n", line); fail++; continue; }
        *sp = 0;
        if (!plain_name(line)) { fprintf(stderr, "not a plain file name: %s\n", line); fail++; continue; }
        snprintf(path, sizeof path, "%s/%s", dir, line);
        if (slurp(path, &n)) { fprintf(stderr, "cannot read %s\n", path); fail++; continue; }
        verdict_line(file_buf, n, got, sizeof got);
        if (strcmp(got, sp + 1) != 0) { fail++; printf("MISMATCH %s\n  expected: %s\n  got:      %s\n", line, sp + 1, got); }
        else pass++;
    }
    fclose(f);
    printf("MJB1_CONFORMANCE impl=c pass=%u fail=%u\n", pass, fail);
    return fail || !pass ? 1 : 0;
}

/* ---- vector generator -------------------------------------------------------- */
/* Every refused vector starts from one well-formed document and changes one
 * thing. The expected line of an accepted vector takes its order from the
 * generator's intent, not from mjb_check, so the checker is tested against it. */
static uint8_t doc[MAXDOC + 64];
static unsigned doc_n;
static FILE *gen_expected;
static int gen_fail;
static const char *gen_dir;

static void fill(uint8_t *p, size_t n, uint8_t seed) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + 7 * i); }
static uint8_t *nd(unsigned i) { return doc + HDR + NODE * i; }
static size_t doc_len(void) { return HDR + (size_t)doc_n * NODE; }

static void header(unsigned count, uint8_t ceiling) {
    memset(doc, 0, sizeof doc);
    doc_n = count;
    memcpy(doc, "MJB1", 4);
    doc[H_VERSION] = 1;
    doc[H_CEILING] = ceiling;
    p16(doc + H_COUNT, (uint16_t)count);
    fill(doc + H_OBJECTIVE, 32, 0x0B);
    fill(doc + H_TENANT, 32, 0x7E);
    fill(doc + H_SUBJECT, 32, 0x5B);
    fill(doc + H_APPROVAL, 32, 0xA9);
    p32(doc + H_INCARNATION, 1);
    p64(doc + H_EXPIRES, 2000000000u);
    p64(doc + H_B_TIME, 10000);
    p64(doc + H_B_FUEL, 1000000);
    p64(doc + H_B_MEMORY, (uint64_t)1 << 30);
    p64(doc + H_B_WORK, 1000000);
    p32(doc + H_B_IN, 4096);
    p32(doc + H_B_OUT, 1024);
}

static void common(unsigned i) {
    uint8_t *n = nd(i);
    fill(n + N_JOB, 14, 0x4A); p16(n + N_JOB + 14, (uint16_t)(i + 1));
    fill(n + N_IDEM, 14, 0x1D); p16(n + N_IDEM + 14, (uint16_t)(i + 1));
    p32(n + N_GEN, 1);
    n[N_CANCEL] = 1;
    p32(n + N_TIME, 100);
    p64(n + N_FUEL, 1000);
    p64(n + N_MEMORY, (uint64_t)1 << 20);
    p64(n + N_WORK, 1000);
    p64(n + N_EXPIRES, 1999999999u);
    fill(n + N_CAP, 32, 0xCA);
    memcpy(n + N_TENANT, doc + H_TENANT, 32);
}

static void compute(unsigned i, uint8_t op) {
    uint8_t *n = nd(i);
    common(i);
    n[N_KIND] = 1; n[N_OP] = op; n[N_PROFILE] = 0; n[N_EFFECT] = 1;
    n[N_VERIFIER] = 1; n[N_RETRY] = 2; n[N_ATTEMPTS] = 3;
    n[N_PRECISION] = 0; n[N_SUBSTRATE] = 1; n[N_RTYPE] = 2; n[N_PURE] = 1;
}

static void neural(unsigned i, uint8_t op, uint8_t prof, uint16_t tin, uint16_t tout, uint16_t rin, uint16_t rout) {
    uint8_t *n = nd(i);
    common(i);
    n[N_KIND] = 2; n[N_OP] = op; n[N_PROFILE] = prof; n[N_EFFECT] = 0;
    p16(n + N_IN, tin); p16(n + N_OUT, tout); p16(n + N_REQ_IN, rin); p16(n + N_REQ_OUT, rout);
    n[N_VERIFIER] = 2; fill(n + N_VREF, 32, 0x5E);
    n[N_RETRY] = 2; n[N_ATTEMPTS] = 2;
    n[N_PRECISION] = 2; n[N_SUBSTRATE] = 3; n[N_RTYPE] = 6; n[N_PURE] = 0;
    fill(n + N_MODEL, 32, 0x3D);
}

static void dep(unsigned i, unsigned on) {
    uint8_t *n = nd(i);
    unsigned s = n[N_DEPS_N]++;
    p16(n + N_DEPS + DEPLEN * s, (uint16_t)on);
    p32(n + N_DEPS + DEPLEN * s + 2, g32(nd(on) + N_GEN));
}

static void operand(unsigned i, uint8_t kind, uint8_t seed) {
    uint8_t *n = nd(i);
    unsigned s = n[N_OPS_N]++;
    uint8_t *o = n + N_OPERANDS + OPLEN * s;
    o[0] = kind;
    p32(o + 4, 1);
    fill(o + 8, 32, seed);
}

/* compute(ARITH, 1 CONTENT operand) -> compute(REDUCE) -> neural ROUTE 64/16 */
static void base3(void) {
    header(3, 1);
    compute(0, 1); operand(0, 3, 0x21);
    compute(1, 3); dep(1, 0);
    neural(2, 1, 1, 64, 16, 40, 8); dep(2, 1); operand(2, 1, 0x31);
}

static void emit(const char *name, size_t n, const char *expect) {
    char path[4096];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", gen_dir, name);
    if (!(f = create_file(path, "wb")) || fwrite(doc, 1, n, f) != n || fclose(f) != 0) {
        fprintf(stderr, "cannot write %s\n", path);
        gen_fail = 1;
        return;
    }
    fprintf(gen_expected, "%s %s\n", name, expect);
}

static void ok(const char *name, const char *order) {
    char line[1024];
    ok_line(doc, doc_len(), order, line, sizeof line);
    emit(name, doc_len(), line);
}

static void bad_len(const char *name, size_t n, const char *code) {
    char line[128];
    snprintf(line, sizeof line, "refuse %s", code);
    emit(name, n, line);
}
static void bad(const char *name, const char *code) { bad_len(name, doc_len(), code); }

static int make_vectors(const char *dir) {
    char path[4096];
    unsigned i;
    gen_dir = dir;
    snprintf(path, sizeof path, "%s/expected.txt", dir);
    if (!(gen_expected = create_file(path, "w"))) { fprintf(stderr, "cannot write %s\n", path); return 2; }
    fprintf(gen_expected,
        "# MJB1 document vectors. Spec: ../SPEC.md (Draft v0.1, wire version 1).\n"
        "# Line: <file> <verdict line>, verdict line as printed by tools/mjb_verify.c:\n"
        "#   ok nodes=N incarnation=I ceiling=C objective=H64 tenant=H64 digest=H64 order=i,j,...\n"
        "#   refuse <code from SPEC.md section 6>\n"
        "# Generated by tools/mjb_verify.c --make-vectors; do not edit by hand.\n");

    /* ---- accepted ---- */
    base3();
    ok("ok-base3.mjb", "0,1,2");

    /* 11 nodes: two independent sums, reduce, mean, compare, two neural
     * routes, an independent numeric check, a summary, a compile step and
     * one EFFECT node under an EFFECT ceiling. */
    header(11, 2);
    compute(0, 1); operand(0, 3, 0x41);
    compute(1, 1); operand(1, 3, 0x42);
    compute(2, 3); dep(2, 0); dep(2, 1);
    compute(3, 1); dep(3, 2);
    compute(4, 4); dep(4, 3); operand(4, 3, 0x43);
    neural(5, 1, 1, 64, 16, 48, 4); operand(5, 3, 0x44);
    neural(6, 1, 2, 128, 32, 100, 4); operand(6, 1, 0x45);
    compute(7, 6); dep(7, 3); nd(7)[N_VERIFIER] = 2; fill(nd(7) + N_VREF, 32, 0x77);
    neural(8, 4, 3, 256, 64, 200, 60); dep(8, 4); dep(8, 5); dep(8, 6); operand(8, 5, 0x46);
    compute(9, 5); dep(9, 8); operand(9, 4, 0x47);
    compute(10, 1); dep(10, 4); dep(10, 7); operand(10, 2, 0x48);
    nd(10)[N_EFFECT] = 2; nd(10)[N_PURE] = 0; nd(10)[N_VERIFIER] = 3; fill(nd(10) + N_VREF, 32, 0x99);
    nd(10)[N_RETRY] = 3; nd(10)[N_ATTEMPTS] = 2; nd(10)[N_CANCEL] = 2;
    ok("ok-sample-11.mjb", "0,1,2,3,4,5,6,7,8,9,10");

    header(64, 1);
    for (i = 0; i < 64; i++) { compute(i, 1); if (i) dep(i, i - 1); else operand(0, 3, 0x51); }
    {
        char ord[512];
        unsigned o[64];
        for (i = 0; i < 64; i++) o[i] = i;
        order_text(o, 64, ord, sizeof ord);
        ok("ok-chain-64.mjb", ord);
    }

    header(4, 1);
    compute(2, 1); operand(2, 3, 0x61);
    compute(3, 1); dep(3, 2);
    compute(0, 1); dep(0, 3);
    compute(1, 1); dep(1, 3);
    ok("ok-reverse-order.mjb", "2,3,0,1");

    header(9, 1);
    for (i = 0; i < 8; i++) { compute(i, 1); operand(i, 3, (uint8_t)(0x70 + i)); }
    compute(8, 2);
    for (i = 0; i < 8; i++) dep(8, i);
    operand(8, 1, 0x81); operand(8, 2, 0x82); operand(8, 4, 0x83); operand(8, 5, 0x84);
    nd(8)[N_RTYPE] = 4; nd(8)[N_RANK] = 4; nd(8)[N_PRECISION] = 1;
    p32(nd(8) + N_DIMS, 2); p32(nd(8) + N_DIMS + 4, 3); p32(nd(8) + N_DIMS + 8, 4); p32(nd(8) + N_DIMS + 12, 5);
    ok("ok-fanin-8-tensor.mjb", "0,1,2,3,4,5,6,7,8");

    header(1, 0);
    neural(0, 2, 1, 64, 16, 64, 16); operand(0, 3, 0x91);
    ok("ok-minimal-exact-64-16.mjb", "0");

    header(1, 0);
    neural(0, 3, 4, 512, 128, 300, 100); operand(0, 3, 0x92);
    ok("ok-specialist-512-128.mjb", "0");

    header(1, 0);
    neural(0, 1, 2, 40, 10, 40, 10); operand(0, 3, 0x93);
    ok("ok-optimizer-smaller-caps.mjb", "0");

    /* ---- refused: header, in check order ---- */
    base3(); bad_len("bad-length-short.mjb", 100, "MJB_BAD_LENGTH");
    base3(); bad_len("bad-length-empty.mjb", 0, "MJB_BAD_LENGTH");
    base3(); doc[3] = '2'; bad("bad-magic.mjb", "MJB_BAD_MAGIC");
    base3(); doc[H_VERSION] = 0; bad("bad-version-downgrade.mjb", "MJB_DOWNGRADE");
    base3(); doc[H_VERSION] = 2; bad("bad-version-unknown.mjb", "MJB_BAD_VERSION");
    base3(); p16(doc + H_COUNT, 0); bad_len("bad-count-zero.mjb", HDR, "MJB_BAD_COUNT");
    base3(); p16(doc + H_COUNT, 65); bad_len("bad-count-65.mjb", HDR, "MJB_BAD_COUNT");
    base3(); bad_len("bad-length-mismatch.mjb", doc_len() - 1, "MJB_BAD_LENGTH");
    base3(); bad_len("bad-length-trailing.mjb", doc_len() + 1, "MJB_BAD_LENGTH");
    base3(); doc[H_RES0 + 1] = 1; bad("bad-reserved0.mjb", "MJB_RESERVED_NONZERO");
    base3(); doc[H_CEILING] = 3; bad("bad-ceiling-enum.mjb", "MJB_BAD_ENUM");
    base3(); memset(doc + H_OBJECTIVE, 0, 32); bad("bad-no-objective.mjb", "MJB_NO_OBJECTIVE");
    base3(); memset(doc + H_TENANT, 0, 32); bad("bad-no-tenant.mjb", "MJB_NO_TENANT");
    base3(); memset(doc + H_SUBJECT, 0, 32); bad("bad-no-subject.mjb", "MJB_NO_SUBJECT");
    base3(); memset(doc + H_APPROVAL, 0, 32); bad("bad-no-approval.mjb", "MJB_NO_APPROVAL");
    base3(); p32(doc + H_INCARNATION, 0); bad("bad-no-incarnation.mjb", "MJB_NO_OBJECTIVE");
    base3(); p64(doc + H_EXPIRES, 0); bad("bad-header-expiry-zero.mjb", "MJB_BAD_EXPIRY");

    /* ---- refused: one node rule each ---- */
    base3(); memset(nd(1) + N_JOB, 0, 16); bad("bad-no-job-id.mjb", "MJB_NO_JOB");
    base3(); memset(nd(1) + N_IDEM, 0, 16); bad("bad-no-idempotence-key.mjb", "MJB_NO_JOB");
    base3(); p32(nd(0) + N_GEN, 0); bad("bad-no-generation.mjb", "MJB_NO_JOB");
    base3(); nd(1)[N_RES1] = 1; bad("bad-reserved1.mjb", "MJB_RESERVED_NONZERO");
    base3(); nd(0)[N_DEPS + 1] = 1; bad("bad-reserved-unused-dep.mjb", "MJB_RESERVED_NONZERO");
    base3(); nd(1)[N_DEPS + DEPLEN + 5] = 1; bad("bad-reserved-unused-dep-generation.mjb", "MJB_RESERVED_NONZERO");
    base3(); nd(1)[N_OPERANDS + 20] = 1; bad("bad-reserved-unused-operand.mjb", "MJB_RESERVED_NONZERO");
    base3(); nd(0)[N_OPERANDS + 2] = 1; bad("bad-reserved-operand-pad.mjb", "MJB_RESERVED_NONZERO");
    base3(); p32(nd(0) + N_DIMS, 1); bad("bad-reserved-dims.mjb", "MJB_RESERVED_NONZERO");
    base3(); nd(0)[N_KIND] = 3; bad("bad-enum-kind.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_OP] = 7; bad("bad-enum-op-compute.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_OP] = 0; bad("bad-enum-op-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(2)[N_OP] = 5; bad("bad-enum-op-neural.mjb", "MJB_BAD_ENUM");
    base3(); nd(2)[N_PROFILE] = 5; bad("bad-enum-profile.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_EFFECT] = 3; bad("bad-enum-effect.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_VERIFIER] = 4; bad("bad-enum-verifier.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_RETRY] = 0; bad("bad-enum-retry-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_RETRY] = 4; bad("bad-enum-retry-four.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_ATTEMPTS] = 0; bad("bad-enum-attempts-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_ATTEMPTS] = 9; bad("bad-enum-attempts-nine.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_CANCEL] = 0; bad("bad-enum-cancel-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_CANCEL] = 3; bad("bad-enum-cancel-three.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_PRECISION] = 7; bad("bad-enum-precision.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_SUBSTRATE] = 0; bad("bad-enum-substrate-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_SUBSTRATE] = 0x09; bad("bad-enum-substrate-high.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_DEPS_N] = 9; bad("bad-enum-dep-count.mjb", "MJB_BAD_ENUM");
    base3(); operand(0, 3, 0x22); operand(0, 3, 0x23); operand(0, 3, 0x24); nd(0)[N_OPS_N] = 5;
    bad("bad-enum-operand-count.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_RTYPE] = 0; bad("bad-enum-result-type-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_RTYPE] = 8; bad("bad-enum-result-type-eight.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_RANK] = 5; bad("bad-enum-rank.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_PURE] = 2; bad("bad-enum-pure.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_OPERANDS] = 6; bad("bad-enum-operand-kind-six.mjb", "MJB_BAD_ENUM");
    base3(); nd(0)[N_OPERANDS] = 0; bad("bad-enum-operand-kind-zero.mjb", "MJB_BAD_ENUM");
    base3(); nd(1)[N_TENANT + 31] ^= 1; bad("bad-cross-tenant.mjb", "MJB_CROSS_TENANT");
    base3(); memset(nd(1) + N_CAP, 0, 32); bad("bad-no-capability.mjb", "MJB_NO_CAPABILITY");
    base3(); nd(0)[N_EFFECT] = 2; bad("bad-unauthorized-effect.mjb", "MJB_UNAUTHORIZED_EFFECT");
    base3(); doc[H_CEILING] = 0; bad("bad-unauthorized-compute-under-none.mjb", "MJB_UNAUTHORIZED_EFFECT");
    base3(); nd(2)[N_VERIFIER] = 0; bad("bad-no-verifier-kind-zero.mjb", "MJB_NO_VERIFIER");
    base3(); nd(0)[N_VERIFIER] = 0; bad("bad-no-verifier-kind-zero-no-ref.mjb", "MJB_NO_VERIFIER");
    base3(); memset(nd(2) + N_VREF, 0, 32); bad("bad-no-verifier-checker-no-ref.mjb", "MJB_NO_VERIFIER");
    base3(); fill(nd(0) + N_VREF, 32, 0x55); bad("bad-no-verifier-recompute-with-ref.mjb", "MJB_NO_VERIFIER");
    base3(); nd(0)[N_PURE] = 0; bad("bad-no-verifier-recompute-impure.mjb", "MJB_NO_VERIFIER");
    base3(); nd(2)[N_PURE] = 1; bad("bad-impure-neural.mjb", "MJB_IMPURE");
    base3(); doc[H_CEILING] = 2; nd(0)[N_EFFECT] = 2; bad("bad-impure-effect.mjb", "MJB_IMPURE");
    base3(); p16(nd(0) + N_IN, 10); bad("bad-token-compute-with-tokens.mjb", "MJB_TOKEN_PROFILE");
    base3(); nd(0)[N_PROFILE] = 1; bad("bad-token-compute-with-profile.mjb", "MJB_TOKEN_PROFILE");
    base3(); fill(nd(0) + N_MODEL, 32, 0x3D); bad("bad-token-compute-with-model.mjb", "MJB_TOKEN_PROFILE");
    base3(); p16(nd(0) + N_REQ_IN, 5); bad("bad-token-compute-required.mjb", "MJB_TOKEN_PROFILE");
    base3(); nd(2)[N_PROFILE] = 0; bad("bad-token-neural-zero-profile.mjb", "MJB_TOKEN_PROFILE");
    base3(); p16(nd(2) + N_IN, 65); bad("bad-token-neural-over-profile-input.mjb", "MJB_TOKEN_PROFILE");
    base3(); p16(nd(2) + N_OUT, 17); bad("bad-token-neural-over-profile-output.mjb", "MJB_TOKEN_PROFILE");
    base3(); p16(nd(2) + N_OUT, 0); p16(nd(2) + N_REQ_OUT, 0); bad("bad-token-neural-zero-cap.mjb", "MJB_TOKEN_PROFILE");
    base3(); memset(nd(2) + N_MODEL, 0, 32); bad("bad-token-neural-no-model.mjb", "MJB_TOKEN_PROFILE");
    base3(); p16(nd(2) + N_REQ_IN, 90); bad("bad-needs-expansion-64-16-input.mjb", "MJB_NEEDS_EXPANSION");
    base3(); p16(nd(2) + N_REQ_OUT, 20); bad("bad-needs-expansion-64-16-output.mjb", "MJB_NEEDS_EXPANSION");
    base3(); nd(0)[N_RETRY] = 1; nd(0)[N_ATTEMPTS] = 2; bad("bad-retry-never-multi.mjb", "MJB_BAD_RETRY");
    base3(); doc[H_CEILING] = 2; nd(2)[N_EFFECT] = 2; bad("bad-retry-effect-idempotent.mjb", "MJB_BAD_RETRY");
    base3(); p32(nd(1) + N_TIME, 0); bad("bad-zero-cap-time.mjb", "MJB_ZERO_CAP");
    base3(); p64(nd(1) + N_FUEL, 0); bad("bad-zero-cap-fuel.mjb", "MJB_ZERO_CAP");
    base3(); p64(nd(1) + N_MEMORY, 0); bad("bad-zero-cap-memory.mjb", "MJB_ZERO_CAP");
    base3(); p64(nd(1) + N_WORK, 0); bad("bad-zero-cap-work.mjb", "MJB_ZERO_CAP");
    base3(); p64(nd(1) + N_EXPIRES, 0); bad("bad-node-expiry-zero.mjb", "MJB_BAD_EXPIRY");
    base3(); p64(nd(1) + N_EXPIRES, 2000000001u); bad("bad-node-expiry-after-header.mjb", "MJB_BAD_EXPIRY");
    base3(); memset(nd(0) + N_OPERANDS + 8, 0, 32); bad("bad-missing-operand-digest.mjb", "MJB_MISSING_OPERAND");
    base3(); p32(nd(0) + N_OPERANDS + 4, 0); bad("bad-missing-operand-generation.mjb", "MJB_MISSING_OPERAND");

    /* ---- refused: whole graph ---- */
    base3(); memcpy(nd(2) + N_JOB, nd(1) + N_JOB, 16); bad("bad-duplicate-job.mjb", "MJB_DUPLICATE_JOB");
    base3(); memcpy(nd(2) + N_IDEM, nd(1) + N_IDEM, 16); bad("bad-duplicate-idempotence-key.mjb", "MJB_DUPLICATE_JOB");
    base3(); p16(nd(1) + N_DEPS, 1); bad("bad-missing-dep-self.mjb", "MJB_MISSING_DEP");
    base3(); p16(nd(1) + N_DEPS, 3); bad("bad-missing-dep-out-of-range.mjb", "MJB_MISSING_DEP");
    base3(); p32(nd(0) + N_GEN, 2); bad("bad-stale-generation.mjb", "MJB_STALE_GENERATION");
    base3(); dep(0, 1); bad("bad-cycle-two.mjb", "MJB_CYCLE");
    base3(); dep(0, 2); bad("bad-cycle-three.mjb", "MJB_CYCLE");
    base3(); p64(doc + H_B_TIME, 299); bad("bad-over-budget-time.mjb", "MJB_OVER_BUDGET");
    base3(); p64(doc + H_B_FUEL, 2999); bad("bad-over-budget-fuel.mjb", "MJB_OVER_BUDGET");
    base3(); p64(doc + H_B_WORK, 2999); bad("bad-over-budget-work.mjb", "MJB_OVER_BUDGET");
    base3(); p32(doc + H_B_IN, 63); bad("bad-over-budget-input-tokens.mjb", "MJB_OVER_BUDGET");
    base3(); p32(doc + H_B_OUT, 15); bad("bad-over-budget-output-tokens.mjb", "MJB_OVER_BUDGET");
    base3(); p64(doc + H_B_MEMORY, ((uint64_t)1 << 20) - 1); bad("bad-over-budget-memory.mjb", "MJB_OVER_BUDGET");
    base3(); p64(doc + H_B_FUEL, UINT64_MAX); p64(nd(0) + N_FUEL, UINT64_MAX); bad("bad-over-budget-overflow.mjb", "MJB_OVER_BUDGET");

    if (fclose(gen_expected) != 0) gen_fail = 1;
    return gen_fail ? 2 : 0;
}

int main(int argc, char **argv) {
    char out[1024];
    size_t n;
    if (argc == 2 && argv[1][0] != '-') {
        if (slurp(argv[1], &n)) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
        verdict_line(file_buf, n, out, sizeof out);
        puts(out);
        return strncmp(out, "ok ", 3) == 0 ? 0 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "--corpus") == 0) return corpus(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--make-vectors") == 0) return make_vectors(argv[2]);
    fprintf(stderr, "usage: mjb_verify FILE | --corpus DIR | --make-vectors DIR\n");
    return 2;
}
