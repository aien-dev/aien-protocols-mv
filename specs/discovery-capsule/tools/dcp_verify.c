/* dcp_verify.c: reference checker for the DCP1 family (Discovery Capsule,
 * owner consent, retraction, retraction ack, experience lineage).
 * Spec: ../SPEC.md (Draft v0.1, contract 0.1.0, wire version 1).
 *
 * Self-contained C99: its own SHA-256 (FIPS 180-4), libc only, no heap, no
 * clock. dcp_check() is a pure function of one read-only buffer and pins the
 * static rules of SPEC.md section 10 with vectors. Signatures (P-256) and the
 * stateful recipient rules of section 11 are checked by the Rust crate
 * crates/aien-discovery-capsule, not here: the signature bytes of the vectors
 * are fixed filler.
 *
 * Usage:
 *   dcp_verify FILE                print one verdict line
 *   dcp_verify --corpus DIR        check every DIR/expected.txt line, print
 *                                  DCP1_CONFORMANCE impl=c pass=N fail=M
 *   dcp_verify --make-vectors DIR  write the vector files and DIR/expected.txt
 *
 * Verdict line:
 *   ok type=MAGIC digest=H64 key=H66   (record digest, signature excluded;
 *                                       the signing key)
 *   refuse CODE                        (CODE from SPEC.md section 12)
 *
 * Exit status: 0 on accept / all corpus lines agree, 1 otherwise, 2 on usage
 * or I/O error.
 *
 * Mutation hooks: -DDCP_MUTANT=K disables check K; tools/mutate-verifier.sh
 * requires the vectors to catch every mutant.
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef DCP_MUTANT
#define DCP_MUTANT 0
#endif
#define CHECK(k) (DCP_MUTANT != (k))

enum {
    CHK_MIN_LEN = 1, CHK_MAGIC, CHK_DOWNGRADE, CHK_VERSION, CHK_EXACT_LEN,
    CHK_P_RES0, CHK_P_RES1, CHK_P_DIMS, CHK_P_SCOPE, CHK_P_PERMS, CHK_P_PRECISION,
    CHK_P_CAPS, CHK_P_RANK, CHK_P_LICENSE, CHK_P_ABI, CHK_P_DIGESTS, CHK_P_POLICY,
    CHK_P_KEY, CHK_P_VALID_FROM, CHK_P_EXPIRES, CHK_P_FAILURES, CHK_P_REVOCATION,
    CHK_P_PRIVATE, CHK_P_RECIPIENTS, CHK_P_AMPLIFY, CHK_P_CONSENT,
    CHK_C_RES0, CHK_C_RES1, CHK_C_SLOTS, CHK_C_PURPOSES, CHK_C_COUNT, CHK_C_VERSION,
    CHK_C_DIGESTS, CHK_C_USED, CHK_C_KEY, CHK_C_ISSUED, CHK_C_RETENTION, CHK_C_AMPLIFY,
    CHK_R_RES0, CHK_R_RES1, CHK_R_SCOPE, CHK_R_ERASURE, CHK_R_SEQ, CHK_R_DIGESTS,
    CHK_R_OWNER_KEY, CHK_R_SIGNER_KEY, CHK_R_EFFECTIVE, CHK_R_PREV,
    CHK_A_RES, CHK_A_STATUS, CHK_A_DIGEST, CHK_A_KEY, CHK_A_TIME,
    CHK_L_RES, CHK_L_PARENT_SLOTS, CHK_L_INFL_SLOTS, CHK_L_COUNTS, CHK_L_FIELDS,
    CHK_L_USED, CHK_L_KEY, CHK_L_SELF, CHK_L_DUP,
    CHK_LAST
};

enum {
    DCP_OK = 0, DCP_BAD_LENGTH, DCP_BAD_MAGIC, DCP_DOWNGRADE, DCP_BAD_VERSION,
    DCP_RESERVED_NONZERO, DCP_BAD_ENUM, DCP_UNKNOWN_LICENSE, DCP_FALSE_ERASURE_CLAIM,
    DCP_MISSING_FIELD, DCP_BAD_KEY, DCP_BAD_VALIDITY, DCP_INCONSISTENT,
    DCP_SCOPE_CONFLICT, DCP_PERMISSION_AMPLIFICATION, DCP_NO_CONSENT,
    DCP_ANCESTOR_CYCLE, DCP_DUPLICATE, DCP_CODE_COUNT
};
static const char *const code_names[DCP_CODE_COUNT] = {
    "OK", "DCP_BAD_LENGTH", "DCP_BAD_MAGIC", "DCP_DOWNGRADE", "DCP_BAD_VERSION",
    "DCP_RESERVED_NONZERO", "DCP_BAD_ENUM", "DCP_UNKNOWN_LICENSE", "DCP_FALSE_ERASURE_CLAIM",
    "DCP_MISSING_FIELD", "DCP_BAD_KEY", "DCP_BAD_VALIDITY", "DCP_INCONSISTENT",
    "DCP_SCOPE_CONFLICT", "DCP_PERMISSION_AMPLIFICATION", "DCP_NO_CONSENT",
    "DCP_ANCESTOR_CYCLE", "DCP_DUPLICATE"
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
static int z32(const uint8_t *b, size_t at) { return all_zero(b + at, 32); }
static int key_ok(const uint8_t *b, size_t at) { return b[at] == 0x02 || b[at] == 0x03; }

/* ---- record types (spec section 1) ----------------------------------------- */
typedef struct { const char *magic; size_t len, key_at, sig_at; } layout;
static const layout layouts[5] = {
    { "DCP1", 676, 576, 612 }, { "DCC1", 388, 288, 324 }, { "DCR1", 284, 185, 220 },
    { "DCA1", 148, 48, 84 },   { "DCL1", 588, 488, 524 }
};
static const layout *find_layout(const uint8_t *b) {
    for (int i = 0; i < 5; i++) if (!memcmp(b, layouts[i].magic, 4)) return &layouts[i];
    return NULL;
}

#define P_READ 0x02u
#define P_REDIST 0x04u
#define P_TRAIN 0x08u

static int check_capsule(const uint8_t *b) {
    unsigned rank = b[20], sc = b[5], perms = b[6], d, lic = g16(b + 8);
    uint64_t from = g64(b + 40), until = g64(b + 48);
    if (CHECK(CHK_P_RES0) && !all_zero(b + 21, 3)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_P_RES1) && !all_zero(b + 609, 3)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_P_DIMS)) for (d = rank < 4 ? rank : 4; d < 4; d++) if (g32(b + 24 + 4 * d)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_P_SCOPE) && sc > 3) return DCP_BAD_ENUM;
    if (CHECK(CHK_P_PERMS) && (perms & 0xF0u)) return DCP_BAD_ENUM;
    if (CHECK(CHK_P_PRECISION) && b[7] > 6) return DCP_BAD_ENUM;
    if (CHECK(CHK_P_CAPS) && (g32(b + 16) & ~0x3Fu)) return DCP_BAD_ENUM;
    if (CHECK(CHK_P_RANK) && rank > 4) return DCP_BAD_ENUM;
    if (CHECK(CHK_P_LICENSE) && (lic < 1 || lic > 6)) return DCP_UNKNOWN_LICENSE;
    if (CHECK(CHK_P_ABI) && g32(b + 12) == 0) return DCP_MISSING_FIELD;
    if (CHECK(CHK_P_DIGESTS)) for (d = 64; d < 288; d += 32) if (z32(b, d)) return DCP_MISSING_FIELD;
    if (CHECK(CHK_P_POLICY) && z32(b, 384)) return DCP_MISSING_FIELD;
    if (CHECK(CHK_P_KEY) && !key_ok(b, 576)) return DCP_BAD_KEY;
    if (CHECK(CHK_P_VALID_FROM) && from == 0) return DCP_BAD_VALIDITY;
    if (CHECK(CHK_P_EXPIRES) && until <= from) return DCP_BAD_VALIDITY;
    if (CHECK(CHK_P_FAILURES) && (g16(b + 10) != 0) == z32(b, 288)) return DCP_INCONSISTENT;
    if (CHECK(CHK_P_REVOCATION) && (g64(b + 56) != 0) == z32(b, 480)) return DCP_INCONSISTENT;
    if (CHECK(CHK_P_PRIVATE) && sc == 0 && perms != 0) return DCP_SCOPE_CONFLICT;
    if (CHECK(CHK_P_RECIPIENTS) && (sc == 1) == z32(b, 416)) return DCP_SCOPE_CONFLICT;
    if (CHECK(CHK_P_AMPLIFY) && (perms & (P_REDIST | P_TRAIN)) && !(perms & P_READ)) return DCP_PERMISSION_AMPLIFICATION;
    if (CHECK(CHK_P_CONSENT) && ((perms & (P_READ | P_REDIST | P_TRAIN)) || sc != 0) && z32(b, 448)) return DCP_NO_CONSENT;
    return DCP_OK;
}

static int check_consent(const uint8_t *b) {
    unsigned n = b[6], lim = n < 4 ? n : 4, s;
    if (CHECK(CHK_C_RES0) && b[7]) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_C_RES1) && !all_zero(b + 321, 3)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_C_SLOTS)) for (s = lim; s < 4; s++) if (!z32(b, 160 + 32 * s)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_C_PURPOSES) && (b[5] == 0 || (b[5] & 0xF0u))) return DCP_BAD_ENUM;
    if (CHECK(CHK_C_COUNT) && n > 4) return DCP_BAD_ENUM;
    if (CHECK(CHK_C_VERSION) && g32(b + 8) == 0) return DCP_MISSING_FIELD;
    if (CHECK(CHK_C_DIGESTS) && (z32(b, 32) || z32(b, 64) || z32(b, 96) || z32(b, 128))) return DCP_MISSING_FIELD;
    if (CHECK(CHK_C_USED)) for (s = 0; s < lim; s++) if (z32(b, 160 + 32 * s)) return DCP_MISSING_FIELD;
    if (CHECK(CHK_C_KEY) && !key_ok(b, 288)) return DCP_BAD_KEY;
    if (CHECK(CHK_C_ISSUED) && g64(b + 16) == 0) return DCP_BAD_VALIDITY;
    if (CHECK(CHK_C_RETENTION) && g64(b + 24) <= g64(b + 16)) return DCP_BAD_VALIDITY;
    if (CHECK(CHK_C_AMPLIFY) && (b[5] & (P_REDIST | P_TRAIN)) && !(b[5] & P_READ)) return DCP_PERMISSION_AMPLIFICATION;
    return DCP_OK;
}

static int check_retraction(const uint8_t *b) {
    uint64_t seq = g64(b + 8);
    if (CHECK(CHK_R_RES0) && b[7]) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_R_RES1) && !all_zero(b + 218, 2)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_R_SCOPE) && (b[5] == 0 || (b[5] & 0xF0u))) return DCP_BAD_ENUM;
    if (CHECK(CHK_R_ERASURE) && b[6]) return DCP_FALSE_ERASURE_CLAIM;
    if (CHECK(CHK_R_SEQ) && seq == 0) return DCP_MISSING_FIELD;
    if (CHECK(CHK_R_DIGESTS) && (z32(b, 24) || z32(b, 88) || z32(b, 120))) return DCP_MISSING_FIELD;
    if (CHECK(CHK_R_OWNER_KEY) && !key_ok(b, 152)) return DCP_BAD_KEY;
    if (CHECK(CHK_R_SIGNER_KEY) && !key_ok(b, 185)) return DCP_BAD_KEY;
    if (CHECK(CHK_R_EFFECTIVE) && g64(b + 16) == 0) return DCP_BAD_VALIDITY;
    if (CHECK(CHK_R_PREV) && (seq == 1) != z32(b, 56)) return DCP_INCONSISTENT;
    return DCP_OK;
}

static int check_ack(const uint8_t *b) {
    if (CHECK(CHK_A_RES) && (!all_zero(b + 6, 2) || !all_zero(b + 81, 3))) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_A_STATUS) && (b[5] < 1 || b[5] > 2)) return DCP_BAD_ENUM;
    if (CHECK(CHK_A_DIGEST) && z32(b, 16)) return DCP_MISSING_FIELD;
    if (CHECK(CHK_A_KEY) && !key_ok(b, 48)) return DCP_BAD_KEY;
    if (CHECK(CHK_A_TIME) && g64(b + 8) == 0) return DCP_BAD_VALIDITY;
    return DCP_OK;
}

static int check_lineage(const uint8_t *b) {
    unsigned np = b[5], ni = b[6], pl = np < 4 ? np : 4, il = ni < 8 ? ni : 8, s, t;
    if (CHECK(CHK_L_RES) && (b[7] || !all_zero(b + 521, 3))) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_L_PARENT_SLOTS)) for (s = pl; s < 4; s++) if (!z32(b, 104 + 32 * s)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_L_INFL_SLOTS)) for (s = il; s < 8; s++) if (!z32(b, 232 + 32 * s)) return DCP_RESERVED_NONZERO;
    if (CHECK(CHK_L_COUNTS) && (np > 4 || ni > 8)) return DCP_BAD_ENUM;
    if (CHECK(CHK_L_FIELDS) && (z32(b, 8) || z32(b, 40) || z32(b, 72))) return DCP_MISSING_FIELD;
    if (CHECK(CHK_L_USED)) {
        for (s = 0; s < pl; s++) if (z32(b, 104 + 32 * s)) return DCP_MISSING_FIELD;
        for (s = 0; s < il; s++) if (z32(b, 232 + 32 * s)) return DCP_MISSING_FIELD;
    }
    if (CHECK(CHK_L_KEY) && !key_ok(b, 488)) return DCP_BAD_KEY;
    if (CHECK(CHK_L_SELF)) for (s = 0; s < pl; s++) if (!memcmp(b + 104 + 32 * s, b + 8, 32)) return DCP_ANCESTOR_CYCLE;
    if (CHECK(CHK_L_DUP))
        for (s = 0; s < pl; s++)
            for (t = s + 1; t < pl; t++) if (!memcmp(b + 104 + 32 * s, b + 104 + 32 * t, 32)) return DCP_DUPLICATE;
    return DCP_OK;
}

static int dcp_check(const uint8_t *b, size_t len, const layout **out) {
    const layout *l;
    *out = NULL;
    if (CHECK(CHK_MIN_LEN) && len < 5) return DCP_BAD_LENGTH;
    l = find_layout(b);
    if (!l) {
        if (CHECK(CHK_MAGIC)) return DCP_BAD_MAGIC;
        l = &layouts[0]; /* mutant only: read an unknown record as a capsule */
    }
    if (CHECK(CHK_DOWNGRADE) && b[4] == 0) return DCP_DOWNGRADE;
    if (CHECK(CHK_VERSION) && b[4] > 1) return DCP_BAD_VERSION;
    if (CHECK(CHK_EXACT_LEN) && len != l->len) return DCP_BAD_LENGTH;
    *out = l;
    switch (l->magic[2]) {
    case 'P': return check_capsule(b);
    case 'C': return check_consent(b);
    case 'R': return check_retraction(b);
    case 'A': return check_ack(b);
    default:  return check_lineage(b);
    }
}

static void hex(char *out, const uint8_t *p, size_t n) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[p[i] >> 4]; out[2*i+1] = H[p[i] & 15]; }
    out[2*n] = 0;
}

static void ok_line(const uint8_t *b, const layout *l, char *line, size_t cap) {
    char dig[65], key[67];
    uint8_t d[32];
    sha_once(b, l->sig_at, d);
    hex(dig, d, 32);
    hex(key, b + l->key_at, 33);
    snprintf(line, cap, "ok type=%s digest=%s key=%s", l->magic, dig, key);
}

static void verdict_line(const uint8_t *b, size_t len, char *line, size_t cap) {
    const layout *l;
    int code = dcp_check(b, len, &l);
    if (code != DCP_OK) snprintf(line, cap, "refuse %s", code_names[code]);
    else ok_line(b, l, line, cap);
}

/* ---- file I/O ------------------------------------------------------------------ */
#define FILE_CAP 4096u
static uint8_t file_buf[FILE_CAP];

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
    printf("DCP1_CONFORMANCE impl=c pass=%u fail=%u\n", pass, fail);
    return fail || !pass ? 1 : 0;
}

/* ---- vector generator ------------------------------------------------------------ */
/* Every refused vector is one well-formed record with one change. Signature
 * bytes are fixed filler: this checker does not verify signatures. The
 * expected line of an accepted vector is built from the layout table, not from
 * dcp_check. */
static uint8_t rec[1024];
static size_t rec_len;
static FILE *gen_expected;
static int gen_fail;
static const char *gen_dir;

static void fill(uint8_t *p, size_t n, uint8_t seed) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + 7 * i); }
static void key(size_t at, uint8_t seed) { rec[at] = 0x02 | (seed & 1); fill(rec + at + 1, 32, seed); }

static void start(const char *magic, size_t len) {
    memset(rec, 0, sizeof rec);
    memcpy(rec, magic, 4);
    rec[4] = 1;
    rec_len = len;
}

/* NAMED, DISCOVER|READ|TRAIN, one known failure, no retraction yet. */
static void capsule(void) {
    size_t at;
    start("DCP1", 676);
    rec[5] = 1; rec[6] = 0x0B; rec[7] = 0;
    p16(rec + 8, 1); p16(rec + 10, 1);
    p32(rec + 12, 7); p32(rec + 16, 0x05);
    rec[20] = 2; p32(rec + 24, 16); p32(rec + 28, 16);
    p64(rec + 40, 1800000000u); p64(rec + 48, 1900000000u);
    for (at = 64; at < 576; at += 32) fill(rec + at, 32, (uint8_t)(at / 32 + 0x20));
    memset(rec + 320, 0, 32);           /* utility verdict: NOT_RUN */
    memset(rec + 352, 0, 32);           /* scientific-T verdict: NOT_RUN */
    memset(rec + 480, 0, 32);           /* revocation head: none */
    memset(rec + 512, 0, 32);           /* no parent */
    key(576, 0xA1);
    fill(rec + 612, 64, 0x51);
}

static void consent(void) {
    start("DCC1", 388);
    rec[5] = 0x0B; rec[6] = 2;
    p32(rec + 8, 1); p32(rec + 12, 86400);
    p64(rec + 16, 1800000000u); p64(rec + 24, 1950000000u);
    fill(rec + 32, 32, 0x61); fill(rec + 64, 32, 0x62); fill(rec + 96, 32, 0x63); fill(rec + 128, 32, 0x64);
    fill(rec + 160, 32, 0x65); fill(rec + 192, 32, 0x66);
    key(288, 0xA1);
    fill(rec + 324, 64, 0x52);
}

static void retraction(uint64_t seq) {
    start("DCR1", 284);
    rec[5] = 0x06;
    p64(rec + 8, seq); p64(rec + 16, 1850000000u);
    fill(rec + 24, 32, 0x71);
    if (seq != 1) fill(rec + 56, 32, 0x72);
    fill(rec + 88, 32, 0x73); fill(rec + 120, 32, 0x74);
    key(152, 0xA1); key(185, 0xA1);
    fill(rec + 220, 64, 0x53);
}

static void ack(void) {
    start("DCA1", 148);
    rec[5] = 1;
    p64(rec + 8, 1850000100u);
    fill(rec + 16, 32, 0x81);
    key(48, 0xB2);
    fill(rec + 84, 64, 0x54);
}

static void lineage(unsigned parents, unsigned influenced) {
    unsigned s;
    start("DCL1", 588);
    rec[5] = (uint8_t)parents; rec[6] = (uint8_t)influenced;
    fill(rec + 8, 32, 0x91); fill(rec + 40, 32, 0x92); fill(rec + 72, 32, 0x93);
    for (s = 0; s < parents; s++) fill(rec + 104 + 32 * s, 32, (uint8_t)(0xA0 + s));
    for (s = 0; s < influenced; s++) fill(rec + 232 + 32 * s, 32, (uint8_t)(0xC0 + s));
    key(488, 0xA1);
    fill(rec + 524, 64, 0x55);
}

static void emit(const char *name, size_t n, const char *expect) {
    char path[4096];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", gen_dir, name);
    if (!(f = create_file(path, "wb")) || fwrite(rec, 1, n, f) != n || fclose(f) != 0) {
        fprintf(stderr, "cannot write %s\n", path);
        gen_fail = 1;
        return;
    }
    fprintf(gen_expected, "%s %s\n", name, expect);
}

static void ok(const char *name) {
    char line[1024];
    ok_line(rec, find_layout(rec), line, sizeof line);
    emit(name, rec_len, line);
}
static void bad_len(const char *name, size_t n, const char *code) {
    char line[128];
    snprintf(line, sizeof line, "refuse %s", code);
    emit(name, n, line);
}
static void bad(const char *name, const char *code) { bad_len(name, rec_len, code); }

static int make_vectors(const char *dir) {
    char path[4096];
    gen_dir = dir;
    snprintf(path, sizeof path, "%s/expected.txt", dir);
    if (!(gen_expected = create_file(path, "w"))) { fprintf(stderr, "cannot write %s\n", path); return 2; }
    fprintf(gen_expected,
        "# DCP1 family vectors. Spec: ../SPEC.md (Draft v0.1, wire version 1).\n"
        "# Line: <file> <verdict line>, verdict line as printed by tools/dcp_verify.c:\n"
        "#   ok type=MAGIC digest=H64 key=H66   (digest excludes the signature)\n"
        "#   refuse <code from SPEC.md section 12>\n"
        "# Signature bytes are filler; signatures are checked by the Rust crate.\n"
        "# Generated by tools/dcp_verify.c --make-vectors; do not edit by hand.\n");

    /* ---- accepted ---- */
    capsule(); ok("ok-capsule-named.dcp");
    capsule(); rec[5] = 0; rec[6] = 0; memset(rec + 416, 0, 32); memset(rec + 448, 0, 32);
    ok("ok-capsule-private-default.dcp");
    capsule(); rec[5] = 3; rec[6] = 0x0F; memset(rec + 416, 0, 32); p16(rec + 10, 0); memset(rec + 288, 0, 32);
    p64(rec + 56, 3); fill(rec + 480, 32, 0x3E); fill(rec + 512, 32, 0x3F); p16(rec + 8, 6);
    ok("ok-capsule-public-after-retractions.dcp");
    capsule(); rec[6] = 0x01; ok("ok-capsule-named-discover-only.dcp");
    consent(); ok("ok-consent-two-custodians.dcp");
    consent(); rec[6] = 0; memset(rec + 160, 0, 64); rec[5] = 0x02; ok("ok-consent-read-only.dcp");
    retraction(1); ok("ok-retraction-first.dcp");
    retraction(2); key(185, 0xB4); ok("ok-retraction-by-custodian.dcp");
    ack(); ok("ok-ack-enforced.dcp");
    ack(); rec[5] = 2; ok("ok-ack-enforced-with-retained.dcp");
    lineage(0, 0); ok("ok-lineage-root.dcp");
    lineage(2, 3); ok("ok-lineage-parents-influenced.dcp");
    lineage(4, 8); ok("ok-lineage-full.dcp");

    /* ---- refused: generic ---- */
    capsule(); bad_len("bad-length-short.dcp", 4, "DCP_BAD_LENGTH");
    capsule(); bad_len("bad-length-empty.dcp", 0, "DCP_BAD_LENGTH");
    capsule(); rec[3] = '9'; bad("bad-magic.dcp", "DCP_BAD_MAGIC");
    capsule(); rec[4] = 0; bad("bad-version-downgrade.dcp", "DCP_DOWNGRADE");
    capsule(); rec[4] = 2; bad("bad-version-unknown.dcp", "DCP_BAD_VERSION");
    capsule(); bad_len("bad-length-capsule-short.dcp", 675, "DCP_BAD_LENGTH");
    retraction(1); bad_len("bad-length-retraction-trailing.dcp", 285, "DCP_BAD_LENGTH");

    /* ---- refused: capsule ---- */
    capsule(); rec[22] = 1; bad("bad-capsule-reserved0.dcp", "DCP_RESERVED_NONZERO");
    capsule(); rec[610] = 1; bad("bad-capsule-reserved1.dcp", "DCP_RESERVED_NONZERO");
    capsule(); p32(rec + 32, 1); bad("bad-capsule-dims-past-rank.dcp", "DCP_RESERVED_NONZERO");
    capsule(); rec[5] = 4; bad("bad-capsule-scope.dcp", "DCP_BAD_ENUM");
    capsule(); rec[6] = 0x1B; bad("bad-capsule-permission-bit.dcp", "DCP_BAD_ENUM");
    capsule(); rec[7] = 7; bad("bad-capsule-precision.dcp", "DCP_BAD_ENUM");
    capsule(); p32(rec + 16, 0x45); bad("bad-capsule-capability-bit.dcp", "DCP_BAD_ENUM");
    capsule(); rec[20] = 5; bad("bad-capsule-rank.dcp", "DCP_BAD_ENUM");
    capsule(); p16(rec + 8, 0); bad("bad-capsule-license-unknown-zero.dcp", "DCP_UNKNOWN_LICENSE");
    capsule(); p16(rec + 8, 7); bad("bad-capsule-license-unknown-seven.dcp", "DCP_UNKNOWN_LICENSE");
    capsule(); p32(rec + 12, 0); bad("bad-capsule-no-abi.dcp", "DCP_MISSING_FIELD");
    capsule(); memset(rec + 64, 0, 32); bad("bad-capsule-no-meaning.dcp", "DCP_MISSING_FIELD");
    capsule(); memset(rec + 224, 0, 32); bad("bad-capsule-no-verifier.dcp", "DCP_MISSING_FIELD");
    capsule(); memset(rec + 256, 0, 32); bad("bad-capsule-no-evidence.dcp", "DCP_MISSING_FIELD");
    capsule(); memset(rec + 384, 0, 32); bad("bad-capsule-no-recipient-policy.dcp", "DCP_MISSING_FIELD");
    capsule(); rec[576] = 0x04; bad("bad-capsule-owner-key.dcp", "DCP_BAD_KEY");
    capsule(); p64(rec + 40, 0); bad("bad-capsule-valid-from-zero.dcp", "DCP_BAD_VALIDITY");
    capsule(); p64(rec + 48, 1800000000u); bad("bad-capsule-expires-not-after.dcp", "DCP_BAD_VALIDITY");
    capsule(); memset(rec + 288, 0, 32); bad("bad-capsule-failures-without-digest.dcp", "DCP_INCONSISTENT");
    capsule(); p16(rec + 10, 0); bad("bad-capsule-failure-digest-without-count.dcp", "DCP_INCONSISTENT");
    capsule(); p64(rec + 56, 2); bad("bad-capsule-revocation-seq-without-head.dcp", "DCP_INCONSISTENT");
    capsule(); fill(rec + 480, 32, 0x3E); bad("bad-capsule-revocation-head-without-seq.dcp", "DCP_INCONSISTENT");
    capsule(); rec[5] = 0; rec[6] = 0x02; memset(rec + 416, 0, 32); bad("bad-capsule-private-with-read.dcp", "DCP_SCOPE_CONFLICT");
    capsule(); memset(rec + 416, 0, 32); bad("bad-capsule-named-without-set.dcp", "DCP_SCOPE_CONFLICT");
    capsule(); rec[5] = 3; bad("bad-capsule-public-with-set.dcp", "DCP_SCOPE_CONFLICT");
    capsule(); rec[6] = 0x09; bad("bad-capsule-train-without-read.dcp", "DCP_PERMISSION_AMPLIFICATION");
    capsule(); rec[6] = 0x04; bad("bad-capsule-redistribute-without-read.dcp", "DCP_PERMISSION_AMPLIFICATION");
    capsule(); memset(rec + 448, 0, 32); bad("bad-capsule-no-consent.dcp", "DCP_NO_CONSENT");
    capsule(); rec[6] = 0x01; memset(rec + 448, 0, 32); bad("bad-capsule-named-discover-no-consent.dcp", "DCP_NO_CONSENT");

    /* ---- refused: consent ---- */
    consent(); rec[7] = 1; bad("bad-consent-reserved0.dcp", "DCP_RESERVED_NONZERO");
    consent(); rec[322] = 1; bad("bad-consent-reserved1.dcp", "DCP_RESERVED_NONZERO");
    consent(); fill(rec + 224, 32, 0x67); bad("bad-consent-undeclared-custodian-slot.dcp", "DCP_RESERVED_NONZERO");
    consent(); rec[5] = 0; bad("bad-consent-no-purpose.dcp", "DCP_BAD_ENUM");
    consent(); rec[5] = 0x1B; bad("bad-consent-purpose-bit.dcp", "DCP_BAD_ENUM");
    consent(); fill(rec + 224, 32, 0x67); fill(rec + 256, 32, 0x68); rec[6] = 5; bad("bad-consent-custodian-count.dcp", "DCP_BAD_ENUM");
    consent(); p32(rec + 8, 0); bad("bad-consent-no-version.dcp", "DCP_MISSING_FIELD");
    consent(); memset(rec + 64, 0, 32); bad("bad-consent-no-recipient.dcp", "DCP_MISSING_FIELD");
    consent(); memset(rec + 192, 0, 32); bad("bad-consent-empty-declared-custodian.dcp", "DCP_MISSING_FIELD");
    consent(); rec[288] = 0x00; bad("bad-consent-owner-key.dcp", "DCP_BAD_KEY");
    consent(); p64(rec + 16, 0); bad("bad-consent-issued-zero.dcp", "DCP_BAD_VALIDITY");
    consent(); p64(rec + 24, 1800000000u); bad("bad-consent-retention-not-after.dcp", "DCP_BAD_VALIDITY");
    consent(); rec[5] = 0x09; bad("bad-consent-train-without-read.dcp", "DCP_PERMISSION_AMPLIFICATION");

    /* ---- refused: retraction ---- */
    retraction(1); rec[7] = 1; bad("bad-retraction-reserved0.dcp", "DCP_RESERVED_NONZERO");
    retraction(1); rec[219] = 1; bad("bad-retraction-reserved1.dcp", "DCP_RESERVED_NONZERO");
    retraction(1); rec[5] = 0; bad("bad-retraction-no-scope.dcp", "DCP_BAD_ENUM");
    retraction(1); rec[5] = 0x16; bad("bad-retraction-scope-bit.dcp", "DCP_BAD_ENUM");
    retraction(1); rec[6] = 1; bad("bad-retraction-claims-erasure.dcp", "DCP_FALSE_ERASURE_CLAIM");
    retraction(1); p64(rec + 8, 0); bad("bad-retraction-seq-zero.dcp", "DCP_MISSING_FIELD");
    retraction(1); memset(rec + 24, 0, 32); bad("bad-retraction-no-target.dcp", "DCP_MISSING_FIELD");
    retraction(1); memset(rec + 120, 0, 32); bad("bad-retraction-no-tombstone.dcp", "DCP_MISSING_FIELD");
    retraction(1); rec[152] = 0x05; bad("bad-retraction-owner-key.dcp", "DCP_BAD_KEY");
    retraction(1); rec[185] = 0x05; bad("bad-retraction-signer-key.dcp", "DCP_BAD_KEY");
    retraction(1); p64(rec + 16, 0); bad("bad-retraction-effective-zero.dcp", "DCP_BAD_VALIDITY");
    retraction(2); memset(rec + 56, 0, 32); bad("bad-retraction-seq2-without-prev.dcp", "DCP_INCONSISTENT");
    retraction(1); fill(rec + 56, 32, 0x72); bad("bad-retraction-seq1-with-prev.dcp", "DCP_INCONSISTENT");

    /* ---- refused: ack ---- */
    ack(); rec[7] = 1; bad("bad-ack-reserved0.dcp", "DCP_RESERVED_NONZERO");
    ack(); rec[82] = 1; bad("bad-ack-reserved1.dcp", "DCP_RESERVED_NONZERO");
    ack(); rec[5] = 0; bad("bad-ack-status-zero.dcp", "DCP_BAD_ENUM");
    ack(); rec[5] = 3; bad("bad-ack-status-erased.dcp", "DCP_BAD_ENUM");
    ack(); memset(rec + 16, 0, 32); bad("bad-ack-no-retraction.dcp", "DCP_MISSING_FIELD");
    ack(); rec[48] = 0x04; bad("bad-ack-key.dcp", "DCP_BAD_KEY");
    ack(); p64(rec + 8, 0); bad("bad-ack-time-zero.dcp", "DCP_BAD_VALIDITY");

    /* ---- refused: lineage ---- */
    lineage(2, 3); rec[7] = 1; bad("bad-lineage-reserved0.dcp", "DCP_RESERVED_NONZERO");
    lineage(2, 3); rec[523] = 1; bad("bad-lineage-reserved1.dcp", "DCP_RESERVED_NONZERO");
    lineage(2, 3); fill(rec + 104 + 64, 32, 0xAF); bad("bad-lineage-unused-parent-slot.dcp", "DCP_RESERVED_NONZERO");
    lineage(2, 3); fill(rec + 232 + 96, 32, 0xCF); bad("bad-lineage-unused-influenced-slot.dcp", "DCP_RESERVED_NONZERO");
    lineage(4, 3); rec[5] = 5; bad("bad-lineage-parent-count.dcp", "DCP_BAD_ENUM");
    lineage(2, 8); rec[6] = 9; bad("bad-lineage-influenced-count.dcp", "DCP_BAD_ENUM");
    lineage(2, 3); memset(rec + 8, 0, 32); bad("bad-lineage-no-content.dcp", "DCP_MISSING_FIELD");
    lineage(2, 3); memset(rec + 40, 0, 32); bad("bad-lineage-no-dataset.dcp", "DCP_MISSING_FIELD");
    lineage(2, 3); memset(rec + 72, 0, 32); bad("bad-lineage-no-consent.dcp", "DCP_MISSING_FIELD");
    lineage(2, 3); memset(rec + 136, 0, 32); bad("bad-lineage-empty-parent.dcp", "DCP_MISSING_FIELD");
    lineage(2, 3); memset(rec + 264, 0, 32); bad("bad-lineage-empty-influenced.dcp", "DCP_MISSING_FIELD");
    lineage(2, 3); rec[488] = 0x01; bad("bad-lineage-key.dcp", "DCP_BAD_KEY");
    lineage(2, 3); memcpy(rec + 136, rec + 8, 32); bad("bad-lineage-self-parent.dcp", "DCP_ANCESTOR_CYCLE");
    lineage(3, 3); memcpy(rec + 168, rec + 104, 32); bad("bad-lineage-duplicate-parent.dcp", "DCP_DUPLICATE");

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
    fprintf(stderr, "usage: dcp_verify FILE | --corpus DIR | --make-vectors DIR\n");
    return 2;
}
