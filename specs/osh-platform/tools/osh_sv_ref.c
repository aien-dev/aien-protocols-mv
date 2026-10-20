/* osh_sv_ref.c: reference model for the OSH stream and task vectors (OSHSV1).
 *
 * Contract: ../STREAM_TASK.md (OSH Platform ABI v1 DRAFT, revision 2, not frozen), written against
 * ../OSH_PLATFORM_ABI.md at aien-protocols-mv commit fb5fca98e667. Corpus format: ../vectors/README.md, section
 * "Stream and task vectors". This program plays one adapter that has every feature and both capability domains, and
 * runs every vectors/s*.vec and vectors/t*.vec file against it. It is a check that the corpus is self-consistent and
 * has teeth (tools/mutate-stream-ref.sh), not evidence about Omega or Aienux, and it qualifies nothing physical.
 *
 * Model choices the spec does not pin (each UNVERIFIED, listed in the handoff and in STREAM_TASK.md ST11):
 *  - limits: 8 pipes of 65536 bytes, 16 handle slots per principal table, 16 tasks;
 *  - handle cell form generation << 32 | (slot + 1), opaque to the corpus;
 *  - a task runs one step per scheduler round, and checks a pending interrupt before each step;
 *  - the default capability generation is 7 in domain 1 and 0x100000007 in domain 2.
 *
 * Usage: osh_sv_ref --corpus DIR [--pin corpus=SHA] [--pin toolchain=TEXT]
 * Build: cc -std=c99 -O2 -Wall -Wextra -Werror -pedantic osh_sv_ref.c. -DSV_MUTANT=K disables check K (enum mut).
 * C99 and libc only. */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SV_MUTANT
#define SV_MUTANT 0
#endif
/* Every check the vectors must catch. tools/mutate-stream-ref.sh builds one model per entry with that check off. */
enum mut {
    MUT_NONE = 0,
    MUT_WRITE_RIGHT = 1,
    MUT_EOF_ANY,
    MUT_NO_BROKEN_PIPE,
    MUT_ZERO_WRITE_NO_READER,
    MUT_UNBOUNDED,
    MUT_NO_LATCH,
    MUT_NO_GENERATION,
    MUT_NO_EPOCH,
    MUT_FRAME_VERSION,
    MUT_FRAME_RESERVED,
    MUT_GEN_TRUNCATE,
    MUT_GEN_32BIT_COMPARE,
    MUT_DOMAIN_BRIDGE,
    MUT_BIND_ONCE,
    MUT_PARTIAL_NO_CANCEL,
    MUT_CRASH_REPLAY,
    MUT_TASK_KEEPS_ENDS,
    MUT_DUP_NO_SUBSET,
    MUT_LIMIT_LEAK,
    MUT_STAGE_FAIL_ABORTS,
    MUT_WAIT_NO_RELEASE,
    MUT_TERMINATE_IGNORABLE,
    MUT_LAST
};
#define MUT(k) (SV_MUTANT == (k))

enum err {
    E_OK = 0, E_DENIED, E_REVOKED, E_STALE, E_NOT_FOUND, E_UNAVAILABLE, E_INVALID_ARG, E_LIMIT, E_INTERRUPTED,
    E_BROKEN_PIPE, E_IO, E_OUTCOME_UNKNOWN, E_CAP_DOMAIN_MISMATCH, E_CAP_GEN_NARROW, E_NOT_SUPPORTED, E_WOULD_BLOCK,
    E_PARTIAL_LAUNCH, E_COUNT
};
static const char *const k_err[E_COUNT] = {"OK", "DENIED", "REVOKED", "STALE", "NOT_FOUND", "UNAVAILABLE",
                                           "INVALID_ARG", "LIMIT", "INTERRUPTED", "BROKEN_PIPE", "IO",
                                           "OUTCOME_UNKNOWN", "CAP_DOMAIN_MISMATCH", "CAP_GEN_NARROW",
                                           "NOT_SUPPORTED", "WOULD_BLOCK", "PARTIAL_LAUNCH"};
enum outc { O_NOT_STARTED = 0, O_COMPLETED, O_FAILED_NO_EFFECT, O_CANCELLED, O_UNKNOWN };
static const char *const k_out[] = {"NOT_STARTED", "COMPLETED", "FAILED_NO_EFFECT", "CANCELLED", "OUTCOME_UNKNOWN"};

/* ---- limits (section ST9 minimums; the model uses exactly them) ---- */
#define CAP_BYTES 65536u
#define NPIPES 8
#define NSLOTS 16
#define NTASKS 16
#define NTABLES (2 + NTASKS) /* A, B, then one table per task */
#define NNAMES 96
#define MAXSTAGES 8

/* ---- rights (ST4.11) ---- */
#define R_READ 0x01u
#define R_WRITE 0x02u
#define R_MAP 0x04u
#define R_GRANT 0x08u
#define R_DERIVE 0x10u
#define R_REVOKE 0x20u
#define R_CTL (R_GRANT | R_DERIVE | R_REVOKE)

#define FRAME_MAGIC 0x4F534846u

struct pipe {
    uint8_t buf[CAP_BYTES * 2]; /* twice the capacity so MUT_UNBOUNDED has room to misbehave */
    uint32_t head, len, inc;
    unsigned readers, writers;
    int live, revoked, latch[2];
};
struct slot {
    int live;
    uint32_t gen, inc;
    uint64_t epoch;
    unsigned pipe, end, rights;
};
struct table {
    struct slot s[NSLOTS];
    uint32_t gens[NSLOTS];
};
struct href { /* a named handle as the vector sees it (opaque cell) */
    char name[24];
    unsigned table, slot;
    uint32_t gen;
    uint64_t epoch;
};

enum prog { P_EXIT, P_EMIT, P_CAT, P_DRAIN, P_FLOOD, P_HANG, P_STUBBORN };
enum tstate { T_FREE = 0, T_RUNNING, T_ENDED };
struct task {
    int state, intr, lost, intent_open;
    uint32_t gen;
    uint64_t epoch;
    enum prog prog;
    int arg, status, outcome, cancelled;
    uint8_t data[256];
    size_t dlen, dpos;
    uint8_t carry[4096];
    size_t clen;
    int in_slot, out_slot;   /* slot in the task's table, -1 none */
    int src_virtual;         /* stdin is the pipeline source */
    int sink_virtual;        /* stdout is the pipeline sink */
    int pipeline;            /* index into pipelines or -1 */
};
struct tref {
    char name[24];
    unsigned idx;
    uint32_t gen;
    uint64_t epoch;
};
struct cap {
    char name[24];
    unsigned index;
    uint64_t gen;
    int revoked;
};
struct binding {
    char name[24];
    int none;
    unsigned domain, index;
    uint64_t gen;
};
struct pline {
    char name[24];
    int live, n;
    int task[MAXSTAGES];      /* task index, or -1 */
    int outcome[MAXSTAGES], status[MAXSTAGES];
    uint8_t src[256];
    size_t slen, spos;
    uint8_t sink[4096];
    size_t sinklen;
    uint64_t epoch;
};

static struct {
    struct pipe pipes[NPIPES];
    struct table tables[NTABLES];
    struct task tasks[NTASKS];
    struct href h[NNAMES];
    unsigned nh;
    struct tref t[NNAMES];
    unsigned nt;
    struct cap caps[16];
    unsigned ncaps;
    struct binding b[16];
    unsigned nb;
    struct pline p[4];
    unsigned np;
    uint64_t epoch;
    unsigned domain; /* authority domain of this vector, 0 = any */
    unsigned open_intents, crashed_unknown;
} M;

static int g_fail;
static const char *g_file;
static unsigned g_line;

static void bad(const char *msg)
{
    fprintf(stderr, "VECTOR_ERROR %s:%u %s\n", g_file, g_line, msg);
    g_fail = 1;
}

static void model_reset(void)
{
    memset(&M, 0, sizeof M);
    M.epoch = 1;
    for (unsigned t = 0; t < NTABLES; t++)
        for (unsigned i = 0; i < NSLOTS; i++)
            M.tables[t].gens[i] = 0;
}

/* ---------------- handles and pipes ---------------- */

static struct href *hname(const char *n, int create)
{
    for (unsigned i = 0; i < M.nh; i++)
        if (!strcmp(M.h[i].name, n))
            return &M.h[i];
    if (!create || M.nh == NNAMES || strlen(n) >= sizeof M.h[0].name)
        return 0;
    struct href *r = &M.h[M.nh++];
    memset(r, 0, sizeof *r);
    strcpy(r->name, n);
    return r;
}

static int slot_alloc(unsigned t, unsigned pipe, unsigned end, unsigned rights)
{
    struct table *tb = &M.tables[t];
    for (unsigned i = 0; i < NSLOTS; i++)
        if (!tb->s[i].live) {
            tb->gens[i]++;
            tb->s[i].live = 1;
            tb->s[i].gen = tb->gens[i];
            tb->s[i].inc = M.pipes[pipe].inc;
            tb->s[i].epoch = M.epoch;
            tb->s[i].pipe = pipe;
            tb->s[i].end = end;
            tb->s[i].rights = rights;
            if (end == 0)
                M.pipes[pipe].readers++;
            else
                M.pipes[pipe].writers++;
            return (int)i;
        }
    return -1;
}

static void pipe_free_if_done(unsigned p)
{
    struct pipe *q = &M.pipes[p];
    if (q->live && q->readers == 0 && q->writers == 0) {
        memset(q->buf, 0, sizeof q->buf);
        q->live = 0;
        q->revoked = 0;
        q->head = q->len = 0;
        q->latch[0] = q->latch[1] = 0;
    }
}

static void slot_release(unsigned t, unsigned i)
{
    struct slot *s = &M.tables[t].s[i];
    if (!s->live)
        return;
    struct pipe *q = &M.pipes[s->pipe];
    if (s->inc == q->inc && q->live) {
        if (s->end == 0 && q->readers)
            q->readers--;
        else if (s->end == 1 && q->writers)
            q->writers--;
        if (s->end == 0 && q->readers == 0) { /* bytes nobody can read any more are discarded (ST4.5) */
            memset(q->buf, 0, sizeof q->buf);
            q->head = q->len = 0;
        }
        pipe_free_if_done(s->pipe);
    }
    s->live = 0;
}

/* ST3.2 check order. need: rights; want_end: 0 read, 1 write, -1 either; close_ok: a revoked stream may be closed. */
static int resolve(unsigned t, const struct href *h, unsigned need, int want_end, int close_ok, unsigned *pipe,
                   unsigned *end)
{
    if (!h || h->gen == 0 || h->slot >= NSLOTS)
        return E_INVALID_ARG;
    if (h->table != t)
        return E_STALE; /* a handle names an entry of its own table only */
    const struct slot *s = &M.tables[t].s[h->slot];
    if (!s->live || (s->gen != h->gen && !MUT(MUT_NO_GENERATION)))
        return E_STALE;
    if (h->epoch != M.epoch && !MUT(MUT_NO_EPOCH))
        return E_STALE;
    if ((s->rights & need) != need)
        return E_DENIED;
    if (want_end >= 0 && s->end != (unsigned)want_end)
        return E_DENIED;
    const struct pipe *q = &M.pipes[s->pipe];
    if (!q->live || q->inc != s->inc)
        return E_STALE;
    if (q->revoked && !close_ok)
        return E_REVOKED;
    *pipe = s->pipe;
    *end = s->end;
    return E_OK;
}

static int op_create(unsigned t, struct href *r, struct href *w)
{
    unsigned idx = NPIPES;
    for (unsigned i = 0; i < NPIPES; i++)
        if (!M.pipes[i].live) {
            idx = i;
            break;
        }
    if (idx == NPIPES)
        return E_LIMIT;
    struct pipe *q = &M.pipes[idx];
    q->inc++;
    q->live = 1;
    q->revoked = 0;
    q->head = q->len = 0;
    q->readers = q->writers = 0;
    q->latch[0] = q->latch[1] = 0;
    int rs = slot_alloc(t, idx, 0, R_READ | R_CTL);
    if (rs < 0) {
        pipe_free_if_done(idx);
        return E_LIMIT;
    }
    int ws = slot_alloc(t, idx, 1, R_WRITE | R_CTL);
    if (ws < 0) {
        if (!MUT(MUT_LIMIT_LEAK))
            slot_release(t, (unsigned)rs);
        return E_LIMIT;
    }
    r->table = w->table = t;
    r->slot = (unsigned)rs;
    w->slot = (unsigned)ws;
    r->gen = M.tables[t].s[rs].gen;
    w->gen = M.tables[t].s[ws].gen;
    r->epoch = w->epoch = M.epoch;
    return E_OK;
}

static int latched(struct pipe *q, unsigned end)
{
    if (q->latch[end]) {
        q->latch[end] = 0;
        return 1;
    }
    return 0;
}

static int op_read(unsigned t, const struct href *h, uint8_t *out, size_t max, size_t *n)
{
    unsigned p, end;
    *n = 0;
    int e = resolve(t, h, R_READ, 0, 0, &p, &end);
    if (e)
        return e;
    struct pipe *q = &M.pipes[p];
    if (latched(q, 0))
        return E_INTERRUPTED;
    if (max == 0)
        return E_OK;
    if (q->len == 0)
        return (q->writers == 0 || MUT(MUT_EOF_ANY)) ? E_OK : E_WOULD_BLOCK;
    size_t take = max < q->len ? max : q->len;
    for (size_t i = 0; i < take; i++) {
        out[i] = q->buf[q->head];
        q->buf[q->head] = 0;
        q->head = (q->head + 1) % (uint32_t)sizeof q->buf;
    }
    q->len -= (uint32_t)take;
    *n = take;
    return E_OK;
}

static int op_write(unsigned t, const struct href *h, const uint8_t *in, size_t len, size_t *n)
{
    unsigned p, end;
    *n = 0;
    int e = resolve(t, h, MUT(MUT_WRITE_RIGHT) ? 0 : R_WRITE, MUT(MUT_WRITE_RIGHT) ? -1 : 1, 0, &p, &end);
    if (e)
        return e;
    struct pipe *q = &M.pipes[p];
    if (latched(q, 1))
        return E_INTERRUPTED;
    if (len == 0 && MUT(MUT_ZERO_WRITE_NO_READER))
        return E_OK;
    if (q->readers == 0 && !MUT(MUT_NO_BROKEN_PIPE))
        return E_BROKEN_PIPE;
    if (len == 0)
        return E_OK;
    size_t cap = MUT(MUT_UNBOUNDED) ? sizeof q->buf : CAP_BYTES;
    size_t room = cap - q->len;
    if (room == 0)
        return E_WOULD_BLOCK;
    size_t put = len < room ? len : room;
    for (size_t i = 0; i < put; i++)
        q->buf[(q->head + q->len + i) % (uint32_t)sizeof q->buf] = in[i];
    q->len += (uint32_t)put;
    *n = put;
    return E_OK;
}

static int op_close(unsigned t, const struct href *h)
{
    if (!h || h->gen == 0 || h->slot >= NSLOTS)
        return E_INVALID_ARG;
    if (h->table != t)
        return E_STALE;
    struct slot *s = &M.tables[t].s[h->slot];
    if (!s->live || (s->gen != h->gen && !MUT(MUT_NO_GENERATION)) || (h->epoch != M.epoch && !MUT(MUT_NO_EPOCH)))
        return E_STALE;
    const struct pipe *q = &M.pipes[s->pipe];
    int stale = !q->live || q->inc != s->inc;
    slot_release(t, h->slot);
    return stale ? E_STALE : E_OK;
}

static int op_dup(unsigned t, const struct href *h, unsigned to, unsigned rights, struct href *out)
{
    unsigned p, end;
    unsigned need = to == t ? R_DERIVE : R_GRANT;
    int e = resolve(t, h, need, -1, 0, &p, &end);
    if (e)
        return e;
    unsigned dr = end == 0 ? R_READ : R_WRITE;
    if (!(rights & dr) || (rights & ~(dr | R_CTL)))
        return E_INVALID_ARG;
    if ((rights & ~M.tables[t].s[h->slot].rights) && !MUT(MUT_DUP_NO_SUBSET))
        return E_DENIED;
    int ns = slot_alloc(to, p, end, rights);
    if (ns < 0)
        return E_LIMIT;
    out->table = to;
    out->slot = (unsigned)ns;
    out->gen = M.tables[to].s[ns].gen;
    out->epoch = M.epoch;
    return E_OK;
}

static int op_revoke(unsigned t, const struct href *h)
{
    unsigned p, end;
    int e = resolve(t, h, R_REVOKE, -1, 0, &p, &end);
    if (e)
        return e;
    struct pipe *q = &M.pipes[p];
    q->revoked = 1;
    q->latch[0] = q->latch[1] = 0;
    {
        memset(q->buf, 0, sizeof q->buf);
        q->head = q->len = 0;
    }
    return E_OK;
}

/* An interrupt aimed at the end h names (ST4.7). With nobody parked it is latched for the next call. */
static int op_cancel(unsigned t, const struct href *h)
{
    unsigned p, end;
    if (!h || h->table != t || h->slot >= NSLOTS || !M.tables[t].s[h->slot].live)
        return resolve(t, h, 0, -1, 0, &p, &end);
    unsigned need = M.tables[t].s[h->slot].end == 0 ? R_READ : R_WRITE;
    int e = resolve(t, h, need, -1, 0, &p, &end);
    if (e)
        return e;
    if (!MUT(MUT_NO_LATCH))
        M.pipes[p].latch[end] = 1;
    return E_OK;
}

/* ---------------- capabilities and bindings (ST5) ---------------- */

static struct cap *cname(const char *n)
{
    for (unsigned i = 0; i < M.ncaps; i++)
        if (!strcmp(M.caps[i].name, n))
            return &M.caps[i];
    return 0;
}
static struct binding *bname(const char *n)
{
    for (unsigned i = 0; i < M.nb; i++)
        if (!strcmp(M.b[i].name, n))
            return &M.b[i];
    return 0;
}

/* steps 0 to 2: the shape of the binding (checked before any effect of a launch) */
static int bind_shape(const struct binding *b)
{
    if (!b || b->none)
        return E_DENIED;
    if (b->domain != 1 && b->domain != 2)
        return E_CAP_DOMAIN_MISMATCH;
    if (b->domain == 1 && b->gen > 0xFFFFFFFFull && !MUT(MUT_GEN_TRUNCATE))
        return E_CAP_GEN_NARROW;
    return E_OK;
}

/* steps 3 to 6: against the authority, at the moment of the effect */
static int bind_effect(const struct binding *b)
{
    int e = bind_shape(b);
    if (e)
        return e;
    if (b->domain != M.domain && !MUT(MUT_DOMAIN_BRIDGE))
        return E_CAP_DOMAIN_MISMATCH;
    uint64_t g = b->gen;
    if (b->domain == 1)
        g &= 0xFFFFFFFFull; /* only reachable under MUT_GEN_TRUNCATE: shape refused anything wider */
    for (unsigned i = 0; i < M.ncaps; i++) {
        const struct cap *c = &M.caps[i];
        if (c->index != b->index)
            continue;
        int same = MUT(MUT_GEN_32BIT_COMPARE) ? (uint32_t)c->gen == (uint32_t)g : c->gen == g;
        if (!same)
            return E_STALE;
        return c->revoked ? E_REVOKED : E_OK;
    }
    return E_STALE;
}

/* ---------------- tasks ---------------- */

static void task_end(unsigned ti, int status, int outcome)
{
    struct task *k = &M.tasks[ti];
    k->state = T_ENDED;
    k->status = status;
    k->outcome = outcome;
    if (!MUT(MUT_TASK_KEEPS_ENDS))
        for (unsigned i = 0; i < NSLOTS; i++)
            slot_release(2 + ti, i);
}

static struct href g_tmp; /* a handle into a task's own table */
static const struct href *task_h(unsigned ti, int slot)
{
    const struct slot *s = &M.tables[2 + ti].s[slot];
    g_tmp.table = 2 + ti;
    g_tmp.slot = (unsigned)slot;
    g_tmp.gen = s->gen;
    g_tmp.epoch = s->epoch;
    return &g_tmp;
}

/* Task output: to its stdout pipe, to the pipeline sink, or discarded. */
static int task_out(unsigned ti, const uint8_t *b, size_t len, size_t *n)
{
    struct task *k = &M.tasks[ti];
    if (k->sink_virtual) {
        struct pline *pl = &M.p[k->pipeline];
        size_t room = sizeof pl->sink - pl->sinklen, put = len < room ? len : room;
        memcpy(pl->sink + pl->sinklen, b, put);
        pl->sinklen += put;
        *n = len; /* the sink never applies backpressure; overflow is a vector error caught by out= */
        return E_OK;
    }
    if (k->out_slot < 0) {
        *n = len;
        return E_OK;
    }
    return op_write(2 + ti, task_h(ti, k->out_slot), b, len, n);
}
static int task_in(unsigned ti, uint8_t *b, size_t max, size_t *n)
{
    struct task *k = &M.tasks[ti];
    *n = 0;
    if (k->src_virtual) {
        struct pline *pl = &M.p[k->pipeline];
        size_t take = pl->slen - pl->spos < max ? pl->slen - pl->spos : max;
        memcpy(b, pl->src + pl->spos, take);
        pl->spos += take;
        *n = take;
        return E_OK;
    }
    if (k->in_slot < 0)
        return E_OK;
    return op_read(2 + ti, task_h(ti, k->in_slot), b, max, n);
}

/* One step of a running task. Returns 1 if it made progress. */
static int task_step(unsigned ti)
{
    struct task *k = &M.tasks[ti];
    if (k->state != T_RUNNING)
        return 0;
    if (k->intr && k->prog != P_STUBBORN) {
        k->intr = 0;
        task_end(ti, 130, k->cancelled ? O_CANCELLED : O_COMPLETED);
        return 1;
    }
    k->intr = 0;
    size_t n = 0;
    int e;
    switch (k->prog) {
    case P_EXIT:
        task_end(ti, k->arg, O_COMPLETED);
        return 1;
    case P_EMIT:
    case P_FLOOD:
        if (k->prog == P_FLOOD && k->dpos == k->dlen)
            k->dpos = 0;
        if (k->dpos == k->dlen) {
            task_end(ti, k->arg, O_COMPLETED);
            return 1;
        }
        e = task_out(ti, k->data + k->dpos, k->dlen - k->dpos, &n);
        if (e == E_BROKEN_PIPE) {
            task_end(ti, 141, O_COMPLETED);
            return 1;
        }
        if (e == E_INTERRUPTED) {
            task_end(ti, 130, k->cancelled ? O_CANCELLED : O_COMPLETED);
            return 1;
        }
        if (e != E_OK)
            return 0; /* WOULD_BLOCK: parked */
        k->dpos += n;
        return n > 0;
    case P_CAT:
    case P_DRAIN:
        if (k->clen) {
            e = task_out(ti, k->carry, k->clen, &n);
            if (e == E_BROKEN_PIPE) {
                task_end(ti, 141, O_COMPLETED);
                return 1;
            }
            if (e != E_OK)
                return 0;
            memmove(k->carry, k->carry + n, k->clen - n);
            k->clen -= n;
            return n > 0;
        }
        e = task_in(ti, k->carry, sizeof k->carry, &n);
        if (e == E_WOULD_BLOCK)
            return 0;
        if (e == E_INTERRUPTED) {
            task_end(ti, 130, k->cancelled ? O_CANCELLED : O_COMPLETED);
            return 1;
        }
        if (e != E_OK || n == 0) {
            task_end(ti, e == E_OK ? 0 : 1, O_COMPLETED);
            return 1;
        }
        k->clen = k->prog == P_CAT ? n : 0;
        return 1;
    case P_HANG:
    case P_STUBBORN:
        return 0;
    }
    return 0;
}

static void sched_run(void)
{
    for (int round = 0; round < 100000; round++) {
        int progress = 0;
        for (unsigned i = 0; i < NTASKS; i++)
            progress |= task_step(i);
        if (!progress)
            return;
    }
}

static void intent_close(unsigned ti)
{
    if (M.tasks[ti].intent_open) {
        M.tasks[ti].intent_open = 0;
        M.open_intents--;
    }
}

static void task_release(unsigned ti)
{
    intent_close(ti);
    for (unsigned i = 0; i < NSLOTS; i++)
        slot_release(2 + ti, i);
    M.tasks[ti].state = T_FREE;
}

static int task_cancel(unsigned ti, int terminate)
{
    struct task *k = &M.tasks[ti];
    if (k->state != T_RUNNING)
        return E_OK;
    k->cancelled = 1;
    if (terminate && !MUT(MUT_TERMINATE_IGNORABLE)) {
        task_end(ti, 137, O_CANCELLED);
        return E_OK;
    }
    k->intr = 1;
    return E_OK;
}

/* ST6.5 cleanup of a set of tasks: interrupt, grace (the scheduler runs until nothing moves), terminate. */
static void cleanup_tasks(const int *list, int n)
{
    for (int i = 0; i < n; i++)
        if (list[i] >= 0)
            task_cancel((unsigned)list[i], 0);
    sched_run();
    for (int i = 0; i < n; i++)
        if (list[i] >= 0)
            task_cancel((unsigned)list[i], 1);
}

static int parse_prog(char **tok, int ntok, struct task *k, int *consumed)
{
    const char *p = tok[0];
    *consumed = 1;
    k->arg = 0;
    k->dlen = k->dpos = 0;
    if (!strcmp(p, "exit") || !strcmp(p, "emit")) {
        if (!strcmp(p, "exit")) {
            if (ntok < 2)
                return -1;
            k->prog = P_EXIT;
            k->arg = atoi(tok[1]);
            *consumed = 2;
            return 0;
        }
        return -1; /* emit is handled by the caller (needs the byte decoder) */
    }
    if (!strcmp(p, "cat")) k->prog = P_CAT;
    else if (!strcmp(p, "drain")) k->prog = P_DRAIN;
    else if (!strcmp(p, "flood")) {
        k->prog = P_FLOOD;
        memcpy(k->data, "y\n", 2);
        k->dlen = 2;
    } else if (!strcmp(p, "hang")) k->prog = P_HANG;
    else if (!strcmp(p, "stubborn")) k->prog = P_STUBBORN;
    else return -1;
    return 0;
}

/* ---------------- corpus parsing ---------------- */

static int unq(const char *q, uint8_t *out, size_t cap, size_t *n)
{
    size_t len = strlen(q), o = 0;
    if (len < 2 || q[0] != '"' || q[len - 1] != '"')
        return -1;
    for (size_t i = 1; i + 1 < len; i++) {
        unsigned c = (unsigned char)q[i];
        if (c == '\\') {
            if (i + 2 >= len) return -1;
            if (q[i + 1] == 'x') {
                if (i + 4 >= len) return -1;
                char hx[3] = {q[i + 2], q[i + 3], 0};
                c = (unsigned)strtoul(hx, 0, 16);
                i += 3;
            } else {
                c = (unsigned char)q[i + 1];
                i++;
            }
        }
        if (o == cap) return -1;
        out[o++] = (uint8_t)c;
    }
    *n = o;
    return 0;
}

static void q_out(char *dst, size_t cap, const uint8_t *b, size_t n)
{
    size_t o = 0;
    dst[o++] = '"';
    for (size_t i = 0; i < n && o + 6 < cap; i++) {
        if (b[i] == '"' || b[i] == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char)b[i];
        } else if (b[i] < 0x20 || b[i] > 0x7E) {
            o += (size_t)snprintf(dst + o, cap - o, "\\x%02x", b[i]);
        } else {
            dst[o++] = (char)b[i];
        }
    }
    dst[o++] = '"';
    dst[o] = 0;
}

static int split(char *s, char **tok, int max)
{
    int n = 0;
    while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        if (n == max) return -1;
        tok[n++] = s;
        int inq = 0;
        while (*s && (inq || (*s != ' ' && *s != '\t'))) {
            if (*s == '\\' && inq && s[1]) { s += 2; continue; }
            if (*s == '"') inq = !inq;
            s++;
        }
        if (*s) *s++ = 0;
    }
    return n;
}

static unsigned tbl(const char *s)
{
    if (!strcmp(s, "A")) return 0;
    if (!strcmp(s, "B")) return 1;
    return 99;
}

static unsigned rights_of(const char *s)
{
    unsigned r = 0;
    for (; *s; s++)
        switch (*s) {
        case 'r': r |= R_READ; break;
        case 'w': r |= R_WRITE; break;
        case 'm': r |= R_MAP; break;
        case 'g': r |= R_GRANT; break;
        case 'd': r |= R_DERIVE; break;
        case 'v': r |= R_REVOKE; break;
        default: return 0x100;
        }
    return r;
}

static struct tref *tname(const char *n, int create)
{
    for (unsigned i = 0; i < M.nt; i++)
        if (!strcmp(M.t[i].name, n))
            return &M.t[i];
    if (!create || M.nt == NNAMES || strlen(n) >= sizeof M.t[0].name)
        return 0;
    struct tref *r = &M.t[M.nt++];
    memset(r, 0, sizeof *r);
    strcpy(r->name, n);
    return r;
}

static int task_lookup(const struct tref *r, unsigned *ti)
{
    if (!r) return E_INVALID_ARG;
    const struct task *k = &M.tasks[r->idx];
    if (k->state == T_FREE || k->gen != r->gen || (r->epoch != M.epoch && !MUT(MUT_NO_EPOCH)))
        return E_STALE;
    *ti = r->idx;
    return E_OK;
}

static int task_alloc(unsigned *ti)
{
    for (unsigned i = 0; i < NTASKS; i++)
        if (M.tasks[i].state == T_FREE) {
            uint32_t g = M.tasks[i].gen + 1;
            memset(&M.tasks[i], 0, sizeof M.tasks[i]);
            M.tasks[i].gen = g;
            M.tasks[i].epoch = M.epoch;
            M.tasks[i].in_slot = M.tasks[i].out_slot = -1;
            M.tasks[i].pipeline = -1;
            for (unsigned s = 0; s < NSLOTS; s++)
                M.tables[2 + i].s[s].live = 0;
            *ti = i;
            return E_OK;
        }
    return E_LIMIT;
}

/* give the task its own duplicate of a stream end (ST6.1) */
static int task_take(unsigned ti, unsigned pipe, unsigned end)
{
    return slot_alloc(2 + ti, pipe, end, end == 0 ? R_READ : R_WRITE);
}

static void list_out(char *dst, size_t cap, const int *v, int n, int outcomes)
{
    size_t o = 0;
    dst[0] = 0;
    for (int i = 0; i < n; i++) {
        if (outcomes)
            o += (size_t)snprintf(dst + o, cap - o, "%s%s", i ? "," : "", k_out[v[i]]);
        else if (v[i] < 0)
            o += (size_t)snprintf(dst + o, cap - o, "%s-", i ? "," : "");
        else
            o += (size_t)snprintf(dst + o, cap - o, "%s%d", i ? "," : "", v[i]);
    }
}

static struct pline *pname(const char *n, int create)
{
    for (unsigned i = 0; i < M.np; i++)
        if (!strcmp(M.p[i].name, n))
            return &M.p[i];
    if (!create || M.np == 4 || strlen(n) >= sizeof M.p[0].name)
        return 0;
    struct pline *r = &M.p[M.np++];
    memset(r, 0, sizeof *r);
    strcpy(r->name, n);
    return r;
}

static void pl_result(char *res, size_t cap, struct pline *pl, int err, int status)
{
    char st[128], oc[256];
    list_out(st, sizeof st, pl->status, pl->n, 0);
    list_out(oc, sizeof oc, pl->outcome, pl->n, 1);
    snprintf(res, cap, "%s status=%d outcomes=%s statuses=%s", k_err[err], status, oc, st);
}

/* launch P bind=B [in=Q] [inject=K:ERR] [revoke=K:CAP] : stage ! stage ... (ST7) */
static void cmd_launch(char **tok, int n, char *res, size_t cap)
{
    struct pline *pl = pname(tok[1], 1);
    if (!pl) { bad("too many pipelines"); return; }
    pl->live = 1;
    pl->epoch = M.epoch;
    pl->slen = pl->spos = pl->sinklen = 0;
    const struct binding *b = 0;
    int inject_at = 0, inject_err = 0, revoke_at = 0;
    struct cap *rc = 0;
    int i = 2;
    for (; i < n && strcmp(tok[i], ":"); i++) {
        if (!strncmp(tok[i], "bind=", 5)) {
            b = bname(tok[i] + 5);
            if (!b) { bad("unknown binding"); return; }
        } else if (!strncmp(tok[i], "in=", 3)) {
            if (unq(tok[i] + 3, pl->src, sizeof pl->src, &pl->slen)) { bad("bad in="); return; }
        } else if (!strncmp(tok[i], "inject=", 7)) {
            inject_at = atoi(tok[i] + 7);
            const char *c = strchr(tok[i], ':');
            for (int e = 0; c && e < E_COUNT; e++)
                if (!strcmp(c + 1, k_err[e])) inject_err = e;
            if (!c || !inject_err) { bad("bad inject="); return; }
        } else if (!strncmp(tok[i], "revoke=", 7)) {
            revoke_at = atoi(tok[i] + 7);
            const char *c = strchr(tok[i], ':');
            rc = c ? cname(c + 1) : 0;
            if (!rc) { bad("bad revoke="); return; }
        } else { bad("unknown launch option"); return; }
    }
    if (i >= n) { bad("launch needs ':'"); return; }
    /* stages */
    struct task proto[MAXSTAGES + 2];
    int kind[MAXSTAGES + 2]; /* 0 program, 1 nosuch, 2 foreign */
    int ns = 0;
    i++;
    while (i < n) {
        if (ns == MAXSTAGES + 2) { bad("too many stages"); return; }
        memset(&proto[ns], 0, sizeof proto[ns]);
        kind[ns] = 0;
        int used = 1;
        if (!strcmp(tok[i], "nosuch")) kind[ns] = 1;
        else if (!strcmp(tok[i], "foreign")) kind[ns] = 2;
        else if (!strcmp(tok[i], "emit")) {
            if (i + 1 >= n || unq(tok[i + 1], proto[ns].data, sizeof proto[ns].data, &proto[ns].dlen)) { bad("emit"); return; }
            proto[ns].prog = P_EMIT;
            used = 2;
            if (i + 2 < n && strcmp(tok[i + 2], "!")) { proto[ns].arg = atoi(tok[i + 2]); used = 3; }
        } else if (parse_prog(tok + i, n - i, &proto[ns], &used)) { bad("unknown program"); return; }
        i += used;
        ns++;
        if (i < n) {
            if (strcmp(tok[i], "!")) { bad("stages are separated by '!'"); return; }
            i++;
        }
    }
    pl->n = ns > MAXSTAGES ? MAXSTAGES : ns;
    for (int s = 0; s < MAXSTAGES; s++) {
        pl->task[s] = -1;
        pl->outcome[s] = O_FAILED_NO_EFFECT;
        pl->status[s] = -1;
    }
    /* steps 1 to 3: no effect yet; a refusal starts nothing */
    int pre = E_OK, pst = 1;
    if (ns > MAXSTAGES) pre = E_LIMIT, pst = 1;
    for (int s = 0; !pre && s < ns; s++)
        if (kind[s] == 2) pre = E_UNAVAILABLE, pst = 126;
    if (!pre && (pre = bind_shape(b)) != E_OK) pst = 126;
    /* step 4: all pipes */
    int pp[MAXSTAGES][2];
    struct href ph[MAXSTAGES][2];
    for (int s = 0; s < MAXSTAGES; s++) pp[s][0] = pp[s][1] = -1;
    for (int s = 0; !pre && s + 1 < ns; s++) {
        memset(ph[s], 0, sizeof ph[s]);
        if (op_create(0, &ph[s][0], &ph[s][1]) != E_OK) {
            pre = E_LIMIT, pst = 1;
            for (int u = 0; u <= s; u++) {
                if (pp[u][0] >= 0) op_close(0, &ph[u][0]);
                if (pp[u][1] >= 0) op_close(0, &ph[u][1]);
            }
            break;
        }
        pp[s][0] = 1;
        pp[s][1] = 1;
    }
    if (pre) {
        for (int s = 0; s < pl->n; s++) pl->status[s] = pst;
        pl_result(res, cap, pl, pre, pst);
        pl->live = 0;
        return;
    }
    /* step 5 and 6: start left to right */
    int started = 0, fail = 0, fail_err = 0;
    int bind_once = MUT(MUT_BIND_ONCE) ? bind_effect(b) : 0;
    for (int s = 0; s < ns; s++) {
        if (revoke_at == s + 1) rc->revoked = 1;
        int st_e = E_OK, st_status = 0;
        if (kind[s] == 1) st_e = E_NOT_FOUND, st_status = 127;
        else {
            int be = MUT(MUT_BIND_ONCE) ? bind_once : bind_effect(b);
            if (be) st_e = be, st_status = 126;
        }
        if (st_e && MUT(MUT_STAGE_FAIL_ABORTS)) { fail = s + 1; fail_err = st_e; break; }
        if (!st_e && inject_at == s + 1) { fail = s + 1; fail_err = inject_err; break; }
        if (st_e) {
            pl->outcome[s] = O_FAILED_NO_EFFECT;
            pl->status[s] = st_status;
        } else {
            unsigned ti;
            if (task_alloc(&ti)) { fail = s + 1; fail_err = E_LIMIT; break; }
            struct task *k = &M.tasks[ti];
            uint32_t g = k->gen;
            *k = proto[s];
            k->gen = g;
            k->epoch = M.epoch;
            k->state = T_RUNNING;
            k->pipeline = (int)(pl - M.p);
            k->in_slot = k->out_slot = -1;
            if (s == 0) k->src_virtual = 1;
            else k->in_slot = task_take(ti, M.tables[0].s[ph[s - 1][0].slot].pipe, 0);
            if (s == ns - 1) k->sink_virtual = 1;
            else k->out_slot = task_take(ti, M.tables[0].s[ph[s][1].slot].pipe, 1);
            k->intent_open = 1;
            M.open_intents++;
            pl->task[s] = (int)ti;
            pl->outcome[s] = O_COMPLETED;
            started++;
        }
        /* the adapter closes its own copies of this stage's ends right after starting (or failing) it */
        if (s > 0 && pp[s - 1][0] >= 0) { op_close(0, &ph[s - 1][0]); pp[s - 1][0] = -1; }
        if (s + 1 < ns && pp[s][1] >= 0) { op_close(0, &ph[s][1]); pp[s][1] = -1; }
    }
    if (fail) {
        for (int u = 0; u + 1 < ns; u++)
            for (int e = 0; e < 2; e++)
                if (pp[u][e] >= 0) { op_close(0, &ph[u][e]); pp[u][e] = -1; }
        pl->outcome[fail - 1] = O_FAILED_NO_EFFECT;
        pl->status[fail - 1] = 1;
        for (int s = fail; s < ns; s++) { pl->outcome[s] = O_NOT_STARTED; pl->status[s] = -1; }
        if (started == 0) {
            pl_result(res, cap, pl, fail_err, 1);
            pl->live = 0;
            return;
        }
        if (!MUT(MUT_PARTIAL_NO_CANCEL)) {
            cleanup_tasks(pl->task, fail - 1);
            for (int s = 0; s < fail - 1; s++) {
                if (pl->task[s] < 0) continue;
                unsigned ti = (unsigned)pl->task[s];
                pl->outcome[s] = O_CANCELLED;
                pl->status[s] = M.tasks[ti].status;
                task_release(ti);
                pl->task[s] = -1;
            }
        }
        pl_result(res, cap, pl, E_PARTIAL_LAUNCH, 1);
        if (!MUT(MUT_PARTIAL_NO_CANCEL)) pl->live = 0;
        return;
    }
    snprintf(res, cap, "OK");
}

static void cmd_waitp(struct pline *pl, char *res, size_t cap)
{
    if (!pl || !pl->live || (pl->epoch != M.epoch && !MUT(MUT_NO_EPOCH))) { snprintf(res, cap, "STALE"); return; }
    for (int s = 0; s < pl->n; s++)
        if (pl->task[s] >= 0 && M.tasks[pl->task[s]].state == T_RUNNING) { snprintf(res, cap, "WOULD_BLOCK"); return; }
    for (int s = 0; s < pl->n; s++) {
        if (pl->task[s] < 0) continue;
        unsigned ti = (unsigned)pl->task[s];
        pl->outcome[s] = M.tasks[ti].outcome;
        pl->status[s] = M.tasks[ti].status;
        task_release(ti);
        pl->task[s] = -1;
    }
    char base[512], out[1024];
    int last = pl->status[pl->n - 1];
    pl_result(base, sizeof base, pl, E_OK, last < 0 ? 1 : last);
    q_out(out, sizeof out, pl->sink, pl->sinklen);
    snprintf(res, cap, "%s out=%s", base, out);
    pl->live = 0;
}

/* ---------------- one vector file ---------------- */

static void exec_line(char **tok, int n, char *res, size_t cap)
{
    static uint8_t bufs[2][CAP_BYTES * 2]; /* one per nesting level: a peer action runs inside bread / bwrite */
    static int depth;
    if (depth > 1) { bad("a peer action cannot block"); return; }
    uint8_t *buf = bufs[depth];
    const size_t bufcap = sizeof bufs[0];
    const char *c = tok[0];
    size_t got = 0;
    int e;
    res[0] = 0;
#define NEED(k) do { if (n < (k)) { bad("missing argument"); return; } } while (0)
    if (!strcmp(c, "create")) {
        NEED(4);
        unsigned t = tbl(tok[3]);
        if (t > 1) { bad("table"); return; }
        struct href *r = hname(tok[1], 1), *w = hname(tok[2], 1);
        if (!r || !w) { bad("names"); return; }
        struct href nr = *r, nw = *w;
        e = op_create(t, &nr, &nw);
        if (!e) { *r = nr; *w = nw; }
        snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "write") || !strcmp(c, "fill") || !strcmp(c, "bwrite")) {
        NEED(3);
        struct href *h = hname(tok[1], 0);
        size_t len = 0;
        if (!strcmp(c, "fill")) {
            NEED(4);
            len = !strcmp(tok[2], "cap") ? CAP_BYTES : strtoul(tok[2], 0, 10);
            if (len > bufcap) { bad("fill"); return; }
            memset(buf, (int)strtoul(tok[3], 0, 16), len);
        } else if (unq(tok[2], buf, bufcap, &len)) { bad("bytes"); return; }
        unsigned t = h ? h->table : 0;
        e = op_write(t, h, buf, len, &got);
        if (!strcmp(c, "bwrite")) {
            NEED(4);
            if (e == E_WOULD_BLOCK) {
                if (strcmp(tok[3], "none")) {
                    char pr[256];
                    depth++;
                    exec_line(tok + 3, n - 3, pr, sizeof pr);
                    depth--;
                    if (strncmp(pr, "OK", 2)) { bad("peer action did not return OK"); return; }
                }
                e = op_write(t, h, buf, len, &got);
                if (e == E_WOULD_BLOCK) e = E_INTERRUPTED; /* stalled peer: the deadline stand-in */
            }
        }
        if (e == E_OK) snprintf(res, cap, "OK n=%zu", got);
        else snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "read") || !strcmp(c, "bread") || !strcmp(c, "skim")) {
        NEED(3);
        struct href *h = hname(tok[1], 0);
        size_t max = strtoul(tok[2], 0, 10);
        if (max > bufcap) { bad("max"); return; }
        unsigned t = h ? h->table : 0;
        e = op_read(t, h, buf, max, &got);
        if (!strcmp(c, "bread")) {
            NEED(4);
            if (e == E_WOULD_BLOCK) {
                if (strcmp(tok[3], "none")) {
                    char pr[256];
                    depth++;
                    exec_line(tok + 3, n - 3, pr, sizeof pr);
                    depth--;
                    if (strncmp(pr, "OK", 2)) { bad("peer action did not return OK"); return; }
                }
                e = op_read(t, h, buf, max, &got);
                if (e == E_WOULD_BLOCK) e = E_INTERRUPTED;
            }
        }
        if (e == E_OK && got && !strcmp(c, "skim")) snprintf(res, cap, "OK n=%zu", got);
        else if (e == E_OK && got) {
            static char q[CAP_BYTES * 8];
            q_out(q, sizeof q, buf, got);
            snprintf(res, cap, "OK n=%zu data=%s", got, q);
        } else if (e == E_OK) snprintf(res, cap, "OK n=0");
        else snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "close") || !strcmp(c, "revoke") || !strcmp(c, "cancel")) {
        NEED(2);
        struct href *h = hname(tok[1], 0);
        unsigned t = h ? h->table : 0;
        e = !strcmp(c, "close") ? op_close(t, h) : !strcmp(c, "revoke") ? op_revoke(t, h) : op_cancel(t, h);
        snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "dup")) {
        NEED(5);
        struct href *h = hname(tok[1], 0), *o = hname(tok[2], 1);
        unsigned to = tbl(tok[3]), r = rights_of(tok[4]);
        if (!o || to > 1 || r > 0xFF) { bad("dup"); return; }
        struct href no = *o;
        e = op_dup(h ? h->table : 0, h, to, r, &no);
        if (!e) *o = no;
        snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "release") || !strcmp(c, "sweep")) {
        /* section 12 cleanup of one table; `sweep` is the same without the adapter-specific count */
        NEED(2);
        unsigned t = tbl(tok[1]), k = 0;
        if (t > 1) { bad("table"); return; }
        for (unsigned i = 0; i < NSLOTS; i++)
            if (M.tables[t].s[i].live) { slot_release(t, i); k++; }
        if (!strcmp(c, "sweep")) snprintf(res, cap, "OK");
        else snprintf(res, cap, "OK n=%u", k);
    } else if (!strcmp(c, "saturate")) {
        /* saturate H T last=D: duplicate H (its data right only) into T until LIMIT; D names the last duplicate */
        NEED(4);
        struct href *h = hname(tok[1], 0), *d = strncmp(tok[3], "last=", 5) ? 0 : hname(tok[3] + 5, 1);
        unsigned to = tbl(tok[2]);
        if (!h || !d || to > 1 || !M.tables[h->table].s[h->slot].live) { bad("saturate"); return; }
        unsigned dr = M.tables[h->table].s[h->slot].end == 0 ? R_READ : R_WRITE;
        struct href nd;
        int made = 0;
        for (;;) {
            nd = *d; /* keeps the name */
            e = op_dup(h->table, h, to, dr, &nd);
            if (e) break;
            *d = nd;
            made = 1;
        }
        if (!made) { bad("saturate made no duplicate"); return; }
        snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "exhaust")) {
        NEED(3);
        unsigned t = tbl(tok[1]);
        unsigned min = (unsigned)strtoul(tok[2] + (strncmp(tok[2], "min=", 4) ? 0 : 4), 0, 10);
        struct href rr[NPIPES + 1], ww[NPIPES + 1];
        unsigned k = 0, before = 0;
        for (unsigned i = 0; i < NSLOTS; i++) before += (unsigned)M.tables[t].s[i].live;
        int last = E_OK;
        while (k <= NPIPES) {
            memset(&rr[k], 0, sizeof rr[k]);
            memset(&ww[k], 0, sizeof ww[k]);
            last = op_create(t, &rr[k], &ww[k]);
            if (last) break;
            k++;
        }
        unsigned live_slots = 0;
        for (unsigned i = 0; i < NSLOTS; i++) live_slots += (unsigned)M.tables[t].s[i].live;
        int leak = live_slots != before + 2 * k; /* the refused create left nothing allocated (ST9) */
        for (unsigned i = 0; i < k; i++) { op_close(t, &rr[i]); op_close(t, &ww[i]); }
        if (k < min) snprintf(res, cap, "TOO_FEW n=%u", k);
        else if (leak) snprintf(res, cap, "LEAK");
        else snprintf(res, cap, "%s", k_err[last]);
    } else if (!strcmp(c, "frame")) {
        NEED(3);
        unsigned t = tbl(tok[1]);
        uint64_t f[16];
        size_t nc = 0, slen = 0;
        int has = strcmp(tok[2], "-") != 0;
        if (has && unq(tok[2], buf, bufcap, &slen)) { bad("slice"); return; }
        for (int i = 3; i < n; i++) {
            if (nc == 16) { bad("frame too long"); return; }
            if (tok[i][0] == '$') {
                struct href *h = hname(tok[i] + 1, 0);
                f[nc++] = h ? ((uint64_t)h->gen << 32 | (h->slot + 1)) : 0;
            } else f[nc++] = strtoull(tok[i], 0, 16);
        }
        static const unsigned nargs[6] = {0, 0, 2, 2, 1, 3};
        int ef;
        if (nc < 4 || f[0] != FRAME_MAGIC) ef = E_INVALID_ARG;
        else if (f[1] != 1 && !MUT(MUT_FRAME_VERSION)) ef = E_NOT_SUPPORTED;
        else if (f[3] != 0 && !MUT(MUT_FRAME_RESERVED)) ef = E_INVALID_ARG;
        else if (f[2] == 0 || f[2] > 5) ef = E_NOT_SUPPORTED; /* 6 to 15 are assigned but not in this model */
        else {
            unsigned op = (unsigned)f[2];
            struct href fh;
            memset(&fh, 0, sizeof fh);
            if (op != 1 && nc > 4) {
                fh.table = t;
                fh.gen = (uint32_t)(f[4] >> 32);
                fh.slot = (unsigned)(f[4] & 0xFFFFFFFFu) - 1u;
                fh.epoch = M.epoch;
                for (unsigned i = 0; i < M.nh; i++) /* the cell carries no epoch; the model's names do */
                    if (M.h[i].table == t && M.h[i].slot == fh.slot && M.h[i].gen == fh.gen) fh.epoch = M.h[i].epoch;
            }
            if (nc != 4 + nargs[op] || (op != 1 && fh.gen == 0)) ef = E_INVALID_ARG;
            else if (op == 1) {
                struct href a, b;
                memset(&a, 0, sizeof a);
                memset(&b, 0, sizeof b);
                ef = op_create(t, &a, &b);
                /* the new ends are unnamed: a vector releases them with `release` */
            } else if (op == 2 || op == 3) {
                if (f[5] & ~1ull) ef = E_INVALID_ARG;
                else ef = op == 2 ? op_read(t, &fh, buf, slen, &got) : op_write(t, &fh, buf, slen, &got);
            } else if (op == 4) ef = op_close(t, &fh);
            else {
                if ((f[5] & ~0x3Full) || f[6] > 1) ef = E_INVALID_ARG;
                else {
                    struct href o;
                    memset(&o, 0, sizeof o);
                    ef = op_dup(t, &fh, f[6] ? 1 - t : t, (unsigned)f[5], &o);
                    if (!ef) { /* register the anonymous handle so `release` can clean it */ }
                }
            }
        }
        if (ef == E_OK && (f[2] == 2 || f[2] == 3)) snprintf(res, cap, "OK n=%zu", got);
        else snprintf(res, cap, "%s", k_err[ef]);
    } else if (!strcmp(c, "cap")) {
        NEED(2);
        if (M.ncaps == 16 || M.domain == 0) { bad("cap needs a domain header"); return; }
        struct cap *k = &M.caps[M.ncaps];
        memset(k, 0, sizeof *k);
        snprintf(k->name, sizeof k->name, "%s", tok[1]);
        k->index = 3 + M.ncaps;
        k->gen = M.domain == 1 ? 7 : 0x100000007ull;
        for (int i = 2; i < n; i++)
            if (!strncmp(tok[i], "gen=", 4)) k->gen = strtoull(tok[i] + 4, 0, 0);
        if (M.domain == 1 && k->gen > 0xFFFFFFFFull) { bad("domain-1 authority cannot mint a 64-bit generation"); return; }
        M.ncaps++;
        snprintf(res, cap, "OK");
    } else if (!strcmp(c, "revokecap")) {
        NEED(2);
        struct cap *k = cname(tok[1]);
        if (!k) { bad("cap"); return; }
        k->revoked = 1;
        snprintf(res, cap, "OK");
    } else if (!strcmp(c, "bind")) {
        NEED(3);
        if (M.nb == 16) { bad("bindings"); return; }
        struct binding *b = &M.b[M.nb];
        memset(b, 0, sizeof *b);
        snprintf(b->name, sizeof b->name, "%s", tok[1]);
        if (!strcmp(tok[2], "none")) b->none = 1;
        else {
            if (strncmp(tok[2], "cap=", 4) || !cname(tok[2] + 4)) { bad("bind cap="); return; }
            const struct cap *k = cname(tok[2] + 4);
            b->domain = M.domain;
            b->index = k->index;
            b->gen = k->gen;
            for (int i = 3; i < n; i++) {
                if (!strncmp(tok[i], "gen=", 4)) b->gen = strtoull(tok[i] + 4, 0, 0);
                else if (!strncmp(tok[i], "domain=", 7)) b->domain = (unsigned)strtoul(tok[i] + 7, 0, 0);
                else if (!strncmp(tok[i], "index=", 6)) b->index = (unsigned)strtoul(tok[i] + 6, 0, 0);
                else { bad("bind option"); return; }
            }
        }
        M.nb++;
        snprintf(res, cap, "OK");
    } else if (!strcmp(c, "spawn")) {
        /* spawn T <program> [in=H|-] [out=H|-] bind=B */
        NEED(4);
        struct tref *r = tname(tok[1], 1);
        struct task proto;
        memset(&proto, 0, sizeof proto);
        int i = 2, used = 1;
        if (!strcmp(tok[2], "emit")) {
            if (unq(tok[3], proto.data, sizeof proto.data, &proto.dlen)) { bad("emit"); return; }
            proto.prog = P_EMIT;
            used = 2;
        } else if (parse_prog(tok + 2, n - 2, &proto, &used)) { bad("program"); return; }
        i += used;
        struct href *in = 0, *out = 0;
        const struct binding *b = 0;
        for (; i < n; i++) {
            if (!strncmp(tok[i], "in=", 3)) in = strcmp(tok[i] + 3, "-") ? hname(tok[i] + 3, 0) : 0;
            else if (!strncmp(tok[i], "out=", 4)) out = strcmp(tok[i] + 4, "-") ? hname(tok[i] + 4, 0) : 0;
            else if (!strncmp(tok[i], "bind=", 5)) b = bname(tok[i] + 5);
            else { bad("spawn option"); return; }
        }
        if (!r) { bad("task name"); return; }
        unsigned ip = 0, ie = 0, op = 0, oe = 0;
        e = E_OK;
        if (in) {
            e = resolve(in->table, in, 0, -1, 0, &ip, &ie); /* the end decides, ST6.1 */
            if (!e && ie != 0) e = E_INVALID_ARG;
        }
        if (!e && out) {
            e = resolve(out->table, out, 0, -1, 0, &op, &oe);
            if (!e && oe != 1) e = E_INVALID_ARG;
        }
        if (!e) e = bind_effect(b);
        unsigned ti = 0;
        if (!e) e = task_alloc(&ti);
        if (!e) {
            struct task *k = &M.tasks[ti];
            uint32_t g = k->gen;
            *k = proto;
            k->gen = g;
            k->epoch = M.epoch;
            k->state = T_RUNNING;
            k->pipeline = -1;
            k->in_slot = in ? task_take(ti, ip, 0) : -1;
            k->out_slot = out ? task_take(ti, op, 1) : -1;
            k->intent_open = 1;
            M.open_intents++;
            r->idx = ti;
            r->gen = g;
            r->epoch = M.epoch;
        }
        snprintf(res, cap, "%s", k_err[e]);
    } else if (!strcmp(c, "run")) {
        sched_run();
        snprintf(res, cap, "OK");
    } else if (!strcmp(c, "wait") || !strcmp(c, "state") || !strcmp(c, "tcancel") || !strcmp(c, "lose")) {
        NEED(2);
        unsigned ti;
        e = task_lookup(tname(tok[1], 0), &ti);
        if (e) { snprintf(res, cap, "%s", k_err[e]); return; }
        struct task *k = &M.tasks[ti];
        if (!strcmp(c, "state")) snprintf(res, cap, "OK state=%s", k->state == T_RUNNING ? "RUNNING" : "ENDED");
        else if (!strcmp(c, "tcancel")) {
            NEED(3);
            snprintf(res, cap, "%s", k_err[task_cancel(ti, !strcmp(tok[2], "terminate"))]);
        } else if (!strcmp(c, "lose")) {
            if (k->state != T_ENDED) { bad("lose needs an ended task"); return; }
            k->lost = 1;
            snprintf(res, cap, "OK");
        } else if (k->state == T_RUNNING) snprintf(res, cap, "WOULD_BLOCK");
        else if (k->lost) {
            snprintf(res, cap, "OUTCOME_UNKNOWN status=1 outcome=OUTCOME_UNKNOWN");
            task_release(ti);
        } else {
            snprintf(res, cap, "OK status=%d outcome=%s", k->status, k_out[k->outcome]);
            if (!MUT(MUT_WAIT_NO_RELEASE)) task_release(ti);
        }
    } else if (!strcmp(c, "launch")) {
        NEED(4);
        cmd_launch(tok, n, res, cap);
    } else if (!strcmp(c, "waitp")) {
        NEED(2);
        cmd_waitp(pname(tok[1], 0), res, cap);
    } else if (!strcmp(c, "cancelp")) {
        NEED(3);
        struct pline *pl = pname(tok[1], 0);
        if (!pl || !pl->live) { snprintf(res, cap, "STALE"); return; }
        for (int s = 0; s < pl->n; s++)
            if (pl->task[s] >= 0) task_cancel((unsigned)pl->task[s], !strcmp(tok[2], "terminate"));
        snprintf(res, cap, "OK");
    } else if (!strcmp(c, "reset")) {
        /* ABI section 12 cleanup, then a new session_epoch */
        int list[NTASKS], k = 0;
        for (unsigned i = 0; i < NTASKS; i++)
            list[i] = M.tasks[i].state == T_RUNNING ? (k++, (int)i) : -1;
        cleanup_tasks(list, NTASKS);
        for (unsigned i = 0; i < NTASKS; i++)
            if (M.tasks[i].state != T_FREE) task_release(i);
        for (unsigned t = 0; t < 2; t++)
            for (unsigned i = 0; i < NSLOTS; i++) slot_release(t, i);
        for (unsigned i = 0; i < M.np; i++) M.p[i].live = 0;
        M.epoch++;
        snprintf(res, cap, "OK cancelled=%d", k);
    } else if (!strcmp(c, "crash")) {
        /* the adapter process is gone: nothing is cleaned, nothing records an outcome; its tables restart empty */
        M.crashed_unknown = M.open_intents;
        for (unsigned i = 0; i < NTASKS; i++) M.tasks[i].state = T_FREE, M.tasks[i].intent_open = 0;
        for (unsigned t = 0; t < NTABLES; t++) memset(&M.tables[t], 0, sizeof M.tables[t]);
        for (unsigned i = 0; i < NPIPES; i++) {
            uint32_t inc = M.pipes[i].inc;
            memset(&M.pipes[i], 0, sizeof M.pipes[i]);
            M.pipes[i].inc = inc;
        }
        for (unsigned i = 0; i < M.np; i++) M.p[i].live = 0;
        M.open_intents = 0;
        M.epoch++;
        snprintf(res, cap, "OK");
    } else if (!strcmp(c, "recover")) {
        snprintf(res, cap, "OK unknown=%u replayed=%u", MUT(MUT_CRASH_REPLAY) ? 0 : M.crashed_unknown,
                 MUT(MUT_CRASH_REPLAY) ? M.crashed_unknown : 0);
        M.crashed_unknown = 0;
    } else if (!strcmp(c, "limits")) {
        snprintf(res, cap, "OK max_pipe_bytes>=65536 max_streams>=16 max_tasks>=8");
        if (!(CAP_BYTES >= 65536 && NSLOTS >= 16 && NTASKS >= 8)) snprintf(res, cap, "LIMIT");
    } else {
        bad("unknown command");
    }
#undef NEED
}

static int check_items(char **tok, int n)
{
    for (int i = 1; i < n; i++) {
        if (!strcmp(tok[i], "empty")) {
            for (unsigned t = 0; t < NTABLES; t++)
                for (unsigned s = 0; s < NSLOTS; s++)
                    if (M.tables[t].s[s].live) return 0;
            for (unsigned p = 0; p < NPIPES; p++)
                if (M.pipes[p].live) return 0;
            for (unsigned k = 0; k < NTASKS; k++)
                if (M.tasks[k].state != T_FREE) return 0;
            if (M.open_intents || M.crashed_unknown) return 0;
        } else if (!strncmp(tok[i], "pipes=", 6)) {
            unsigned live = 0;
            for (unsigned p = 0; p < NPIPES; p++) live += (unsigned)M.pipes[p].live;
            if (live != strtoul(tok[i] + 6, 0, 10)) return 0;
        } else {
            bad("unknown check item");
            return 0;
        }
    }
    return 1;
}

static int run_file(const char *path, const char *base, int *nfail)
{
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    model_reset();
    g_file = base;
    g_line = 0;
    g_fail = 0;
    static char line[4096];
    char res[CAP_BYTES * 8 + 64];
    int have_case = 0, have_kind = 0, have_exec = 0, have_needs = 0, have_domain = 0, last_check_empty = 0, mism = 0;
    while (fgets(line, sizeof line, f)) {
        g_line++;
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        char *s = line;
        while (*s == ' ') s++;
        if (!*s || *s == '#') continue;
        char *arrow = strstr(s, " => ");
        char *want = 0;
        if (arrow) { *arrow = 0; want = arrow + 4; }
        char *tok[64];
        int n = split(s, tok, 64);
        if (n <= 0) { bad("cannot split"); continue; }
        if (!strcmp(tok[0], "case")) { have_case = 1; continue; }
        if (!strcmp(tok[0], "kind")) { have_kind = n == 2 && (!strcmp(tok[1], "positive") || !strcmp(tok[1], "negative")); continue; }
        if (!strcmp(tok[0], "exec")) { have_exec = n == 2 && (!strcmp(tok[1], "host-logic") || !strcmp(tok[1], "native-qemu")); continue; }
        if (!strcmp(tok[0], "needs")) { have_needs = n >= 2; continue; }
        if (!strcmp(tok[0], "domain")) {
            have_domain = n == 2;
            M.domain = !strcmp(tok[1], "any") ? 0 : (unsigned)atoi(tok[1]);
            continue;
        }
        if (!have_case || !have_kind || !have_exec || !have_needs || !have_domain) { bad("header incomplete before first step"); break; }
        if (!strcmp(tok[0], "check")) {
            last_check_empty = 0;
            for (int i = 1; i < n; i++) last_check_empty |= !strcmp(tok[i], "empty");
            if (!check_items(tok, n)) {
                printf("MISMATCH %s:%u check failed\n", base, g_line);
                mism = 1;
            }
            continue;
        }
        last_check_empty = 0;
        if (!want) { bad("step without ' => '"); continue; }
        exec_line(tok, n, res, sizeof res);
        if (strcmp(res, want)) {
            printf("MISMATCH %s:%u got \"%.200s\" want \"%.200s\"\n", base, g_line, res, want);
            mism = 1;
        }
    }
    fclose(f);
    if (!last_check_empty) bad("a vector must end with 'check empty'");
    if (g_fail || mism) { (*nfail)++; return 1; }
    printf("PASS %s\n", base);
    return 0;
}

static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

int main(int argc, char **argv)
{
    const char *dir = 0, *corpus_pin = "unpinned", *tc_pin = "unpinned";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--corpus") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--pin") && i + 1 < argc) {
            const char *p = argv[++i];
            if (!strncmp(p, "corpus=", 7)) corpus_pin = p + 7;
            else if (!strncmp(p, "toolchain=", 10)) tc_pin = p + 10;
        } else { fprintf(stderr, "usage: osh_sv_ref --corpus DIR [--pin corpus=SHA] [--pin toolchain=TEXT]\n"); return 2; }
    }
    if (!dir) { fprintf(stderr, "usage: osh_sv_ref --corpus DIR\n"); return 2; }
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "cannot open %s\n", dir); return 2; }
    char *names[256];
    int nn = 0;
    struct dirent *de;
    while ((de = readdir(d)) && nn < 256) {
        size_t L = strlen(de->d_name);
        if (L > 4 && (de->d_name[0] == 's' || de->d_name[0] == 't') && !strcmp(de->d_name + L - 4, ".vec"))
            names[nn++] = strdup(de->d_name);
    }
    closedir(d);
    qsort(names, (size_t)nn, sizeof names[0], cmpstr);
    printf("OSHSV1_RUN impl=reference-model mutant=%d corpus=%s toolchain=%s target=host\n", SV_MUTANT, corpus_pin, tc_pin);
    int nfail = 0;
    for (int i = 0; i < nn; i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        run_file(path, names[i], &nfail);
        free(names[i]);
    }
    printf("OSHSV1_CONFORMANCE impl=reference-model vectors=%d pass=%d fail=%d not_run=0\n", nn, nn - nfail, nfail);
    return nn > 0 && nfail == 0 ? 0 : 1;
}
