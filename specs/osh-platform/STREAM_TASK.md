# OSH Platform ABI v1: streams and tasks (draft revision 2)

**Status**: v1 DRAFT, revision 2, **not frozen**. Part of [`OSH_PLATFORM_ABI.md`](OSH_PLATFORM_ABI.md) (same `abi_version` 1, same freeze rule). This file makes sections 8.1, 8.4, 10 and 12 of that document precise for byte streams and tasks; where the two differ, this file wins until the freeze. Nothing here is frozen and nothing here is a claim that an adapter conforms.
**Origin**: `aien-dev/aien-protocols-mv#43` under `aien-dev/aien-architecture-mv#158`. Written against `OSH_PLATFORM_ABI.md` at commit `fb5fca98e667`, Omega's Linux host adapter at omega-mv `a8ffd2b912c8` (`src/osh/host/osh_exec.c`, `osh_caps.c`), and the AIENOS native pipe at aienos-mv `f8700d4cb65e` (branch `feat/native-pipe-1`, PR #433, `native/kernel/core/pipe.h`). The comparison is in [`AUDIT_STREAM_TASK.md`](AUDIT_STREAM_TASK.md).
**Conformance corpus**: `vectors/s*.vec` and `vectors/t*.vec`, format in [`vectors/README.md`](vectors/README.md) (section "Stream and task vectors"), reference model and checker in `tools/osh_sv_ref.c` and `tools/check-stream-vectors.sh`.
**License**: Community Specification License 1.0

Every rule below that no implementation has yet shown is marked UNVERIFIED. An UNVERIFIED rule is still normative for the draft: the vectors test it, and the freeze either confirms it or changes it with a new revision.

## ST1. Terms

- **Stream end**: one end of a pipe (read end or write end) or one opened storage stream. A **handle** names one stream end inside one principal's handle table. A handle is a transient id (section 4.3 of the ABI): it is never persisted and never used as identity.
- **Data right**: the right a stream end needs for its data operation: read on a read end, write on a write end. A handle never carries the data right of the other end.
- **Task**: one started program (a Linux process, or an AIENOS task). A **task id** is a transient id.
- **Pipeline launch**: the adapter's execution of one request record (section 7): create the pipes, start the commands left to right, wait, clean up. It is built from `PIPE_CREATE`, `TASK_SPAWN`, `TASK_WAIT`, `TASK_CANCEL` and `STREAM_CLOSE`.
- **Authority root**: the capability authority the adapter calls (section 9). It mints and revokes. Revocation is never a platform operation (ABI section 9.5).

## ST2. Platform call frame (settles ABI section 3 for frames)

A platform call is a frame of cells plus at most one borrowed byte slice:

| cell | field | value |
|---|---|---|
| 0 | `magic` | `0x4F534846` ("OSHF") |
| 1 | `abi_version` | `1` |
| 2 | `op` | operation id (table below) |
| 3 | reserved | `0` |
| 4 onward | arguments | exactly the count the operation defines |

The frame has exactly `4 + nargs` cells. The result is `{error u32, value u64, value2 u64}`; `value2` is used only by `PIPE_CREATE` (the write end) and is 0 otherwise.

Check order, first failure wins, all before any effect (same order as ABI section 3, mapped onto section 8.6 errors because a platform frame answers with platform errors, not shell-core refusal codes): fewer than 4 cells or wrong `magic` is `INVALID_ARG`; `abi_version` not exactly 1 is `NOT_SUPPORTED`; reserved cell nonzero is `INVALID_ARG`; `op` not in the table, or in the table but not provided by this adapter, is `NOT_SUPPORTED`; wrong cell count, a handle cell the adapter cannot decode, or unknown flag bits is `INVALID_ARG`. Evidence: the AIENOS dispatch uses exactly this order.

Operation ids (draft assignment, freezes with the ABI). Ids 1 to 5 are taken from the AIENOS implementation; ids 6 to 15 are assigned here and are UNVERIFIED (no implementation); 0 and 16 to 255 are unassigned and are always `NOT_SUPPORTED`.

| op | operation | args | value |
|---|---|---|---|
| 1 | `PIPE_CREATE` | none | read end (value), write end (value2) |
| 2 | `STREAM_READ` | handle, flags | bytes read |
| 3 | `STREAM_WRITE` | handle, flags | bytes written |
| 4 | `STREAM_CLOSE` | handle | 0 |
| 5 | `STREAM_DUP` | handle, rights, target (0 own table, 1 named peer table) | new handle |
| 6 | `STREAM_OPEN` | location descriptor, mode | handle |
| 7 | `TASK_SPAWN` | resolved ref, stdin, stdout, stderr, binding ref | task id |
| 8 | `TASK_WAIT` | task id, deadline | exit status |
| 9 | `TASK_CANCEL` | task id, mode (1 interrupt, 2 terminate) | 0 |
| 10 | `TASK_STATE` | task id | state (ST6.4) |
| 11 | `RESOLVE` | search context | class and target ref |
| 12 | `PERM_CHECK` | binding ref, op | 0 |
| 13 | `LIMITS_GET` | none | limit record ref |
| 14 | `LOC_GETCWD` | none | location ref |
| 15 | `LOC_CHDIR` | location ref, binding ref | 0 |

Flags for `STREAM_READ` and `STREAM_WRITE`: bit 0 `BLOCK` (park instead of `WOULD_BLOCK`); every other bit is reserved and must be 0. Argument layouts of ops 6 to 15 beyond the cell count are open freeze items (ABI section 14, item 8).

Handle cells are adapter-private encodings (the AIENOS register form `generation << 32 | index` is one). The shell core and the vectors treat a handle cell as opaque. A handle cell of 0 is never valid.

## ST3. Handles, ownership and epochs

1. A handle is valid only in the table of the principal that holds it. `PIPE_CREATE` puts both ends into the caller's table. `STREAM_DUP` with target 1 puts a new handle into another principal's table (transfer).
2. Every use of a handle checks, at the moment of the effect, in this order: the handle cell is well formed (nonzero, in range; else `INVALID_ARG`); it names a live entry of the caller's table with the same generation, created in the current `session_epoch` (else `STALE`); the entry carries the operation's right and names the end the operation needs (else `DENIED`); the entry belongs to the current incarnation of its stream (else `STALE`); the stream is not revoked (else `REVOKED`, except for `STREAM_CLOSE`). Evidence: AIENOS `resolve` uses exactly this order; Omega's capability mapping agrees on the names (stale generation `STALE`, revoked `REVOKED`, anything else `DENIED`).
3. Two counters make a handle stale and both must be checked: the `session_epoch` of ABI section 4.4 (a session reset ends every handle of the session) and the per-object incarnation (a closed handle, or a handle to a pipe slot that was freed and reused, never reaches the new object). The width and layout of the incarnation counter are adapter-private; an adapter that cannot tell incarnations apart must retire the slot rather than reuse it.
4. A Linux adapter must not expose raw file descriptor numbers as handles: the kernel reuses descriptor numbers, which would let a closed handle reach a new stream instead of failing `STALE`. It keeps its own table with an incarnation per entry (UNVERIFIED: no Linux adapter exposes stream handles yet).
5. `PIPE_CREATE` needs no binding and no prior capability: it creates a private object whose only authority is over itself, and it is bounded by `LIMIT`. Evidence: the ABI signature has no binding; AIENOS and Omega (`pipe2`) both create pipes unconditionally.

## ST4. Byte-stream semantics

A pipe is a bounded first-in first-out byte buffer with capacity `C` = `LIMITS_GET.max_pipe_bytes`, at least 65,536 bytes (ABI section 8.5). Bytes are bytes: NUL and bytes at or above `0x80` pass unchanged.

Each data operation does its checks in this order and stops at the first that applies: handle checks (ST3.2), a latched interrupt on that end (ST4.7), for a write the reader check (ST4.5), the length-zero rule (ST4.3), then the buffer state.

1. **Partial read.** `STREAM_READ(h, max)` with `max > 0` on a pipe holding `b > 0` bytes returns `OK` with `n = min(max, b)`, the oldest bytes first. It never waits for more bytes once it has at least one.
2. **Partial write.** `STREAM_WRITE(h, len)` with `len > 0` and a reader present stores `n = min(len, C - b)` bytes and returns `OK` with that `n` when `n > 0`. The caller loops. There is no all-or-nothing size: v1 makes no `PIPE_BUF`-style atomicity promise. (A Linux kernel pipe refuses a non-blocking write of up to 4,096 bytes that does not fit whole; a Linux adapter that serves `STREAM_WRITE` straight from a kernel pipe differs here. Open freeze item ST11.6.)
3. **Zero length.** `max = 0` or `len = 0` moves nothing and never blocks. A zero-length read returns `OK` with `n = 0`; this is not end of stream and the stream state is not consulted. A zero-length write still reports a missing reader: `BROKEN_PIPE`; otherwise `OK` with `n = 0`, even when the pipe is full. Authority is checked first in both cases. Evidence: AIENOS. (A Linux `write(fd, buf, 0)` on a pipe returns 0 without checking for readers; a Linux adapter must check, for example with `poll` for `POLLERR` on the write end. UNVERIFIED for Linux.)
4. **End of stream.** A read with `max > 0` on an empty pipe returns `OK` with `n = 0` (end of stream) only when every write-end handle is closed: the caller's, every duplicate, and every one held by a task. Bytes written before the last writer closed are delivered first. While any write end is open, an empty pipe gives `WOULD_BLOCK` (or parks with `BLOCK`).
5. **No reader.** A write when every read-end handle is closed returns `BROKEN_PIPE` and stores nothing. Bytes still buffered when the last reader closes are discarded and never delivered.
6. **Backpressure.** A write with `len > 0` on a full pipe returns `WOULD_BLOCK`, or with `BLOCK` parks until space, a close, a revoke or an interrupt. Nothing is ever buffered beyond `C`. A read on an empty pipe with a writer present behaves the same way. A parked call re-checks ST3.2 when it resumes, and returns as soon as it moved at least one byte.
7. **Interrupt.** An interrupt aimed at a stream end (the way `TASK_CANCEL(interrupt)` or a shell-level interrupt reaches a call on that end) makes the call parked on that end return `INTERRUPTED` with nothing moved. If no call is parked, the interrupt is latched on that end and the next data call on that end returns `INTERRUPTED` once; the call after that runs normally. An interrupted call never moved a byte, so the caller may retry it without repeating an effect (ABI section 10). Evidence: AIENOS. UNVERIFIED for Linux, where a signal that arrives outside a system call is not latched onto the next one: a Linux adapter latches it itself.
8. **Close and wake.** `STREAM_CLOSE(h)` releases the handle. Closing the last write end wakes every parked reader, which then sees the buffered bytes and then end of stream. Closing the last read end wakes every parked writer, which returns `BROKEN_PIPE` (or, if it already moved bytes in this call, `OK` with that count). Closing a handle of a revoked stream works and returns `OK`. Closing a closed or stale handle returns `STALE`. When both ends are closed the pipe is freed and its bytes are scrubbed.
9. **Revocation.** When the authority root revokes a pipe, the buffered bytes are scrubbed, every parked call on either end returns `REVOKED`, and every later read, write, dup or interrupt on any handle of that pipe returns `REVOKED`; no byte is delivered after the revoke. Only `STREAM_CLOSE` still works, so handles can be released. Revocation during a parked read or a parked write is covered by vectors.
10. **Duplicate.** `STREAM_DUP(h, rights, target)` makes a new handle on the same end. `rights` must contain the end's data right and nothing that is not a stream right (`INVALID_ARG`), and must be a subset of `h`'s rights. A duplicate into the caller's own table needs the derive right on `h`, into another principal's table the grant right (`DENIED` without it). Each duplicate counts as a separate reader or writer for ST4.4 and ST4.5. This is the capability form; the draft's `STREAM_DUP(src_stream, dst_fd)` is withdrawn in revision 2 (ST11.3). Descriptor duplication in a request record (redirection kind 4, `N>&M`) is the adapter's private business when it builds a task's standard streams for `TASK_SPAWN`; it is not a platform operation.
11. **Stream rights letters** (used by the vectors): `r` read, `w` write, `d` derive, `g` grant, `v` revoke (held by the authority root's delegate; revocation itself is still the root's act). `m` (map) is never a stream right.

## ST5. Capability domains and generations (settles ABI section 9.3)

Every effect that needs authority (`TASK_SPAWN`, write-class `STREAM_OPEN`, `LOC_CHDIR` into a protected location) carries a binding `{principal_id[32], domain u8, cap_index u32, cap_generation u64, resource_class u16, operation u16}`. The effect boundary checks it in this order at the moment of the effect, first failure wins, nothing happens on failure:

0. No binding at all: `DENIED` (ABI section 8.4).
1. `domain` is neither 1 nor 2: `CAP_DOMAIN_MISMATCH`.
2. `domain` is 1 and `cap_generation` is above `0xFFFFFFFF`: `CAP_GEN_NARROW`. The generation is never truncated: a domain-1 binding with generation `0x1_00000007` is refused even if a live capability has generation 7.
3. `domain` differs from the domain of the resource's authority: `CAP_DOMAIN_MISMATCH`. v1 has no bridge.
4. `cap_index` is not live, or `cap_generation` differs from the live generation in all of its bits (32 bits in domain 1, 64 bits in domain 2): `STALE`. A domain-2 authority compares all 64 bits: generation `0x7` does not match a live `0x1_00000007`.
5. The capability was revoked: `REVOKED`.
6. The capability does not grant this resource and operation: `DENIED`.

Evidence: steps 1, 2, 4, 5 and 6 are Omega's order (`authorize` then the capability root mapping); step 3 is Omega's hosted adapter (domain 2 only). AIENOS kernel tables are domain 1 with 32-bit generations. The full order across both domains is UNVERIFIED until both adapters run the vectors.

## ST6. Tasks

### ST6.1 Binding a task to streams

`TASK_SPAWN(resolved, argv, env, stdio{0,1,2}, binding)` gives the new task its own duplicate of each standard stream; the caller keeps its own handles, and the caller closing its copy is what lets end of stream reach a reader (ST4.4). A `stdin` slot needs a read end, `stdout` and `stderr` need write ends; a stale handle in a slot is `STALE` and a handle of the wrong end is `INVALID_ARG`, both before the binding is checked and before the task exists (UNVERIFIED order). A slot may be empty (the task sees end of stream on input and its output is discarded). When a task ends for any reason, every stream end it holds is closed, with the wake rules of ST4.8.

### ST6.2 Lifetime of a task id

A task id is valid from a successful `TASK_SPAWN` until the `TASK_WAIT` that returns the task's final status (the task is reaped then). Any later use of that id, and any use of an id from an earlier `session_epoch`, is `STALE`. `TASK_WAIT` with deadline 0 on a task that has not ended returns `WOULD_BLOCK` and reaps nothing. UNVERIFIED: no adapter implements `TASK_WAIT` with a deadline.

### ST6.3 Exit status

A task that exits normally has its exit code. A task the adapter ended with `TASK_CANCEL(interrupt)` has status 130 and outcome `CANCELLED`; with `TASK_CANCEL(terminate)` status 137 and outcome `CANCELLED`. A task killed by a signal someone else sent (Linux) is `COMPLETED` with status 128 plus the signal, as in ABI section 8.4; `CANCELLED` is only the adapter's own act. A task that writes to a stream with no reader and does not handle `BROKEN_PIPE` ends with status 141 (Linux: death by `SIGPIPE`; native: the same number by rule). Statuses 130, 137 and 141 on a native adapter are UNVERIFIED conventions chosen to equal the Linux numbers.

### ST6.4 State

`TASK_STATE` returns 1 `RUNNING` or 2 `ENDED` (ended, not yet reaped). UNVERIFIED numbering.

### ST6.5 Cancellation

`TASK_CANCEL(interrupt)` delivers an interrupt: the task's parked stream call returns `INTERRUPTED` (ST4.7). A task may handle an interrupt and keep running. `TASK_CANCEL(terminate)` ends the task unconditionally: it cannot be ignored (Linux `SIGKILL`). Cancelling an ended, unreaped task returns `OK` and changes nothing. Cancelling a reaped task is `STALE`.

Cleanup of a running pipeline (ABI section 12, on `ERROR`, reset, shutdown or partial launch): interrupt every running task, wait a bounded grace period, terminate the survivors, reap every task, close every stream end the adapter holds for that pipeline. After cleanup no task of that pipeline is running, no pipe end is open in the adapter, and every task id is released.

## ST7. Pipeline launch, refusal before effects, partial launch

The adapter launches a request record in this order. Steps 1 to 4 make no effect; a refusal there starts nothing and every command's outcome is `FAILED_NO_EFFECT`.

1. Shape: `ncmds` 1 to 8 (more is `LIMIT`; a record above 8 is already refused by the decoder, ABI section 7.1), every field valid (`REQ_FIELD`).
2. `RESOLVE` every external command. A class this adapter does not provide refuses the whole pipeline: `UNAVAILABLE`, status 126. Classes never fall back to each other.
3. Binding checks of ST5 steps 0 to 2 (shape of the binding), plus `PERM_CHECK`: a failure refuses the whole pipeline with that error, status 126.
4. Create all `ncmds - 1` pipes. Failure: `LIMIT`, status 1; pipes already created are closed.
5. Start commands left to right. For each command, at the moment of its effect: a name that was not found gives that command status 127 (`NOT_FOUND`, outcome `FAILED_NO_EFFECT`); a binding that fails ST5 steps 3 to 6 now (for example revoked after an earlier command started) gives that command status 126 with that error and outcome `FAILED_NO_EFFECT`. In both cases the adapter closes that command's pipe ends so its neighbours see end of stream or `BROKEN_PIPE`, and the other commands still run, as in a POSIX shell. Evidence: Omega `run_pipeline`.
6. A **launch failure** is a resource failure of `TASK_SPAWN` itself (Linux `fork` failure, task table full: `LIMIT` or `IO`). If no command has started yet, the pipeline returns that error, status 1, the failing command `FAILED_NO_EFFECT`, the rest `NOT_STARTED`. If at least one command started, the adapter cancels and reaps the started ones (ST6.5 cleanup), closes every pipe, and returns `PARTIAL_LAUNCH`, status 1, with outcomes: started commands `CANCELLED` (status as they ended: 130 interrupted, 137 terminated), the failing one `FAILED_NO_EFFECT` with status 1, later ones `NOT_STARTED` with no status. A started command that had already ended on its own before the cleanup still reports `CANCELLED` (Omega does this; UNVERIFIED as a rule).
7. Wait for all, reap all. Pipeline status is the last command's status (ABI section 7.2); a nonzero status of an earlier command does not change it.

Every operation an adapter does not provide is refused with a defined error before any effect: `NOT_SUPPORTED` for an op id, `UNAVAILABLE` for a resolution class or location scheme. An adapter never reports success for something it did not do.

## ST8. Effects, outcomes and OUTCOME_UNKNOWN

1. An effect is one `TASK_SPAWN` or one write-class `STREAM_OPEN` (ABI section 10). Pipe creation, reads, writes, closes and duplicates are not effects and have no intent record.
2. Before each effect the adapter makes a durable intent record; after it ends, an outcome record (`NOT_STARTED`, `COMPLETED(status)`, `FAILED_NO_EFFECT(error)`, `CANCELLED`, `OUTCOME_UNKNOWN`). If the intent cannot be made durable, the effect does not happen (`FAILED_NO_EFFECT`, `IO`).
3. After an adapter crash or restart, every intent with no outcome is reported `OUTCOME_UNKNOWN` and is **never replayed**; the restart also advances `session_epoch`, so every earlier handle and task id is `STALE`.
4. While running, a started task whose fate the adapter can no longer determine (Linux: someone else reaped the child, `waitpid` gives `ECHILD`) is reported by `TASK_WAIT` as error `OUTCOME_UNKNOWN`, status 1, outcome `OUTCOME_UNKNOWN`. It is never reported as success and never restarted. Evidence: Omega `wait_all` and its journal recovery.

## ST9. Limits

`LIMITS_GET` reports `{max_streams, max_tasks, max_pipe_bytes, max_output_bytes}`. v1 minimums (ABI section 8.5): 16 open stream handles per session besides the 3 standard ones (so at least 8 pipes with both ends held), 8 concurrent tasks per pipeline, 65,536 bytes per pipe. A request beyond a limit returns `LIMIT` and leaves nothing allocated; nothing is ever truncated silently.

## ST10. Conformance and receipts

1. The corpus `vectors/s*.vec` and `vectors/t*.vec` is shared by every adapter. Each vector names the features it needs and its authority domain. An adapter runs every vector it can; for any vector that needs a feature or a domain it does not have, it reports `NOT_RUN` with the reason. It never reports `PASS` for a vector it did not run, and never skips silently.
2. Each vector is marked `exec host-logic` (the adapter's state logic run in a host unit test is valid evidence) or `exec native-qemu` (it involves real parking, real tasks or real concurrent execution: AIENOS evidence counts only from a native run under QEMU, Omega evidence only from real Linux processes). The reference model in this repository runs every vector as logic; its result is a check of the corpus, not evidence about any adapter.
3. A run report is a receipt only if its first line pins all of: the implementation repository and full commit, this corpus's repository and full commit, the compiler and its version, and the target (`host` or `qemu-<machine>`). Format in `vectors/README.md`. Results without those pins are not receipts.

## ST11. Open freeze items for streams and tasks

These are recorded, not settled, and the ABI must not freeze while one is open.

1. Op ids 6 to 15 and their argument layouts (ST2) have no implementation.
2. Status numbers 130, 137 and 141 on a native adapter (ST6.3) and the `TASK_STATE` numbering (ST6.4).
3. `STREAM_DUP(src_stream, dst_fd)` from the draft is withdrawn in favour of the capability form (ST4.10); the freeze confirms that no consumer needs a platform-level `dst_fd` form.
4. Minimum stream count: AIENOS currently has 8 handle slots per table and 4 pipes per pool, below ST9 (16 handles, 8 pipes, and 7 pipes for an 8-command pipeline). Either AIENOS grows or the minimum changes with a revision; the limit vector fails on AIENOS until then.
5. Section 12 says interrupt, grace, terminate. Omega's partial-launch cleanup sends `SIGTERM` and `SIGCONT` with no escalation, and labels the failing command `NOT_STARTED` instead of `FAILED_NO_EFFECT`; the vectors follow this document, so Omega differs until it changes or this text does.
6. Partial-write atomicity: Linux kernel pipes are all-or-nothing for non-blocking writes of up to 4,096 bytes; this text requires partial writes (ST4.2). Settle before the freeze whether the Linux adapter buffers to conform or the rule allows `WOULD_BLOCK` there.
7. Zero-length write on a pipe with no reader is `BROKEN_PIPE` here (AIENOS); Linux returns 0. The Linux adapter must check readers itself (ST4.3).
8. Latched interrupts (ST4.7) are AIENOS behaviour; a Linux adapter must emulate them.
9. The exact grace period of ST6.5 is not fixed; vectors only require that cleanup ends with every task reaped.

## ST12. Revision history

- Revision 1 (`fb5fca98e667` and earlier): ABI sections 8.1, 8.4, 10, 12 only.
- Revision 2 (this file, aien-protocols-mv#43): platform call frame layout and draft op ids (ST2); handle check order and incarnations (ST3); byte-stream semantics (ST4); `STREAM_DUP` changed to the capability form (incompatible with revision 1, allowed only because v1 is not frozen); domain check order (ST5); task binding, lifetime, statuses, cancellation (ST6); launch order and partial launch (ST7); outcome rules (ST8); conformance and receipts (ST10). `abi_version` stays 1 because nothing in v1 is frozen (ABI header); after the freeze, any change of this size bumps `abi_version`.
