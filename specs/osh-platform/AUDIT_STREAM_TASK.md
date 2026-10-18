# Audit: OSH ABI v1 streams and tasks against the two implementations

**Status**: informative, part of aien-protocols-mv#43. Not a freeze and not a conformance claim: no adapter has run the stream and task vectors yet, so every "differs" below is read from source, not observed.
**Sources read**: `OSH_PLATFORM_ABI.md` at aien-protocols-mv `fb5fca98e667` (v1 DRAFT); Omega Linux host adapter at omega-mv `a8ffd2b912c84197d08f963b05f9c7d8b30a3f8a` (`src/osh/host/osh_exec.c`, `osh_caps.c`, `osh_host.h`); AIENOS native pipe at aienos-mv `f8700d4cb65e47225a04102cd8a4fa5b8791c6f1` (branch `feat/native-pipe-1`, PR #433: `native/kernel/core/pipe.h`, `pipe.c`, `osh_err.h`, `tests/fixtures/pipe/`), plus the AIENOS handoff that lists its UNVERIFIED choices.
**Result**: [`STREAM_TASK.md`](STREAM_TASK.md) (draft revision 2) settles what the evidence supports; the rest is listed in its section ST11.

## A1. What each side implements today

| ABI item | Omega Linux host adapter | AIENOS native (feat/native-pipe-1) |
|---|---|---|
| `PIPE_CREATE` | `pipe2(O_CLOEXEC)` per pipeline link inside `run_pipeline`; not a platform op the core calls | `ck_pipe_create`, op 1 of a versioned frame dispatch |
| `STREAM_READ` / `WRITE` | done by the child processes on raw descriptors; the adapter never reads or writes a pipe itself | `ck_stream_read` / `ck_stream_write`, ops 2 and 3, partial I/O, `BLOCK` flag |
| `STREAM_CLOSE` | `close()` of parent copies right after each fork | `ck_stream_close`, op 4 |
| `STREAM_DUP` | `dup2` in the child for `N>&M`; no platform op | capability form, op 5 (rights plus target table) |
| `TASK_SPAWN` / `WAIT` / `CANCEL` / `STATE` | `fork` + `execve`, `waitpid`; cancel only as `SIGTERM`+`SIGCONT` on partial launch and `SIGKILL` on a stopped member | none (task lifecycle is a separate AIENOS issue) |
| Binding checks | `authorize` (valid, domain 1 or 2, domain-1 narrow, `PERM_CHECK`) then a per-effect hook; hosted authority is domain 2 only | pipe ends are domain-1 kernel capabilities checked by `ck_cap_lookup`; no binding record on pipe ops |
| Intent and outcome records | durable journal, `OUTCOME_UNKNOWN` on recovery, never replayed | RAM-only records in the test-only `osh_op` layer |
| Error numbering (8.6) | `osh_host.h` | `osh_err.h`, same numbers and names |

Both agree on the section 8.6 numbering and names, on the refusal namespaces staying separate, on never treating an unknown error as `OK`, and on the domain-1 narrowing refusal.

## A2. The AIENOS UNVERIFIED choices, one by one

| AIENOS choice | Evidence | Disposition in revision 2 |
|---|---|---|
| Op ids 1 to 5 | only implementation with op ids; Omega has no frames | Settled as draft numbering (ST2). Ids 6 to 15 assigned with no implementation: open ST11.1 |
| Call frame layout (magic, version, op, reserved, args; exact cell count) | matches ABI section 3 header and its check order | Settled (ST2), with the frame refusals mapped onto 8.6 errors: `INVALID_ARG` for length, magic, reserved, arg count; `NOT_SUPPORTED` for version and unknown op |
| `PIPE_CREATE` returning the write end in `value2` | only implementation | Settled (ST2) |
| `STREAM_DUP` in capability form instead of `(src_stream, dst_fd)` | Omega does descriptor duplication privately at spawn; AIENOS needs attenuation and transfer | Settled: capability form (ST4.10). The `dst_fd` form is withdrawn, an incompatible draft change recorded in ST12; confirm at freeze (ST11.3) |
| `PIPE_CREATE` needs no prior capability | ABI gives it no binding; both implementations create pipes unconditionally | Settled (ST3.5), bounded by `LIMIT` |
| Capability resource layout (tag, end bit, 3-bit index, 20-bit epoch) and pool of 4 pipes | private to the kernel | Layout: adapter-private, not ABI (ST2, ST3.3). Pool of 4 is below what ST9 implies: open ST11.4 |
| Error mapping (closed or reused handle `STALE`, missing right or wrong end `DENIED`, revoked `REVOKED`, malformed frame `INVALID_ARG`, other version or unknown op `NOT_SUPPORTED`) | Omega's capability mapping uses the same names for the same causes | Settled, including AIENOS's check order (ST3.2) |
| Pending cancel: an interrupt with nobody waiting interrupts the next call once | AIENOS only; a Linux signal outside a system call is not latched | Settled as the rule (ST4.7); Linux must emulate: open ST11.8 |
| 8-slot capability table, below "3 standard plus 16 open streams" | ABI 8.5 minimum stands | Open ST11.4; the `s018_limits` vector fails on AIENOS until it grows or the minimum changes |

## A3. Contradictions and gaps found in the draft and in Omega

1. **Platform frame refusals.** ABI section 3 lists the frame `OSHF` among blobs refused with `ABI_*` codes, but those are shell-core status codes (5.3) and a platform call answers with section 8.6 errors. Revision 2 maps them (ST2). The ABI text now points at ST2.
2. **`STREAM_DUP(src_stream, dst_fd)`** mixes two things: duplicating a capability and choosing a child's descriptor. Neither implementation exposes the second as a platform op. Withdrawn (ST4.10).
3. **Zero-length write with no reader.** AIENOS returns `BROKEN_PIPE`; Linux `write(fd, p, 0)` returns 0. Revision 2 follows AIENOS (ST4.3); open ST11.7.
4. **Partial writes.** AIENOS stores what fits; a Linux non-blocking pipe write of up to 4,096 bytes is all or nothing (`EAGAIN`). Omega does not serve `STREAM_WRITE` itself today, so nothing conflicts yet; open ST11.6 for when it does.
5. **Cleanup order (ABI section 12: interrupt, grace, terminate).** Omega's partial-launch cleanup sends `SIGTERM` and `SIGCONT` and then waits with no deadline; a child that ignores `SIGTERM` would hold the shell. Its stopped-member path uses `SIGKILL`. Revision 2 keeps section 12 and defines terminate as non-ignorable (ST6.5); Omega differs (ST11.5). The `t006_partial_launch` vector expects status 130 for an interrupted `hang`, where Omega's `SIGTERM` would give 143.
6. **Failing command's outcome on a launch failure.** Omega marks it `NOT_STARTED` with the error; section 10 has `FAILED_NO_EFFECT(error)` for exactly this. Revision 2 uses `FAILED_NO_EFFECT` (ST7.6); Omega differs (ST11.5).
7. **Per-command denial is not a partial launch.** Omega refuses a single command whose effect check fails (status 126) and lets the others run, as it does for a name not found (127). The draft did not say this; revision 2 adopts it (ST7.5), so `PARTIAL_LAUNCH` means only a resource failure of the spawn itself (ST7.6).
8. **Raw descriptors as handles.** If a Linux adapter ever exposes stream handles, descriptor reuse would defeat `STALE`. Revision 2 requires an adapter table with incarnations (ST3.4).
9. **Domain check order.** Omega checks narrowing before matching the resource's domain, so a domain-1 binding with a 64-bit generation against a domain-2 resource is `CAP_GEN_NARROW`, not `CAP_DOMAIN_MISMATCH`. Adopted (ST5); vector `t011_domain2_generation` pins it.
10. **`TASK_WAIT` deadline, `TASK_STATE` values, cancel statuses on a native adapter.** Not specified before and not implemented anywhere. Revision 2 defines them (ST6.2 to ST6.4) as UNVERIFIED.

## A4. Which vectors each implementation can run today (read from source, not run)

- **AIENOS `feat/native-pipe-1`**: the stream vectors `s001` to `s020` map onto its fixture runner with small changes (`fill W cap`, `skim`, `sweep`, `saturate`, `exhaust`, `limits` are new commands; kernel counters are gone). Expected to differ: `s018_limits` (pool of 4, table of 8). `s021_epoch` needs `reset` and `journal`; every `t*` vector needs tasks: `NOT_RUN` until the task issue lands.
- **Omega Linux host adapter**: has no stream handle API, so `s*` vectors are `NOT_RUN` until it exposes one (or a harness drives its pipes). Task and launch vectors need a harness that provides the conformance programs and a test authority; expected to differ on `t006_partial_launch` (A3.5, A3.6) and on any vector that needs the new `TASK_*` ops.

These predictions are a reading of the code at the commits above. They become evidence only as receipts in the ST10.3 format.
