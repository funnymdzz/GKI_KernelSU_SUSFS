# PVR bridge observer, phase 1

Status: source and patch-anchor/decoder tests only. No kernel compilation, cloud dispatch, boot validation, KABI comparison or replay success yet.

## Boundaries

This private built-in observer wraps the native ioctl syscall after the existing security check. It never edits ioctl arguments, return values, exported symbols, kernel structure layouts or GPU registers. It does not observe compat ioctls or in-kernel vfs_ioctl calls. Its source is built only when the existing CONFIG_DEBUG_FS is enabled; do not change that configuration solely to accommodate this observer without reviewing ABI consequences.

Runtime capture is disabled at boot. The observer recognizes only the reference DDK's 32-byte DRM services ioctl (0xc0206440), and requires an exact initial-namespace TGID and character-device major/minor. Do not claim this reference ABI matches a device until verified. Processes in a container must use the host TGID, not their namespace-local PID. Start the target stopped or under a launch barrier to capture its first ioctl.

All controls and record reads require CAP_SYS_ADMIN and root-only debugfs permissions. Records contain sensitive process data; do not publish captures without review. Do not relax SELinux or global debugfs access merely to run a test.

## Controls

Debugfs paths below are relative to the existing debugfs mount:

```
pvr_observe/control
pvr_observe/records
```

Commands accepted by control:

```
start HOST_TGID CHAR_DEVICE_MAJOR CHAR_DEVICE_MINOR
stop
reset
```

Read control for enabled state, inflight count, used bytes and lost records. `stop` does not cancel an inflight ioctl: its post record still completes. Reading records and resetting require disabled capture and zero inflight operations. Save control before/after exporting records. Do not reset or restart during an export. Reset clears retained records/loss counters but sequence numbers remain monotonic.

There is a 16 MiB retaining buffer, allocated on first start, never overwritten. Each pre/post payload is capped at 64 KiB. Truncation and copy failures are flags, and allocation/buffer/header-copy failures increment the loss counter. A full buffer continues counting lost records without blocking the GPU on consumer progress. Any loss, flagged record or incomplete pair makes the capture unsuitable as a complete baseline.

## Record ABI v1

LP64 little-endian ARM64 only. An 80-byte header is followed by min(requested, 65536) bytes. Header fields:

```
u32 magic=0x4f525650, version=1, bytes, phase (0 pre / 1 post)
u64 sequence, monotonic timestamp_ns, userspace address
s64 ioctl syscall result (pre=0)
u32 tgid, tid, command, bridge group, bridge function
u32 requested, captured, flags (1 truncated, 2 copy failed)
```

A failed user copy discards/zeros the entire payload and reports captured=0. Captured bytes are zero only when unavailable or legitimately zero, distinguished by flags. Paired records share a sequence. Post records use the original wrapper's output pointer and size; the wrapper itself is copied once before the call. The original DRM ioctl returns bridge data through that pointed buffer.

## Important limitations

- User-memory snapshots have a TOCTOU window relative to KMD's own copies. Concurrent buffer mutation can invalidate the comparison.
- Capture calls copy_from_user and allocators in syscall context, and may sleep or trigger userfault handling. Timing is perturbed. This is not a zero-risk/zero-overhead observer.
- A global observer mutex serializes snapshots, not KMD execution. Timestamp/sequence order alone does not establish GPU submission or dependency order.
- Only wrapper-selected top-level input/output bytes are copied. Indirect command arrays, PMR contents, mapping lifetimes, FD contents, CCB/KCCB and asynchronous fault registers are NOT captured.
- A successful ioctl is not a successful GPU job. Pair these records with existing per-run HWR/fault snapshots; this observer cannot guarantee a pre-reset fault dump.
- No exports/layout changes is a design constraint, not proof of KABI compatibility. Export the actual build config and Module.symvers and compare against the running kernel's vendor-module CRC requirements before booting. The existing workflow's stock config camouflage and disabled strict checks cannot establish compatibility.

## Patch generation

`python3 make_patch.py PATH_TO_COMMON` emits a patch using exact syscall anchors. Apply only after dry-run validation against the actual fully patched kernel tree. It deliberately rejects duplicate/changed anchors and an already integrated observer rather than guessing. The native syscall body is wrapped; neither the exported vfs_ioctl function nor its signature changes.

Next phases: integrate an opt-in cloud-build input, pin source provenance, export real config/symbol artifacts, compile and inspect; then bounded schema-aware indirect capture with loss reporting and separately validated fault observation. Complete replay still requires allocation/mapping/cache/synchronization dependency reconstruction.
