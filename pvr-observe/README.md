# PVR bridge observer, phase 1

Status: bridge-only run 38376250065 and command-snapshot run 38412335488 booted temporarily; root and Droidspaces were confirmed. Command capture includes a verified correct vendor triangle. New indirect/CCB/KCCB/PMR probe extensions are pending cloud and device acceptance. No revision establishes complete replay or fixes the DCE fault.

## New default-off extensions

`indirect on|off` on the existing control selects a separate v3 stream for all kick pointer spans, context/framework buffers, PMR mapping-table/annotation and sparse page-index arrays. Supported schemas are in `pvr_observe_indirect.h`; unsupported calls and loss are counted explicitly. PMR metadata is not PMR contents.

Separate `probe_control` and `extra_control` accept `config HOST_TGID SLOTS OFFLINE_SHA256 LOADED_SRCVERSION`, `start`, `stop`, `reset`. No probes are installed at boot. Both gate the known module artifact's offline SHA attestation plus actual loaded owner/name/srcversion; the kernel does not hash loaded module text. Missing srcversion fails closed. A module reference is held until probes are drained/unregistered.

`probes` contains bounded PRE_RELEASE client-CCB/helper snapshots. `publish` captures valid KCCB slot bytes after write-index stores at the verified pinned-module instruction point, before the next barrier. `extra` contains KCCB candidate entry metadata and bounded successful existing PMR CPU-map return snapshots. None proves firmware consumption. Probe copies admit direct-map RAM only and reject IO/vmap aliases; missing bytes remain flagged. Buffers are preallocated and handlers never call PMR acquisition or read GPU registers.

These controls are independent: stop all enabled channels before export/reset. Coordinate an exclusive window with other users, including the clean-room process. Do not reconfigure shared live captures. New binary layouts are defined in the headers; device decode/acceptance is still pending.

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

## Opt-in command snapshots (source extension, not deployed)

After stopping, draining, saving the old capture and resetting, write `commands on` before `start`. The boot default is off; `commands off` restores bridge-only capture. Changing this mode requires disabled/drained capture and empty buffers. Reset clears both buffers and both loss counters, but preserves the selected mode. A second 16 MiB buffer is allocated only on start with this mode enabled.

This explicitly selects the reference DDK25.3 volcanic LP64 little-endian KickTA3D2 layout, not an auto-detected device ABI. For group 130/function 10, exactly 256 successfully copied input bytes are required. From that SAME retained pre-input snapshot, TA pointer/length at +0x78/+0xf8, 3D at +0x68/+0xc0, and PR at +0x70/+0xc4 are read. Each pointed command is independently copied before KMD execution, capped at 64 KiB, without modifying it. This does not validate the command's firmware layout. A null pointer with nonzero length produces a copy-error record; zero length produces a marker even with a null pointer.

The original `records` stream remains version 1. A separate root-only `commands` debugfs file uses the same 80-byte header with version 2 and phase 2=TA, 3=3D, 4=PR; result is zero, sequence and process identity match the parent pre/post pair. The userspace address and requested/captured lengths refer to that nested command, not the bridge descriptor. Control adds `commands`, `command_bytes`, `command_lost`, and `command_schema=ddk25.3-volcanic-lp64-le`. Capacity failures increment `command_lost`; unusable parent snapshots also increment it. Main-stream failures still increment `lost`. Any loss/flags, missing markers, schema mismatch, orphan or duplicate snapshots invalidate a command window.

Export both files only after stop and active=0, saving final control. Use `checks/pvr_observer_commands.py BRIDGE_RECORDS COMMAND_RECORDS FINAL_CONTROL` from the project workspace to check pointer/length/identity/timestamp correspondence and byte counts. Run the existing bridge session validator separately with initial/final control for a clean-start claim. Capturing three snapshots is NOT enough for replay: pointed GPU memory, PMR data, mappings, synchronization dependencies, final KMD CCB/KCCB and fault registers remain absent. Kernel compilation, temporary boot and an actual paired command-window test are still required before using this extension as evidence.

## Important limitations

- User-memory snapshots have a TOCTOU window relative to KMD's own copies. Concurrent buffer mutation can invalidate the comparison.
- Capture calls copy_from_user and allocators in syscall context, and may sleep or trigger userfault handling. Timing is perturbed. This is not a zero-risk/zero-overhead observer.
- A global observer mutex serializes snapshots, not KMD execution. Timestamp/sequence order alone does not establish GPU submission or dependency order.
- Default mode copies only top-level input/output bytes. Opt-in commands mode additionally snapshots three reference Kick command spans, not other indirect arrays. PMR contents, mapping lifetimes, FD contents, CCB/KCCB and asynchronous fault registers remain NOT captured.
- A successful ioctl is not a successful GPU job. Pair these records with existing per-run HWR/fault snapshots; this observer cannot guarantee a pre-reset fault dump.
- No exports/layout changes is a design constraint, not proof of KABI compatibility. Export the actual build config and Module.symvers and compare against the running kernel's vendor-module CRC requirements before booting. The existing workflow's stock config camouflage and disabled strict checks cannot establish compatibility.

## Patch generation

`python3 make_patch.py PATH_TO_COMMON` emits a patch using exact syscall anchors. Apply only after dry-run validation against the actual fully patched kernel tree. It deliberately rejects duplicate/changed anchors and an already integrated observer rather than guessing. The native syscall body is wrapped; neither the exported vfs_ioctl function nor its signature changes.

Next: cloud-build this command-snapshot revision with the accepted root/Droidspaces configuration (SUSFS may remain disabled), inspect actual config/symbol artifacts, then offer a magiskboot-repacked image for the user's temporary boot. Validate a short command window before comparing matched vendor/Mesa workloads. Complete replay still requires allocation/mapping/cache/synchronization dependency reconstruction.
