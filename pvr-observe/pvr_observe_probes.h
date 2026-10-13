/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PVR_OBSERVE_PROBES_H
#define PVR_OBSERVE_PROBES_H
/*
 * Optional, OFF until explicitly configured and started. Include in exactly one
 * translation unit (pvr_observe.c); this file does not install itself.
 *
 * Evidence: checks/PVR_DEVICE_CCB_PROBE_FINDINGS.md and
 * checks/pvr_device_ccb_release_decomp.txt, artifact SHA below, arm64 LE only.
 * x0=count, x1=helpers, stride 144. No inferred x2/x3/context identity.
 * KCCB deliberately OMITTED: no verified signature in that evidence.
 * No kretprobe: retained ring pointers could become stale/reused and a return
 * does not prove KCCB publication. Every record is PRE_RELEASE, not finalCCB.
 * Acquire writes headers in the observed binary; release entry itself does not
 * write them. Nevertheless these are entry-time, non-atomic host RAM snapshots.
 *
 * Control API (process context, CAP_SYS_ADMIN, independently serialized here):
 *   pvro_probes_init()                         no allocation/registration
 *   pvro_probes_config(tgid, slots, artifact_sha256, expected_srcversion)
 *   pvro_probes_start()                        register DISABLED, gate, enable
 *   pvro_probes_stop()                         disable/drain/unregister/unpin
 *   pvro_probes_reset()                        stopped only; clears records
 *   pvro_probes_status(char *out, size_t len)   text; returns bytes or errno
 *   pvro_probes_read(char __user *, size_t, loff_t *) stopped-only binary
 *   pvro_probes_exit()                         stop and free; process context
 * All return int except status/read (ssize_t), exit (void).
 * Call init once before exposing control, exit after withdrawing control files.
 * Caller must add include/lifecycle/control/debugfs wiring separately. No new
 * module exports, parameters, initcalls, MMIO, or vendor module modification.
 *
 * Identity gate: artifact_sha256 is an OPERATOR ATTESTATION about the offline
 * module file, NOT a kernel hash verification. Actual kernel checks are owning
 * module name and exact nonempty srcversion; srcversion is NOT SHA256 and does
 * not authenticate text, config, signing, or relocations. A nonempty loaded
 * srcversion and separately verified expected value are required; absence fails closed.
 * A module lifetime reference is held from the gate through unregister. An
 * untrusted operator can lie about provenance: do not use this as authentication.
 *
 * No-fault reads are admitted ONLY for direct-map RAM (virt_addr_valid on every
 * crossed page). This intentionally rejects vmalloc/vmap/ioremap/user addresses,
 * including otherwise valid vendor ring mappings, rather than risk reading MMIO.
 * No address fallback, forced registration, symbol scanning, or page faulting.
 *
 * Binary format: native arm64 LE, fixed sizeof(struct pvro_probe_record) slots,
 * version=1, bytes=sizeof(record); layout available below (explicit fixed-width
 * fields, 8-aligned). Stop before reading. Addresses are privileged sensitive
 * data. Zero captured length means absent/failed; flags must always be checked.
 * FULL drops are in status, not necessarily in a record. No overwrite policy.
 */
#include <linux/capability.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>

#define PVROP_SHA "e3277ee9b9bcf8f3f90067f6b40f3ae94d592d17ea67dd653063221fe1e241cf"
#define PVROP_HELPERS 8U
#define PVROP_STRIDE 144U
#define PVROP_RAW 1024U
#define PVROP_RING 4096U
#define PVROP_SLOTS 64U
#define PVROP_CAPACITY_MAX (1024U * 1024U)
#define PVROP_SRCVERSION_LEN 25U /* module srcversion: 24 hex characters */
#define PVROP_COPY_FAILED BIT(0)
#define PVROP_BAD_LAYOUT BIT(1)
#define PVROP_BUDGET BIT(2)
#define PVROP_WRAP BIT(3)
#define PVROP_NON_RAM BIT(4)
#define PVROP_PRE_RELEASE BIT(5)

struct pvro_probe_helper {
	u64 command_address;
	u32 requested, captured, flags, reserved;
	u8 helper[PVROP_STRIDE];
	u8 command[PVROP_RAW];
};
struct pvro_probe_record {
	u32 magic, version, bytes, flags;
	u64 sequence, timestamp_ns, helper_address, ccb_address;
	u64 control_address, ring_address;
	u32 tgid, tid, count, helpers_captured;
	u32 old_write, capacity, allocation_bytes, ring_offset;
	u32 ring_captured, padding_offset, padding_requested, padding_captured;
	u32 ccb_captured, control_captured, reserved[2];
	u8 ccb[64]; /* +0 ctrl, +8 ring, +32 write, +48 byte count, +56 cap */
	u8 control[16]; /* opaque, not decoded as FW state */
	struct pvro_probe_helper helpers[PVROP_HELPERS];
	u8 ring[PVROP_RING];
	u8 padding[PVROP_RING];
};

static DEFINE_MUTEX(pvrop_control_lock);
static DEFINE_RAW_SPINLOCK(pvrop_capture_lock);
static struct pvro_probe_record *pvrop_records;
static struct kprobe pvrop_probe;
static struct module *pvrop_owner;
static bool pvrop_initialized, pvrop_configured, pvrop_registered, pvrop_enabled;
static u32 pvrop_tgid, pvrop_slots, pvrop_used;
static u64 pvrop_sequence;
static char pvrop_srcversion[PVROP_SRCVERSION_LEN];
static unsigned long pvrop_nmissed;
static atomic64_t pvrop_full = ATOMIC64_INIT(0);
static atomic64_t pvrop_busy = ATOMIC64_INIT(0);
static atomic64_t pvrop_nmi = ATOMIC64_INIT(0);
static atomic64_t pvrop_invalid = ATOMIC64_INIT(0);
static atomic64_t pvrop_copy_errors = ATOMIC64_INIT(0);

static u32 pvrop_u32(const u8 *p)
{
	u32 v;
	memcpy(&v, p, sizeof(v));
	return v;
}
static u64 pvrop_u64(const u8 *p)
{
	u64 v;
	memcpy(&v, p, sizeof(v));
	return v;
}
/* Bounded, no sleeping, no vmalloc metadata traversal. Never access IO aliases. */
static bool pvrop_ram(u64 address, u32 length)
{
	unsigned long a = (unsigned long)address, last, page;

	if (!length || !a || address != (u64)a ||
	    length > PVROP_RING || a > ULONG_MAX - (length - 1))
		return false;
	last = a + length - 1;
	for (page = a & PAGE_MASK; ; page += PAGE_SIZE) {
		if (!virt_addr_valid((void *)page))
			return false;
		if (page == (last & PAGE_MASK))
			break;
	}
	return true;
}
static bool pvrop_copy(void *dst, u64 address, u32 length, u32 *flags)
{
	if (!length)
		return true;
	if (!pvrop_ram(address, length)) {
		*flags |= PVROP_NON_RAM;
		return false;
	}
	if (copy_from_kernel_nofault(dst, (const void *)(unsigned long)address,
				     length)) {
		/* Never expose partial bytes as a successful snapshot. */
		memset(dst, 0, length);
		*flags |= PVROP_COPY_FAILED;
		return false;
	}
	return true;
}

static int pvrop_entry(struct kprobe *probe, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64) && !defined(CONFIG_CPU_BIG_ENDIAN)
	struct pvro_probe_record *r;
	unsigned long irqflags;
	u32 i, total = 0;
	u64 address, ccb = 0, end;

	(void)probe;
	if (!READ_ONCE(pvrop_enabled) ||
	    (u32)task_tgid_nr(current) != READ_ONCE(pvrop_tgid))
		return 0;
	if (in_nmi()) {
		atomic64_inc(&pvrop_nmi);
		return 0;
	}
	/* Contention/nesting drops instead of extending a spin wait in the KMD. */
	if (!raw_spin_trylock_irqsave(&pvrop_capture_lock, irqflags)) {
		atomic64_inc(&pvrop_busy);
		return 0;
	}
	if (!pvrop_enabled)
		goto out;
	if (pvrop_used == pvrop_slots) {
		atomic64_inc(&pvrop_full);
		goto out;
	}
	r = &pvrop_records[pvrop_used++]; /* pre-zeroed at config/reset */
	r->magic = 0x504f5250; /* PROP */
	r->version = 1;
	r->bytes = sizeof(*r);
	r->flags = PVROP_PRE_RELEASE;
	r->sequence = ++pvrop_sequence;
	r->timestamp_ns = ktime_get_mono_fast_ns();
	r->tgid = task_tgid_nr(current);
	r->tid = task_pid_nr(current);
	r->count = (u32)regs->regs[0]; /* actual ABI is unsigned int */
	r->helper_address = regs->regs[1];
	if (!r->count || r->count > PVROP_HELPERS)
		goto bad;
	address = r->helper_address;
	if (address > U64_MAX - (u64)r->count * PVROP_STRIDE)
		goto bad;
	for (i = 0; i < r->count; i++) {
		struct pvro_probe_helper *h = &r->helpers[i];
		u32 alloc, dm, off;
		u64 this_ccb;

		if (!pvrop_copy(h->helper, address + i * PVROP_STRIDE,
				PVROP_STRIDE, &r->flags))
			goto done;
		r->helpers_captured++;
		this_ccb = pvrop_u64(h->helper);
		if (!i)
			ccb = this_ccb;
		if (!ccb || this_ccb != ccb)
			goto bad;
		h->requested = pvrop_u32(h->helper + 68);
		h->command_address = pvrop_u64(h->helper + 72);
		dm = pvrop_u32(h->helper + 84);
		alloc = pvrop_u32(h->helper + 88);
		off = pvrop_u32(h->helper + 92);
		if (alloc < 16 || (alloc & 7) || dm < 16 || (dm & 7) ||
		    (off & 7) || off > alloc || dm > alloc - off ||
		    dm != (((u64)h->requested + 23) & ~7ULL) ||
		    h->requested > dm - 16 || alloc > U32_MAX - total)
			goto bad;
		total += alloc;
		if (h->requested > PVROP_RAW) {
			h->flags |= PVROP_BUDGET;
			r->flags |= PVROP_BUDGET;
		} else if (pvrop_copy(h->command, h->command_address,
				      h->requested, &h->flags)) {
			h->captured = h->requested;
		}
		r->flags |= h->flags;
	}
	r->ccb_address = ccb;
	r->allocation_bytes = total;
	if (!pvrop_copy(r->ccb, ccb, sizeof(r->ccb), &r->flags))
		goto done;
	r->ccb_captured = sizeof(r->ccb);
	r->control_address = pvrop_u64(r->ccb);
	r->ring_address = pvrop_u64(r->ccb + 8);
	r->old_write = pvrop_u32(r->ccb + 32);
	r->capacity = pvrop_u32(r->ccb + 56);
	if (r->capacity < 32 || r->capacity > PVROP_CAPACITY_MAX ||
	    (r->capacity & (r->capacity - 1)) ||
	    r->old_write >= r->capacity || (r->old_write & 7) ||
	    (u64)total + 17 > r->capacity || !r->ring_address ||
	    r->ring_address > U64_MAX - r->capacity)
		goto bad;
	if (pvrop_copy(r->control, r->control_address, sizeof(r->control),
			&r->flags))
		r->control_captured = sizeof(r->control);
	end = (u64)r->old_write + total + 16;
	if (end <= r->capacity) {
		r->ring_offset = r->old_write;
	} else {
		r->flags |= PVROP_WRAP;
		r->ring_offset = 0;
		r->padding_offset = r->old_write;
		r->padding_requested = r->capacity - r->old_write;
		if (r->padding_requested > PVROP_RING)
			r->flags |= PVROP_BUDGET;
		else if (pvrop_copy(r->padding,
				r->ring_address + r->padding_offset,
				r->padding_requested, &r->flags))
			r->padding_captured = r->padding_requested;
	}
	if (total > PVROP_RING)
		r->flags |= PVROP_BUDGET;
	else if (pvrop_copy(r->ring, r->ring_address + r->ring_offset,
			    total, &r->flags))
		r->ring_captured = total;
	goto done;
 bad:
	r->flags |= PVROP_BAD_LAYOUT;
	atomic64_inc(&pvrop_invalid);
 done:
	if (r->flags & (PVROP_COPY_FAILED | PVROP_NON_RAM))
		atomic64_inc(&pvrop_copy_errors);
 out:
	raw_spin_unlock_irqrestore(&pvrop_capture_lock, irqflags);
#endif
	return 0; /* Never changes regs or skips the original instruction. */
}
NOKPROBE_SYMBOL(pvrop_entry);
NOKPROBE_SYMBOL(pvrop_copy);
NOKPROBE_SYMBOL(pvrop_ram);
NOKPROBE_SYMBOL(pvrop_u32);
NOKPROBE_SYMBOL(pvrop_u64);

static int __maybe_unused pvro_probes_init(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvrop_control_lock);
	pvrop_initialized = true; /* static initialization supplies the OFF state */
	mutex_unlock(&pvrop_control_lock);
	return 0;
}

static int __maybe_unused pvro_probes_config(u32 tgid, u32 slots,
		const char *artifact_sha256, const char *expected_srcversion)
{
	struct pvro_probe_record *new_records;
	u32 i;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
#if !defined(CONFIG_ARM64) || defined(CONFIG_CPU_BIG_ENDIAN) || \
    !defined(CONFIG_KPROBES) || !defined(CONFIG_MODULES)
	return -EOPNOTSUPP;
#endif
	if (!tgid || tgid > INT_MAX || !slots || slots > PVROP_SLOTS ||
	    !artifact_sha256 || strcmp(artifact_sha256, PVROP_SHA) ||
	    !expected_srcversion || strlen(expected_srcversion) != 24)
		return -EINVAL;
	for (i = 0; i < 24; i++)
		if (!isxdigit(expected_srcversion[i]))
			return -EINVAL;
	mutex_lock(&pvrop_control_lock);
	if (!pvrop_initialized) {
		ret = -EINVAL;
		goto out;
	}
	/* Do not silently replace evidence or a registered probe. */
	if (pvrop_registered || pvrop_enabled || pvrop_used) {
		ret = -EBUSY;
		goto out;
	}
	new_records = vzalloc(array_size(slots, sizeof(*new_records)));
	if (!new_records) {
		ret = -ENOMEM;
		goto out;
	}
	vfree(pvrop_records);
	pvrop_records = new_records;
	pvrop_tgid = tgid;
	pvrop_slots = slots;
	strscpy(pvrop_srcversion, expected_srcversion, sizeof(pvrop_srcversion));
	pvrop_configured = true;
 out:
	mutex_unlock(&pvrop_control_lock);
	return ret;
}

/* Control mutex held. unregister_kprobe drains handlers before returning. */
static void pvrop_stop_locked(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pvrop_capture_lock, flags);
	WRITE_ONCE(pvrop_enabled, false);
	raw_spin_unlock_irqrestore(&pvrop_capture_lock, flags);
	if (pvrop_registered) {
		disable_kprobe(&pvrop_probe);
		unregister_kprobe(&pvrop_probe);
		pvrop_nmissed += pvrop_probe.nmissed;
		pvrop_registered = false;
	}
	if (pvrop_owner) {
		module_put(pvrop_owner);
		pvrop_owner = NULL;
	}
}

static int __maybe_unused pvro_probes_start(void)
{
	int ret;
#if defined(CONFIG_MODULES)
	struct module *owner;
#endif
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvrop_control_lock);
	if (!pvrop_initialized || !pvrop_configured) {
		ret = -EINVAL;
		goto out;
	}
	if (pvrop_registered || pvrop_enabled || pvrop_used) {
		ret = -EBUSY;
		goto out;
	}
	memset(&pvrop_probe, 0, sizeof(pvrop_probe));
	pvrop_probe.symbol_name = "pvrsrvkm:RGXCmdHelperReleaseCmdCCB";
	pvrop_probe.pre_handler = pvrop_entry;
	pvrop_probe.flags = KPROBE_FLAG_DISABLED;
	ret = register_kprobe(&pvrop_probe);
	if (ret)
		goto out;
	pvrop_registered = true;
#if defined(CONFIG_MODULES)
	/* Module address lookup requires preemption disabled. No kallsyms hacks. */
	preempt_disable();
	owner = __module_address((unsigned long)pvrop_probe.addr);
	if (owner && !strcmp(owner->name, "pvrsrvkm") &&
	    owner->srcversion && !strcmp(owner->srcversion, pvrop_srcversion) &&
	    try_module_get(owner))
		pvrop_owner = owner;
	preempt_enable();
#endif
	if (!pvrop_owner) {
		ret = -ESTALE;
		pvrop_stop_locked();
		goto out;
	}
	/* No events admitted before owning-module identity/lifetime checks pass. */
	WRITE_ONCE(pvrop_enabled, true);
	ret = enable_kprobe(&pvrop_probe);
	if (ret)
		pvrop_stop_locked();
 out:
	mutex_unlock(&pvrop_control_lock);
	return ret;
}

static int __maybe_unused pvro_probes_stop(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvrop_control_lock);
	pvrop_stop_locked();
	mutex_unlock(&pvrop_control_lock);
	return 0;
}
static int __maybe_unused pvro_probes_reset(void)
{
	int ret = 0;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvrop_control_lock);
	if (pvrop_registered || pvrop_enabled) {
		ret = -EBUSY;
		goto out;
	}
	if (pvrop_records)
		memset(pvrop_records, 0, array_size(pvrop_slots, sizeof(*pvrop_records)));
	pvrop_used = 0;
	pvrop_sequence = 0;
	pvrop_nmissed = 0;
	atomic64_set(&pvrop_full, 0);
	atomic64_set(&pvrop_busy, 0);
	atomic64_set(&pvrop_nmi, 0);
	atomic64_set(&pvrop_invalid, 0);
	atomic64_set(&pvrop_copy_errors, 0);
 out:
	mutex_unlock(&pvrop_control_lock);
	return ret;
}
static ssize_t __maybe_unused pvro_probes_status(char *out, size_t len)
{
	unsigned long flags;
	u32 used;
	ssize_t ret;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!out || !len)
		return -EINVAL;
	mutex_lock(&pvrop_control_lock);
	raw_spin_lock_irqsave(&pvrop_capture_lock, flags);
	used = pvrop_used;
	raw_spin_unlock_irqrestore(&pvrop_capture_lock, flags);
	ret = scnprintf(out, len,
		"configured=%u enabled=%u registered=%u tgid=%u records=%u slots=%u record_bytes=%zu full=%lld busy=%lld nmi=%lld invalid=%lld copy_errors=%lld kprobe_missed=%lu scope=PRE_RELEASE kccb=omitted identity=kernel-name-srcversion+offline-sha-attestation kernel_sha256_verified=0 srcversion=%s ram=direct-map-only\n",
		pvrop_configured, pvrop_enabled, pvrop_registered, pvrop_tgid,
		used, pvrop_slots, sizeof(struct pvro_probe_record),
		atomic64_read(&pvrop_full), atomic64_read(&pvrop_busy),
		atomic64_read(&pvrop_nmi), atomic64_read(&pvrop_invalid),
		atomic64_read(&pvrop_copy_errors),
		pvrop_nmissed + (pvrop_registered ? READ_ONCE(pvrop_probe.nmissed) : 0),
		pvrop_srcversion);
	mutex_unlock(&pvrop_control_lock);
	return ret;
}
static ssize_t __maybe_unused pvro_probes_read(char __user *out, size_t len,
					     loff_t *offset)
{
	ssize_t ret;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvrop_control_lock);
	if (pvrop_enabled || pvrop_registered)
		ret = -EBUSY;
	else if (!pvrop_records)
		ret = 0;
	else
		ret = simple_read_from_buffer(out, len, offset, pvrop_records,
				(size_t)pvrop_used * sizeof(*pvrop_records));
	mutex_unlock(&pvrop_control_lock);
	return ret;
}
static void __maybe_unused pvro_probes_exit(void)
{
	/* Internal teardown, not a user command: must always drain on exit. */
	mutex_lock(&pvrop_control_lock);
	pvrop_stop_locked();
	vfree(pvrop_records);
	pvrop_records = NULL;
	pvrop_slots = pvrop_used = 0;
	pvrop_configured = pvrop_initialized = false;
	mutex_unlock(&pvrop_control_lock);
}
#endif /* PVR_OBSERVE_PROBES_H */
