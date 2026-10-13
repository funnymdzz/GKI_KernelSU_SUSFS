/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PVR_OBSERVE_EXTRA_PROBES_H
#define PVR_OBSERVE_EXTRA_PROBES_H
/* Include AFTER pvr_observe_probes.h, in one translation unit only.
 * Default OFF. Control/lifecycle wiring deliberately left to the caller.
 * API: pvro_extra_{init,config,start,stop,reset,status,read,exit}; config has
 * the same (tgid, slots, offline_sha256, expected_srcversion) signature as
 * pvro_probes_config. CAP_SYS_ADMIN; control functions are process-context.
 *
 * Evidence: checks/pvr_kernel_extra_hook_findings.json, module PVROP_SHA,
 * ARM64 little endian. RGXSendCommandRaw 0x8b52c:
 * x0=device-info, x1=opaque 112-byte command, x2=optional slot-output.
 * CPU KCCB pointer at dev+0x198; local control at +0x188 (u32 write index,
 * cached read index, wrap mask), shared control at +0x180 (8 raw bytes).
 * The 112 raw input bytes are opaque candidate bytes, not valid-copy length;
 * some commands publish fewer bytes. ENTRY ONLY: neither
 * command publication, selected slot, successful send nor firmware consumption
 * is observed. Do NOT dereference optional slot-output at entry.
 * PMRAcquireKernelMappingData 0x557f4: x0=PMR, x1=offset, x2=size,
 * x3=CPU-pointer-output, x4=mapped-size-output, x5=handle-output; W0=0 success.
 * Outputs are 64-bit on this artifact. Return snapshot is partial PMR content,
 * not a complete PMR, its origin, lifetime, or subsequent firmware consumption.
 * Maps may change concurrently; no atomic/coherent snapshot claim is made.
 *
 * Uses pvrop_ram/copy: only nofault direct-map RAM, rejecting IO/vmap/user
 * addresses. No calls into the vendor driver, MMIO, handler allocation/sleep.
 * All records and kretprobe instance data are preallocated before enable.
 * Identity: exact loaded owner name/srcversion + OFFLINE SHA ATTESTATION, NOT
 * a runtime SHA verification/authentication (same limitations as prior header).
 * Own probes, owning-module reference, mutex, capture lock and loss counters.
 * Stop drains both probes before releasing reference or exposing binary data.
 * Binary: native ARM64 LE fixed records below; version=1. Failed byte copies
 * expose zero data and zero captured length, never partial failed bytes.
 */
#define PVROX_SLOTS 64U
#define PVROX_RAW 112U
#define PVROX_MAP 4096U
#define PVROX_MAXACTIVE 64
#define PVROX_KCCB_ENTRY BIT(8)
#define PVROX_MAP_RETURN BIT(9)
#define PVROX_MAP_FAILED BIT(10)
#define PVROX_PARTIAL BIT(11)

struct pvro_extra_record {
	u32 magic, version, bytes, flags;
	u64 sequence, timestamp_ns, entry_timestamp_ns;
	u32 tgid, tid, kind, return_w0; /* kind: 1 KCCB entry, 2 PMR return */
	u64 object, command_address, optional_slot_output;
	u64 cpu_kccb, primary_control, secondary_control;
	u32 command_captured, primary_captured, secondary_captured, write_index;
	u32 cached_read_index, wrap_mask;
	u8 command[PVROX_RAW], secondary[8];
	u64 offset, requested_size, cpu_output, size_output, handle_output;
	u64 cpu_address, mapped_size, mapping_handle;
	u32 metadata_captured, content_captured;
	u8 content[PVROX_MAP];
};
struct pvro_extra_map_call {
	u64 object, offset, requested_size, cpu_output, size_output, handle_output;
	u64 timestamp_ns;
	u32 tgid, tid;
};
static DEFINE_MUTEX(pvro_extra_control_lock);
static DEFINE_RAW_SPINLOCK(pvro_extra_capture_lock);
static struct pvro_extra_record *pvro_extra_records;
static struct kprobe pvro_extra_command_probe;
static struct kretprobe pvro_extra_map_probe;
static struct module *pvro_extra_owner;
static bool pvro_extra_initialized, pvro_extra_configured, pvro_extra_enabled;
static bool pvro_extra_command_registered, pvro_extra_map_registered;
static u32 pvro_extra_tgid, pvro_extra_slots, pvro_extra_used;
static u64 pvro_extra_sequence;
static char pvro_extra_srcversion[PVROP_SRCVERSION_LEN];
static unsigned long pvro_extra_command_missed, pvro_extra_map_kp_missed;
static unsigned long pvro_extra_return_missed;
static atomic64_t pvro_extra_full = ATOMIC64_INIT(0);
static atomic64_t pvro_extra_busy = ATOMIC64_INIT(0);
static atomic64_t pvro_extra_nmi = ATOMIC64_INIT(0);
static atomic64_t pvro_extra_copy_errors = ATOMIC64_INIT(0);

/* Capture lock held. Buffers have been zeroed at configuration/reset. */
static struct pvro_extra_record *pvro_extra_reserve(u32 kind, u32 tgid, u32 tid)
{
	struct pvro_extra_record *r;
	if (!pvro_extra_enabled)
		return NULL;
	if (pvro_extra_used >= pvro_extra_slots) {
		atomic64_inc(&pvro_extra_full);
		return NULL;
	}
	r = &pvro_extra_records[pvro_extra_used++];
	r->magic = 0x58525650; /* PVRX */
	r->version = 1;
	r->bytes = sizeof(*r);
	r->sequence = ++pvro_extra_sequence;
	r->timestamp_ns = ktime_get_mono_fast_ns();
	r->kind = kind;
	r->tgid = tgid;
	r->tid = tid;
	return r;
}
static void pvro_extra_count_copy(struct pvro_extra_record *r)
{
	if (r->flags & (PVROP_COPY_FAILED | PVROP_NON_RAM))
		atomic64_inc(&pvro_extra_copy_errors);
}
static int pvro_extra_command_entry(struct kprobe *kp, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64) && !defined(CONFIG_CPU_BIG_ENDIAN)
	struct pvro_extra_record *r;
	unsigned long irqflags;
	u8 devptrs[32] = { 0 }, control[12] = { 0 };
	(void)kp;
	if (!READ_ONCE(pvro_extra_enabled) ||
	    (u32)task_tgid_nr(current) != READ_ONCE(pvro_extra_tgid))
		return 0;
	if (in_nmi()) {
		atomic64_inc(&pvro_extra_nmi);
		return 0;
	}
	if (!raw_spin_trylock_irqsave(&pvro_extra_capture_lock, irqflags)) {
		atomic64_inc(&pvro_extra_busy);
		return 0;
	}
	r = pvro_extra_reserve(1, task_tgid_nr(current), task_pid_nr(current));
	if (!r)
		goto out;
	r->flags = PVROX_KCCB_ENTRY;
	r->object = regs->regs[0];
	r->command_address = regs->regs[1];
	r->optional_slot_output = regs->regs[2];
	r->entry_timestamp_ns = r->timestamp_ns;
	if (pvrop_copy(r->command, r->command_address, PVROX_RAW, &r->flags))
		r->command_captured = PVROX_RAW;
	if (r->object > U64_MAX - 0x19f) {
		r->flags |= PVROP_BAD_LAYOUT;
		goto done;
	}
	if (!pvrop_copy(devptrs, r->object + 0x180, sizeof(devptrs), &r->flags))
		goto done;
	r->secondary_control = pvrop_u64(devptrs);
	r->primary_control = pvrop_u64(devptrs + 8);
	r->cpu_kccb = pvrop_u64(devptrs + 24);
	if (pvrop_copy(control, r->primary_control, sizeof(control), &r->flags)) {
		r->primary_captured = sizeof(control);
		r->write_index = pvrop_u32(control);
		r->cached_read_index = pvrop_u32(control + 4);
		r->wrap_mask = pvrop_u32(control + 8);
	}
	if (pvrop_copy(r->secondary, r->secondary_control, sizeof(r->secondary),
		       &r->flags))
		r->secondary_captured = sizeof(r->secondary);
 done:
	pvro_extra_count_copy(r);
 out:
	raw_spin_unlock_irqrestore(&pvro_extra_capture_lock, irqflags);
#endif
	return 0;
}
static int pvro_extra_map_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64) && !defined(CONFIG_CPU_BIG_ENDIAN)
	struct pvro_extra_map_call *c = (void *)ri->data;
	if (!READ_ONCE(pvro_extra_enabled) ||
	    (u32)task_tgid_nr(current) != READ_ONCE(pvro_extra_tgid))
		return 1; /* suppress return handler for unrelated tasks */
	if (in_nmi()) {
		atomic64_inc(&pvro_extra_nmi);
		return 1;
	}
	c->object = regs->regs[0];
	c->offset = regs->regs[1];
	c->requested_size = regs->regs[2];
	c->cpu_output = regs->regs[3];
	c->size_output = regs->regs[4];
	c->handle_output = regs->regs[5];
	c->timestamp_ns = ktime_get_mono_fast_ns();
	c->tgid = task_tgid_nr(current);
	c->tid = task_pid_nr(current);
	return 0;
#else
	return 1;
#endif
}
static int pvro_extra_map_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64) && !defined(CONFIG_CPU_BIG_ENDIAN)
	struct pvro_extra_map_call *c = (void *)ri->data;
	struct pvro_extra_record *r;
	unsigned long irqflags;
	u64 cpu = 0, size = 0, handle = 0;
	u32 n;
	if (!READ_ONCE(pvro_extra_enabled))
		return 0;
	if (in_nmi()) {
		atomic64_inc(&pvro_extra_nmi);
		return 0;
	}
	if (!raw_spin_trylock_irqsave(&pvro_extra_capture_lock, irqflags)) {
		atomic64_inc(&pvro_extra_busy);
		return 0;
	}
	r = pvro_extra_reserve(2, c->tgid, c->tid);
	if (!r)
		goto out;
	r->flags = PVROX_MAP_RETURN | PVROX_PARTIAL;
	r->entry_timestamp_ns = c->timestamp_ns;
	r->object = c->object;
	r->offset = c->offset;
	r->requested_size = c->requested_size;
	r->cpu_output = c->cpu_output;
	r->size_output = c->size_output;
	r->handle_output = c->handle_output;
	r->return_w0 = (u32)regs_return_value(regs);
	if (r->return_w0) {
		r->flags |= PVROX_MAP_FAILED;
		goto done; /* output contents are undefined on failed calls */
	}
	/* Commit metadata only when ALL output reads succeed. */
	if (!pvrop_copy(&cpu, c->cpu_output, sizeof(cpu), &r->flags) ||
	    !pvrop_copy(&size, c->size_output, sizeof(size), &r->flags) ||
	    !pvrop_copy(&handle, c->handle_output, sizeof(handle), &r->flags))
		goto done;
	r->cpu_address = cpu;
	r->mapped_size = size;
	r->mapping_handle = handle;
	r->metadata_captured = 24;
	/* Size==0 request can mean whole PMR: returned mapped size is the bound.
	 * Nonzero request is an additional conservative bound, never enlarge it. */
	n = min_t(u64, size, PVROX_MAP);
	if (c->requested_size)
		n = min_t(u64, n, c->requested_size);
	if (size > n)
		r->flags |= PVROP_BUDGET;
	if (n && pvrop_copy(r->content, cpu, n, &r->flags))
		r->content_captured = n;
 done:
	pvro_extra_count_copy(r);
 out:
	raw_spin_unlock_irqrestore(&pvro_extra_capture_lock, irqflags);
#endif
	return 0;
}
NOKPROBE_SYMBOL(pvro_extra_reserve);
NOKPROBE_SYMBOL(pvro_extra_count_copy);
NOKPROBE_SYMBOL(pvro_extra_command_entry);
NOKPROBE_SYMBOL(pvro_extra_map_entry);
NOKPROBE_SYMBOL(pvro_extra_map_return);

static int __maybe_unused pvro_extra_init(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_extra_control_lock);
	pvro_extra_initialized = true;
	mutex_unlock(&pvro_extra_control_lock);
	return 0;
}
static int __maybe_unused pvro_extra_config(u32 tgid, u32 slots,
		const char *sha, const char *srcversion)
{
	struct pvro_extra_record *records;
	u32 i;
	int ret = 0;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
#if !defined(CONFIG_ARM64) || defined(CONFIG_CPU_BIG_ENDIAN) || \
    !defined(CONFIG_KPROBES) || !defined(CONFIG_KRETPROBES) || !defined(CONFIG_MODULES)
	return -EOPNOTSUPP;
#endif
	if (!tgid || tgid > INT_MAX || !slots || slots > PVROX_SLOTS ||
	    !sha || strcmp(sha, PVROP_SHA) || !srcversion || strlen(srcversion) != 24)
		return -EINVAL;
	for (i = 0; i < 24; i++)
		if (!isxdigit(srcversion[i]))
			return -EINVAL;
	mutex_lock(&pvro_extra_control_lock);
	if (!pvro_extra_initialized) {
		ret = -EINVAL;
		goto out;
	}
	if (pvro_extra_enabled || pvro_extra_command_registered ||
	    pvro_extra_map_registered || pvro_extra_used) {
		ret = -EBUSY;
		goto out;
	}
	/* 64 records consume < 1 MiB; allocation exclusively in process context. */
	records = vzalloc(array_size(slots, sizeof(*records)));
	if (!records) {
		ret = -ENOMEM;
		goto out;
	}
	vfree(pvro_extra_records);
	pvro_extra_records = records;
	pvro_extra_tgid = tgid;
	pvro_extra_slots = slots;
	strscpy(pvro_extra_srcversion, srcversion, sizeof(pvro_extra_srcversion));
	pvro_extra_configured = true;
 out:
	mutex_unlock(&pvro_extra_control_lock);
	return ret;
}
static void pvro_extra_stop_locked(void)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&pvro_extra_capture_lock, flags);
	WRITE_ONCE(pvro_extra_enabled, false);
	raw_spin_unlock_irqrestore(&pvro_extra_capture_lock, flags);
	if (pvro_extra_map_registered) {
		disable_kprobe(&pvro_extra_map_probe.kp);
		unregister_kretprobe(&pvro_extra_map_probe);
		pvro_extra_map_kp_missed += pvro_extra_map_probe.kp.nmissed;
		pvro_extra_return_missed += pvro_extra_map_probe.nmissed;
		pvro_extra_map_registered = false;
	}
	if (pvro_extra_command_registered) {
		disable_kprobe(&pvro_extra_command_probe);
		unregister_kprobe(&pvro_extra_command_probe);
		pvro_extra_command_missed += pvro_extra_command_probe.nmissed;
		pvro_extra_command_registered = false;
	}
	if (pvro_extra_owner) {
		module_put(pvro_extra_owner);
		pvro_extra_owner = NULL;
	}
}
static int __maybe_unused pvro_extra_start(void)
{
	int ret;
#if defined(CONFIG_MODULES)
	struct module *owner, *map_owner;
#endif
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_extra_control_lock);
	if (!pvro_extra_initialized || !pvro_extra_configured) {
		ret = -EINVAL;
		goto out;
	}
	if (pvro_extra_enabled || pvro_extra_command_registered ||
	    pvro_extra_map_registered || pvro_extra_used) {
		ret = -EBUSY;
		goto out;
	}
	memset(&pvro_extra_command_probe, 0, sizeof(pvro_extra_command_probe));
	pvro_extra_command_probe.symbol_name = "pvrsrvkm:RGXSendCommandRaw";
	pvro_extra_command_probe.pre_handler = pvro_extra_command_entry;
	pvro_extra_command_probe.flags = KPROBE_FLAG_DISABLED;
	ret = register_kprobe(&pvro_extra_command_probe);
	if (ret)
		goto out;
	pvro_extra_command_registered = true;
	memset(&pvro_extra_map_probe, 0, sizeof(pvro_extra_map_probe));
	pvro_extra_map_probe.kp.symbol_name = "pvrsrvkm:PMRAcquireKernelMappingData";
	pvro_extra_map_probe.kp.flags = KPROBE_FLAG_DISABLED;
	pvro_extra_map_probe.entry_handler = pvro_extra_map_entry;
	pvro_extra_map_probe.handler = pvro_extra_map_return;
	pvro_extra_map_probe.data_size = sizeof(struct pvro_extra_map_call);
	pvro_extra_map_probe.maxactive = PVROX_MAXACTIVE;
	ret = register_kretprobe(&pvro_extra_map_probe);
	if (ret)
		goto fail;
	pvro_extra_map_registered = true;
#if defined(CONFIG_MODULES)
	preempt_disable();
	owner = __module_address((unsigned long)pvro_extra_command_probe.addr);
	map_owner = __module_address((unsigned long)pvro_extra_map_probe.kp.addr);
	if (owner && owner == map_owner && !strcmp(owner->name, "pvrsrvkm") &&
	    owner->srcversion && !strcmp(owner->srcversion, pvro_extra_srcversion) &&
	    try_module_get(owner))
		pvro_extra_owner = owner;
	preempt_enable();
#endif
	if (!pvro_extra_owner) {
		ret = -ESTALE;
		goto fail;
	}
	WRITE_ONCE(pvro_extra_enabled, true);
	ret = enable_kprobe(&pvro_extra_command_probe);
	if (ret)
		goto fail;
	ret = enable_kprobe(&pvro_extra_map_probe.kp);
	if (!ret)
		goto out;
 fail:
	pvro_extra_stop_locked();
 out:
	mutex_unlock(&pvro_extra_control_lock);
	return ret;
}
static int __maybe_unused pvro_extra_stop(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_extra_control_lock);
	pvro_extra_stop_locked();
	mutex_unlock(&pvro_extra_control_lock);
	return 0;
}
static int __maybe_unused pvro_extra_reset(void)
{
	int ret = 0;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_extra_control_lock);
	if (pvro_extra_enabled || pvro_extra_command_registered || pvro_extra_map_registered) {
		ret = -EBUSY;
		goto out;
	}
	if (pvro_extra_records)
		memset(pvro_extra_records, 0,
		       array_size(pvro_extra_slots, sizeof(*pvro_extra_records)));
	pvro_extra_used = 0;
	pvro_extra_sequence = 0;
	pvro_extra_command_missed = pvro_extra_map_kp_missed = pvro_extra_return_missed = 0;
	atomic64_set(&pvro_extra_full, 0);
	atomic64_set(&pvro_extra_busy, 0);
	atomic64_set(&pvro_extra_nmi, 0);
	atomic64_set(&pvro_extra_copy_errors, 0);
 out:
	mutex_unlock(&pvro_extra_control_lock);
	return ret;
}
static ssize_t __maybe_unused pvro_extra_status(char *out, size_t len)
{
	unsigned long flags;
	u32 used;
	ssize_t ret;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!out || !len)
		return -EINVAL;
	mutex_lock(&pvro_extra_control_lock);
	raw_spin_lock_irqsave(&pvro_extra_capture_lock, flags);
	used = pvro_extra_used;
	raw_spin_unlock_irqrestore(&pvro_extra_capture_lock, flags);
	ret = scnprintf(out, len,
		"configured=%u enabled=%u command_registered=%u map_registered=%u tgid=%u records=%u slots=%u record_bytes=%zu full=%lld busy=%lld nmi=%lld copy_errors=%lld command_missed=%lu map_kprobe_missed=%lu retprobe_maxactive_missed=%lu maxactive=%u scope=KCCB_ENTRY+PMR_MAP_RETURN firmware_consumed=0 publish_success=unobserved pmr_content=partial ram=direct-map-only kernel_sha256_verified=0 identity=kernel-name-srcversion+offline-sha-attestation srcversion=%s\n",
		pvro_extra_configured, pvro_extra_enabled, pvro_extra_command_registered,
		pvro_extra_map_registered, pvro_extra_tgid, used, pvro_extra_slots,
		sizeof(struct pvro_extra_record), atomic64_read(&pvro_extra_full),
		atomic64_read(&pvro_extra_busy), atomic64_read(&pvro_extra_nmi),
		atomic64_read(&pvro_extra_copy_errors),
		pvro_extra_command_missed + (pvro_extra_command_registered ?
			READ_ONCE(pvro_extra_command_probe.nmissed) : 0),
		pvro_extra_map_kp_missed + (pvro_extra_map_registered ?
			READ_ONCE(pvro_extra_map_probe.kp.nmissed) : 0),
		pvro_extra_return_missed + (pvro_extra_map_registered ?
			READ_ONCE(pvro_extra_map_probe.nmissed) : 0),
		PVROX_MAXACTIVE, pvro_extra_srcversion);
	mutex_unlock(&pvro_extra_control_lock);
	return ret;
}
static ssize_t __maybe_unused pvro_extra_read(char __user *out, size_t len,
					    loff_t *offset)
{
	ssize_t ret;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_extra_control_lock);
	if (pvro_extra_enabled || pvro_extra_command_registered || pvro_extra_map_registered)
		ret = -EBUSY;
	else if (!pvro_extra_records)
		ret = 0;
	else
		ret = simple_read_from_buffer(out, len, offset, pvro_extra_records,
				(size_t)pvro_extra_used * sizeof(*pvro_extra_records));
	mutex_unlock(&pvro_extra_control_lock);
	return ret;
}
static void __maybe_unused pvro_extra_exit(void)
{
	mutex_lock(&pvro_extra_control_lock);
	pvro_extra_stop_locked();
	vfree(pvro_extra_records);
	pvro_extra_records = NULL;
	pvro_extra_slots = pvro_extra_used = 0;
	pvro_extra_configured = pvro_extra_initialized = false;
	mutex_unlock(&pvro_extra_control_lock);
}
#endif /* PVR_OBSERVE_EXTRA_PROBES_H */
