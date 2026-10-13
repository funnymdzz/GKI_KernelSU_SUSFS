/* SPDX-License-Identifier: GPL-2.0 */
/* Exact pinned arm64 module: RGXSendCommandRaw+0x230, after write-index stores. */
struct pvro_publish_record {
	u32 magic, version, bytes, flags;
	u64 sequence, timestamp_ns, slot_address, shared_control, local_control;
	u32 tgid, tid, old_slot, new_slot, requested, captured;
	u32 shared_write, local_write;
	u8 command[112];
};
static struct pvro_publish_record *pvrop_publish_buffer;
static u32 pvrop_publish_used;
static u64 pvrop_publish_lost;
static struct kprobe pvrop_publish_probe;
static bool pvrop_publish_registered;
static u32 pvrop_valid_command_bytes(u32 type)
{
	switch (type) {
	case 0x2abc0065: return 36;
	case 0x2abc0066: case 0x2abc0073: case 0x2abc00c8: case 0x2abc012d: return 20;
	case 0x2abc0068: return 32;
	case 0x2abc0069: case 0x2abc006a: case 0x2abc006b: case 0x2abc006e:
	case 0x2abc0070: case 0x2abc0072: return 16;
	case 0x2abc006c: case 0x2abc0074: case 0x2abc012c: return 24;
	case 0x2abc006d: return 112;
	case 0x2abc0071: return 64;
	case 0x2abc00ca: case 0x2abc00cb: return 12;
	case 0x2abc006f: case 0x2abc00cd: case 0x2abc00ce: case 0x2abc00d2:
	case 0x2abc00d5: case 0x2abc00d6: case 0x2abc00d7: case 0x2abc012f: return 8;
	case 0x2abc012e: return 52;
	default: return 0;
	}
}
static int pvrop_publish_entry(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct pvro_publish_record *r;
	unsigned long irqflags;
	u32 type = 0;
	if (!READ_ONCE(pvrop_enabled) || task_tgid_nr(current) != pvrop_tgid)
		return 0;
	if (in_nmi() || !raw_spin_trylock_irqsave(&pvrop_capture_lock, irqflags)) {
		atomic64_inc(&pvrop_busy);
		return 0;
	}
	if (!pvrop_enabled)
		goto out;
	if (pvrop_publish_used == PVROP_SLOTS) {
		pvrop_publish_lost++;
		goto out;
	}
	r = &pvrop_publish_buffer[pvrop_publish_used++];
	r->magic = 0x50554250; r->version = 1; r->bytes = sizeof(*r);
	r->sequence = ++pvrop_sequence; r->timestamp_ns = ktime_get_mono_fast_ns();
	r->tgid = task_tgid_nr(current); r->tid = task_pid_nr(current);
	r->slot_address = regs->regs[22]; r->shared_control = regs->regs[20];
	r->local_control = regs->regs[24]; r->old_slot = (u32)regs->regs[26];
	r->new_slot = (u32)regs->regs[27];
	if (!pvrop_copy(&type, r->slot_address, 4, &r->flags))
		goto out;
	r->requested = pvrop_valid_command_bytes(type);
	if (!r->requested) { r->flags |= PVROP_BAD_LAYOUT; goto out; }
	if (pvrop_copy(r->command, r->slot_address, r->requested, &r->flags))
		r->captured = r->requested;
	pvrop_copy(&r->shared_write, r->shared_control, 4, &r->flags);
	pvrop_copy(&r->local_write, r->local_control, 4, &r->flags);
	if (r->shared_write != r->new_slot || r->local_write != r->new_slot)
		r->flags |= PVROP_BAD_LAYOUT;
 out:
	raw_spin_unlock_irqrestore(&pvrop_capture_lock, irqflags);
#endif
	return 0;
}
NOKPROBE_SYMBOL(pvrop_publish_entry);
NOKPROBE_SYMBOL(pvrop_valid_command_bytes);

static int pvro_publish_start(void)
{
	int result;
	struct module *owner;
	if (!pvrop_registered || !pvrop_owner || pvrop_publish_used)
		return -EBUSY;
	if (!pvrop_publish_buffer)
		pvrop_publish_buffer = vzalloc(PVROP_SLOTS * sizeof(*pvrop_publish_buffer));
	if (!pvrop_publish_buffer)
		return -ENOMEM;
	memset(&pvrop_publish_probe, 0, sizeof(pvrop_publish_probe));
	pvrop_publish_probe.symbol_name = "pvrsrvkm:RGXSendCommandRaw";
	pvrop_publish_probe.offset = 0x230;
	pvrop_publish_probe.pre_handler = pvrop_publish_entry;
	pvrop_publish_probe.flags = KPROBE_FLAG_DISABLED;
	result = register_kprobe(&pvrop_publish_probe);
	if (result)
		return result;
	preempt_disable();
	owner = __module_address((unsigned long)pvrop_publish_probe.addr);
	preempt_enable();
	if (owner != pvrop_owner) {
		unregister_kprobe(&pvrop_publish_probe);
		return -ESTALE;
	}
	result = enable_kprobe(&pvrop_publish_probe);
	if (result) {
		unregister_kprobe(&pvrop_publish_probe);
		return result;
	}
	pvrop_publish_registered = true;
	return 0;
}
static void pvro_publish_stop(void)
{
	if (pvrop_publish_registered) {
		unregister_kprobe(&pvrop_publish_probe);
		pvrop_publish_lost += pvrop_publish_probe.nmissed;
		pvrop_publish_registered = false;
	}
}
static void pvro_publish_reset(void)
{
	if (pvrop_publish_buffer)
		memset(pvrop_publish_buffer, 0, PVROP_SLOTS * sizeof(*pvrop_publish_buffer));
	pvrop_publish_used = 0; pvrop_publish_lost = 0;
}
static ssize_t pvro_publish_read(struct file *file, char __user *data,
				 size_t length, loff_t *offset)
{
	ssize_t result;
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	mutex_lock(&pvrop_control_lock);
	if (pvrop_registered || pvrop_publish_registered)
		result = -EBUSY;
	else
		result = simple_read_from_buffer(data, length, offset, pvrop_publish_buffer,
			pvrop_publish_used * sizeof(*pvrop_publish_buffer));
	mutex_unlock(&pvrop_control_lock);
	return result;
}
static const struct file_operations pvro_publish_ops = {
	.read = pvro_publish_read, .llseek = default_llseek,
};
