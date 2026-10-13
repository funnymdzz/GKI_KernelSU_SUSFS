/* SPDX-License-Identifier: GPL-2.0 */
#define PVRO_OVERFLOW 4U
static bool pvro_indirect_enabled;
static void *pvro_indirect_buffer;
static u32 pvro_indirect_used;
static u64 pvro_indirect_lost, pvro_indirect_unsupported;

struct pvro_span { u16 pointer, count, stride, fixed; };

static void pvro_indirect_span(struct pvro_transaction *tx, const void *input,
			       const struct pvro_span *span)
{
	struct pvro_record record = {
		.magic = 0x4f525650, .version = 3, .phase = span->pointer,
		.sequence = tx->sequence, .timestamp_ns = ktime_get_ns(),
		.tgid = tx->tgid, .tid = tx->tid, .command = PVRO_IOCTL,
		.group = tx->bridge.group, .function = tx->bridge.function,
	};
	u32 count = 1, length;
	u64 requested;
	void *payload;

	memcpy(&record.user_address, (const char *)input + span->pointer, 8);
	if (!span->fixed)
		memcpy(&count, (const char *)input + span->count, 4);
	requested = (u64)count * span->stride;
	record.requested = min_t(u64, requested, U32_MAX);
	length = min_t(u64, requested, PVRO_LIMIT);
	if (requested > U32_MAX)
		record.flags |= PVRO_OVERFLOW;
	if (requested != length)
		record.flags |= PVRO_SHORT;
	if (record.user_address > U64_MAX - requested) {
		record.flags |= PVRO_OVERFLOW;
		length = 0;
	}
	if (PVRO_CAPACITY - pvro_indirect_used < sizeof(record) + length) {
		pvro_indirect_lost++;
		return;
	}
	payload = (char *)pvro_indirect_buffer + pvro_indirect_used + sizeof(record);
	memset(payload, 0, length);
	if (length && copy_from_user(payload,
			(void __user *)(unsigned long)record.user_address, length)) {
		memset(payload, 0, length);
		record.flags |= PVRO_COPY_ERROR;
	} else {
		record.captured = length;
	}
	record.bytes = sizeof(record) + length;
	memcpy((char *)pvro_indirect_buffer + pvro_indirect_used, &record, sizeof(record));
	pvro_indirect_used += record.bytes;
}

static void pvro_capture_indirect(struct pvro_transaction *tx, const void *input,
				 u32 captured, u32 flags)
{
	static const struct pvro_span kick[] = {
		{0x30,0xc8,4,0}, {0x38,0xc8,4,0},
		{0x40,0xcc,4,0}, {0x48,0xcc,4,0},
		{0x50,0xd0,4,0}, {0x58,0xd0,4,0},
		{0x60,0xf4,4,0}, {0x68,0xc0,1,0},
		{0x70,0xc4,1,0}, {0x78,0xf8,1,0},
		{0x80,0,32,1}, {0x88,0,32,1},
		{0x90,0xc8,8,0}, {0x98,0xcc,8,0},
		{0xa0,0xd0,8,0}, {0xa8,0xf4,8,0},
	};
	static const struct pvro_span context[] = {
		{0x10,0x30,1,0}, {0x18,0x34,1,0}, {0x20,0x38,1,0},
	};
	static const struct pvro_span pmr_create[] = {
		{0x08,0x24,4,0}, {0x10,0x18,1,0},
	};
	static const struct pvro_span sparse[] = {
		{0x08,0x18,4,0}, {0x10,0x1c,4,0},
	};
	const struct pvro_span *spans;
	u32 expected, nr, i;

	if (tx->bridge.group == 130 && tx->bridge.function == 10) {
		spans = kick; nr = ARRAY_SIZE(kick); expected = 256;
	} else if (tx->bridge.group == 130 && tx->bridge.function == 13) {
		spans = context; nr = ARRAY_SIZE(context); expected = 72;
	} else if (tx->bridge.group == 6 && tx->bridge.function == 8) {
		spans = pmr_create; nr = ARRAY_SIZE(pmr_create); expected = 56;
	} else if (tx->bridge.group == 6 && tx->bridge.function == 18) {
		spans = sparse; nr = ARRAY_SIZE(sparse); expected = 36;
	} else {
		pvro_indirect_unsupported++;
		return;
	}
	if (flags || captured != expected || tx->bridge.input_size != expected) {
		pvro_indirect_lost++;
		return;
	}
	for (i = 0; i < nr; i++)
		pvro_indirect_span(tx, input, &spans[i]);
}

static ssize_t pvro_indirect_read(struct file *file, char __user *data,
				 size_t length, loff_t *offset)
{
	ssize_t result;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_lock);
	if (pvro_enabled || pvro_active)
		result = -EBUSY;
	else
		result = simple_read_from_buffer(data, length, offset,
				pvro_indirect_buffer, pvro_indirect_used);
	mutex_unlock(&pvro_lock);
	return result;
}
static const struct file_operations pvro_indirect_ops = {
	.read = pvro_indirect_read, .llseek = default_llseek,
};
