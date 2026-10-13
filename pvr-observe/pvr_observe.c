// SPDX-License-Identifier: GPL-2.0
#include <linux/capability.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "pvr_observe.h"

#define PVRO_CAPACITY (16U * 1024U * 1024U)
#define PVRO_LIMIT (64U * 1024U)
#define PVRO_IOCTL 0xc0206440U
#define PVRO_SHORT 1U
#define PVRO_COPY_ERROR 2U

struct pvro_bridge {
	u32 group, function;
	u64 input, output;
	u32 input_size, output_size;
};

struct pvro_record {
	u32 magic, version, bytes, phase;
	u64 sequence, timestamp_ns, user_address;
	s64 result;
	u32 tgid, tid, command, group, function, requested, captured, flags;
};

struct pvro_transaction {
	struct pvro_bridge bridge;
	u64 sequence;
	u32 tgid, tid;
};

static DEFINE_MUTEX(pvro_lock);
static void *pvro_buffer;
static u32 pvro_used, pvro_active;
static u64 pvro_sequence, pvro_lost;
static unsigned int pvro_pid, pvro_major, pvro_minor;
static bool pvro_enabled;

static void pvro_append(struct pvro_transaction *tx, u32 phase, long result)
{
	struct pvro_record record = {
		.magic = 0x4f525650, .version = 1, .phase = phase,
		.sequence = tx->sequence, .timestamp_ns = ktime_get_ns(),
		.result = result, .tgid = tx->tgid, .tid = tx->tid,
		.command = PVRO_IOCTL, .group = tx->bridge.group,
		.function = tx->bridge.function,
		.user_address = phase ? tx->bridge.output : tx->bridge.input,
		.requested = phase ? tx->bridge.output_size : tx->bridge.input_size,
	};
	u32 length = min(record.requested, PVRO_LIMIT);
	void *payload;

	if (length != record.requested)
		record.flags |= PVRO_SHORT;
	if (PVRO_CAPACITY - pvro_used < sizeof(record) + length) {
		pvro_lost++;
		return;
	}
	payload = (char *)pvro_buffer + pvro_used + sizeof(record);
	memset(payload, 0, length);
	if (length && copy_from_user(payload,
			(void __user *)(unsigned long)record.user_address, length)) {
		memset(payload, 0, length);
		record.flags |= PVRO_COPY_ERROR;
	} else {
		record.captured = length;
	}
	record.bytes = sizeof(record) + length;
	memcpy((char *)pvro_buffer + pvro_used, &record, sizeof(record));
	pvro_used += record.bytes;
}

struct pvro_transaction *pvro_begin(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct pvro_transaction *tx = NULL;
	dev_t device;

	if (!READ_ONCE(pvro_enabled) || cmd != PVRO_IOCTL ||
	    !S_ISCHR(file_inode(file)->i_mode))
		return NULL;
	device = file_inode(file)->i_rdev;
	mutex_lock(&pvro_lock);
	if (!pvro_enabled || task_tgid_nr(current) != pvro_pid ||
	    MAJOR(device) != pvro_major || MINOR(device) != pvro_minor)
		goto out;
	tx = kzalloc(sizeof(*tx), GFP_KERNEL);
	if (!tx) {
		pvro_lost++;
		goto out;
	}
	if (copy_from_user(&tx->bridge, (void __user *)arg, sizeof(tx->bridge))) {
		pvro_lost++;
		kfree(tx);
		tx = NULL;
		goto out;
	}
	tx->tgid = task_tgid_nr(current);
	tx->tid = task_pid_nr(current);
	tx->sequence = ++pvro_sequence;
	pvro_active++;
	pvro_append(tx, 0, 0);
 out:
	mutex_unlock(&pvro_lock);
	return tx;
}

void pvro_end(struct pvro_transaction *tx, long result)
{
	if (!tx)
		return;
	mutex_lock(&pvro_lock);
	pvro_append(tx, 1, result);
	pvro_active--;
	mutex_unlock(&pvro_lock);
	kfree(tx);
}

static ssize_t pvro_control_read(struct file *file, char __user *data,
				size_t length, loff_t *offset)
{
	char status[256];
	int size;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pvro_lock);
	size = scnprintf(status, sizeof(status),
		"enabled=%u pid=%u major=%u minor=%u bytes=%u active=%u lost=%llu limit=%u capacity=%u abi=lp64-drm32\n",
		pvro_enabled, pvro_pid, pvro_major, pvro_minor, pvro_used,
		pvro_active, pvro_lost, PVRO_LIMIT, PVRO_CAPACITY);
	mutex_unlock(&pvro_lock);
	return simple_read_from_buffer(data, length, offset, status, size);
}

static ssize_t pvro_control_write(struct file *file, const char __user *data,
				 size_t length, loff_t *offset)
{
	char command[96], trailing;
	unsigned int pid, major, minor;
	ssize_t result = length;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!length || length >= sizeof(command))
		return -EINVAL;
	if (copy_from_user(command, data, length))
		return -EFAULT;
	command[length] = 0;
	mutex_lock(&pvro_lock);
	if (sysfs_streq(command, "stop")) {
		WRITE_ONCE(pvro_enabled, false);
	} else if (sysfs_streq(command, "reset")) {
		if (pvro_enabled || pvro_active) {
			result = -EBUSY;
		} else {
			pvro_used = 0;
			pvro_lost = 0;
		}
	} else if (sscanf(command, "start %u %u %u %c", &pid, &major, &minor,
			  &trailing) == 3 && pid && major &&
		   MAJOR(MKDEV(major, minor)) == major &&
		   MINOR(MKDEV(major, minor)) == minor) {
		if (pvro_enabled || pvro_active) {
			result = -EBUSY;
			goto out;
		}
		if (!pvro_buffer)
			pvro_buffer = vzalloc(PVRO_CAPACITY);
		if (!pvro_buffer) {
			result = -ENOMEM;
			goto out;
		}
		pvro_pid = pid;
		pvro_major = major;
		pvro_minor = minor;
		WRITE_ONCE(pvro_enabled, true);
	} else {
		result = -EINVAL;
	}
 out:
	mutex_unlock(&pvro_lock);
	return result;
}

static ssize_t pvro_data_read(struct file *file, char __user *data,
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
						pvro_buffer, pvro_used);
	mutex_unlock(&pvro_lock);
	return result;
}

static const struct file_operations pvro_control_ops = {
	.read = pvro_control_read,
	.write = pvro_control_write,
	.llseek = default_llseek,
};
static const struct file_operations pvro_data_ops = {
	.read = pvro_data_read,
	.llseek = default_llseek,
};

static int __init pvro_init(void)
{
	struct dentry *directory = debugfs_create_dir("pvr_observe", NULL);

	if (IS_ERR_OR_NULL(directory))
		return 0;
	debugfs_create_file("control", 0600, directory, NULL, &pvro_control_ops);
	debugfs_create_file("records", 0400, directory, NULL, &pvro_data_ops);
	return 0;
}
late_initcall(pvro_init);
