/* SPDX-License-Identifier: GPL-2.0 */
#include "pvr_observe_probes.h"
#include "pvr_observe_publish.h"
static DEFINE_MUTEX(pvro_probe_api_lock);

static ssize_t pvro_probe_control_read(struct file *file, char __user *data,
				      size_t length, loff_t *offset)
{
	char status[768];
	ssize_t size;
	unsigned long flags;
	mutex_lock(&pvro_probe_api_lock);
	size = pvro_probes_status(status, sizeof(status));
	if (size >= 0) {
		raw_spin_lock_irqsave(&pvrop_capture_lock, flags);
		size += scnprintf(status + size, sizeof(status) - size,
			"publish_registered=%u publish_records=%u publish_lost=%llu publish_scope=after-index-stores-before-barrier\n",
			pvrop_publish_registered, pvrop_publish_used, pvrop_publish_lost);
		raw_spin_unlock_irqrestore(&pvrop_capture_lock, flags);
	}
	mutex_unlock(&pvro_probe_api_lock);
	if (size < 0)
		return size;
	return simple_read_from_buffer(data, length, offset, status, size);
}

static ssize_t pvro_probe_control_write(struct file *file, const char __user *data,
				       size_t length, loff_t *offset)
{
	char command[192], sha[65], srcversion[25], trailing;
	unsigned int pid, slots;
	int result;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!length || length >= sizeof(command))
		return -EINVAL;
	if (copy_from_user(command, data, length))
		return -EFAULT;
	command[length] = 0;
	mutex_lock(&pvro_probe_api_lock);
	if (sysfs_streq(command, "start")) {
		result = pvro_probes_start();
		if (!result) {
			result = pvro_publish_start();
			if (result)
				pvro_probes_stop();
		}
	} else if (sysfs_streq(command, "stop")) {
		pvro_publish_stop();
		result = pvro_probes_stop();
	} else if (sysfs_streq(command, "reset")) {
		result = pvro_probes_reset();
		if (!result) {
			mutex_lock(&pvrop_control_lock);
			pvro_publish_reset();
			mutex_unlock(&pvrop_control_lock);
		}
	}
	else if (sscanf(command, "config %u %u %64s %24s %c", &pid, &slots,
			sha, srcversion, &trailing) == 4)
		result = pvro_probes_config(pid, slots, sha, srcversion);
	else
		result = -EINVAL;
	mutex_unlock(&pvro_probe_api_lock);
	return result ? result : length;
}

static ssize_t pvro_probe_data_read(struct file *file, char __user *data,
				   size_t length, loff_t *offset)
{
	return pvro_probes_read(data, length, offset);
}
static const struct file_operations pvro_probe_control_ops = {
	.read = pvro_probe_control_read, .write = pvro_probe_control_write,
	.llseek = default_llseek,
};
static const struct file_operations pvro_probe_data_ops = {
	.read = pvro_probe_data_read, .llseek = default_llseek,
};
