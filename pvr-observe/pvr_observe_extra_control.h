/* SPDX-License-Identifier: GPL-2.0 */
#include "pvr_observe_extra_probes.h"
static ssize_t pvro_extra_control_read(struct file *file, char __user *data,
				      size_t length, loff_t *offset)
{
	char status[768];
	ssize_t size = pvro_extra_status(status, sizeof(status));
	if (size < 0) return size;
	return simple_read_from_buffer(data, length, offset, status, size);
}
static ssize_t pvro_extra_control_write(struct file *file, const char __user *data,
				       size_t length, loff_t *offset)
{
	char command[192], sha[65], srcversion[25], trailing;
	unsigned int pid, slots;
	int result;
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	if (!length || length >= sizeof(command)) return -EINVAL;
	if (copy_from_user(command, data, length)) return -EFAULT;
	command[length] = 0;
	if (sysfs_streq(command, "start")) result = pvro_extra_start();
	else if (sysfs_streq(command, "stop")) result = pvro_extra_stop();
	else if (sysfs_streq(command, "reset")) result = pvro_extra_reset();
	else if (sscanf(command, "config %u %u %64s %24s %c", &pid, &slots,
			sha, srcversion, &trailing) == 4)
		result = pvro_extra_config(pid, slots, sha, srcversion);
	else result = -EINVAL;
	return result ? result : length;
}
static ssize_t pvro_extra_data_read(struct file *file, char __user *data,
				   size_t length, loff_t *offset)
{
	return pvro_extra_read(data, length, offset);
}
static const struct file_operations pvro_extra_control_ops = {
	.read = pvro_extra_control_read, .write = pvro_extra_control_write,
	.llseek = default_llseek,
};
static const struct file_operations pvro_extra_data_ops = {
	.read = pvro_extra_data_read, .llseek = default_llseek,
};
