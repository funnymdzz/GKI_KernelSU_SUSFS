#ifndef PVR_OBSERVE_H
#define PVR_OBSERVE_H

struct pvro_transaction;
#ifdef CONFIG_DEBUG_FS
struct pvro_transaction *pvro_begin(struct file *file, unsigned int cmd,
				   unsigned long arg);
void pvro_end(struct pvro_transaction *transaction, long result);
#else
static inline struct pvro_transaction *pvro_begin(struct file *file,
		unsigned int cmd, unsigned long arg)
{
	return NULL;
}
static inline void pvro_end(struct pvro_transaction *transaction, long result)
{
}
#endif
#endif
