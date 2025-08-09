#ifndef COMPAT_H
#define COMPAT_H

#include <linux/compat.h>

typedef struct _COPY_MEMORY32 {
    pid_t pid;
    compat_uptr_t addr;
    compat_uptr_t buffer;
    compat_size_t size;
} COPY_MEMORY32;

typedef struct _MODULE_BASE32 {
    pid_t pid;
    compat_uptr_t name;
    compat_uptr_t base;
} MODULE_BASE32;

long dispatch_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

#endif /* COMPAT_H */
