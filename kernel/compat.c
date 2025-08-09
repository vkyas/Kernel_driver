#include <linux/slab.h>
#include <linux/uaccess.h>
#include "comm.h"
#include "compat.h"
#include "memory.h"
#include "process.h"

extern bool is_driver_verified(void);
extern long handle_module_base(unsigned long arg);

#define COPY_CHUNK 256

long dispatch_compat_ioctl(struct file *filp, unsigned int cmd,
                           unsigned long arg)
{
    if (cmd != OP_INIT_KEY && !is_driver_verified())
        return -EPERM;

    switch (cmd) {
    case OP_INIT_KEY:
        return filp->f_op->unlocked_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));

    case OP_READ_MEM: {
        COPY_MEMORY32 cm32;
        COPY_MEMORY cm64;

        if (copy_from_user(&cm32, compat_ptr(arg), sizeof(cm32)))
            return -EFAULT;
        cm64.pid   = cm32.pid;
        cm64.addr  = cm32.addr;
        cm64.size  = cm32.size;
        cm64.buffer = compat_ptr(cm32.buffer);

        return read_process_memory(cm64.pid, cm64.addr, cm64.buffer, cm64.size) ? 0 : -EFAULT;
    }

    case OP_WRITE_MEM: {
        COPY_MEMORY32 cm32;
        COPY_MEMORY cm64;

        if (copy_from_user(&cm32, compat_ptr(arg), sizeof(cm32)))
            return -EFAULT;
        cm64.pid   = cm32.pid;
        cm64.addr  = cm32.addr;
        cm64.size  = cm32.size;
        cm64.buffer = compat_ptr(cm32.buffer);

        return write_process_memory(cm64.pid, cm64.addr, cm64.buffer, cm64.size) ? 0 : -EFAULT;
    }

    case OP_MODULE_BASE: {
        MODULE_BASE32 mb32;
        MODULE_BASE mb64;
        char name[256];

        if (copy_from_user(&mb32, compat_ptr(arg), sizeof(mb32)))
            return -EFAULT;

        mb64.pid  = mb32.pid;
        mb64.name = compat_ptr(mb32.name);

        if (strncpy_from_user(name, mb64.name, sizeof(name) - 1) < 0)
            return -EFAULT;
        name[sizeof(name) - 1] = '\0';

        mb64.base = get_module_base(mb64.pid, name);

        if (put_user(mb64.base, &((MODULE_BASE32 __user *)compat_ptr(arg))->base))
            return -EFAULT;
        return 0;
    }

    default:
        return -EINVAL;
    }
}
