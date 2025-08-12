#include <linux/slab.h>
#include "comm.h"
#include "compat.h"
#include "memory.h"
#include "process.h"

extern bool is_driver_verified(void);

long dispatch_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    if (cmd != OP_INIT_KEY && !is_driver_verified()) {
        return -EPERM;
    }
    switch (cmd) {
        case OP_INIT_KEY: {
            return filp->f_op->unlocked_ioctl(filp, cmd, arg);
        }
        case OP_READ_MEM: {
            COPY_MEMORY32 __user *p32 = compat_ptr(arg);
            COPY_MEMORY cm64 = {0};
            compat_uptr_t buffer_ptr32;
            if (get_user(cm64.pid, &p32->pid) ||
                get_user(cm64.addr, &p32->addr) ||
                get_user(cm64.size, &p32->size))
                return -EFAULT;
            if (get_user(buffer_ptr32, &p32->buffer)) return -EFAULT;
            cm64.buffer = compat_ptr(buffer_ptr32);
            
            if (!read_process_memory(cm64.pid, cm64.addr, cm64.buffer, cm64.size)) return -EFAULT;
            break;
        }
        case OP_WRITE_MEM: {
            COPY_MEMORY32 __user *p32 = compat_ptr(arg);
            COPY_MEMORY cm64 = {0};
            compat_uptr_t buffer_ptr32;
            if (get_user(cm64.pid, &p32->pid) ||
                get_user(cm64.addr, &p32->addr) ||
                get_user(cm64.size, &p32->size))
                return -EFAULT;
            
            if (get_user(buffer_ptr32, &p32->buffer)) return -EFAULT;
            cm64.buffer = compat_ptr(buffer_ptr32);
            if (!write_process_memory(cm64.pid, cm64.addr, cm64.buffer, cm64.size)) return -EFAULT;
            break;
        }
        case OP_MODULE_BASE: {
            MODULE_BASE32 __user *p32 = compat_ptr(arg);
            MODULE_BASE mb64 = {0};
            compat_uptr_t name_ptr32;
            char name_buffer[256] = {0};
            if (get_user(mb64.pid, &p32->pid)) return -EFAULT;
            if (get_user(name_ptr32, &p32->name)) return -EFAULT;
            mb64.name = compat_ptr(name_ptr32);
            if (copy_from_user(name_buffer, mb64.name, sizeof(name_buffer) - 1) != 0) return -EFAULT;
            name_buffer[sizeof(name_buffer) - 1] = '\0';
            mb64.base = get_module_base(mb64.pid, name_buffer);
            if (put_user(mb64.base, &p32->base)) return -EFAULT;
            break;
        }
        default:
            return -EINVAL;
    }
    return 0;
}