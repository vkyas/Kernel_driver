#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/capability.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "compat.h"

#define DEVICE_NAME "kamid"

static const char g_secret_key[] = "O4K48z4LOz7WwslW";
static __read_mostly bool g_is_verified;

bool is_driver_verified(void)
{
    return smp_load_acquire(&g_is_verified);
}

int dispatch_open(struct inode *node, struct file *file) { return 0; }
int dispatch_close(struct inode *node, struct file *file) { return 0; }

static long handle_module_base(unsigned long arg)
{
    MODULE_BASE mb;
    char name_buffer[256];

    if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
        return -EFAULT;
    if (strncpy_from_user(name_buffer, (void __user *)mb.name,
                          sizeof(name_buffer) - 1) < 0)
        return -EFAULT;
    name_buffer[sizeof(name_buffer) - 1] = '\0';

    mb.base = get_module_base(mb.pid, name_buffer);
    if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
        return -EFAULT;
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd,
                    unsigned long const arg)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    if (cmd != OP_INIT_KEY && !is_driver_verified())
        return -EPERM;

    switch (cmd) {
    case OP_INIT_KEY: {
        char user_key[sizeof(g_secret_key)];
        if (copy_from_user(user_key, (void __user *)arg, sizeof(user_key)))
            return -EFAULT;

        bool ok = !memcmp(user_key, g_secret_key, sizeof(g_secret_key));
        smp_store_release(&g_is_verified, ok);
        return ok ? 0 : -EACCES;
    }
    case OP_READ_MEM: {
        COPY_MEMORY cm;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        return read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
    }
    case OP_WRITE_MEM: {
        COPY_MEMORY cm;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        return write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
    }
    case OP_MODULE_BASE:
        return handle_module_base(arg);
    default:
        return -EINVAL;
    }
}

static const struct file_operations dispatch_functions = {
    .owner          = THIS_MODULE,
    .open           = dispatch_open,
    .release        = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
    .compat_ioctl   = dispatch_compat_ioctl,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &dispatch_functions,
};

static int __init driver_entry(void)
{
    int ret = misc_register(&misc);
    if (ret)
        pr_err("kamid: misc_register failed %d\n", ret);
    else
        pr_info("kamid: loaded /dev/%s\n", DEVICE_NAME);
    return ret;
}

static void __exit driver_unload(void)
{
    misc_deregister(&misc);
    pr_info("kamid: unloaded\n");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("High-performance secure memory driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamid");
