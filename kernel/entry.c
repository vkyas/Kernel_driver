#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "verify.h"
#include "hide_pid.h"

#define DEVICE_NAME "kamid"

static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

static long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg)
{
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char key[0x100] = {0};
    char name[0x100] = {0};
    pid_t target_pid;
    static bool is_verified = false;
    int result = 0;

    if (cmd == OP_INIT_KEY && !is_verified) {
        if (copy_from_user(key, (void __user*)arg, sizeof(key)-1) != 0) {
            return -EFAULT;
        }
        is_verified = init_key(key, sizeof(key));
        if (is_verified == false) {
            return -EACCES;
        }
        return 0;
    }

    if (!is_verified) {
        return -EACCES;
    }

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            return -EFAULT;
        }
        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
            return -EIO;
        }
        break;

    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
            return -EFAULT;
        }
        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
            return -EIO;
        }
        break;

    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0) {
            return -EFAULT;
        }
        if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) != 0) {
            return -EFAULT;
        }
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) != 0) {
            return -EFAULT;
        }
        break;

    case OP_HIDE_PID:
        if (copy_from_user(&target_pid, (void __user*)arg, sizeof(target_pid)) != 0) {
            return -EFAULT;
        }
        result = hide_process(target_pid);
        if (result < 0) {
            return result;
        }
        break;

    case OP_RED_PID:
        if (copy_from_user(&target_pid, (void __user*)arg, sizeof(target_pid)) != 0) {
            return -EFAULT;
        }
        result = restore_process(target_pid);
        if (result < 0) {
            return result;
        }
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

static int __init driver_entry(void)
{
    int ret;
    ret = misc_register(&misc);
    return ret;
}

static void __exit driver_unload(void)
{
    hide_cleanup();
    misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamid");
MODULE_VERSION("1.0");
