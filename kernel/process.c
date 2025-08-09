#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/mmap_lock.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/jhash.h>
#include "process.h"

#define ARC_PATH_MAX 256

static inline u32 fast_hash(const char *s)
{
    u32 h = 2166136261u;
    while (*s) {
        h ^= (u8)(*s++);
        h *= 16777619u;
    }
    return h;
}

uintptr_t get_module_base(pid_t pid, char *name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    char buf[ARC_PATH_MAX];
    char *path_nm, *base_name;
    const u32 target_hash = fast_hash(name);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (unlikely(!task)) {
        rcu_read_unlock();
        return 0;
    }

    mm = get_task_mm(task);
    if (unlikely(!mm)) {
        rcu_read_unlock();
        return 0;
    }
    rcu_read_unlock();

    mmap_read_lock(mm);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
            path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf));
            if (unlikely(IS_ERR(path_nm)))
                continue;

            base_name = strrchr(path_nm, '/');
            base_name = base_name ? base_name + 1 : path_nm;

            if (fast_hash(base_name) == target_hash &&
                !strcmp(base_name, name)) {
                base_addr = vma->vm_start;
                break;
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    return base_addr;
}
