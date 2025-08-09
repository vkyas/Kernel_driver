#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/mmap_lock.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/pagemap.h>
#include "memory.h"

#define MAX_BATCH 16

static inline bool _access_process_memory(pid_t pid, uintptr_t addr,
                                          void *buffer, size_t size,
                                          bool write)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *pages[MAX_BATCH];
    unsigned long offset, copied = 0;
    int pinned, i;
    void *kaddr;

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (unlikely(!task))
        return false;

    mm = get_task_mm(task);
    if (unlikely(!mm)) {
        put_task_struct(task);
        return false;
    }

    mmap_read_lock(mm);

    while (copied < size) {
        unsigned long len = min_t(size_t, size - copied,
                                  PAGE_SIZE - (addr + copied) % PAGE_SIZE);
        unsigned long start = addr + copied;

        pinned = pin_user_pages_remote(mm, start,
                                       min_t(size_t, MAX_BATCH,
                                             (size - copied + PAGE_SIZE - 1) >> PAGE_SHIFT),
                                       write ? FOLL_WRITE : 0,
                                       pages, NULL, NULL);
        if (unlikely(pinned <= 0))
            goto unlock_fail;

        for (i = 0; i < pinned; i++) {
            offset = start % PAGE_SIZE;
            len = min(len, PAGE_SIZE - offset);

            kaddr = kmap_local_page(pages[i]);
            if (write) {
                if (copy_from_user(kaddr + offset, buffer + copied, len)) {
                    kunmap_local(kaddr);
                    unpin_user_pages_dirty_lock(pages, i + 1, true);
                    goto unlock_fail;
                }
                set_page_dirty_lock(pages[i]);
            } else {
                if (copy_to_user(buffer + copied, kaddr + offset, len)) {
                    kunmap_local(kaddr);
                    unpin_user_pages_dirty_lock(pages, i + 1, false);
                    goto unlock_fail;
                }
            }
            kunmap_local(kaddr);
            start += len;
            copied += len;
            len = min_t(size_t, size - copied, PAGE_SIZE);
        }
        unpin_user_pages_dirty_lock(pages, pinned, write);
    }

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return true;

unlock_fail:
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return false;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    return _access_process_memory(pid, addr, buffer, size, false);
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    return _access_process_memory(pid, addr, buffer, size, true);
}
