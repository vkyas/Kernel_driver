#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/mmap_lock.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include "memory.h"

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
  struct task_struct *task;
  struct mm_struct *mm;
  struct page *page;
  void *kaddr;
  unsigned long offset;
  bool result = false;

  task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
  if (!task) return false;

  mm = get_task_mm(task);
  if (!mm) {
    put_task_struct(task);
    return false;
  }

  mmap_read_lock(mm);

  if (pin_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL, NULL) <= 0) {
    goto unlock_and_release;
  }

  offset = addr & (PAGE_SIZE - 1);
  if (size > PAGE_SIZE - offset) {
    size = PAGE_SIZE - offset;
  }

  kaddr = kmap_local_page(page);
  if (copy_to_user(buffer, kaddr + offset, size) == 0) {
    result = true;
  }

  kunmap_local(kaddr);
  unpin_user_page(page);

unlock_and_release:
  mmap_read_unlock(mm);
  mmput(mm);
  put_task_struct(task);

  return result;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
  struct task_struct *task;
  struct mm_struct *mm;
  struct page *page;
  void *kaddr;
  unsigned long offset;
  bool result = false;

  task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
  if (!task) return false;

  mm = get_task_mm(task);
  if (!mm) {
    put_task_struct(task);
    return false;
  }

  mmap_read_lock(mm);

  if (pin_user_pages_remote(mm, addr, 1, FOLL_WRITE | FOLL_FORCE, &page, NULL, NULL) <= 0) {
    goto unlock_and_release_write;
  }

  offset = addr & (PAGE_SIZE - 1);
  if (size > PAGE_SIZE - offset) {
    size = PAGE_SIZE - offset;
  }

  kaddr = kmap_local_page(page);
  if (copy_from_user(kaddr + offset, buffer, size) == 0) {
    set_page_dirty(page);
    result = true;
  }

  kunmap_local(kaddr);
  unpin_user_page(page);

unlock_and_release_write:
  mmap_read_unlock(mm);
  mmput(mm);
  put_task_struct(task);

  return result;
}
