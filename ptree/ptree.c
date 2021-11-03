#define pr_fmt(fmt) "%s:%s: " fmt "\n", KBUILD_MODNAME, __func__

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid_namespace.h> /* remove after we're in-tree */

#include <linux/ptree.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Trugman & Chen Glayher");
MODULE_DESCRIPTION("HW1");

struct task_struct* get_task(int pid)
{
    if (pid == 0)
        return &init_task;

    return pid_task(find_vpid(pid), PIDTYPE_PID);
}

void fill_info(int level, const struct task_struct *task, struct prinfo *buf)
{
	buf->parent_pid = task_ppid_nr(task);
	buf->pid = task->tgid;
	buf->state = task->state;
	buf->uid = task_uid(task).val;
	strncpy(buf->comm, task->comm, sizeof(buf->comm));
	buf->level = level;
}

int fill_children(struct prinfo *buf, int nr, int self, int next)
{
    struct task_struct *parent;
    struct task_struct *child;
    struct prinfo *parent_info;

    parent_info = &buf[self];
    parent = get_task(parent_info->pid);

    list_for_each_entry(child, &parent->children, sibling) {
        if (next == nr)
            return -ENOMEM;

        fill_info(parent_info->level + 1, child, &buf[next]);
        ++next;
    }

    return next;
}

int __get_ptree(struct prinfo *buf, int nr, int pid)
{
    int rv;
    int curr;
    int total;
    struct task_struct *root;

    curr = 0;
    total = 1;

    root = get_task(pid);
    if (!root)
        return -EINVAL;

    fill_info(curr, root, &buf[curr]);

    while (curr < total) {
        rv = fill_children(buf, nr, curr, total);
        if (rv < 0)
            return rv;

        curr += 1;
        total = rv;
    }

    return total;
}

int get_ptree(struct prinfo *buf, int *nr, int pid)
{
    int rv;

    if (buf == NULL || nr == NULL || *nr == 0)
        return -EINVAL;

    rcu_read_lock();
    rv = __get_ptree(buf, *nr, pid);
    rcu_read_unlock();
    if (rv < 0)
        return rv;

    *nr = rv;
    return 0;
}

static int __init ptree_init(void)
{
    return register_ptree(get_ptree);
}

static void __exit ptree_cleanup(void)
{
    unregister_ptree(get_ptree);
}

module_init(ptree_init);
module_exit(ptree_cleanup);
