#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/ptree.h>

static const char *PTREE_MODULE_NAME = "ptree";

DEFINE_SPINLOCK(ptree_lock);
static ptree_func ptree_fp = NULL;

static ptree_func try_get_ptree_once(void)
{
    ptree_func fp = NULL;

    spin_lock(&ptree_lock);
    if (ptree_fp) {
        struct module* module = find_module(PTREE_MODULE_NAME);
        if (module && try_module_get(module))
            fp = ptree_fp;
    }
    spin_unlock(&ptree_lock);

    return fp;
}

static ptree_func try_get_ptree(void)
{
    ptree_func fp = try_get_ptree_once();
    if (fp)
        return fp;

    if (request_module(PTREE_MODULE_NAME))
        return NULL;

    return try_get_ptree_once();
}

static void put_ptree(void)
{
    spin_lock(&ptree_lock);
    if (ptree_fp) {
        struct module* module = find_module(PTREE_MODULE_NAME);
        if (module)
            module_put(module);
    }
    spin_unlock(&ptree_lock);
}

/**
 * ptree() - Return process tree under specified pid
 *
 * @buf:   an array of prinfo structs to contain the process tree
 * @nr:    the length of the buf array
 * @pid:   pid for which to retrieve the process tree
 *
 * This syscall collects information about the process tree running under
 * the specified pid and returns an array that describes it.
 *
 * Return: On success, the buffer is filled with the process tree
 *         information, and the return value is 0.
 *         On error, a negative errno number will be returned.
 */
SYSCALL_DEFINE3(ptree, struct prinfo __user *, buf, int __user *, nr, int, pid)
{
    ptree_func fp;

    struct prinfo *kbuf = NULL;
    int knr;

    int rv;

    if (get_user(knr, nr)) {
        pr_err("get_user failed");
        rv = -EFAULT;
        goto out;
    }

	if (pid <= 0) {
        pr_err("negative pid");
		rv = -EINVAL;
        goto out;
    }

    kbuf = kmalloc(knr * sizeof(*kbuf), GFP_KERNEL);
    if (!kbuf) {
        pr_err("kmalloc failed");
        rv = -ENOMEM;
        goto out;
    }

    fp = try_get_ptree();
    if (!fp) {
        pr_err("try_get_ptree failed");
        rv = -ENOSYS;
        goto out;
    }

    rv = fp(kbuf, &knr, pid);

    put_ptree();

    if (rv) // Don't report errors here, these can expected
        goto out;

    if (copy_to_user(buf, kbuf, knr * sizeof(*kbuf))) {
        pr_err("copy_to_user failed");
        rv = -EFAULT;
        goto out;
    }

    if (put_user(knr, nr)) {
        pr_err("put_user failed");
        rv = -EFAULT;
        goto out;
    }

    rv = 0;

out:
    if (kbuf)
        kfree(kbuf);

	return rv;
}

int register_ptree(ptree_func fp)
{
    int rv = -EBUSY;

    spin_lock(&ptree_lock);

    if (!ptree_fp) {
        ptree_fp = fp;
        rv = 0;
    }

    spin_unlock(&ptree_lock);

    return rv;
}
EXPORT_SYMBOL_GPL(register_ptree);

void unregister_ptree(ptree_func fp)
{
    spin_lock(&ptree_lock);

    if (ptree_fp == fp)
        ptree_fp = NULL;

    spin_unlock(&ptree_lock);
}
EXPORT_SYMBOL_GPL(unregister_ptree);
