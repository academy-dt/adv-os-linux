#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/mapspages.h>

static const char *PTREE_MODULE_NAME = "mapspages";

DEFINE_SPINLOCK(mapspages_lock);
static mapspages_func mapspages_fp = NULL;

static mapspages_func try_get_mapspages_once(void)
{
    mapspages_func fp = NULL;

    spin_lock(&mapspages_lock);
    if (mapspages_fp) {
        struct module* module = find_module(PTREE_MODULE_NAME);
        if (module && try_module_get(module))
            fp = mapspages_fp;
    }
    spin_unlock(&mapspages_lock);

    return fp;
}

static mapspages_func try_get_mapspages(void)
{
    mapspages_func fp = try_get_mapspages_once();
    if (fp)
        return fp;

    if (request_module(PTREE_MODULE_NAME))
        return NULL;

    return try_get_mapspages_once();
}

static void put_mapspages(void)
{
    spin_lock(&mapspages_lock);
    if (mapspages_fp) {
        struct module* module = find_module(PTREE_MODULE_NAME);
        if (module)
            module_put(module);
    }
    spin_unlock(&mapspages_lock);
}

/**
 * mapspages() - Return information about own memory regions
 *
 * @start: is the (userspace) starting virtual address of memory range
 *         for which to generate the report (inclusive).
 * @end:   is the (userspace) ending virtual address of memory range
 *         for which to generate the report (exclusive).
 * @buf:   points to a buffer to store the textual report.
 * @size:  indicates the size of the buffer in bytes.
 *         The system call copies at most as many entries that fit
 *         the buffer (in full) without breaking any.
 *
 * Return: On success, the buffer is filled with the memory regions
 *         information, and the return value is 0.
 *         On error, a negative errno number will be returned.
 */
SYSCALL_DEFINE4(mapspages, unsigned long, start, unsigned long, end, char __user *, buf, size_t, size)
{
    mapspages_func fp;
    int rv;

    char *kbuf = NULL;

    if (start > end) {
        pr_err("bad address range");
        rv = -EINVAL;
        goto out;
    }

    if (!buf || size == 0) {
        pr_err("bad output parameters");
        rv = -EINVAL;
        goto out;
    }

    if (unlikely(!access_ok(buf, size))) {
        pr_err("bad userspace buffer");
        rv = -EFAULT;
        goto out;
    }

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) {
        pr_err("kmalloc failed");
        rv = -ENOMEM;
        goto out;
    }

    fp = try_get_mapspages();
    if (!fp) {
        pr_err("try_get_mapspages failed");
        rv = -ENOSYS;
        goto out;
    }

    rv = fp(start, end, kbuf, size);
    if (rv) {
        // logged from the inside
        goto out;
    }

    put_mapspages();

    if (copy_to_user(buf, kbuf, size)) {
        pr_err("copy_to_user failed");
        rv = -EFAULT;
        goto out;
    }

out:
    if (kbuf)
        kfree(kbuf);

    return rv;
}

int register_mapspages(mapspages_func fp)
{
    int rv = -EBUSY;

    spin_lock(&mapspages_lock);

    if (!mapspages_fp) {
        mapspages_fp = fp;
        rv = 0;
    }

    spin_unlock(&mapspages_lock);

    return rv;
}
EXPORT_SYMBOL_GPL(register_mapspages);

void unregister_mapspages(mapspages_func fp)
{
    spin_lock(&mapspages_lock);

    if (mapspages_fp == fp)
        mapspages_fp = NULL;

    spin_unlock(&mapspages_lock);
}
EXPORT_SYMBOL_GPL(unregister_mapspages);
