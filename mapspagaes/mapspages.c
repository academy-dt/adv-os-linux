#define pr_fmt(fmt) "%s:%s: " fmt "\n", KBUILD_MODNAME, __func__

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#include <linux/mapspages.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Trugman & Chen Glayher");
MODULE_DESCRIPTION("HW2");

int get_mapspages(unsigned long start, unsigned long end, char *buf, size_t size)
{
    pr_info("getting mapspages: %lu - %lu -> %p [%zu]", start, end, buf, size);

    return 0;
}

static int __init mapspages_init(void)
{
    return register_mapspages(get_mapspages);
}

static void __exit mapspages_cleanup(void)
{
    unregister_mapspages(get_mapspages);
}

module_init(mapspages_init);
module_exit(mapspages_cleanup);
