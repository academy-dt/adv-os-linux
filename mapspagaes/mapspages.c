#define pr_fmt(fmt) "%s:%s: " fmt "\n", KBUILD_MODNAME, __func__

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm.h>

#include <linux/mapspages.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Trugman & Chen Glayher");
MODULE_DESCRIPTION("HW2");

static int __show_vma_prefix(char *buf, size_t size,
				   unsigned long start, unsigned long end,
				   vm_flags_t flags, unsigned long long pgoff,
				   dev_t dev, unsigned long ino)
{
    return snprintf(buf, size,
                    "%8lx-%8lx, %c%c%c%c %08llx %02d:%02d %-8lu\n",
                    start, end,
                    flags & VM_READ ? 'r' : '-',
                    flags & VM_WRITE ? 'w' : '-',
                    flags & VM_EXEC ? 'x' : '-',
                    flags & VM_MAYSHARE ? 's' : 'p',
                    pgoff, MAJOR(dev), MINOR(dev), ino);
}

static int __enum_vma(struct vm_area_struct *vma, char *buf, size_t size)
{
    struct file *file = vma->vm_file;

    unsigned long ino = 0;
    unsigned long long pgoff = 0;
    dev_t dev = 0;

    int rv;

    if (file) {
        struct inode *inode = file_inode(vma->vm_file);
        dev = inode->i_sb->s_dev;
        ino = inode->i_ino;
        pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
    }

    rv = __show_vma_prefix(buf, size,
                           vma->vm_start, vma->vm_end,
                           vma->vm_flags, pgoff,
                           dev, ino);
    return (rv < size) ? rv : -ENOMEM;
}

int enum_mapspages(struct mm_struct *mm, unsigned long start, unsigned long end, char *buf, size_t size)
{
	struct vm_area_struct *vma;
	unsigned long addr;

    int off = 0;
    int rv = 0;

	addr = start;
    vma = find_vma(mm, start);
    if (!vma) {
        pr_err("find vma failed");
        return -ENOMEM;
    }

    while (addr < end) {
        rv = __enum_vma(vma, &buf[off], size - off);
        if (rv < 0)
            break;
        off += rv;

        vma = vma->vm_next;
        if (!vma)
            break;

        addr = vma->vm_start;
    }

    return (rv < 0) ? rv : 0;
}

int get_mapspages(unsigned long start, unsigned long end, char *buf, size_t size)
{
    int rv;
	struct mm_struct *mm;

    pr_info("getting mapspages: %lu - %lu -> %p [%zu]", start, end, buf, size);

	mm = current->mm;
    down_read(&mm->mmap_sem);
    rv = enum_mapspages(mm, start, end, buf, size);
    up_read(&mm->mmap_sem);

    return rv;
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
