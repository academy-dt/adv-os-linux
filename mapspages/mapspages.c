#define pr_fmt(fmt) "%s:%s: " fmt "\n", KBUILD_MODNAME, __func__

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>

#include <linux/mapspages.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Trugman & Chen Gleichger");
MODULE_DESCRIPTION("HW2");

struct walk_data {
    char *buf;
    size_t size;
};

static void put_char(struct walk_data *data, char c)
{
    *data->buf  = c;
    data->buf  += 1;
    data->size -= 1;
}

static int mapspages_pte_entry(pte_t *pte, unsigned long start, unsigned long end,
                               struct mm_walk *walk)
{
    char c = '.';
    struct walk_data *data = walk->private;

    if (data->size == 0) {
        return 0;
    }

    if (pte_present(*pte)) {
        struct page *page = pte_page(*pte);
        if (!page) {
            c = 'E';
        } else {
            int ref = page_ref_count(page);
            if (ref > 9) {
                c = 'X';
            } else {
                c = '0' + ref;
            }
        }
    }

    put_char(data, c);
    return 0;
}

static const struct mm_walk_ops walk_ops = {
    .pte_entry = mapspages_pte_entry,
};

static int __show_vma_prefix(struct vm_area_struct *vma, unsigned long start, unsigned long end,
                             char *buf, size_t size)
{
    struct file *file = vma->vm_file;

    unsigned long ino = 0;
    unsigned long long pgoff = 0;
    dev_t dev = 0;

    vm_flags_t flags = vma->vm_flags;

    if (file) {
        struct inode *inode = file_inode(vma->vm_file);
        dev = inode->i_sb->s_dev;
        ino = inode->i_ino;
        pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
    }

    return snprintf(buf, size,
                    "%8lx-%8lx %c%c%c%c %08llx %02d:%02d %-8lu ",
                    start, end,
                    flags & VM_READ ? 'r' : '-',
                    flags & VM_WRITE ? 'w' : '-',
                    flags & VM_EXEC ? 'x' : '-',
                    flags & VM_MAYSHARE ? 's' : 'p',
                    pgoff, MAJOR(dev), MINOR(dev), ino);
}

static int __show_vma_pages(struct vm_area_struct *vma, unsigned long start, unsigned long end,
                            char *buf, size_t size)
{
    int err;
    struct walk_data data = {
        .buf = buf,
        .size = size,
    };

    err = walk_page_range(vma->vm_mm, start, end, &walk_ops, &data);
    if (err < 0)
        return err;

    if (data.size > 0)
        put_char(&data, '\n');

    return data.buf - buf;
}

static int __enum_vma(struct vm_area_struct *vma, unsigned long start, unsigned long end,
                      char *buf, size_t size)
{
    int rv;
    int off = 0;

    start = max(start, vma->vm_start);
    end = min(end, vma->vm_end);

    rv = __show_vma_prefix(vma, start, end, &buf[off], size - off);
    if (rv >= size)
        return -ENOMEM;
    off += rv;

    rv = __show_vma_pages(vma, start, end, &buf[off], size - off);
    if (rv >= size)
        return -ENOMEM;
    off += rv;

    return off;
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
        rv = __enum_vma(vma, start, end, &buf[off], size - off);
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
    unsigned long aligned_end;

    aligned_end = PAGE_ALIGN(end);
    pr_info("getting mapspages: %lx - %lx (%lx) -> %p [%zu]", start, end, aligned_end, buf, size);

	mm = current->mm;
    down_read(&mm->mmap_sem);
    rv = enum_mapspages(mm, start, aligned_end, buf, size);
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
