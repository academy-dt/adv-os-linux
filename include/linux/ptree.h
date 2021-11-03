/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PTREE_H
#define _LINUX_PTREE_H

#include <linux/prinfo.h>

typedef int (*ptree_func)(struct prinfo *buf, int *nr, int pid);

extern int register_ptree(ptree_func func);
extern void unregister_ptree(ptree_func func);

#endif /* _LINUX_PTREE_H */
