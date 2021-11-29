/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MAPSPAGES_H
#define _LINUX_MAPSPAGES_H

typedef int (*mapspages_func)(unsigned long start, unsigned long end,
                              char *buf, size_t size);

extern int register_mapspages(mapspages_func func);
extern void unregister_mapspages(mapspages_func func);

#endif /* _LINUX_MAPSPAGES_H */
