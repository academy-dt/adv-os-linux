#define _GNU_SOURCE

#include <stdio.h>
#include <sched.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "shared.h"

void* get_stack_start()
{
    FILE* fp = fopen("/proc/self/stat", "r");
    if (!fp) {
        LOG("Open stat file failed");
        return NULL;
    }

    int bytes = 0;
    char format[256];
    for (unsigned i = 0; i < 27; ++i) {
        bytes += sprintf(&format[bytes], "%%*s ");
    }
    sprintf(&format[bytes], "%%lu");

    unsigned long stack_bottom;
    int tokens = fscanf(fp, format, &stack_bottom);
    if (tokens != 1) {
        LOG("Scan stat file failed");
        return NULL;
    }

    return (void *)stack_bottom;
}

void* get_stack_bottom()
{
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOG("Open maps file failed");
        return NULL;
    }

    unsigned long stack_bottom = 0;

    ssize_t read;
    size_t len = 0;
    char * line = NULL;

    while ((read = getline(&line, &len, fp)) != -1) {
        char stack_tag[16];
        unsigned long stack_temp;

        if (sscanf(line, "%*x-%lx %*s %*s %*s %*s %16s",
                   &stack_temp, stack_tag) != 2) {
            continue;
        }

        if (strcmp(stack_tag, "[stack]") != 0) {
            continue;
        }

        stack_bottom = stack_temp;
        break;
    }

    free(line);
    fclose(fp);
    return (void *)stack_bottom;
}

size_t get_stack_size()
{
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        return 0;
    }

    size_t stack_size;

    ssize_t read;
    size_t len = 0;
    char * line = NULL;

    while ((read = getline(&line, &len, fp)) != -1) {
        if (sscanf(line, "VmStk\t: %lu kB", &stack_size) == 1) {
            break;
        }
    }

    free(line);
    fclose(fp);
    return stack_size * 1024;
}

int map_rw(size_t nr, unsigned read_mask, unsigned write_mask)
{
    size_t page_size = getpagesize();
    size_t len = nr * page_size;
    char *map = mmap(NULL, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        LOG("Allocate buffer failed");
        return -1;
    }
    LOG("Allocated buffer @ %p", map);

    for (unsigned i = 0; i < nr; ++i) {
        unsigned mask = (1 << i);
        if (write_mask & mask) {
            map[i * page_size] = 'X';
        } else if (read_mask & mask) {
            char c = map[i * page_size];
            (void)c;
        }
    }

    int rv = print_map(map, len);
    munmap(map, len);
    return rv;
}

int test1()
{
    LOG_FUNC();
    return map_rw(10, 0, 0);
}

int test2()
{
    LOG_FUNC();
    return map_rw(10, 0x3FF, 0);
}

int test3()
{
    LOG_FUNC();
    return map_rw(10, 0x2AA, 0);
}

int test4()
{
    LOG_FUNC();
    return map_rw(10, 0, 0x1F);
}

int test5()
{
    LOG_FUNC();
    return map_rw(10, 0x00F, 0x3C0);
}

int test6()
{
    LOG_FUNC();
    return map_rw(2000, 0, 0);
}

int thread_main(void *args)
{
    sleep(3000);
    return 0;
}

int test7()
{
    LOG_FUNC();

    void* stack_bottom = get_stack_bottom();
    if (stack_bottom == 0) {
        LOG("Get stack bottom failed");
        return -1;
    }

    void* stack_start = get_stack_start();
    if (stack_start == 0) {
        LOG("Get stack start failed");
        return -1;
    }

	size_t stack_size = get_stack_size();
	if (stack_size == 0) {
	    LOG("Get stack size failed");
        return -1;
    }

    void *stack;
    void *stack_top;
    size_t size;

    stack_top = (void *)((unsigned long)stack_bottom - stack_size);
    size = (unsigned long)&size - (unsigned long)stack_top;

    stack = alloca(size);
    (void)stack; // Compiler complains it's unused

    for (unsigned i = 0; i < 8; ++i) {
        int rv = clone(thread_main, (void *)stack_top, 0, NULL);
        if (rv == -1) {
            LOG("Clone thread failed: %s (%d)", strerror(errno), errno);
            return -1;
        }
    }

    return print_maps((unsigned long)stack_top, (unsigned long)stack_bottom);
}

int test8()
{
    LOG_FUNC();
    return 0;
}

int test9()
{
    LOG_FUNC();

    while (1)
    {
        char *mem = malloc(1024);
        if (mem) {
            mem[0] = '.';
        }
    }
}

typedef int (*tester)(void);

int main(int argc, char **argv)
{
    if (argc < 2) {
        LOG("Usage: %s <test-num>...", argv[0]);
        return 2;
    }

    tester testers[] = { test1, test2, test3, test4, test5, test6,
                         test7, test8, test9 };
    size_t testers_nr = sizeof(testers)/sizeof(testers[0]);

    for (int i = 1; i < argc; ++i) {
        int v = atoi(argv[i]);
        if (v < 1 || v > testers_nr) {
            LOG("No tester: %d", v);
            continue;
        }

        testers[v - 1]();
    }

    return 0;
}
