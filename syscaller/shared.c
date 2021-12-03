#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

static const long SYS_MAPSPAGES = 449;

static int mapspages(unsigned long start, unsigned long end, char *buf, size_t size)
{
    return syscall(SYS_MAPSPAGES, start, end, buf, size);
}

int print_maps(unsigned long start, unsigned long end)
{
    char buf[65536];

    LOG("syscall(%ld, %lx, %lx, %p, %zu)", SYS_MAPSPAGES,
        start, end, buf, sizeof(buf));
    LOG("");

    int err = mapspages(start, end, buf, sizeof(buf));
    if (err) {
        LOG("Error: %s (%d)", strerror(errno), errno);
    } else {
        LOG("%s", buf);
    }

    LOG("Press return to continue...");
    getchar();

    return err;
}

int print_map(char *map, size_t len)
{
    unsigned long start = (unsigned long)map;
    unsigned long end   = (unsigned long)map + len;
    return print_maps(start, end);
}
