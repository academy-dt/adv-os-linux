#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

static const long SYS_MAPSPAGES = 449;

int mapspages(unsigned long start, unsigned long end, char *buf, size_t size)
{
    LOG("syscall(%ld, %lu, %lu, %p, %zu)", SYS_MAPSPAGES,
        start, end, buf, size);
    int err = syscall(SYS_MAPSPAGES, start, end, buf, size);
    if (err) {
        LOG("Error: %s (%d)", strerror(-err), -err);
        return -1;
    }

    LOG("%s", buf);

    return 0;
}

int main(int argc, char **argv)
{
    unsigned long start, end;
    size_t size;
    char *buf;

    if (argc != 4) {
        LOG("Usage: %s <start> <end> <buf-size>", argv[0]);
        return 2;
    }

    if (sscanf(argv[1], "0x%lx", &start) != 1) {
        start = atol(argv[1]);
    }

    if (sscanf(argv[2], "0x%lx", &end) != 1) {
        end = atol(argv[2]);
    }

    size  = atol(argv[3]);

    buf = malloc(size);
    if (!buf) {
        LOG("Allocate buffer failed");
        return 2;
    }

    int rv = mapspages(start, end, buf, size);
    free(buf);
    return rv;
}
