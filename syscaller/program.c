#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/prinfo.h>

#define LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

static const pid_t ROOT_PID = 1;
static const long SYS_PTREE = 449;
static const size_t BUF_INIT = 32;
static const size_t BUF_MAX = INT16_MAX;

void dump(struct prinfo *buf)
{
    LOG("%d,%s,%d,%d,%ld,%d", buf->level, buf->comm,
           buf->pid, buf->parent_pid, buf->state, buf->uid);
}

int ptree(size_t buf_size, pid_t pid)
{
    int nr = buf_size;
    struct prinfo *buf = malloc(nr * sizeof(*buf));
    if (!buf) {
        return -1;
    }

    if (syscall(SYS_PTREE, buf, &nr, pid) != 0) {
        return -1;
    }

    for (int i = 0; i < nr; ++i) {
        dump(&buf[i]);
    }
    return 0;
}

int main(int argc, char **argv)
{
    pid_t pid = ROOT_PID;
    if (argc > 2) {
        LOG("Usage: %s <pid>", argv[0]);
        return 2;
    }

    if (argc == 2) {
        pid = atoi(argv[1]);
    }

    for (size_t size = BUF_INIT; size < BUF_MAX; size *= 2) {
        int ret = ptree(size, pid);
        if (ret == 0) {
            break;
        }

        if (errno != ENOMEM) {
            perror("ptree");
            break;
        }
    }

    return 0;
}
