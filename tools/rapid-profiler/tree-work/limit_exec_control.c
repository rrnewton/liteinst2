/* Prospective bounded child fixtures only; no supervisor or fork. Root owns
 * compilation/execution and joins these observations with the existing timer. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_all(int fd, const void *data, size_t length) {
    const char *next = data;
    while (length) {
        ssize_t n = write(fd, next, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        next += n;
        length -= (size_t)n;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct rlimit file, cpu, core, descriptors, stack;
    if (getrlimit(RLIMIT_FSIZE, &file) || getrlimit(RLIMIT_CPU, &cpu) ||
        getrlimit(RLIMIT_CORE, &core) || getrlimit(RLIMIT_NOFILE, &descriptors) ||
        getrlimit(RLIMIT_STACK, &stack) || file.rlim_cur != 1048576 ||
        file.rlim_max != 1048576) return 2;
    if (!strcmp(argv[1], "probe")) {
        printf("limit-exec-control-v1 pid=%jd ppid=%jd argc=%d "
            "fsize_soft=%ju fsize_hard=%ju cpu_soft=%ju cpu_hard=%ju "
            "core_soft=%ju core_hard=%ju nofile_soft=%ju nofile_hard=%ju "
            "stack_soft=%ju stack_hard=%ju\n", (intmax_t)getpid(), (intmax_t)getppid(), argc,
            (uintmax_t)file.rlim_cur, (uintmax_t)file.rlim_max,
            (uintmax_t)cpu.rlim_cur, (uintmax_t)cpu.rlim_max,
            (uintmax_t)core.rlim_cur, (uintmax_t)core.rlim_max,
            (uintmax_t)descriptors.rlim_cur, (uintmax_t)descriptors.rlim_max,
            (uintmax_t)stack.rlim_cur, (uintmax_t)stack.rlim_max);
        return fflush(stdout) ? 3 : 0;
    }
    if (!strcmp(argv[1], "overflow") && argc == 2) {
        struct stat st;
        struct sigaction action;
        sigset_t blocked;
        if (fstat(STDOUT_FILENO, &st) || !S_ISREG(st.st_mode) || st.st_size != 0 ||
            sigaction(SIGXFSZ, NULL, &action) || action.sa_handler != SIG_DFL ||
            sigprocmask(SIG_SETMASK, NULL, &blocked) || sigismember(&blocked, SIGXFSZ) != 0) return 2;
        char data[4096];
        memset(data, 'x', sizeof(data));
        for (unsigned i = 0; i < 256; ++i)
            if (write_all(STDOUT_FILENO, data, sizeof(data))) return 3;
        /* Expected actual SIGXFSZ. Returning for ANY reason is not its pass. */
        (void)write_all(STDOUT_FILENO, "!", 1);
        return 4;
    }
    return 2;
}
