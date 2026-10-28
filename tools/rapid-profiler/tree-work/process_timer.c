/* One owned child's fork-to-wait4 enclosure. No timeout or cleanup policy:
 * bounded_command.py retains those responsibilities, including orphan cleanup.
 * A record is an observation, never evidence of functional or owner success. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static int scaled(int64_t seconds, int64_t fraction, uint64_t base, uint64_t *out) {
    if (seconds < 0 || fraction < 0 || (uint64_t)fraction >= base ||
        (uint64_t)seconds > (UINT64_MAX - (uint64_t)fraction) / base)
        return -1;
    *out = (uint64_t)seconds * base + (uint64_t)fraction;
    return 0;
}

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
    if (argc < 5 || argv[1][0] != '/' || strlen(argv[2]) != 64 ||
        strspn(argv[2], "0123456789abcdef") != 64 || strcmp(argv[3], "--") ||
        argv[4][0] != '/') return 2;
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) || action.sa_handler != SIG_DFL ||
        (action.sa_flags & SA_NOCLDWAIT)) return 2;
    struct timespec resolution, start, end;
    if (clock_getres(CLOCK_MONOTONIC, &resolution)) return 2;
    int record = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (record < 0) return 2;
    int errors[2];
    if (pipe2(errors, O_CLOEXEC)) { close(record); return 2; }
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (!child) {
        close(errors[0]);
        close(record);
        execve(argv[4], argv + 4, environ);
        int error = errno;
        (void)write_all(errors[1], &error, sizeof(error));
        _exit(127);
    }
    close(errors[1]);
    int status;
    struct rusage usage;
    pid_t waited;
    do { waited = wait4(child, &status, 0, &usage); } while (waited < 0 && errno == EINTR);
    /* No consuming wait or status/pipe inspection between wait4 and this read. */
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 2;
    if (waited != child || (!WIFEXITED(status) && !WIFSIGNALED(status))) return 2;
    unsigned char pipe_data[sizeof(int) + 1];
    size_t count = 0;
    while (count < sizeof(pipe_data)) {
        ssize_t n = read(errors[0], pipe_data + count, sizeof(pipe_data) - count);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return 2;
        if (!n) break;
        count += (size_t)n;
    }
    if (close(errors[0])) return 2;
    int exec_error = 0;
    if (count) {
        if (count != sizeof(exec_error)) return 2;
        memcpy(&exec_error, pipe_data, count);
        if (exec_error <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 127) return 2;
    }
    uint64_t first, last, user, system, resolution_ns;
    if (scaled(start.tv_sec, start.tv_nsec, 1000000000, &first) ||
        scaled(end.tv_sec, end.tv_nsec, 1000000000, &last) || last <= first ||
        scaled(usage.ru_utime.tv_sec, usage.ru_utime.tv_usec, 1000000, &user) ||
        scaled(usage.ru_stime.tv_sec, usage.ru_stime.tv_usec, 1000000, &system) ||
        user > UINT64_MAX - system ||
        scaled(resolution.tv_sec, resolution.tv_nsec, 1000000000, &resolution_ns) || !resolution_ns)
        return 2;
    char data[1024];
    int n = snprintf(data, sizeof(data),
        "process-timer-v1 token=%s timer_pid=%jd child_pid=%jd wait_pid=%jd argc=%d "
        "wait_status=%d exit=%d signal=%d core=%d exec_errno=%d "
        "start_sec=%jd start_nsec=%ld end_sec=%jd end_nsec=%ld "
        "user_sec=%jd user_usec=%jd system_sec=%jd system_usec=%jd "
        "resolution_ns=%" PRIu64 " process_wall_ns=%" PRIu64 " child_user_us=%" PRIu64
        " child_system_us=%" PRIu64 " child_cpu_us=%" PRIu64 "\n",
        argv[2], (intmax_t)getpid(), (intmax_t)child, (intmax_t)waited, argc - 4,
        status, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
        WIFSIGNALED(status) ? WTERMSIG(status) : 0,
        WIFSIGNALED(status) && WCOREDUMP(status) ? 1 : 0, exec_error,
        (intmax_t)start.tv_sec, start.tv_nsec, (intmax_t)end.tv_sec, end.tv_nsec,
        (intmax_t)usage.ru_utime.tv_sec, (intmax_t)usage.ru_utime.tv_usec,
        (intmax_t)usage.ru_stime.tv_sec, (intmax_t)usage.ru_stime.tv_usec,
        resolution_ns, last - first, user, system, user + system);
    if (n <= 0 || (size_t)n >= sizeof(data) || write_all(record, data, (size_t)n)) return 2;
    if (close(record)) return 2;
    return exec_error == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
