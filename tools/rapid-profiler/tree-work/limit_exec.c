/* Fixed application file cap, then exact same-PID exec. No child or waiter.
 * Separate APP streams keep perf/timer diagnostics outside functional output.
 * The record observes limit setup, NOT successful redirection/exec/application.
 * TOKEN is supplied using process_timing.token(APP_ARGV); the enclosing exact
 * request/timer argv is authoritative. FNV below is only an integrity checksum. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FILE_CAP 1048576
#define ARGV_CAP 1048576

/* Same bounded-write convention as process_timer.c. */
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

/* Raw exec argv bytes, each including its terminating NUL. Empty arguments
 * remain distinct. This is not the canonical-JSON SHA256 token algorithm. */
static int argv_fingerprint(int argc, char **argv, uint64_t *bytes, uint64_t *hash) {
    uint64_t count = 0, value = UINT64_C(14695981039346656037);
    for (int i = 0; i < argc; ++i) {
        const unsigned char *p = (const unsigned char *)argv[i];
        for (;;) {
            if (count == ARGV_CAP) return -1;
            unsigned char byte = *p++;
            ++count;
            value = (value ^ byte) * UINT64_C(1099511628211);
            if (!byte) break;
        }
    }
    *bytes = count;
    *hash = value;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 7 || argv[1][0] != '/' || strnlen(argv[2], 65) != 64 ||
        strspn(argv[2], "0123456789abcdef") != 64 || argv[3][0] != '/' ||
        argv[4][0] != '/' || strcmp(argv[5], "--") || argv[6][0] != '/') return 2;
    uint64_t argv_bytes, argv_hash;
    if (argv_fingerprint(argc - 6, argv + 6, &argv_bytes, &argv_hash)) return 2;
    /* Do not let fresh files occupy a closed standard descriptor. No fork or
     * other thread changes this process's descriptor table during setup. */
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; ++fd)
        if (fcntl(fd, F_GETFD) < 0) return 2;

    /* Refuse a lower inherited soft OR hard limit; never raise either one.
     * CPU, core, stack, descriptor limits, affinity, signal policy and
     * environment receive no mutation. Setup remains inside the child timer. */
    struct rlimit inherited, actual;
    const struct rlimit wanted = { FILE_CAP, FILE_CAP };
    if (getrlimit(RLIMIT_FSIZE, &inherited) ||
        inherited.rlim_cur < wanted.rlim_cur || inherited.rlim_max < wanted.rlim_max ||
        setrlimit(RLIMIT_FSIZE, &wanted) || getrlimit(RLIMIT_FSIZE, &actual) ||
        actual.rlim_cur != wanted.rlim_cur || actual.rlim_max != wanted.rlim_max) return 2;

    const char *paths[3] = { argv[1], argv[3], argv[4] };
    int files[3] = { -1, -1, -1 };
    struct stat info[3];
    /* Preserve every created file on failure. All three must be fresh and
     * distinct before even the setup record is written. */
    for (int i = 0; i < 3; ++i) {
        files[i] = open(paths[i], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (files[i] <= STDERR_FILENO || fchmod(files[i], 0600) || fstat(files[i], &info[i]) ||
            !S_ISREG(info[i].st_mode) || (info[i].st_mode & 07777) != 0600 ||
            info[i].st_uid != geteuid() || info[i].st_nlink != 1 || info[i].st_size != 0)
            goto setup_failed;
        for (int j = 0; j < i; ++j)
            if (files[i] == files[j] || (info[i].st_dev == info[j].st_dev &&
                info[i].st_ino == info[j].st_ino)) goto setup_failed;
    }
    char data[512];
    int n = snprintf(data, sizeof(data),
        "limit-exec-v1 token=%s pid=%jd argc=%d argv_bytes=%" PRIu64
        " argv_fnv1a64=%" PRIu64 " fsize_soft=%ju fsize_hard=%ju\n",
        argv[2], (intmax_t)getpid(), argc - 6, argv_bytes, argv_hash,
        (uintmax_t)actual.rlim_cur, (uintmax_t)actual.rlim_max);
    if (n <= 0 || (size_t)n >= sizeof(data) || write_all(files[0], data, (size_t)n) ||
        fstat(files[0], &info[0]) || info[0].st_size != (off_t)n) goto setup_failed;
    int closed = close(files[0]);
    files[0] = -1; /* Never retry an ambiguous close. */
    if (closed) goto setup_failed;
    /* Sources are distinct descriptors above 2. dup2 deliberately clears
     * CLOEXEC on 1/2; original descriptors retain CLOEXEC until closed below. */
    if (dup2(files[1], STDOUT_FILENO) != STDOUT_FILENO ||
        dup2(files[2], STDERR_FILENO) != STDERR_FILENO) goto setup_failed;
    for (int i = 1; i < 3; ++i) {
        closed = close(files[i]);
        files[i] = -1;
        if (closed) goto setup_failed;
    }

    execv(argv[6], argv + 6);
    int error = errno;
    int length = snprintf(data, sizeof(data), "limit-exec: execv failed errno=%d\n", error);
    if (length > 0 && (size_t)length < sizeof(data))
        (void)write_all(STDERR_FILENO, data, (size_t)length);
    _exit(127);

setup_failed:
    for (int i = 0; i < 3; ++i)
        if (files[i] >= 0) (void)close(files[i]);
    return 2;
}
