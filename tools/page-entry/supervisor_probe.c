/* Separate supervisor controls. No gate/runtime permits or fake wait results. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void stop(int value) __attribute__((noreturn));
static void stop(int value) {
    (void)syscall(SYS_exit_group, value);
    __builtin_trap();
}
static void need(int okay) { if (!okay) stop(97); }
static unsigned number(const char *text) {
    unsigned value = 0, count = 0;
    while (*text) {
        need(*text >= '0' && *text <= '9' && value <= (0x7fffffffU - (unsigned)(*text - '0')) / 10);
        value = value * 10 + (unsigned)(*text++ - '0');
        ++count;
    }
    need(count && value > 2);
    return value;
}
static char *decimal(char *out, unsigned long value) {
    char reverse[32];
    size_t size = 0;
    do { reverse[size++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (size) *out++ = reverse[--size];
    return out;
}
int main(int argc, char **argv) {
    need(argc == 5);
    int live = !strcmp(argv[1], "live"), exited = !strcmp(argv[1], "exited");
    int normal = !strcmp(argv[1], "normal"), malformed = !strcmp(argv[1], "malformed");
    need(live || exited || normal || malformed);
    unsigned first = number(argv[2]), second = number(argv[3]), supervisor = number(argv[4]);
    need(first != second);
    long leader = syscall(SYS_getpid), child = syscall(SYS_fork);
    need(leader > 0 && child >= 0);
    if (child) {
        if (!live) stop(0);
        for (;;) (void)syscall(SYS_pause);
    }
    long parent;
    if (!live) {
        /* Actual reparenting to the dedicated subreaper is the readiness
           condition. The supervisor's fixed wall bound covers any failure. */
        do { parent = syscall(SYS_getppid); if (parent != supervisor) (void)syscall(SYS_sched_yield); }
        while (parent != supervisor);
    } else {
        parent = syscall(SYS_getppid);
        need(parent == leader);
    }
    long self = syscall(SYS_getpid);
    need(self > 0 && self != leader);
    char text[96] = "READY ", *end = text + 6;
    end = decimal(end, (unsigned long)leader); *end++ = ' ';
    end = decimal(end, (unsigned long)self); *end++ = ' ';
    end = decimal(end, (unsigned long)parent); *end++ = '\n';
    need(syscall(SYS_write, first, text, (size_t)(end - text)) == end - text);
    if (live || exited) for (;;) (void)syscall(SYS_pause);
    if (malformed) need(syscall(SYS_write, second, "BROKEN\n", 7) == 7);
    stop(42);
}
