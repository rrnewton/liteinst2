#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "probe_api.h"

#define ITERATIONS 1000
struct entry { uint64_t ino; int64_t offset; unsigned short size; unsigned char type; char name[]; };

/* Same real kernel path is warmed once, then repeated without a retry rule. */
static __attribute__((noinline)) int list_once(void) {
    long fd = syscall(SYS_openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return 10;
    unsigned seen = 0, count = 0;
    int error = 0;
    _Alignas(8) char buffer[4096];
    for (;;) {
        long size = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
        if (size < 0) { error = 11; break; }
        if (!size) break;
        size_t at = 0;
        while (at < (size_t)size) {
            struct entry *item = (void *)(buffer + at);
            if ((size_t)size - at < offsetof(struct entry, name) + 1 ||
                item->size < offsetof(struct entry, name) + 1 || item->size > (size_t)size - at ||
                !memchr(item->name, 0, item->size - offsetof(struct entry, name))) {
                error = 12; break;
            }
            unsigned bit = !strcmp(item->name, ".") ? 1 : !strcmp(item->name, "..") ? 2 :
                           !strcmp(item->name, "alpha.txt") ? 4 : !strcmp(item->name, "beta.txt") ? 8 :
                           !strcmp(item->name, "subdirectory") ? 16 : 0;
            if (!bit || (seen & bit)) { error = 13; break; }
            seen |= bit;
            ++count;
            at += item->size;
        }
        if (error) break;
    }
    if (syscall(SYS_close, fd) != 0) return 14;
    return error ? error : (seen == 31 && count == 5 ? 0 : 15);
}

static uint64_t clock_ns(void) {
    struct timespec t;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

int main(void) {
    uint32_t a = 0, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) :: "memory");
    if (!a || !(b | c | d)) return 2;
    uint32_t low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high) :: "memory");
    if (!(low | high)) return 3;
    long pid = syscall(SYS_getpid);
    if (pid <= 0 || pid != getpid()) return 4;
    unsigned char *memory = mmap(0, 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 5;
    memory[0] = 0x73;
    memory[4095] = 0x8a;
    if (mprotect(memory, 4096, PROT_READ) != 0 || memory[0] != 0x73 || memory[4095] != 0x8a) return 6;
    if (munmap(memory, 4096) != 0) return 7;
    li2_dynamic_snapshot_fn snapshot = (li2_dynamic_snapshot_fn)dlsym(RTLD_DEFAULT, "li2_dynamic_snapshot");
    if (!clock_ns()) return 16;
    int result = list_once();
    if (result) return result;
    struct li2_dynamic_counters before = {0}, after = {0};
    if (snapshot) snapshot(&before);
    uint64_t start = clock_ns();
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        result = list_once();
        if (result) return result;
    }
    uint64_t end = clock_ns();
    if (snapshot) snapshot(&after);
    if (!start || end < start) return 17;
    if (snapshot && (after.nx_faults != before.nx_faults ||
                     after.syscall_traps - before.syscall_traps != ITERATIONS * 4 + 2 ||
                     after.forwarded_syscalls - before.forwarded_syscalls != ITERATIONS * 4 + 2)) return 18;
    char line[512];
    int length;
    if (snapshot) {
        length = snprintf(line, sizeof(line),
            "LI2_STEADY {\"version\":1,\"iterations\":%u,\"warm_iterations\":1,\"elapsed_ns\":%" PRIu64
            ",\"snapshot_present\":true,\"nx_before\":%" PRIu64 ",\"nx_after\":%" PRIu64
            ",\"syscalls\":%" PRIu64 ",\"forwarded\":%" PRIu64 "}\n",
            ITERATIONS, end - start, before.nx_faults, after.nx_faults,
            after.syscall_traps - before.syscall_traps, after.forwarded_syscalls - before.forwarded_syscalls);
    } else {
        length = snprintf(line, sizeof(line),
            "LI2_STEADY {\"version\":1,\"iterations\":%u,\"warm_iterations\":1,\"elapsed_ns\":%" PRIu64
            ",\"snapshot_present\":false,\"nx_before\":null,\"nx_after\":null,\"syscalls\":null,\"forwarded\":null}\n",
            ITERATIONS, end - start);
    }
    if (length < 0 || (size_t)length >= sizeof(line) || write(2, line, length) != length) return 19;
    const char answer[] = "dynamic-probe-ok\n";
    return write(1, answer, sizeof(answer) - 1) == sizeof(answer) - 1 ? 0 : 8;
}
