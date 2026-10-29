#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum { STRINGS = 64, BYTES = 4096, WARMUP = 1024, BATCHES = 8, CALLS = 8192 };
static char strings[STRINGS][BYTES];
/* Every iteration loads this volatile pointer and makes a real dynamic call.
 * The evaluator checks its actual strrchr relocation and the emitted caller. */
char *(*volatile workload_scan)(const char *, int) = strrchr;
struct sample { uint64_t calls, start, end, sum; };
static struct sample samples[BATCHES + 1];

static void require(int ok) {
    if (!ok) _exit(113);
}

static uint64_t raw_time(void) {
    struct timespec t = {0, 0};
    require(syscall(SYS_clock_gettime, CLOCK_MONOTONIC_RAW, &t) == 0);
    require(t.tv_sec >= 0 && t.tv_nsec >= 0 && t.tv_nsec < 1000000000L);
    require((uint64_t)t.tv_sec <= (UINT64_MAX - (uint64_t)t.tv_nsec) / 1000000000);
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}

__attribute__((noinline, noclone)) uint64_t workload_batch(unsigned count) {
    uint64_t sum = 0;
    for (unsigned i = 0; i < count; ++i) {
        unsigned index = (i * 17u) & 63u;
        const char *base = strings[index];
        uintptr_t result = (uintptr_t)workload_scan(base, ':');
        uintptr_t expected = (uintptr_t)base + 63u + 37u * index;
        require(result >= (uintptr_t)base && result < (uintptr_t)base + BYTES - 1);
        require(result == expected);
        sum += result - (uintptr_t)base;
    }
    return sum;
}

int main(int argc, char **argv) {
    (void)argv;
    require(argc == 1);
    for (unsigned j = 0; j < STRINGS; ++j) {
        for (unsigned i = 0; i < BYTES - 1; ++i) strings[j][i] = (char)('A' + j % 23);
        strings[j][63u + 37u * j] = ':';
        strings[j][BYTES - 1] = 0;
    }
    struct timespec resolution = {0, 0};
    require(syscall(SYS_clock_getres, CLOCK_MONOTONIC_RAW, &resolution) == 0);
    require(resolution.tv_sec >= 0 && resolution.tv_nsec >= 0 && resolution.tv_nsec < 1000000000L);
    require((uint64_t)resolution.tv_sec <= (UINT64_MAX - (uint64_t)resolution.tv_nsec) / 1000000000);
    uint64_t resolution_ns = (uint64_t)resolution.tv_sec * 1000000000 + (uint64_t)resolution.tv_nsec;
    require(resolution_ns != 0);
    for (unsigned k = 0; k <= BATCHES; ++k) {
        struct sample *s = &samples[k];
        s->calls = k == 0 ? WARMUP : CALLS;
        s->start = raw_time();
        s->sum = workload_batch((unsigned)s->calls);
        s->end = raw_time();
        require(s->end > s->start && (k == 0 || s->start >= samples[k - 1].end));
    }
    require(printf("LI2_WORKLOAD 1 %d %d %d %d %d %" PRIu64 "\n",
                   STRINGS, BYTES, WARMUP, BATCHES, CALLS, resolution_ns) > 0);
    for (unsigned k = 0; k <= BATCHES; ++k) {
        const struct sample *s = &samples[k];
        require(printf("%u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                       k, s->calls, s->start, s->end, s->end - s->start, s->sum) > 0);
    }
    require(fflush(stdout) == 0 && !ferror(stdout));
    return 0;
}
