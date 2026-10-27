/* Compiled common-corpus input. Kernel and hook domains are distinct.
 * Build with the recorded GNU C profile; actual ELF decoding remains required.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "datasets.h"
#include "journal.h"

#if !defined(__GNUC__) || defined(__clang__) || !defined(__x86_64__)
#error "This finite fixture requires GNU C on x86-64; a new compiler needs new admission"
#endif
#define KERNEL __attribute__((noipa, noinline, noclone, used, visibility("default"), section(".text.li2_sort")))
#define BOUNDARY __attribute__((noipa, noinline, noclone, used, visibility("default")))
#define HOOK __attribute__((noipa, noinline, noclone, used, visibility("default"), section(".text.li2_hooks")))
#define PAGE_BYTES ((size_t)4096)
#define ARRAY_OFFSET ((size_t)64)
#define MAX_ELEMENTS ((size_t)64)
#define RUN_GUARD_LOW UINT64_C(0x72616e67652d6c6f)
#define RUN_GUARD_HIGH UINT64_C(0x72616e67652d6869)

/* All kernel array writes flow through this ABI. The compiled adapter must
 * prove MOV qword [RDI+RSI*8],RDX + RET and the absence of any other writer.
 * Preconditions: array is the current admitted base, index < current length.
 */
KERNEL void li2_array_store(uint64_t *array, size_t index, uint64_t value)
{
    array[index] = value;
}

/* root < n/2 implies left=2*root+1 < n. child+1 is checked before use.
 * Every swap calls the store ABI twice, using the original base unchanged.
 */
KERNEL void li2_sift_down(uint64_t *array, size_t n, size_t root)
{
    while (root < n / 2) {
        size_t child = root * 2 + 1;
        if (child + 1 < n && array[child] < array[child + 1])
            ++child;
        if (array[root] >= array[child])
            return;
        const uint64_t old = array[root];
        li2_array_store(array, root, array[child]);
        li2_array_store(array, child, old);
        root = child;
    }
}

KERNEL void li2_heap_sort(uint64_t *array, size_t n)
{
    if (n < 2)
        return;
    for (size_t parent = n / 2; parent != 0; --parent)
        li2_sift_down(array, n, parent - 1);
    for (size_t end = n; end > 1; --end) {
        const uint64_t old = array[0];
        li2_array_store(array, 0, array[end - 1]);
        li2_array_store(array, end - 1, old);
        li2_sift_down(array, end - 1, 0);
    }
}

/* Kernel entry/exit observation points are ordinary compiled calls. They do
 * not trap, seed state or perform any instrumentation themselves.
 */
BOUNDARY void li2_before_sort(void)
{
    __asm__ volatile("" ::: "memory");
}
BOUNDARY void li2_after_sort(void)
{
    __asm__ volatile("" ::: "memory");
}

volatile struct li2_journal li2_journal = {
    .guard_low = LI2_JOURNAL_GUARD_LOW,
    .version = LI2_JOURNAL_VERSION,
    .capacity = LI2_JOURNAL_CAPACITY,
    .guard_high = LI2_JOURNAL_GUARD_HIGH
};

/* Same-module callbacks. Offset zero is HookContext.instruction_pointer.
 * They never modify the application Context or invoke libc.
 */
HOOK void li2_null_hook(const void *context)
{
    (void)context;
    __asm__ volatile("" ::: "memory");
}
HOOK void li2_record_hook(const void *context)
{
    const uint64_t pc = *(const volatile uint64_t *)context;
    li2_journal_record(&li2_journal, pc);
}

struct li2_run_contract {
    uint64_t guard_low;
    uint64_t mapping_begin;
    uint64_t mapping_bytes;
    uint64_t writable_begin;
    uint64_t writable_bytes;
    uint64_t array_begin;
    uint64_t array_end;
    uint64_t length;
    uint64_t dataset_id;
    uint64_t phase;
    uint64_t guard_high;
};
_Static_assert(sizeof(struct li2_run_contract) == 88, "run contract ABI");
_Static_assert(offsetof(struct li2_run_contract, array_begin) == 40, "array base ABI");
_Static_assert(offsetof(struct li2_run_contract, length) == 56, "array length ABI");
_Static_assert(offsetof(struct li2_run_contract, phase) == 72, "phase ABI");
volatile struct li2_run_contract li2_run = {
    .guard_low = RUN_GUARD_LOW, .guard_high = RUN_GUARD_HIGH
};

static int save_journal(const char *path)
{
    /* Record the full fixed buffer even on a later journal/array check failure.
     * The owning recipe must supply an admitted fresh canonical output parent.
     */
    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    const unsigned char *bytes = (const unsigned char *)(const void *)&li2_journal;
    size_t done = 0;
    while (done < sizeof(li2_journal)) {
        const ssize_t n = write(fd, bytes + done, sizeof(li2_journal) - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            (void)close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    return close(fd);
}

static int journal_valid(void)
{
    if (li2_journal.guard_low != LI2_JOURNAL_GUARD_LOW ||
        li2_journal.guard_high != LI2_JOURNAL_GUARD_HIGH ||
        li2_journal.version != LI2_JOURNAL_VERSION ||
        li2_journal.capacity != LI2_JOURNAL_CAPACITY ||
        li2_journal.active != 0 || li2_journal.count > LI2_JOURNAL_CAPACITY ||
        li2_journal.overflow != 0 || li2_journal.fault != 0 || li2_journal.reserved != 0)
        return 0;
    for (uint64_t i = li2_journal.count; i < LI2_JOURNAL_CAPACITY; ++i)
        if (li2_journal.pcs[i] != 0)
            return 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fputs("usage: heap-sort DATASET NEW_JOURNAL_FILE\n", stderr);
        return 64;
    }
    size_t id = 0;
    while (id < LI2_DATASET_COUNT && strcmp(argv[1], li2_datasets[id].name) != 0)
        ++id;
    if (id == LI2_DATASET_COUNT || sysconf(_SC_PAGESIZE) != (long)PAGE_BYTES) {
        fputs("dataset or page-size refusal\n", stderr);
        return 65;
    }
    const struct li2_dataset *const dataset = &li2_datasets[id];
    if (dataset->length > MAX_ELEMENTS || ARRAY_OFFSET + dataset->length * 8 > PAGE_BYTES) {
        fputs("dataset bound refusal\n", stderr);
        return 65;
    }
    unsigned char *const mapping = mmap(NULL, PAGE_BYTES * 3, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fputs("array mapping failure\n", stderr);
        return 66;
    }
    unsigned char *const middle = mapping + PAGE_BYTES;
    if (mprotect(middle, PAGE_BYTES, PROT_READ | PROT_WRITE) != 0) {
        (void)munmap(mapping, PAGE_BYTES * 3);
        fputs("array protection failure\n", stderr);
        return 66;
    }
    memset(middle, 0xa5, PAGE_BYTES);
    uint64_t *const array = (uint64_t *)(void *)(middle + ARRAY_OFFSET);
    for (size_t i = 0; i < dataset->length; ++i)
        array[i] = dataset->input[i];
    li2_run.mapping_begin = (uintptr_t)mapping;
    li2_run.mapping_bytes = PAGE_BYTES * 3;
    li2_run.writable_begin = (uintptr_t)middle;
    li2_run.writable_bytes = PAGE_BYTES;
    li2_run.array_begin = (uintptr_t)array;
    li2_run.array_end = (uintptr_t)(array + dataset->length);
    li2_run.length = dataset->length;
    li2_run.dataset_id = id;
    li2_run.phase = 1;
    li2_journal.active = 1;
    li2_before_sort();
    li2_heap_sort(array, dataset->length);
    li2_after_sort();
    li2_journal.active = 0;
    li2_run.phase = 2;
    int valid = journal_valid();
    valid = valid && li2_run.guard_low == RUN_GUARD_LOW && li2_run.guard_high == RUN_GUARD_HIGH;
    for (size_t i = 0; i < ARRAY_OFFSET; ++i)
        valid = valid && middle[i] == 0xa5;
    for (size_t i = ARRAY_OFFSET + dataset->length * 8; i < PAGE_BYTES; ++i)
        valid = valid && middle[i] == 0xa5;
    for (size_t i = 0; i < dataset->length; ++i)
        valid = valid && array[i] == dataset->expected[i];
    /* Writing the raw journal is evidence retention, not a successful verdict. */
    if (save_journal(argv[2]) != 0) {
        (void)munmap(mapping, PAGE_BYTES * 3);
        fputs("journal output failure\n", stderr);
        return 67;
    }
    if (!valid) {
        (void)munmap(mapping, PAGE_BYTES * 3);
        fputs("array or journal invariant failure\n", stderr);
        return 68;
    }
    printf("case=%s n=%zu sorted=", dataset->name, dataset->length);
    for (size_t i = 0; i < dataset->length; ++i)
        printf("%s%" PRIu64, i == 0 ? "" : ",", array[i]);
    putchar('\n');
    if (fflush(stdout) != 0 || munmap(mapping, PAGE_BYTES * 3) != 0) {
        fputs("output or unmap failure\n", stderr);
        return 69;
    }
    return 0;
}
