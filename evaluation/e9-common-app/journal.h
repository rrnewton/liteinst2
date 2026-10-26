/* Shared, bounded instrumentation-private journal. No runtime/library calls. */
#ifndef LI2_COMMON_APP_JOURNAL_H
#define LI2_COMMON_APP_JOURNAL_H
#include <stddef.h>
#include <stdint.h>

#define LI2_JOURNAL_CAPACITY UINT64_C(16384)
#define LI2_JOURNAL_GUARD_LOW UINT64_C(0x6c69326a6f75726e)
#define LI2_JOURNAL_GUARD_HIGH UINT64_C(0x7265636f72647321)
#define LI2_JOURNAL_VERSION UINT64_C(1)

struct li2_journal {
    uint64_t guard_low;
    uint64_t version;
    uint64_t capacity;
    uint64_t active;
    uint64_t count;
    uint64_t overflow;
    uint64_t fault;
    uint64_t reserved;
    uint64_t pcs[LI2_JOURNAL_CAPACITY];
    uint64_t guard_high;
};
_Static_assert(sizeof(uint64_t) == 8, "64-bit words required");
_Static_assert(sizeof(void *) == 8, "x86-64 address width required");
_Static_assert(offsetof(struct li2_journal, pcs) == 64, "journal header ABI");
_Static_assert(offsetof(struct li2_journal, guard_high) == 131136, "journal tail ABI");
_Static_assert(sizeof(struct li2_journal) == 131144, "journal full size ABI");

/* Single-threaded only. Every access is a volatile word. Publish count last.
 * The compile-time bound, not mutable capacity, protects the PC array.
 * A bad header/phase or an exhausted journal is sticky failure, not success.
 */
static __attribute__((always_inline)) inline void
li2_journal_record(volatile struct li2_journal *j, uint64_t pc)
{
    if (j->guard_low != LI2_JOURNAL_GUARD_LOW ||
        j->guard_high != LI2_JOURNAL_GUARD_HIGH ||
        j->version != LI2_JOURNAL_VERSION ||
        j->capacity != LI2_JOURNAL_CAPACITY || j->reserved != 0) {
        j->fault = UINT64_C(1);
        return;
    }
    if (j->active != UINT64_C(1)) {
        j->fault = UINT64_C(2);
        return;
    }
    if (j->fault != 0 || j->overflow != 0)
        return;
    const uint64_t n = j->count;
    if (n >= LI2_JOURNAL_CAPACITY) {
        j->overflow = UINT64_C(1);
        return;
    }
    j->pcs[n] = pc;
    j->count = n + UINT64_C(1);
}
#endif
