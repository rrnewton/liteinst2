/* Separate E9 clean-call ABI. This is authored source, not E9 implementation.
 * Root must derive LI2_JOURNAL_ADDRESS from the authenticated original ET_EXEC
 * symbol, then bind this compiled hook ELF and both header/source bytes.
 */
#include "journal.h"
#ifndef LI2_JOURNAL_ADDRESS
#error "LI2_JOURNAL_ADDRESS must be the exact admitted original li2_journal symbol"
#endif
_Static_assert((uint64_t)LI2_JOURNAL_ADDRESS != 0, "no default journal address");
_Static_assert(((uint64_t)LI2_JOURNAL_ADDRESS & 7) == 0, "journal word alignment");

__attribute__((noipa, noinline, used, visibility("default")))
void li2_e9_null(uint64_t pc)
{
    (void)pc;
    __asm__ volatile("" ::: "memory");
}

__attribute__((noipa, noinline, used, visibility("default")))
void li2_e9_record(uint64_t pc)
{
    volatile struct li2_journal *const journal =
        (volatile struct li2_journal *)(uintptr_t)(uint64_t)LI2_JOURNAL_ADDRESS;
    li2_journal_record(journal, pc);
}
