#ifndef LI2_NATIVE_PAGES_H
#define LI2_NATIVE_PAGES_H
#include <stdint.h>
#include <stddef.h>
struct li2_native_counts {
    uint64_t attempts,admissions,closed,blocked,low_address_refusals;
    unsigned last_block;
    uint64_t first_admission_ns,first_source_offset,revisit_count,revisit_ns[16];
};
/* Only the lifecycle owner can make these transitions. All existing pending
   owners and instruction borrows must be empty. Admission authenticates live
   source, backing, aliases, both halos and the whole process address domain. */
int li2_lifecycle_native_admit(uintptr_t pc);
void li2_lifecycle_native_close(void);
const struct li2_native_counts *li2_lifecycle_native_counts(void);
#endif
