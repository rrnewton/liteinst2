#include "witness.h"

/* Real compiled C work. The annotation asserts a state that the producer must
 * independently prove from the actual compiler prefix and original CFI. It is
 * not permission to ignore a prologue, move the site or repair a rejected FDE. */
LI2_UW_PUBLIC LI2_UW_NOINLINE
uint64_t li2_uw_work(const uint8_t *input, size_t length, uint64_t seed,
                     uint64_t *output) {
    __asm__ volatile(
        ".cfi_same_value %%rbx\n"
        ".cfi_same_value %%rbp\n"
        ".cfi_same_value %%r12\n"
        ".cfi_same_value %%r13\n"
        ".cfi_same_value %%r14\n"
        ".cfi_same_value %%r15\n"
        ".global li2_uw_selected\n.hidden li2_uw_selected\n"
        "li2_uw_selected:\n.byte 0x0f,0x1f,0x44,0x00,0x00\n"
        ".global li2_uw_continuation\n.hidden li2_uw_continuation\n"
        "li2_uw_continuation:\n"
        : : : "memory");
    uint64_t value = seed;
    for (size_t i = 0; i < length; ++i)
        value = value * UINT64_C(33) ^ input[i];
    *output = value ^ (uint64_t)length;
    return value;
}

/* A declared readiness/reference walk, never a call to selected work. The
 * post-call operation also makes the intended ordinary return explicit. */
LI2_UW_PUBLIC LI2_UW_NOINLINE
uint64_t li2_uw_reference(uint64_t value) {
    li2_uw_collect_original();
    return value ^ UINT64_C(0x5245464552454e43);
}
