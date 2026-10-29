#include "late.h"
static uint64_t calls;
uint64_t li2_late_leaf(void) {
    return LD_LEAF_MAGIC + ++calls;
}
