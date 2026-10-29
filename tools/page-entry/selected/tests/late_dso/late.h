#ifndef LI2_LATE_DSO_H
#define LI2_LATE_DSO_H
#include "app.h"
#define LD_SONAME "libli2-late.so"
#define LD_LEAF "libli2-late-leaf.so"
#define LD_MAGIC UINT64_C(0x314554414c32494c)
#define LD_LEAF_MAGIC UINT64_C(0x314641454c32494c)
#define LD_CYCLES 2U
struct ld_api {
    uint64_t version;
    int (*setup)(uint64_t, uint64_t);
    int (*step)(unsigned, unsigned, int, uint64_t, const uint32_t[4], struct pa_view *);
    void (*image)(struct pa_image *);
    int (*final)(void);
};
uint64_t li2_late_leaf(void);
void li2_late_note(unsigned, uint64_t);
#endif
