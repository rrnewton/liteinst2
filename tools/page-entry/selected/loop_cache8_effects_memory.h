#ifndef LI2_LOOP_CACHE8_EFFECTS_MEMORY_H
#define LI2_LOOP_CACHE8_EFFECTS_MEMORY_H
#include "lifecycle_loader.h"
#define LC8E_SOURCE UINT64_C(0x410000)
#define LC8E_SOURCE_BYTES 24576U
#define LC8E_DATA UINT64_C(0x500000000000)
#define LC8E_DATA_BYTES 8192U
#define LC8E_STACK UINT64_C(0x500000100000)
#define LC8E_RSP (LC8E_STACK+4096U+128U*1024U-504U)
#define LC8E_STACK_BYTES 224U
#define LC8E_STATE UINT64_C(0x800000)
/* Fixed scalar wire. No pointer in it is dereferenced as runtime authority. */
struct lc8e_memory {
    uint64_t h[16],life[18],maps[16],before[10],after[10];
    uint64_t source_page[6][24],guest[3][8],state[32];
    unsigned char source[LC8E_SOURCE_BYTES],data[LC8E_DATA_BYTES],stack[LC8E_STACK_BYTES];
};
_Static_assert(sizeof(struct lc8e_memory)==35152,"literal effects physical-memory record");
int li2_lifecycle_cache8_effects_memory(struct lc8e_memory *);
#endif
