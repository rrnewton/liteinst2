#ifndef LI2_REGION_PLAN_H
#define LI2_REGION_PLAN_H
#include <stddef.h>
#include <stdint.h>
#define REGION_HEADS 80
#define REGION_RANGES 160
/* Unsafe caller contract, not a permit: singleton; immutable complete original
   5..80-byte read-only scalar CFG; sole external entry; no saved interior resume,
   aliases, fork/exec, remap, foreign writer or callback; valid data for successful
   calls; bounded termination, no CET; private writable helper stack below the
   preserved 128-byte application red zone. The caller independently owns every
   actual mapping and source generation. Planning does not establish any of it.
   Retain handle until RX is revoked, synchronized and unmapped and no invocation,
   fault frame or observer can reference its image/control/PC metadata. */
struct region_boundary { uint64_t original, generated; };
struct region_range { uint64_t start,end,original; };
struct region_plan {
    uint64_t abi,source,source_bytes,allocation,allocation_bytes,image,image_bytes,entry;
    uint64_t heads,ranges,saved_state_bytes,saved_state_mask;
    const unsigned char *bytes;
    unsigned char source_identity[32];
    struct region_boundary body[REGION_HEADS];
    struct region_range pc[REGION_RANGES];
};
void *region_plan_create(uint64_t base,const unsigned char *code,size_t bytes,
                        const uint64_t *leaders,size_t leader_count,uint64_t ret,
                        uint64_t object,uint64_t generation,const unsigned char identity[32],struct region_plan *out);
uint64_t region_callback_count(void);
void region_plan_destroy(void *handle);
#endif
