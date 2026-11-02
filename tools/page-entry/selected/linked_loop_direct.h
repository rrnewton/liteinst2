#ifndef LI2_LINKED_LOOP_DIRECT_H
#define LI2_LINKED_LOOP_DIRECT_H
#include "linked_direct_dispatch.h"
#if !defined(LI2_PERSISTENT_LOOP_PLAN) || LI2_PERSISTENT_LOOP_PLAN != 1
#error "far DIRECT requires the distinct LOOP plan profile"
#endif
#define LI2_LD_VERSION 2U
/* Same bounded record/storage; only out-of-range original-PC miss transfers
   use version2. Descriptor syntax remains the exact original version1.
   The 8-byte target is immutable image data, never a recovery boundary. */
int li2_ld_emit(uintptr_t,const unsigned char *,size_t,unsigned,uintptr_t,uintptr_t,
    const struct li2_jd_binding *,const uintptr_t[2],struct li2_dd_plan *);
int li2_ld_validate(const struct li2_dd_plan *);
/* Requires the same fully authenticated sealed plan and exact savedPC contract
   as the old recovery. No decoding, memory reads or entry authority. */
int li2_ld_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
#endif
