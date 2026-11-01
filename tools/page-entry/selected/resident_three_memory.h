#ifndef LI2_RESIDENT_THREE_MEMORY_H
#define LI2_RESIDENT_THREE_MEMORY_H
#include <stddef.h>
#include "maps_phase.h"
#if !defined(LI2_RESIDENT_THREE_CAPTURE) || LI2_RESIDENT_THREE_CAPTURE != 1 || \
    !defined(LI2_MAPS_MAINTAINED) || LI2_MAPS_MAINTAINED != 1
#error "D3 observation requires its explicit maintained capture profile"
#endif
#if !defined(LI2_RESIDENT_THREE) || LI2_RESIDENT_THREE != 1 || defined(LI2_PERSISTENT_CALL_DISPATCH)
#error "distinct CALL-off D3 stack observer"
#endif
/* This is an observation of the original kernel stack mapping, not permission
   to execute generated code. The runtime still excludes the entire prospective
   envelope from every protected/source/rseq range before capture or spills,
   binds the real source lifetime and seals its separate activation window.
   It is not a proof of a stable stack VALUE and must not authorize RET rereads. */
struct li2_r3o_stack {
    uintptr_t anchor,origin_first,origin_end,first,end;
    uint64_t origin_acquisition;
    struct li2_maps_observation observation;
};
/* May refresh the maintained view (including differential comparison), but
   never reads or writes guest bytes. Caller supplies a distinct, live owned
   output. Refusal leaves that output untouched. The span must be inside the
   original bootstrap extent; a private anonymous replacement is refused. */
/* Pure necessary coarse test: no observer, output write or guest access. It
   grants no mapping permission; query must succeed after actual TRACE close. */
int li2_r3o_stack_advisory(uintptr_t,size_t);
int li2_r3o_stack_query(uintptr_t,size_t,struct li2_r3o_stack *);
struct li2_r3o_memory {
    unsigned attempted,complete,site,copied;
    int result;
    uintptr_t rsp;
    struct li2_r3o_stack origin;
    struct li2_maps_stats before,after;
    unsigned char stack[520];
};
int li2_lifecycle_r3o_memory(uintptr_t,unsigned,struct li2_r3o_memory *);
#endif
