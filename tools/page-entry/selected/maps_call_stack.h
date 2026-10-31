#ifndef LI2_MAPS_CALL_STACK_H
#define LI2_MAPS_CALL_STACK_H
#include <stddef.h>
#include "maps_phase.h"
#if !defined(LI2_PERSISTENT_CALL_DISPATCH) || LI2_PERSISTENT_CALL_DISPATCH != 1 || \
    !defined(LI2_MAPS_MAINTAINED) || LI2_MAPS_MAINTAINED != 1
#error "CALL stack provenance requires its explicit maintained profile"
#endif
/* This is an observation of the original kernel stack mapping, not permission
   to execute generated code. The runtime still excludes the entire prospective
   envelope from every protected/source/rseq range before capture or spills,
   binds the real source lifetime and seals its separate activation window.
   It is not a proof of a stable stack VALUE and must not authorize RET rereads. */
struct li2_maps_call_stack {
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
int li2_maps_call_stack_advisory(uintptr_t,size_t);
int li2_maps_call_stack_query(uintptr_t,size_t,struct li2_maps_call_stack *);
#endif
