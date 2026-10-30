#ifndef LI2_RSEQ_REGION_LIVE_H
#define LI2_RSEQ_REGION_LIVE_H
#include "write_footprint.h"
#include <sys/ucontext.h>
struct li2_rseq_region_live {
    unsigned attempted,complete,registered;
    int result;
    uintptr_t session;
    uint64_t epoch;
    struct li2_write_registers registers;
};
/* Caller supplies an authentic current frame and complete initially zero,
   protected output disjoint from that frame and all rseq/session storage.
   ONLY the live half of the distinct completed-generation certificate owner;
   this function grants no instruction, write, source or executable authority.
   Before each call the caller must authenticate the actual R/NX immutable
   certificate for the currently claimed slot and monotonic publication
   generation, full source/key/plan/image and exact archive/policy. That same
   generation must own a completed cold proof from the unchanged complete
   region/rseq validators, including every actual original NONE footprint.
   A live slot bit, mirror, hash, old permit, previous generation or supplied
   descriptor is not that proof. Preserve ownership through this check and
   execution, and revoke it before certificate/code mutation or reuse. Current
   frame/TLS/source/permissions, live borrow and cleanup remain caller duties.
   Old li2_rseq_check_region retains its entire original contract. */
int li2_rseq_region_live(const ucontext_t *,struct li2_rseq_region_live *);
#endif
