#ifndef LI2_REGISTER_RUN_PUBLISH_H
#define LI2_REGISTER_RUN_PUBLISH_H
#include "register_run.h"
#include "private_code_query.h"
#define LI2_RUN_CACHE_PAGES 64U
#define LI2_RUN_CACHE_BYTES (LI2_RUN_CACHE_PAGES*LI2_STEP_PAGE)
enum li2_run_cache_error {
    LI2_CACHE_ARGUMENT=740,LI2_CACHE_REUSE,LI2_CACHE_IDENTITY,LI2_CACHE_PROTECTION,
    LI2_CACHE_ALLOCATION,LI2_CACHE_SOURCE,LI2_CACHE_PLAN,LI2_CACHE_WRITE,
    LI2_CACHE_RX,LI2_CACHE_SYNC,LI2_CACHE_QUERY,LI2_CACHE_BYTES,LI2_CACHE_REENTRY,
    LI2_CACHE_BRK,LI2_CACHE_RESET
};
enum li2_run_cache_phase { LI2_CACHE_EMPTY,LI2_CACHE_INITIALIZING,
    LI2_CACHE_READY,LI2_CACHE_FAILED };
enum li2_run_publication_phase { LI2_PUBLICATION_EMPTY,LI2_PUBLICATION_WRITING,
    LI2_PUBLICATION_COMPLETE,LI2_PUBLICATION_FAILED };
/* Trusted runtime adapters, not application callbacks. add() atomically adds
   exactly the supplied interval to the syscall guard; contains() means FULL
   coverage, never merely overlap. Both are required. Code/metadata stay private
   and inaccessible to application mutation throughout this unsafe profile. */
struct li2_run_protection {
    void *context;
    int (*add)(void *,uintptr_t,size_t);
    int (*contains)(void *,uintptr_t,size_t);
};
struct li2_run_cache;
struct li2_run_cache_initialization {
    unsigned metadata_started,metadata_complete,allocation_started,allocated;
    unsigned arena_protection_started,arena_protection_complete,complete;
    long allocation_result;
    int metadata_result,arena_protection_result;
    uintptr_t arena;
    size_t arena_bytes,metadata_bytes;
    struct li2_private_code_query mapping;
};
/* These are retained observations. No field below is an execution permit. */
struct li2_run_publication_progress {
    enum li2_run_publication_phase phase;
    unsigned first_error;long first_detail;
    uint64_t allocation,generation,borrow_sequence;
    uintptr_t entry;
    size_t fill_bytes,code_bytes,verified_bytes;
    unsigned rw_checked,rx_started,rx_complete,sync_started,sync_complete;
    long rx_result,sync_result;
    unsigned cleanup_started,cleanup_complete,cleanup_sync_started;
    long cleanup_result,cleanup_sync_result;
    struct li2_private_code_query before,after,cleanup;
};
struct li2_run_publish_attempt {
    uint64_t ordinal,borrow_sequence;
    unsigned installed,source_complete,plan_complete,hit,miss_before_publication,complete;
    unsigned first_error;long first_detail;
    size_t pages_validated,slot;
    int view_result,validation_result,plan_result;
    struct li2_fetch_progress fetch;
};
struct li2_run_brk_observation {
    unsigned attempted,complete;uintptr_t requested,observed,first,end;
    long query_result;int result;
};
struct li2_run_cache_diagnostic {
    enum li2_run_cache_phase phase;
    unsigned first_error;long first_detail;
    size_t slots_used,complete_slots;
    uint64_t attempts,hits,full_misses;
    unsigned interrupted,interrupted_again;unsigned interrupted_code;
    long interrupted_detail;
    struct li2_run_cache_initialization initialization;
    struct li2_run_publish_attempt last_attempt;
    struct li2_run_brk_observation last_brk;
};
/* One module-owned fixed cache, process lifetime; no destructor/recycling.
   Initialize after lifecycle and the genuine step session, before app entry.
   The session may finish its old selftest afterward; publication requires it.
   *out exposes the retained prefix even on initialization failure. */
int li2_run_cache_initialize(struct li2_step_session *,const struct li2_run_protection *,
                             struct li2_run_cache **out);
/* Requires a NEW genuine held borrow. Rebuilds the supplied descriptive plan.
   Only a full cache returns SLOW, before installing/writing a new publication.
   Every other error is fatal to this cache; caller keeps the actual source
   borrow and routes failure, never retries through the original route. */
int li2_run_cache_publish(struct li2_run_cache *,const struct li2_fetch_ref *,
                          const struct li2_run_plan *,const struct li2_run_publication **);
int li2_run_publication_observe(void *,const struct li2_run_publication *,
                               const struct li2_run_plan *,struct li2_run_slot_observation *);
/* Actual unexpected-event route while publication/inspection is pending.
   Retains the first error and independently revokes an installed WRITING page.
   A nested event during cleanup records reentry without restarting cleanup.
   Caller retains its real event/frame and MUST terminate after this returns;
   this function grants neither continuation nor a source-borrow release. */
int li2_run_cache_interrupt(struct li2_run_cache *,unsigned,long);
/* Mandatory new-route guard before forwarding brk. The other mutating routes
   already refuse registered private ranges; no fork/mremap/alias route is added.
   Other calls leave the last brk observation intact. No argument is rewritten. */
int li2_run_cache_before_syscall(struct li2_run_cache *,long,const long[6]);
const struct li2_run_cache_diagnostic *li2_run_cache_diagnostic(const struct li2_run_cache *);
const struct li2_run_publication_progress *li2_run_publication_progress(
    const struct li2_run_cache *,const struct li2_run_publication *);
const struct li2_private_code_query *li2_run_publication_last_query(
    const struct li2_run_cache *,const struct li2_run_publication *);
#endif
