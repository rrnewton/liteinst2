#ifndef LI2_REGISTER_RUN_REUSE_H
#define LI2_REGISTER_RUN_REUSE_H
#include "register_run_reset.h"
#if !defined(LI2_RUN_CACHE_REUSE)
#error "reuse API requires LI2_RUN_CACHE_REUSE"
#endif
#if defined(LI2_RUN_TIMING) || defined(LI2_ENTRY_TIMING)
#error "immutable publication timing is not qualified for cache reuse"
#endif
/* Linked trusted runtime reads actual singleton owners. No caller-provided
   allow flag/callback. PUBLISH and REVALIDATE allow only this exact new borrow,
   REGISTER_RUN pending route and its rseq pin; QUIESCE requires all consumers
   closed and no held fetch. Zero means all required checks passed; nonzero is
   retained as LI2_CACHE_REUSE detail. Query/guard observations, including rseq
   revalidation, may advance. No app/source/frame/permission mutation or minted
   execution authority is authorized by this interface. */
enum li2_run_reuse_stage {
    LI2_REUSE_PUBLISH=1, LI2_REUSE_REVALIDATE=2, LI2_REUSE_QUIESCE=3
};
int li2_run_reuse_runtime(enum li2_run_reuse_stage,const struct li2_fetch_ref *);
void li2_run_reuse_runtime_failure(const struct li2_run_owner *);
/* Copy by VALUE. Words are descriptive; only the private outstanding lookup
   and registered real-owner lease authorize use. Never point into token slots. */
struct li2_run_handle { uint64_t opaque[4]; };
enum li2_run_retire_phase {
    LI2_RETIRE_NONE, LI2_RETIRE_INSTALLED, LI2_RETIRE_REVOKED,
    LI2_RETIRE_WRITABLE, LI2_RETIRE_REPLACED, LI2_RETIRE_FAILED
};
struct li2_run_retirement {
    enum li2_run_retire_phase phase;
    struct li2_run_handle old_handle;
    struct li2_run_publication_progress old_publication;
    uint64_t completion,attempt;
    uintptr_t entry;
    unsigned consumed,rx_checked,revoke_started,revoke_complete,sync_started;
    unsigned writable_started,writable_complete,cleanup_started,cleanup_complete;
    long revoke_result,sync_result,writable_result,cleanup_result,cleanup_sync_result;
    unsigned first_error;long first_detail;
    size_t verified_bytes;
    struct li2_private_code_query rx,revoked,writable,cleanup;
};
struct li2_run_reuse_observation {
    uint64_t generation,completions,copied_instructions,retirements;
    size_t cursor;
    unsigned lookup,lease,reset_pending,publication_present;
    struct li2_run_handle current;
    struct li2_run_publication_progress publication;
    struct li2_run_retirement retirement;
};
int li2_run_reuse_initialize(struct li2_step_session *,const struct li2_run_protection *,
    struct li2_run_owner *,struct li2_run_completion_history *,struct li2_run_cache **);
int li2_run_reuse_publish(struct li2_run_cache *,const struct li2_fetch_ref *,
    const struct li2_run_plan *,struct li2_run_handle *);
int li2_run_reuse_arm(struct li2_run_cache *,struct li2_run_handle,
    struct li2_run_owner *,const struct li2_fetch_ref *,uint64_t);
int li2_run_reuse_quiesce(struct li2_run_cache *,struct li2_run_completion_history *,
    const ucontext_t *);
/* Descriptive copies only. Invalid/stale handles refuse, never resolve to a
   different generation. Historical owner.publication must not be dereferenced. */
int li2_run_reuse_snapshot(const struct li2_run_cache *,struct li2_run_reuse_observation *);
int li2_run_reuse_publication(const struct li2_run_cache *,struct li2_run_handle,
    struct li2_run_publication_progress *);
/* Internal mandatory hooks: mode is derived from the singleton, not the owner.
   No hook constructs a lease or accepts caller scalar authority. */
int li2_run_reuse_enabled(void);
int li2_run_reuse_arm_check(struct li2_run_owner *,struct li2_step_session *,
    const struct li2_fetch_ref *,uint64_t,const struct li2_run_publisher *,
    const struct li2_run_publication *);
int li2_run_reuse_enter_check(struct li2_run_owner *,enum li2_run_phase);
int li2_run_reuse_observe_owner(struct li2_run_owner *,struct li2_run_slot_observation *);
int li2_run_reuse_reset_ready(struct li2_run_owner *,struct li2_run_completion_history *);
void li2_run_reuse_reset_committed(void);
#endif
