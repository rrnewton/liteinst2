/* Partial all-NX controller prototype. One owned instruction at a time. */
#ifdef LI2_ONESHOT_PUBLICATION
#include "oneshot.h"
#define SELECTED_MASK LI2_ONESHOT_MASK
#else
#define SELECTED_MASK (UINT64_MAX & ~(UINT64_C(1)<<(SIGSEGV-1)) & ~(UINT64_C(1)<<(SIGTRAP-1)) & ~(UINT64_C(1)<<(SIGSYS-1)) & ~(UINT64_C(1)<<(SIGKILL-1)) & ~(UINT64_C(1)<<(SIGSTOP-1)))
#endif
#define SELECTED_RF UINT64_C(0x10000)
#define SELECTED_TF UINT64_C(0x100)
#ifdef LI2_REGISTER_RUN
#include "register_run_reset.h"
static struct li2_run_cache *selected_run_cache;
static struct li2_run_owner selected_run_owner;
static struct li2_run_completion_history selected_run_history;
static struct li2_run_plan selected_run_plan;
static const struct li2_run_publication *selected_run_publication;
#ifdef LI2_RUN_CACHE_REUSE
#include "register_run_reuse.h"
static struct li2_run_handle selected_run_handle;
static ucontext_t *selected_run_reuse_frame;
#endif
static struct li2_run_nested selected_run_interrupted;
static volatile sig_atomic_t selected_run_failing;
static uint64_t selected_run_plan_misses;
static struct li2_run_brk_observation selected_run_private_brk;
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
static const struct li2_tf_run_entry *selected_run_trace_origin;
static volatile sig_atomic_t selected_run_trace_busy;
static volatile sig_atomic_t selected_run_trace_active;
static uint64_t selected_run_trace_candidates,selected_run_trace_preflight_misses;
static uint64_t selected_run_trace_attempts,selected_run_trace_entries,selected_run_trace_completed;
static uint64_t selected_run_trace_plan_misses,selected_run_trace_full_misses;
#endif
#ifdef LI2_RUN_TIMING
#include "register_run_timing.h"
static struct li2_run_timing selected_run_timing;
#endif
#endif
static struct li2_step_session selected_session;
static struct li2_step_owner selected_step;
/* The old pending bit continues to guard every existing dispatch boundary.
   This tag chooses the sole cleanup owner; it is never execution authority. */
enum selected_pending_route { SELECTED_NO_STEP, SELECTED_OLD_STEP, SELECTED_GENERIC_TF, SELECTED_REPEAT
#ifdef LI2_ONESHOT_PUBLICATION
    , SELECTED_ONESHOT
#endif
#ifdef LI2_REGISTER_RUN
    , SELECTED_REGISTER_RUN
#endif
#ifdef LI2_REPEAT_RX_LEASE
    , SELECTED_REPEAT_LEASE
#endif
#ifdef LI2_UNROLLED_HASH
    , SELECTED_UNROLLED_HASH
#endif
#ifdef LI2_SCALAR_REGION
    , SELECTED_SCALAR_REGION
#endif
#ifdef LI2_SCALAR_SPAN_TRACE
#ifdef LI2_LINKED_EPOCH
    , SELECTED_LINKED_EPOCH
#else
    , SELECTED_SCALAR_SPAN
#endif
#endif
};
static volatile sig_atomic_t selected_pending_route;
#ifdef LI2_REPEAT_RX_LEASE
#include "repeat_lease.h"
static struct li2_repeat_lease_owner selected_repeat_lease;
static struct li2_tf_continuation selected_repeat_lease_query;
static uint64_t selected_repeat_lease_queries;
static unsigned selected_repeat_lease_initialized;
#endif
static struct li2_repeat_owner selected_repeat;
static struct li2_step_request selected_repeat_request;
static struct li2_fetch_ref selected_repeat_borrow;
static unsigned selected_repeat_borrow_held;
static struct li2_tf_continuation selected_repeat_query,selected_repeat_previous_query;
static uint64_t selected_repeat_attempts,selected_repeat_steps,selected_repeat_traces;
static uint64_t selected_repeat_queries;
static unsigned selected_repeat_release_started,selected_repeat_release_complete;
static int selected_repeat_release_result;
#ifdef LI2_TF_HANDOFF
#include "tf_chain.h"
static struct li2_tf_chain selected_chain;
#define selected_tf (selected_chain.slots[selected_chain.active].owner)
#define selected_tf_continuation (selected_chain.slots[selected_chain.active].query)
#define selected_tf_attempts (selected_chain.attempts)
#define selected_tf_steps (selected_chain.steps)
#define selected_tf_release_started (selected_chain.slots[selected_chain.active].release.started)
#define selected_tf_release_complete (selected_chain.slots[selected_chain.active].release.complete)
#define selected_tf_release_result (selected_chain.slots[selected_chain.active].release.result)
#else
static struct li2_tf_owner selected_tf;
static struct li2_tf_continuation selected_tf_continuation;
static uint64_t selected_tf_attempts,selected_tf_steps;
static unsigned selected_tf_release_started,selected_tf_release_complete;
static int selected_tf_release_result;
#endif
static struct li2_fetch_ref selected_borrow;
static struct li2_fetch_view selected_view;
static struct li2_selected_hardware selected_hardware;
static struct li2_selected_completion selected_completion;
static struct li2_decoded selected_decoded;
static struct li2_decoder_stats selected_initial_stats;
static unsigned char selected_arena[2*1024*1024] __attribute__((aligned(64)));
static volatile sig_atomic_t selected_step_pending,selected_selftesting;
static uint64_t selected_steps,selected_provider_calls[3],selected_source_syscalls,selected_selftests;
static uint64_t selected_logical_flags;
static unsigned selected_flags_known;
extern uint64_t li2_saved[17];
uint64_t selected_selftest_flags;
extern void selected_selftest_enter(uintptr_t);
extern void selected_selftest_return(void);

static unsigned selected_vdso_close_attempted,selected_vdso_close_observed,selected_vdso_closed;
static long selected_vdso_close_result;
struct selected_builtin_prefix {
    uint32_t kind;
    volatile sig_atomic_t phase;
    long enable_result,restore_result;
    uint32_t a,b,c,d;
};
static struct selected_builtin_prefix selected_builtin_prefix;

#ifdef LI2_ONESHOT_PUBLICATION
#ifdef LI2_ONESHOT_REUSABLE
static struct li2_oneshot_owner selected_oneshot_current,selected_oneshot_last,selected_oneshot_last_refused;
struct selected_oneshot_counts {
    uint64_t attempted,published,restored,completed,retired;
    uint64_t cpuid,syscall,rdtsc,effect_started,effect_returned,refused;
};
static struct selected_oneshot_counts selected_oneshot_counts;
static volatile sig_atomic_t selected_oneshot_resetting;
static unsigned selected_oneshot_current_effect_started,selected_oneshot_current_effect_returned;
#else
static struct li2_oneshot_owner selected_oneshot_owners[LI2_ONESHOT_LIFECYCLE_SLOTS];
#endif
static struct li2_oneshot_owner *selected_oneshot_active;
static struct li2_oneshot_plan selected_oneshot_request;
static struct li2_oneshot_handoff selected_oneshot_handoff;
static volatile unsigned selected_oneshot_failing;
#ifndef LI2_ONESHOT_REUSABLE
static volatile unsigned selected_oneshot_used;
static volatile unsigned selected_oneshot_effect_started[LI2_ONESHOT_LIFECYCLE_SLOTS];
static volatile unsigned selected_oneshot_effect_returned[LI2_ONESHOT_LIFECYCLE_SLOTS];
#endif
#endif
