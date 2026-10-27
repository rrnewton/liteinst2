/* Partial all-NX controller prototype. One owned instruction at a time. */
#define SELECTED_MASK (UINT64_MAX & ~(UINT64_C(1)<<(SIGSEGV-1)) & ~(UINT64_C(1)<<(SIGTRAP-1)) & ~(UINT64_C(1)<<(SIGSYS-1)) & ~(UINT64_C(1)<<(SIGKILL-1)) & ~(UINT64_C(1)<<(SIGSTOP-1)))
#define SELECTED_RF UINT64_C(0x10000)
#define SELECTED_TF UINT64_C(0x100)
static struct li2_step_session selected_session;
static struct li2_step_owner selected_step;
/* The old pending bit continues to guard every existing dispatch boundary.
   This tag chooses the sole cleanup owner; it is never execution authority. */
enum selected_pending_route { SELECTED_NO_STEP, SELECTED_OLD_STEP, SELECTED_GENERIC_TF, SELECTED_REPEAT };
static volatile sig_atomic_t selected_pending_route;
static struct li2_repeat_owner selected_repeat;
static struct li2_step_request selected_repeat_request;
static struct li2_fetch_ref selected_repeat_borrow;
static unsigned selected_repeat_borrow_held;
static struct li2_tf_continuation selected_repeat_query,selected_repeat_previous_query;
static uint64_t selected_repeat_attempts,selected_repeat_steps,selected_repeat_traces;
static uint64_t selected_repeat_queries;
static unsigned selected_repeat_release_started,selected_repeat_release_complete;
static int selected_repeat_release_result;
static struct li2_tf_owner selected_tf;
static struct li2_tf_continuation selected_tf_continuation;
static uint64_t selected_tf_attempts,selected_tf_steps;
static unsigned selected_tf_release_started,selected_tf_release_complete;
static int selected_tf_release_result;
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
