/* Partial all-NX controller prototype. One owned instruction at a time. */
#define SELECTED_MASK (UINT64_MAX & ~(UINT64_C(1)<<(SIGSEGV-1)) & ~(UINT64_C(1)<<(SIGTRAP-1)) & ~(UINT64_C(1)<<(SIGSYS-1)) & ~(UINT64_C(1)<<(SIGKILL-1)) & ~(UINT64_C(1)<<(SIGSTOP-1)))
#define SELECTED_RF UINT64_C(0x10000)
#define SELECTED_TF UINT64_C(0x100)
static struct li2_step_session selected_session;
static struct li2_step_owner selected_step;
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
