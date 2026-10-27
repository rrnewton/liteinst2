#ifndef LI2_FORK_PROFILE_H
#define LI2_FORK_PROFILE_H
/* Fixed private storage lies in the bridge's protected PT_LOAD mappings. */
#define FORK_WAIT_RECORDS 8
#define FORK_COUNTERS 15
struct fork_wait_record { long args[6],result; unsigned completed; };
struct fork_profile_state {
    unsigned enabled,role,attempted,returned,child_ready,fail_step;
    int sinks[2];
    struct stat sink_identity[2];
    long before_pid,self_pid,parent_pid,fork_result,child_pid;
    uintptr_t application_pc,application_sp;
    uint64_t inherited[FORK_COUNTERS];
    struct li2_lifecycle_counts inherited_lifecycle;
    long child_pid_result,child_tid_result,cpuid_before,cpuid_set,cpuid_after;
    long tsc_query,tsc_set,tsc_after_query,membarrier_register,membarrier_query,sud_set;
    int tsc_before,tsc_after;
    unsigned setup_started,setup_complete;
    uint64_t gate_observed;
    size_t wait_used;
    struct fork_wait_record waits[FORK_WAIT_RECORDS];
};
static struct fork_profile_state fork_profile;
static stack_t fork_gate_stack;
static struct action fork_gate_action;
static void handler(int,siginfo_t *,void *);
static void fork_configure(void);
static void fork_report(unsigned,unsigned,long);
static int fork_dispatch(long,const long[6],ucontext_t *,long *);
static int fork_reserved_fd(long);
static int fork_sink_alias(long);
#endif
