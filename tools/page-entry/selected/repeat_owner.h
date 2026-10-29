#ifndef LI2_REPEAT_OWNER_H
#define LI2_REPEAT_OWNER_H
#include "tf_owner.h"

/* Separate original-PC repeated-instruction protocol. The ordinary TF
   classifier and its REP refusals are unchanged. Canonical F3 48 AB
   (STOSQ) or F3 AB (STOSD), with 64-bit RCX/RDI and either actual DF direction.
   Same singleton/signal/CET/source exclusions as li2_step_owner apply.
   Operand faults are terminal, not application signal delivery/restart. */
enum li2_repeat_error { LI2_REPEAT_ENCODING=200, LI2_REPEAT_PROGRESS,
    LI2_REPEAT_FLAGS, LI2_REPEAT_STATE, LI2_REPEAT_CONTINUATION,
    LI2_REPEAT_OVERFLOW };
struct li2_repeat_permissions {
    unsigned open_started[2],opened[2],revoke_started[2],revoked[2];
    long open_result[2],revoke_result[2],open_sync,revoke_sync;
    unsigned revoke_sync_started;
};
struct li2_repeat_owner {
    struct li2_step_owner step;
    struct li2_tf_hooks hooks;
    uint64_t initial_count,remaining,traces,closed_cycles,reopened_cycles;
    uintptr_t actual_post_pc;
    uint64_t actual_post_flags;
    unsigned final,continuation_started,continuation_complete,unexpected_frame_observed;
    int continuation_result;
    /* Last proved-closed cycle survives the reset of current I/O prefixes.
       This is bounded progress/first-error evidence, not a full trace log. */
    struct li2_repeat_permissions last_closed;
};
/* Exact admitted element width, or zero. Descriptive only: arm still
   redecodes and authenticates the complete source/page request. */
unsigned li2_repeat_width(const struct li2_decoded *);
int li2_repeat_candidate(const struct li2_decoded *);
int li2_repeat_arm(struct li2_repeat_owner *,struct li2_step_session *,
                   const struct li2_tf_hooks *,const struct li2_step_request *);
void li2_repeat_begin(struct li2_repeat_owner *,int,siginfo_t *,ucontext_t *);
/* Returns with RUNNING for an actual intermediate TRACE, COMPLETE only for
   the final original-PC continuation. Caller retains the same fetch borrow
   throughout; it must not count/release a RUNNING instruction. */
void li2_repeat_trace(struct li2_repeat_owner *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_repeat_unexpected(struct li2_repeat_owner *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_repeat_abort(struct li2_repeat_owner *,unsigned,long);
#endif
