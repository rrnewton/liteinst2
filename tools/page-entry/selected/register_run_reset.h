#ifndef LI2_REGISTER_RUN_RESET_H
#define LI2_REGISTER_RUN_RESET_H
#include "register_run_publish.h"
/* Fixed protected process-lifetime completion history. Failed/pending owners
   are never copied over or reset. Counters and the latest COMPLETE owner survive
   the next attempt; publications themselves remain owned until process exit. */
struct li2_run_completion_history {
    uint64_t completed_runs,copied_instructions;
    unsigned reset_started,reset_complete,first_error;
    long first_detail;
    struct li2_run_owner last_complete;
};
/* Sole reset edge: immediately after actual li2_run_exit, while still in that
   same handler and BEFORE preparing any other fetch. It checks the unchanged
   real saved endpoint, fresh exit-query/release prefix and exact released fetch
   sequence, retains the complete owner, then clears the reusable attempt only.
   Root must keep its pending route until this succeeds and freshly route the
   still-NX guard afterward. This edits neither actual frame nor publication. */
int li2_run_complete_reset(struct li2_run_owner *,struct li2_run_completion_history *,
                            const struct li2_run_protection *,const ucontext_t *);
#endif
