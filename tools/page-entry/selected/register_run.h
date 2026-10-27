#ifndef LI2_REGISTER_RUN_H
#define LI2_REGISTER_RUN_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include "decoder.h"
#include "step_owner.h"
#include "tf_continuation.h"

#define LI2_RUN_SOURCE_BYTES 15U
#define LI2_RUN_MAX_INSTRUCTIONS 14U
#define LI2_RUN_CODE_BYTES 29U
#define LI2_RUN_POLICY 1U

enum li2_run_status {
    LI2_RUN_OK=0, LI2_RUN_SLOW=1, LI2_RUN_ARGUMENT=700,
    LI2_RUN_DECODE, LI2_RUN_PLAN, LI2_RUN_REUSE, LI2_RUN_SESSION,
    LI2_RUN_PUBLICATION_MISSING, LI2_RUN_PUBLICATION, LI2_RUN_FETCH,
    LI2_RUN_CONTINUATION, LI2_RUN_EVENT, LI2_RUN_FLAGS, LI2_RUN_FRAME,
    LI2_RUN_RESULT, LI2_RUN_REENTRY, LI2_RUN_RELEASE
};
enum li2_run_effect { LI2_RUN_NOP=0, LI2_RUN_IMMEDIATE=1, LI2_RUN_REGISTER=2 };
struct li2_run_instruction {
    uint32_t code;
    unsigned char offset,length,effect,destination,source,width;
    uint64_t immediate;
};
/* Descriptive only. A copied plan never grants source or generated-code authority.
   The complete guard is in source[] but NOT in generated[]. */
struct li2_run_plan {
    uint32_t policy,decoder_result;
    uintptr_t pc,stop;
    size_t source_length,run_length,instruction_count,generated_length;
    unsigned char source[LI2_RUN_SOURCE_BYTES];
    unsigned char generated[LI2_RUN_CODE_BYTES];
    struct li2_run_instruction instructions[LI2_RUN_MAX_INSTRUCTIONS];
    struct li2_decoded guard;
};
int li2_run_plan_bytes(uintptr_t,const unsigned char *,size_t,struct li2_run_plan *);
/* Only successful exact plans are accepted; applies dependent effects in order.
   Used by the owner to compare actual results, never to emulate execution. */
int li2_run_expected(const struct li2_run_plan *,const uint64_t[16],uint64_t[16]);

/* Opaque publisher-owned authority. A complete publication requires actual
   fixed-arena allocation, protected-range registration, W^X, byte verification
   and sync-core. Incomplete owners retain their actual failure prefixes. There
   is no constructor accepting caller scalar fields and no default success hook. */
struct li2_run_publication;
struct li2_run_slot_observation {
    unsigned attempted,owner_observed,mapping_observed,bytes_observed,complete;
    int result,callback_result,actual_prot;
    uintptr_t entry,mapping_first,mapping_end;
    uint64_t allocation,generation;
    size_t length;
    unsigned writable_aliases;
    unsigned char bytes[LI2_RUN_CODE_BYTES];
};
struct li2_run_owner;
struct li2_run_publisher {
    void *context;
    /* Trusted authority boundary, not a predicate supplied by application code.
       Reinspect the genuine live private owner, exact plan binding, protected
       mappings/aliases and completed publication; retain each actual prefix in
       fresh out. No allocation, permission changes, callbacks into app, TLS or
       writes to source/frame. A false success violates this unsafe contract. */
    int (*observe)(void *,const struct li2_run_publication *,
                   const struct li2_run_plan *,struct li2_run_slot_observation *);
    /* Optional bounded diagnostic only. Returning never resumes the target. */
    void (*failure)(void *,const struct li2_run_owner *);
};
enum li2_run_phase {
    LI2_RUN_EMPTY, LI2_RUN_PLANNING, LI2_RUN_MISS, LI2_RUN_ARMED,
    LI2_RUN_ENTERING, LI2_RUN_RUNNING, LI2_RUN_EXIT_CHECKING,
    LI2_RUN_COMPLETE, LI2_RUN_FAILED
};
struct li2_run_event {
    int number,code,error;
    uintptr_t address;
    unsigned observed;
};
struct li2_run_nested {
    struct li2_run_event event;
    greg_t greg[NGREG];
    uint64_t mask;
    unsigned frame_observed;
};
struct li2_run_owner {
    enum li2_run_phase phase;
    unsigned first_error,failure_notified;
    long first_detail;
    volatile sig_atomic_t in_handler;
    struct li2_step_session *session;
    struct li2_fetch_ref borrow;
    struct li2_run_publisher publisher;
    const struct li2_run_publication *publication;
    struct li2_run_plan plan;
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2];
    struct li2_fetch_progress final_fetch;
    size_t page_count;
    uint64_t logical_flags;
    struct li2_run_slot_observation armed_slot,entry_slot,exit_slot;
    struct li2_tf_continuation pre_entry,exit_query;
    struct li2_step_frame before,after;
    struct li2_run_event entry_event,exit_event;
    struct li2_run_nested nested;
    unsigned fetch_view_started,fetch_view_complete,redirected,exit_seen;
    unsigned release_started,release_complete;
    int fetch_result,release_result;
};

/* Fixed zeroed, mutually disjoint private owners retained to process exit.
   Caller already owns the actual singleton/no-debug/no-CET/no-rseq profile,
   blocked asynchronous signals, genuine alternate stack/reserved signal route,
   initialized sealed decoder and genuine step session/selftest. App cannot
   access these owners or the publisher. No app-visible side effects may occur
   between arm and begin, and only the actual dispatcher calls event APIs.
   The caller retains the borrowed source on every arm refusal/MISS; no release
   or fake completion is performed here. A failed lifecycle check may poison
   that borrow and must remain a failure. Owner reuse is intentionally absent. */
int li2_run_arm(struct li2_run_owner *,struct li2_step_session *,
                const struct li2_fetch_ref *,uint64_t logical_flags,
                const struct li2_run_publisher *,const struct li2_run_publication *);
/* Begin changes ONLY saved RIP, to a genuine published entry. No TF is added.
   Exit is a genuine NX SIGSEGV at the retained guard, NOT a TRAP_TRACE. It
   changes no saved state, releases only after all checks, and marks only the
   copied run complete. Guard dispatch needs the ordinary fresh fetch afterward.
   Any actual-event failure is nonreturning; no silent old-route retry. */
void li2_run_begin(struct li2_run_owner *,int,siginfo_t *,ucontext_t *);
void li2_run_exit(struct li2_run_owner *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_run_unexpected(struct li2_run_owner *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_run_abort(struct li2_run_owner *,unsigned,long);
#endif
