#ifndef LI2_STEP_OWNER_H
#define LI2_STEP_OWNER_H
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include "decoder.h"

#define LI2_STEP_PAGE 4096UL
#define LI2_STEP_FP_BYTES 65536UL
#define LI2_STEP_TF UINT64_C(0x100)
#define LI2_STEP_RF UINT64_C(0x10000)

enum li2_step_phase { LI2_STEP_EMPTY, LI2_STEP_ARMED, LI2_STEP_OPENING,
    LI2_STEP_RUNNING, LI2_STEP_REVOKING, LI2_STEP_COMPLETE, LI2_STEP_FAILED };
enum li2_step_error { LI2_STEP_ARGUMENT=1, LI2_STEP_REUSE, LI2_STEP_IDENTITY,
    LI2_STEP_ENCODING, LI2_STEP_INPUT_FLAGS, LI2_STEP_PAGE_BINDING,
    LI2_STEP_FOREIGN_EVENT, LI2_STEP_REENTRY, LI2_STEP_FRAME,
    LI2_STEP_OPEN, LI2_STEP_SYNC_OPEN, LI2_STEP_REVOKE,
    LI2_STEP_SYNC_REVOKE, LI2_STEP_RESULT, LI2_STEP_SELFTEST };
enum li2_step_effect { LI2_STEP_UNCHANGED, LI2_STEP_MOV_IMMEDIATE,
    LI2_STEP_MOV_REGISTER };

/* Descriptive handles from the real mapping owner, never scalar permits.
   authenticate must inspect the still-owned mapping/source generation and
   actual protection. It must not allocate, mutate permissions or use TLS. */
struct li2_step_page {
    uintptr_t address;
    uint64_t object, generation, offset;
    int closed_prot, open_prot;
};
struct li2_step_request {
    struct li2_decoded decoded;
    struct li2_step_page pages[2];
    size_t page_count;
    /* Independently observed at a known-input boundary, not inferred by
       clearing RF in an NX fault frame. General first-entry RF is not solved. */
    uint64_t original_flags;
};
struct li2_step_frame {
    greg_t greg[NGREG];
    uint64_t mask;
    uintptr_t fp_address;
    size_t fp_bytes, initialized;
    unsigned char fp[LI2_STEP_FP_BYTES] __attribute__((aligned(64)));
};
struct li2_step_owner;
struct li2_step_hooks {
    void *context;
    int (*authenticate)(void *,const struct li2_step_page *,int);
    /* Best-effort bounded diagnostics only. Returning cannot resume target. */
    void (*failure)(void *,const struct li2_step_owner *);
};
struct li2_step_session {
    long pid,tid,sync_register,sync_query;
    uint64_t application_mask;
    unsigned initialized,self_test_complete;
};
struct li2_step_owner {
    enum li2_step_phase phase;
    unsigned first_error,in_handler,self_test,trace_seen,revoke_sync_started;
    long first_detail;
    struct li2_step_session *session;
    struct li2_step_hooks hooks;
    struct li2_step_request request;
    struct li2_step_frame before,after;
    unsigned open_started[2],opened[2],revoke_started[2],revoked[2];
    long open_result[2],revoke_result[2],open_sync,revoke_sync;
    int signal_number,signal_code,signal_errno;
    uintptr_t signal_address;
    unsigned destination,width;
    uint64_t immediate;
    enum li2_step_effect effect;
    unsigned source; /* architectural register index, 16 when not applicable */
};

/* All objects are zero-initialized fixed owners, retained to process exit.
   Caller has actual singleton/external-debug exclusion, reserved default
   SIGSEGV/SIGTRAP, a guarded alternate stack, no CET, and no rseq unless the explicit registered-inactive runtime supplies
   its pre-registration zero-word, every pre-effect write, mapping and signal-
   frame proofs (the default rseq exclusion remains) and an immutable
   private source with no writable alias. Async signals are blocked. The
   fixture establishes these separately; this API does not invent them. */
int li2_step_session_init(struct li2_step_session *,uint64_t application_mask);
int li2_step_arm(struct li2_step_owner *,struct li2_step_session *,
                const struct li2_step_hooks *,const struct li2_step_request *,int self_test);
/* Called only by the real reserved signal dispatcher. Neither success path
   changes RIP/RSP, a GPR, uc_sigmask or any byte of the kernel FP frame. Begin
   owns TF; trace removes that bit only after revoke+sync succeeds. */
void li2_step_begin(struct li2_step_owner *,int,siginfo_t *,ucontext_t *);
void li2_step_trace(struct li2_step_owner *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_step_abort(struct li2_step_owner *,unsigned,long);
long li2_step_raw(long,long,long,long,long,long,long);
#endif
