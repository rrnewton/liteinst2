#ifndef LI2_NATIVE_EPOCH_H
#define LI2_NATIVE_EPOCH_H
#include "step_owner.h"
#include "lifecycle_loader.h"

/* Internal scanner-independent close/ingress API. No operation grants X,
   changes source bytes, certifies an opcode, or qualifies a native epoch. */
enum li2_native_error {
    LI2_NATIVE_ARGUMENT=1450, LI2_NATIVE_STATE, LI2_NATIVE_IDENTITY,
    LI2_NATIVE_REENTRY, LI2_NATIVE_MAPPING, LI2_NATIVE_CLOSE,
    LI2_NATIVE_SYNC, LI2_NATIVE_FRAME, LI2_NATIVE_FOREIGN,
    LI2_NATIVE_FLAGS, LI2_NATIVE_RETRY_CHANGED, LI2_NATIVE_OVERFLOW
};
enum li2_native_entry { LI2_NATIVE_READY=0, LI2_NATIVE_REFAULT=1, LI2_NATIVE_NOT_ACTIVE=2 };
enum li2_native_phase { LI2_NATIVE_EMPTY, LI2_NATIVE_IDLE, LI2_NATIVE_ENTERING,
    LI2_NATIVE_RETRY, LI2_NATIVE_FAILED };
struct li2_native_close {
    uint64_t sequence,allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch,pages,attempted,returned,closed,verified;
    uintptr_t last_address,first_error_address;
    long pid,tid,last_result,sync_result,first_detail;
    unsigned busy,complete,first_error,sync_started,sync_returned;
    unsigned cleanup_started,cleanup_complete;
    size_t cleanup_attempted,cleanup_returned;
    long cleanup_first_result,cleanup_sync_result;
    struct li2_fetch_map_progress before,after;
};
struct li2_native_epoch {
    struct li2_step_session *session;
    unsigned phase,first_error,in_handler,first_observed,second_observed;
    long first_detail;
    uint64_t events,retries,ready,logical_flags;
    int signal_number,signal_code,signal_errno;
    uintptr_t signal_address;
    struct li2_step_frame first,second;
};
/* Retained actual lifecycle owner, not caller-filled result storage. Fatal
   prefix stays occupied; abort is best effort and never a completion permit. */
void li2_lifecycle_native_close(void);
const struct li2_native_close *li2_lifecycle_native_close_progress(void);
void li2_lifecycle_native_close_abort(void);

/* Initialize after the existing real session/self-test; whole bridge storage
   is protected by runtime_arm. A native epoch may be enabled only by a separate
   qualified scanner/admission owner preserving TF-clear execution, singleton
   custody, no registered rseq, and the qualified execution-mode envelope.
   RF is normalized for the next instruction start, not reconstructed before
   the native epoch; the actual fault frame is retained unchanged. This module
   does not establish the scanner or execution-mode policy.
   Call nx only from actual nonnested NX dispatch with no active old owner.
   READY writes only *logical_flags. No return path modifies uc or its FP image.
   REFAULT must return that exact frame through real sigreturn: no synthetic
   NX, no old borrow, no readmission, and no intervening application instruction.
   NOT_ACTIVE retains the old known-flags path; it imports no flags. */
int li2_native_epoch_initialize(struct li2_step_session *);
int li2_native_epoch_nx(int,siginfo_t *,ucontext_t *,uint64_t *logical_flags);
const struct li2_native_epoch *li2_native_epoch_progress(void);
void li2_native_epoch_abort(unsigned,long);
#endif
