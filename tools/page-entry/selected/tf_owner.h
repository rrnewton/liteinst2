#ifndef LI2_GENERIC_TF_OWNER_H
#define LI2_GENERIC_TF_OWNER_H
#include "step_owner.h"

/* Descriptive output from the sealed decoder. This is not an RX permit. */
struct li2_tf_classification {
    uint64_t pc,next_pc;
    uint32_t abi_version,policy,code,length,flow,family;
};
_Static_assert(sizeof(struct li2_tf_classification)==40,"TF classification size");
_Static_assert(_Alignof(struct li2_tf_classification)==8,"TF classification alignment");
_Static_assert(offsetof(struct li2_tf_classification,pc)==0 &&
               offsetof(struct li2_tf_classification,next_pc)==8 &&
               offsetof(struct li2_tf_classification,abi_version)==16 &&
               offsetof(struct li2_tf_classification,policy)==20 &&
               offsetof(struct li2_tf_classification,code)==24 &&
               offsetof(struct li2_tf_classification,length)==28 &&
               offsetof(struct li2_tf_classification,flow)==32 &&
               offsetof(struct li2_tf_classification,family)==36,"TF classification offsets");
enum li2_tf_flow { LI2_TF_REFUSED, LI2_TF_FALLTHROUGH, LI2_TF_NEAR_FLOW };
enum li2_tf_family { LI2_TF_NONE, LI2_TF_INTEGER, LI2_TF_STACK,
    LI2_TF_BRANCH, LI2_TF_CALL, LI2_TF_RETURN, LI2_TF_SIMD };
enum li2_tf_error { LI2_TF_CLASSIFICATION=100, LI2_TF_CONTINUATION, LI2_TF_FRAME,
    LI2_TF_RSP_DOMAIN, LI2_TF_XCR_INDEX, LI2_TF_SHSTK_QUERY, LI2_TF_SHSTK_ENABLED, LI2_TF_SHSTK_OBSERVATION, LI2_TF_MPX_ENABLED };
uint32_t li2_decoder_tf_classify(uint64_t,const unsigned char *,size_t,
                               struct li2_tf_classification *);

struct li2_tf_hooks {
    struct li2_step_hooks step;
    /* Read-only: authenticate this actual continuation as live application
       logical RX / actual R, after all temporary source pages were revoked.
       Runtime/vDSO/untracked RX addresses are not application continuations.
       The same source borrow remains held; this must not prepare another one.
       The caller retains a complete query/error prefix before its first I/O. */
    int (*continue_closed)(void *,uintptr_t);
};
/* Actual adjacent CPL3 observations, not a kernel-query-derived permit.
   Exact seeds must both survive; enabled SHSTK writes the same SSP to both. */
#define LI2_SHSTK_SEED_A UINT64_C(0x13579bdf2468ace1)
#define LI2_SHSTK_SEED_B UINT64_C(0xfedcba9876543210)
struct li2_tf_shstk_observation {
    uint64_t version,attempted,complete,reserved,seed_a,seed_b,value_a,value_b;
};
_Static_assert(sizeof(struct li2_tf_shstk_observation)==64,"two-probe evidence size");
int li2_tf_observe_shstk(struct li2_tf_shstk_observation *);
/* Actual XCR0 read; production has no supplied-observation hook. */
uint64_t li2_tf_observe_xcr0(void);
int li2_tf_shstk_observation_disabled(const struct li2_tf_shstk_observation *);
struct li2_tf_owner {
    struct li2_step_owner step;
    struct li2_tf_classification classification;
    struct li2_tf_hooks hooks;
    uintptr_t actual_post_pc;
    uint64_t actual_post_flags;
    unsigned continuation_started,continuation_complete,unexpected_frame_observed;
    int continuation_result;
    /* This retained query belongs only to RDSSPQ's authenticated NX entry.
       Unsupported/error status is not evidence of disabled shadow stacks. */
    unsigned rdssp_query_attempted,rdssp_query_complete;
    long rdssp_query_result;
    uint64_t rdssp_features;
    struct li2_tf_shstk_observation rdssp_observation;
    /* Canonical BND JMP only: attempted precedes XGETBV; complete follows it.
       Both MPX XCR0 bits must be clear before any source RX transition. */
    unsigned bnd_xcr0_attempted,bnd_xcr0_complete;
    uint64_t bnd_xcr0;
};

/* Distinct proof: the CPU executes the original instruction. No emulated GPR,
   flags, memory, branch or FP result is constructed or claimed here. The old
   NOP/MOV owner and its actual startup selftest remain unchanged. Caller owns
   fresh zeroed storage and the old singleton/debug/rseq/signal exclusions. */
int li2_tf_arm(struct li2_tf_owner *,struct li2_step_session *,
               const struct li2_tf_hooks *,const struct li2_step_request *);
void li2_tf_begin(struct li2_tf_owner *,int,siginfo_t *,ucontext_t *);
/* Distinct production path; the original strict query entry stays available. */
void li2_tf_begin_observed_shstk(struct li2_tf_owner *,int,siginfo_t *,ucontext_t *);
void li2_tf_trace(struct li2_tf_owner *,int,siginfo_t *,ucontext_t *);
/* Unexpected real faults retain their actual frame, never count as a completed
   instruction/continuation, revoke the installed prefix, then terminate. This
   profile does not deliver/restart application fault handlers. */
_Noreturn void li2_tf_unexpected(struct li2_tf_owner *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_tf_abort(struct li2_tf_owner *,unsigned,long);
#endif
