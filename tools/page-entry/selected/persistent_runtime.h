#ifndef LI2_PERSISTENT_RUNTIME_H
#define LI2_PERSISTENT_RUNTIME_H
#include "persistent_lifetime.h"
#include "linked_rseq.h"
#if !defined(LI2_PERSISTENT_EPOCH) || LI2_PERSISTENT_EPOCH != 1 || \
    !defined(LI2_LINKED_EPOCH) || LI2_LINKED_EPOCH != 1 || \
    !defined(LI2_MOV_GUARD) || LI2_MOV_GUARD != 1
#error "distinct persistent registered primitive profile required"
#endif
/* Authenticates the real runtime singleton and retained serial. Zero means
   no current authority; a caller-supplied enum or pointer never suffices. */
unsigned li2_pe_owner_phase(const struct li2_pe_token *);
enum li2_pe_source_phase { LI2_PES_IDLE,LI2_PES_SEEDING,LI2_PES_PREPARING,
    LI2_PES_HELD,LI2_PES_RX,LI2_PES_CLOSED,LI2_PES_RELEASED,LI2_PES_FAILED };
struct li2_pe_source_progress {
    unsigned initialized,phase,first_error,pages_copied,bytes_copied[2];
    unsigned release_started,release_complete,aborted;
    long first_detail;
    uint64_t serial,validations;
    uintptr_t generated;
    struct li2_pe_sources source;
    struct li2_fetch_backing last_backing[2];
    struct li2_fetch_map_progress preparation,validation;
    struct li2_private_code_query opened,closed;
};
int li2_pe_source_initialize(void);
int li2_pe_source_begin(const struct li2_pe_token *,uintptr_t);
int li2_pe_source_prepare(const struct li2_pe_token *,const struct li2_fetch_ref *,const uintptr_t[2]);
const struct li2_pe_sources *li2_pe_source_view(const struct li2_pe_token *);
int li2_pe_source_validate(const struct li2_pe_token *,const struct li2_pe_compact *);
int li2_pe_source_opened(const struct li2_pe_token *,const struct li2_pe_compact *);
int li2_pe_source_release(const struct li2_pe_token *,const struct li2_pe_compact *);
int li2_pe_source_abort(const struct li2_pe_token *);
int li2_pe_source_interlock(void);
const struct li2_pe_source_progress *li2_pe_source_progress(void);
struct li2_pe_rseq_progress {
    volatile sig_atomic_t active,checking;
    unsigned first_error,unsafe_terminal,seed_complete,entry_complete,close_complete;
    long first_detail,pid,tid,fs_result,gs_result;
    struct li2_pe_token token;
    const struct li2_step_session *session;
    uint64_t registration_epoch,address,page,length,signature,fs,gs;
    uint64_t word_before,word_entry,word_after,raw_checks,cold_heads,cold_stores;
    uint16_t fs_selector,gs_selector;
    struct li2_rseq_data before,observed,after;
};
int li2_pe_rseq_begin(const struct li2_pe_token *,const struct li2_step_session *,const ucontext_t *);
int li2_pe_rseq_cold(const struct li2_pe_token *,const struct li2_pe_plan *,const ucontext_t *);
int li2_pe_rseq_live(const struct li2_pe_token *,const ucontext_t *,struct li2_link_rseq_live *);
int li2_pe_rseq_close(const struct li2_pe_token *,const ucontext_t *);
void li2_pe_rseq_raw(void);
void li2_pe_rseq_preentry(void);
const struct li2_pe_rseq_progress *li2_pe_rseq_progress(void);
#endif
