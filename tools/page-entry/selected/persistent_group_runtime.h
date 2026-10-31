#ifndef LI2_PERSISTENT_GROUP_RUNTIME_H
#define LI2_PERSISTENT_GROUP_RUNTIME_H
#include "persistent_group_lifetime.h"
#include "linked_rseq.h"
#if !defined(LI2_PERSISTENT_GROUP) || LI2_PERSISTENT_GROUP != 1 || \
    !defined(LI2_PERSISTENT_EPOCH) || LI2_PERSISTENT_EPOCH != 1 || \
    !defined(LI2_LINKED_EPOCH) || LI2_LINKED_EPOCH != 1 || \
    !defined(LI2_MOV_GUARD) || LI2_MOV_GUARD != 1 || defined(LI2_PERSISTENT_DYNAMIC)
#error "exclusive actual group owner; no old dynamic singleton alias"
#endif
/* These callbacks authenticate the actual protected controller/serial. The
   layout is the selected current bank, not a caller-supplied capability.
   cancel_prot returns exact R or RW only while CANCELLING, unconsumed and
   unentered; each of its three extents is independently queried below. */
unsigned li2_pg_owner_phase(const struct li2_pg_token *);
const struct li2_pg_layout *li2_pg_owner_layout(const struct li2_pg_token *);
int li2_pg_owner_cancel_prot(const struct li2_pg_token *,unsigned);
enum li2_pg_source_phase {
    LI2_PGS_IDLE,LI2_PGS_SEEDING,LI2_PGS_PREPARING,LI2_PGS_HELD,LI2_PGS_RX,
    LI2_PGS_CLOSED,LI2_PGS_RELEASED,LI2_PGS_FAILED,LI2_PGS_CANCELLED
};
struct li2_pg_source_progress {
    unsigned initialized,phase,first_error,pages_copied,bytes_copied[2];
    unsigned release_started,release_complete,aborted;
    long first_detail;
    uint64_t serial,validations;
    struct li2_pg_layout layout;
    struct li2_pg_sources source;
    struct li2_fetch_backing last_backing[2];
    struct li2_fetch_map_progress preparation,validation;
    struct li2_private_code_query opened[3],closed[3];
    unsigned opened_extents,opened_pages,closed_extents,closed_pages;
    unsigned cancel_started,cancel_complete,cancel_extents,cancel_pages;
    int cancel_expected_prot[3];
    struct li2_private_code_query cancel_code[3];
    struct li2_span_fetch_observation cancelled_fetch;
};
int li2_pg_source_initialize(void);
int li2_pg_source_begin(const struct li2_pg_token *,const struct li2_pg_layout *);
int li2_pg_source_prepare(const struct li2_pg_token *,const struct li2_fetch_ref *,const uintptr_t[2]);
const struct li2_pg_sources *li2_pg_source_view(const struct li2_pg_token *);
int li2_pg_source_validate(const struct li2_pg_token *,const struct li2_pg_compact *);
int li2_pg_source_opened(const struct li2_pg_token *,const struct li2_pg_compact *);
int li2_pg_source_release(const struct li2_pg_token *,const struct li2_pg_compact *);
int li2_pg_source_abort(const struct li2_pg_token *);
int li2_pg_source_key_equal(const struct li2_pg_source_key *,const struct li2_pg_source_key *);
int li2_pg_source_pair_advisory(uintptr_t);
int li2_pg_source_cancel(const struct li2_pg_token *);
int li2_pg_source_interlock(void);
const struct li2_pg_source_progress *li2_pg_source_progress(void);
struct li2_pg_rseq_progress {
    volatile sig_atomic_t active,checking;
    unsigned first_error,unsafe_terminal,seed_complete,entry_complete,close_complete;
    long first_detail,pid,tid,fs_result,gs_result;
    struct li2_pg_token token;
    const struct li2_step_session *session;
    uint64_t registration_epoch,address,page,length,signature,fs,gs;
    uint64_t word_before,word_entry,word_after,raw_checks,cold_heads,cold_stores,cold_stubs;
    uint16_t fs_selector,gs_selector;
    struct li2_rseq_data before,observed,after;
    unsigned cancel_started,cancel_complete;
};
int li2_pg_rseq_begin(const struct li2_pg_token *,const struct li2_step_session *,const ucontext_t *);
int li2_pg_rseq_cold(const struct li2_pg_token *,const struct li2_pg_plan *,const ucontext_t *);
int li2_pg_rseq_live(const struct li2_pg_token *,const ucontext_t *,struct li2_link_rseq_live *);
int li2_pg_rseq_close(const struct li2_pg_token *,const ucontext_t *);
int li2_pg_rseq_cancel(const struct li2_pg_token *,const ucontext_t *);
void li2_pg_rseq_raw(void);
void li2_pg_rseq_preentry(void);
const struct li2_pg_rseq_progress *li2_pg_rseq_progress(void);
_Static_assert(LI2_PG_CODE_EXTENTS==3 && LI2_PG_CODE_PAGES==17,"actual 8+8+1 closure");
#endif
