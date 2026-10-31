#ifndef LI2_PERSISTENT_GROUP_RUNTIME_H
#define LI2_PERSISTENT_GROUP_RUNTIME_H
#include "persistent_group_lifetime.h"
#include "linked_rseq.h"
#ifdef LI2_PERSISTENT_UNREGISTERED
#if LI2_PERSISTENT_UNREGISTERED != 1 || !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1
#error "unregistered compiled lifetime requires its distinct active-domain opt-in"
#endif
#if defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE)
#error "unregistered lifetime cannot use an older registered-only capture schema"
#endif
enum li2_pgu_lifetime { LI2_PGU_REGISTERED=1,LI2_PGU_UNREGISTERED=2 };
#endif
#ifdef LI2_RSEQ_CURRENT_DATA
#if !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
#error "maintained rseq data is a distinct resident dispatch profile"
#endif
#include "rseq_current_data.h"
#endif
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
#include "persistent_active_domain.h"
#endif
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
#ifdef LI2_PERSISTENT_UNREGISTERED
    unsigned lifetime_mode,word_observed,tls_complete;
    uint64_t registration_calls;
#endif
#ifdef LI2_RSEQ_CURRENT_DATA
    struct li2_rseq_current_data current_observed,current_after;
#endif
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    unsigned domain_bound,domain_count;
    struct li2_pgd_ref domain_ref[LI2_PGD_MEMBERS];
#endif
};
#ifdef LI2_PERSISTENT_UNREGISTERED
/* Descriptive validation only; authority still requires the protected token,
   actual owner/session and all original source/permission/receipt predicates.
   Unregistered zero storage means unavailable, never a zero-word observation. */
static inline int li2_pgu_zero(const void *value,size_t bytes) {
    const unsigned char *b=value;
    for(size_t i=0;i<bytes;i++)if(b[i])return 0;
    return 1;
}
static inline int li2_pgu_progress_valid(const struct li2_pg_rseq_progress *r) {
    if(!r || !r->session || r->pid<=0 || r->pid!=r->tid || r->tls_complete!=1 ||
       r->fs_result || r->gs_result || r->word_before || r->word_entry || r->word_after)return 0;
    if(r->lifetime_mode==LI2_PGU_REGISTERED)
        return r->word_observed==1 && r->registration_epoch && r->length==32 &&
            !(r->address&31) && r->address<=UINTPTR_MAX-32 &&
            r->page==(r->address&~(LI2_REGION_PAGE-1U)) && r->before.complete==1 &&
            r->observed.complete==1 &&
            (!(r->close_complete || r->cancel_complete) || r->after.complete==1);
    if(r->lifetime_mode!=LI2_PGU_UNREGISTERED || r->word_observed ||
       r->address || r->page || r->length || r->signature ||
       !li2_pgu_zero(&r->before,sizeof r->before) ||
       !li2_pgu_zero(&r->observed,sizeof r->observed) ||
       !li2_pgu_zero(&r->after,sizeof r->after))return 0;
#ifdef LI2_RSEQ_CURRENT_DATA
    if(!li2_pgu_zero(&r->current_observed,sizeof r->current_observed) ||
       !li2_pgu_zero(&r->current_after,sizeof r->current_after))return 0;
#endif
    return 1;
}
#endif
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
