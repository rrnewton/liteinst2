#ifndef LI2_PERSISTENT_GROUP_LIFETIME_H
#define LI2_PERSISTENT_GROUP_LIFETIME_H
#include "persistent_group_compact.h"
#include "tf_span_transfer.h"
#include "rseq_guard.h"
#include "private_code_query.h"
struct li2_pg_epoch;
struct li2_pg_generation;
struct li2_pg_token { const struct li2_pg_epoch *owner;uint64_t serial; };
struct li2_pg_source_page {
    struct li2_fetch_page identity;
    struct li2_fetch_backing backing;
    unsigned char bytes[LI2_REGION_PAGE];
};
struct li2_pg_source_key { uintptr_t entry;struct li2_pg_source_page page[2]; };
struct li2_pg_sources {
    unsigned complete,reserved;
    struct li2_fetch_ref anchor;
    uint64_t serial,allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    struct li2_pg_source_key key;
};
enum li2_pg_phase {
    LI2_PG_IDLE,LI2_PG_SEEDING,LI2_PG_SEEDED,LI2_PG_PREPARING,LI2_PG_HELD,
    LI2_PG_CONSUMED,LI2_PG_PUBLISHING,LI2_PG_BOUND,LI2_PG_OPENING,
    LI2_PG_EXECUTING,LI2_PG_RECOVERING,LI2_PG_CLOSING,LI2_PG_RELEASING,
    LI2_PG_CLOSED,LI2_PG_CANCELLED,LI2_PG_FAILED,LI2_PG_CANCELLING
};
/* Actual group owner: three code extents, one source/rseq lifetime. These
   descriptive counts never substitute for the three actual query rows. */
struct li2_pg_progress {
    uint64_t serial,transfer_serial,registration_epoch,publication,generation;
    unsigned phase,first_error,source_count,opened_pages,closed_pages;
    unsigned anchor_released,registration_rechecked,completion_permit;
    long first_detail;
    uintptr_t source[2],generated,proof,table,spill;
    struct li2_pg_layout layout;
};
int li2_pg_epoch_begin(const struct li2_tf_span_transfer *,uint64_t,
    struct li2_step_session *,int,const siginfo_t *,const ucontext_t *,struct li2_pg_token *);
int li2_pg_epoch_sources(const struct li2_pg_token *,const struct li2_fetch_ref *,const uintptr_t[2]);
const struct li2_pg_sources *li2_pg_epoch_sources_view(const struct li2_pg_token *);
int li2_pg_epoch_bind(const struct li2_pg_token *,const struct li2_pg_generation *);
int li2_pg_epoch_enter(const struct li2_pg_token *,int,const siginfo_t *,ucontext_t *);
int li2_pg_epoch_preentry(int,const siginfo_t *,const ucontext_t *);
int li2_pg_epoch_drain(const struct li2_pg_token *);
/* Complete unconsumed/unentered HELD only; exact classified planner miss is
   a controller prerequisite. All17 actual code pages must be NX, then real
   source release and seeded rseq cancellation precede the unchanged resume. */
int li2_pg_epoch_cancel(const struct li2_pg_token *,int,siginfo_t *,ucontext_t *,enum li2_chain_result *);
int li2_pg_epoch_interlock(void);
const struct li2_pg_progress *li2_pg_epoch_progress(void);
_Static_assert(sizeof(struct li2_pg_token)==16,"distinct group owner plus serial");
#endif
