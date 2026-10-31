#ifndef LI2_PERSISTENT_LIFETIME_H
#define LI2_PERSISTENT_LIFETIME_H
#include "persistent_plan.h"
#include "tf_span_transfer.h"
#include "rseq_guard.h"
#include "private_code_query.h"
/* Typed integration contract ONLY: this packet defines no function below and
   no runtime includes this header. It deliberately cannot supply execution
   authority from a standalone planner result or caller-owned description. */
struct li2_pe_epoch;
struct li2_pe_generation;
struct li2_pe_token { const struct li2_pe_epoch *owner;uint64_t serial; };
struct li2_pe_source_page {
    struct li2_fetch_page identity;
    struct li2_fetch_backing backing;
    unsigned char bytes[LI2_REGION_PAGE];
};
struct li2_pe_source_key {
    uintptr_t entry;
    struct li2_pe_source_page page[LI2_PE_SOURCES];
};
/* Descriptive observation obtained from the actual protected owner. Cached
   source keys exclude this fresh anchor and the owner+serial capability. */
struct li2_pe_sources {
    unsigned complete,reserved;
    struct li2_fetch_ref anchor;
    uint64_t serial,allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    struct li2_pe_source_key key;
};
enum li2_pe_phase {
    LI2_PE_IDLE,LI2_PE_SEEDING,LI2_PE_SEEDED,LI2_PE_PREPARING,LI2_PE_HELD,
    LI2_PE_CONSUMED,LI2_PE_PUBLISHING,LI2_PE_BOUND,LI2_PE_OPENING,
    LI2_PE_EXECUTING,LI2_PE_RECOVERING,LI2_PE_CLOSING,LI2_PE_RELEASING,
    LI2_PE_CLOSED,LI2_PE_CANCELLED,LI2_PE_FAILED
};
/* Stable cleanup addresses exist BEFORE the corresponding first RAW. Failure
   records retain their actual phase/prefix; FAILED does not mean drained. */
struct li2_pe_progress {
    uint64_t serial,transfer_serial,registration_epoch,publication,generation;
    unsigned phase,first_error,source_count,opened_pages,closed_pages;
    unsigned anchor_released,registration_rechecked,completion_permit;
    long first_detail;
    uintptr_t source[LI2_PE_SOURCES],generated,proof,table,spill;
};
/* Require a genuine same-event CLOSED TRACE ticket and the actual retained
   serial. Install SEEDING/cleanup ownership before the first rseq mapping/TLS
   query, while NO fresh fetch is held. Neither consumes the transfer nor edits
   the kernel frame. Registered ACTIVE and unregistered IDLE are distinct exact
   cases; they are derived from actual protected state, never a selector. */
int li2_pe_epoch_begin(const struct li2_tf_span_transfer *,uint64_t,
    struct li2_step_session *,int,const siginfo_t *,const ucontext_t *,
    struct li2_pe_token *);
/* Require the actual newer singleton15 borrow at this frame's PC. Install
   PREPARING before RAW; derive both full page identities/backing/bytes from
   lifecycle storage and preserve the same actual anchor on every error. No
   extension of the old fetch wire, caller-supplied VMA, or synthetic NX. */
int li2_pe_epoch_sources(const struct li2_pe_token *,const struct li2_fetch_ref *,
    const uintptr_t[LI2_PE_SOURCES]);
const struct li2_pe_sources *li2_pe_epoch_sources_view(const struct li2_pe_token *);
/* Generation is an actual private slot owner, not a struct supplied by the
   caller. Whole cold reconstruction/static NONE/guard-table proofs precede
   readiness; ready generation is separate from source HELD/live. Consume the
   genuine transfer before any publication write; replacement additionally
   consumes the exact old completed-generation permit before code/proof/table W.
   Warm bind uses immutable primary payload, current source key, actual private
   registry generation and current rseq pin. No decoder on warm entry. */
int li2_pe_epoch_bind(const struct li2_pe_token *,const struct li2_pe_generation *);
/* Actual whole source, code RX, proof/table R/NX, spill RW/NX, session/full
   frame/AF/TLS/mask/rseq checks immediately precede redirection. Only actual
   entry RIP and logical TF handling change; every other field stays authentic. */
int li2_pe_epoch_enter(const struct li2_pe_token *,int,const siginfo_t *,ucontext_t *);
/* Earliest signal ingress, before every returning RAW or old-owner route.
   Authenticate actual registration+zero publication word first; unsafe pin
   takes the existing nonreturning unsafe path. Install RECOVERING before any
   spill read. Preserve raw siginfo/full UC/FP separately; exact boundary-only
   recovery never fabricates a fault or an old execution owner. */
int li2_pe_epoch_preentry(int,const siginfo_t *,const ucontext_t *);
/* After authentic recovery: revoke/synchronize/query all eight generated
   pages, verify both sources+bytes, release actual anchor, THEN refresh rseq
   mapping/TLS. Only a real supported external frontier and all successful
   closures can issue a completion permit. Fault/reject/nested/partial errors
   retain first error, truthful held ranges and NO completed permit. */
int li2_pe_epoch_drain(const struct li2_pe_token *);
/* Only the never-consumed HELD miss: verify/release the new anchor, retain
   RESUMING cleanup owner, then unchanged genuine span_resume. No post-redirect
   descriptive miss or restoration of a destroyed old owner. */
int li2_pe_epoch_cancel(const struct li2_pe_token *,int,siginfo_t *,ucontext_t *,
    enum li2_chain_result *);
int li2_pe_epoch_interlock(void);
const struct li2_pe_progress *li2_pe_epoch_progress(void);
_Static_assert(sizeof(struct li2_pe_token)==16,"owner plus nonreused serial");
#endif
