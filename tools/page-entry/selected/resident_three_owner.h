#ifndef LI2_RESIDENT_THREE_OWNER_H
#define LI2_RESIDENT_THREE_OWNER_H
#include "persistent_group_runtime.h"
#include "sealed_generation.h"
#if !defined(LI2_RESIDENT_THREE) || LI2_RESIDENT_THREE != 1 || \
    !defined(LI2_RESIDENT_SOURCE_LEASE) || LI2_RESIDENT_SOURCE_LEASE != 1 || \
    !defined(LI2_PERSISTENT_SEALED_GENERATION) || LI2_PERSISTENT_SEALED_GENERATION != 1 || \
    !defined(LI2_PERSISTENT_DIRECT_FRONTIER) || LI2_PERSISTENT_DIRECT_FRONTIER != 1 || \
    !defined(LI2_PERSISTENT_UNREGISTERED) || LI2_PERSISTENT_UNREGISTERED != 1 || \
    !defined(LI2_RSEQ_CURRENT_DATA) || LI2_RSEQ_CURRENT_DATA != 1
#error "three residents require their own owner, actual source union and sealed storage"
#endif
#if defined(LI2_PERSISTENT_CALL_DISPATCH) || defined(LI2_PERSISTENT_RET_DISPATCH) || \
    defined(LI2_ADD_GUARD) || defined(LI2_PERSISTENT_RETAINED_EIGHT)
#error "the first resident owner is a distinct direct-branch/NONE subset"
#endif
/* These three publications are not li2_pgd_member objects. Neither the old
   two-member view nor the old two-slot backing owner is widened or cast. */
#define LI2_R3_CERTIFICATES 3U
#ifdef LI2_RESIDENT_STABLE_GENERATION
#define LI2_R3_VERSION 2U
#else
#define LI2_R3_VERSION 1U
#endif
enum li2_r3_phase {
    LI2_R3_IDLE,LI2_R3_CLOSING_TRACE,LI2_R3_HELD,LI2_R3_PLANNING,
    LI2_R3_PUBLISHING,LI2_R3_BOUND,LI2_R3_OPENING,LI2_R3_ACTIVE,
    LI2_R3_RECOVERING,LI2_R3_CLOSING,LI2_R3_DRAINED,LI2_R3_CANCELLED,
    LI2_R3_FAILED
};
struct li2_r3_owner;
struct li2_r3_token { const struct li2_r3_owner *owner;uint64_t serial; };
struct li2_r3_seed {
    unsigned complete,reserved;
    uint64_t serial;
    struct li2_fetch_ref held;
    const struct li2_step_session *session;
    long pid,tid;
    uintptr_t root;
};
/* A seed is returned by value only after the real token, current held fetch,
   unchanged session and actual PID/TID have been authenticated. This copy is
   descriptive: the source provider must recheck the actual owner token. */
unsigned li2_r3_owner_phase(const struct li2_r3_token *);
int li2_r3_owner_seed(const struct li2_r3_token *,struct li2_r3_seed *);
/* The returned pointer is an exact protected owner member. Its complete
   source/guard table and immutable publication remain independently checked
   by the source lease; a caller-selected pointer is not accepted. */
const struct li2_pg_compact *li2_r3_owner_plan(const struct li2_r3_token *,unsigned);
/* Real closure only: no active/pending reference, all three installed code
   extents queried R/NX, directory closed, and the actual held fetch released.
   A caller supplies neither count nor a claimed quiet/completed flag. */
int li2_r3_owner_quiet(void);
/* Internal completion seam, independently read by the rseq provider before
   releasing its real registration pin. It does not accept a close receipt. */
int li2_r3_owner_closed(const struct li2_r3_token *);

/* Distinct rseq lifetime, implemented alongside the actual rseq owner. It
   retains both registered and unregistered validation and the real RAW guard;
   it never forges an old pg token or substitutes a three-member pgd view. */
int li2_r3_rseq_begin(const struct li2_r3_token *,const ucontext_t *);
int li2_r3_rseq_cold(const struct li2_r3_token *,unsigned,const ucontext_t *);
int li2_r3_rseq_live(const struct li2_r3_token *,const ucontext_t *,struct li2_link_rseq_live *);
int li2_r3_rseq_close(const struct li2_r3_token *,const ucontext_t *);
void li2_r3_rseq_raw(void);
void li2_r3_rseq_preentry(void);
struct li2_r3_rseq_progress {
    struct li2_r3_token token;
    const struct li2_step_session *session;
    unsigned active,checking,registered,seed_complete,entry_complete,close_complete;
    uint64_t epoch,calls,address,page,length,signature,fs,gs,raw_checks;
    long pid,tid;
    uint16_t fs_selector,gs_selector;
    unsigned tls_complete,word_observed;
    uint64_t word_before,word_entry,word_after;
    struct li2_rseq_data before,observed,after;
    unsigned cold[LI2_R3_CERTIFICATES];
};
const struct li2_r3_rseq_progress *li2_r3_rseq_progress(void);
#endif
