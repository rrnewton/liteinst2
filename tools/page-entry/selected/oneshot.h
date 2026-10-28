#ifndef LI2_ONESHOT_PROTOTYPE_H
#define LI2_ONESHOT_PROTOTYPE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* PRIVATE SOURCE PROTOTYPE. No old core publication or execution credit. */
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/ucontext.h>
#include "step_owner.h"

#define LI2_ONESHOT_ABI 1U
#define LI2_ONESHOT_PAGE 4096U
#define LI2_ONESHOT_SOURCE_BYTES 5U
#define LI2_ONESHOT_MIN_EXEC UINT64_C(0x200000000)
#define LI2_ONESHOT_MASK (UINT64_MAX & ~(UINT64_C(1)<<(SIGSEGV-1)) & \
    ~(UINT64_C(1)<<(SIGTRAP-1)) & ~(UINT64_C(1)<<(SIGSYS-1)) & \
    ~(UINT64_C(1)<<(SIGILL-1)) & ~(UINT64_C(1)<<(SIGKILL-1)) & \
    ~(UINT64_C(1)<<(SIGSTOP-1)))

enum li2_oneshot_kind { LI2_ONESHOT_SYSCALL=1, LI2_ONESHOT_RDTSC=2 };
enum li2_oneshot_phase { LI2_ONESHOT_EMPTY=0, LI2_ONESHOT_BOUND=1,
    LI2_ONESHOT_WRITING=2, LI2_ONESHOT_PUBLISHED=3, LI2_ONESHOT_LANDED=4,
    LI2_ONESHOT_CLOSING=5, LI2_ONESHOT_RESTORING=6,
    LI2_ONESHOT_RESTORED=7, LI2_ONESHOT_COMPLETED=8, LI2_ONESHOT_FAILED=9 };
enum li2_oneshot_error { LI2_ONESHOT_ARGUMENT=1500, LI2_ONESHOT_ENCODING,
    LI2_ONESHOT_GEOMETRY, LI2_ONESHOT_REUSE, LI2_ONESHOT_FRAME,
    LI2_ONESHOT_IDENTITY, LI2_ONESHOT_BIND, LI2_ONESHOT_SOURCE,
    LI2_ONESHOT_PROTECT, LI2_ONESHOT_SYNC, LI2_ONESHOT_LANDING,
    LI2_ONESHOT_GENERATION, LI2_ONESHOT_REENTRY, LI2_ONESHOT_RELEASE };
/* Refusal never claims completion. UNTOUCHED leaves the authenticated old
   fetch held: root must validate/release exactly that borrow before preparing
   again. RELEASED proves its successful release and no transaction acquisition
   attempt. No callback may return a refusal after acquisition starts. */
enum li2_oneshot_result { LI2_ONESHOT_OK=0,
    LI2_ONESHOT_REFUSED_UNTOUCHED=1, LI2_ONESHOT_TERMINAL=2,
    LI2_ONESHOT_REFUSED_RELEASED=3 };
struct li2_oneshot_page {
    uint64_t address,allocation,generation,offset;
};
struct li2_oneshot_plan {
    uint32_t abi_version,kind;
    uint64_t sequence,pc,next_pc,landing,landing_allocation,landing_generation;
    struct li2_oneshot_page pages[2];
    uint32_t page_count,reserved;
    unsigned char original[5],redirect[5],reserved_bytes[6];
};
struct li2_oneshot_admission_state {
    volatile uint32_t phase;
    volatile uint32_t first_error;
    volatile int64_t first_detail;
    volatile uint64_t sequence;
    volatile uint32_t mutation_started,published,restored,reserved;
};
_Static_assert(sizeof(struct li2_oneshot_plan)==144,"one-shot plan ABI");
_Static_assert(sizeof(struct li2_oneshot_admission_state)==40,"one-shot state ABI");
int li2_admission_oneshot_plan(const struct li2_oneshot_plan *,struct li2_oneshot_plan *);
int li2_admission_oneshot_bind(struct li2_oneshot_admission_state *,uint64_t);
int li2_admission_oneshot_transition(struct li2_oneshot_admission_state *,uint32_t,uint32_t);
void li2_admission_oneshot_fail(struct li2_oneshot_admission_state *,uint32_t,int64_t);

/* Actual observations returned by the trusted lifecycle backend. These are
   diagnostics, not permits: C checks their exact binding before each use.
   observe performs a fresh map/source-owner/alias observation after raw changes;
   it cannot reuse a pre-mutation maps snapshot. All pointers are private. */
struct li2_oneshot_observation {
    struct li2_oneshot_page pages[2];
    uint32_t protection[2],private_mapping[2],writable_aliases[2];
    uint32_t page_count,landing_protection,landing_private,landing_writable_aliases;
    uint64_t landing_page,landing_allocation,landing_generation;
    int64_t pid,tid;
};
/* Signals may see a started action whose effect already happened but whose
   returned/completed flag is unset. That is an uncertain terminal prefix, not
   proof of no effect. Publish inputs before started; result before returned;
   validated outputs before verified, with atomic_signal_fence between stages.
   Nested reserved handlers never resume the interrupted writer. */
struct li2_oneshot_call {
    volatile uint32_t started,returned,verified,reserved;
    volatile int64_t result;
};
enum li2_oneshot_transfer_result { LI2_ONESHOT_TRANSFER_OWNED=0,
    LI2_ONESHOT_TRANSFER_UNTOUCHED=1, LI2_ONESHOT_TRANSFER_RELEASED=2 };
struct li2_oneshot_transfer {
    struct li2_oneshot_call call,old_release,acquire;
    volatile uint32_t old_authenticated,old_borrow_live,transaction_live,reserved;
};
struct li2_oneshot_generation {
    struct li2_oneshot_call call;
    volatile uint32_t restoring,attempted_mask,completed_mask,reserved;
    uint64_t before[2];
    volatile uint64_t after[2];
};
struct li2_oneshot_release {
    struct li2_oneshot_call call;
    volatile uint32_t transaction_live,reserved;
};
struct li2_oneshot_hooks {
    void *context;
    long (*raw)(long,long,long,long,long,long,long);
    /* Check actual kernel frame extents in the guarded altstack; no supplied
       synthetic frame is an execution witness. Called before any frame read. */
    int (*frame_range)(void *,const void *,size_t);
    /* Authenticate and consume the exact old selected_borrow, retain its
       identity/bytes, release it, then acquire the distinct patch transaction.
       Revalidate complete live pages against actual sealed backing bytes,
       private R/NX mappings, landing, singleton/no-pending-owner,
       unregistered-rseq and reserved-signal policy. Never mutate source here.
       The outer call row is owned by C; backend owns old_release/acquire and
       flags, with the publication ordering above. Set old_authenticated only
       after checking actual old ownership; set old_borrow_live=1 before any
       release attempt. Release success clears old_borrow_live; acquisition
       success sets transaction_live before publishing acquire.verified.
       Return OWNED only with both subcalls verified. UNTOUCHED requires actual
       old borrow live and both subcalls zero. RELEASED requires verified old
       release and acquire entirely zero. Both refusals require no transaction.
       Any acquisition attempt/failure or uncertain prefix is terminal, never a
       clean refusal. Terminal cleanup must inspect actual backend ownership,
       never blindly release based on an interrupted diagnostic flag. */
    int (*transfer)(void *,const struct li2_oneshot_plan *,struct li2_oneshot_transfer *);
    /* Advance actual source generations and invalidate all fetch/cache/plan
       observers BEFORE each mutation. Return the exact new page generations.
       C owns call and before; backend owns attempted/completed/after. Set each
       attempted bit before actual generation mutation; publish actual after[i]
       then its completed bit after success, with fences. Invalidate every
       relevant observer before publishing completion. Retain partial output on
       errors. restoring is 0 at publication, 1 at source restoration. */
    int (*advance_generation)(void *,const struct li2_oneshot_plan *,unsigned,
                              struct li2_oneshot_generation *);
    int (*observe)(void *,const struct li2_oneshot_plan *,
                   struct li2_oneshot_observation *);
    /* Release only after exact original bytes and actual R/NX are proven.
       C publishes transaction_live=1 before the call. Backend clears it only
       after actual verified release (with a fence). It must not acquire/reuse
       old selected_borrow or dispatch an effect. C owns the outer call row. */
    int (*release)(void *,const struct li2_oneshot_plan *,struct li2_oneshot_release *);
};
/* One row per attempted protection/sync operation; flags distinguish attempted
   from returned and verified. No success is inferred from an unset result. */
struct li2_oneshot_operation {
    uint32_t kind,page,protection,reserved;
    struct li2_oneshot_call call;
};
#define LI2_ONESHOT_OPERATIONS 32U
struct li2_oneshot_owner {
    struct li2_oneshot_admission_state state;
    struct li2_oneshot_plan plan;
    struct li2_oneshot_hooks hooks;
    const struct li2_step_session *session;
    volatile sig_atomic_t in_handler;
    volatile uint32_t initialized,transferred,source_copied,landing_observed;
    volatile uint32_t source_write_started,write_attempted_mask,write_completed_mask;
    volatile uint32_t restore_started,restore_attempted_mask,restore_completed_mask;
    volatile uint32_t operations,observations;
    struct li2_oneshot_transfer transfer;
    struct li2_oneshot_generation generation[2];
    struct li2_oneshot_release release;
    uint64_t current_generation[2];
    struct li2_oneshot_observation observation[8];
    struct li2_oneshot_call observation_call[8];
    struct li2_oneshot_operation operation[LI2_ONESHOT_OPERATIONS];
    struct li2_step_frame before,after;
    unsigned char original_pages[2][LI2_ONESHOT_PAGE] __attribute__((aligned(64)));
    uintptr_t landing_frame;
};
struct li2_oneshot_handoff {
    uint32_t kind,reserved;
    uint64_t sequence,original_pc,original_next_pc,logical_flags;
    ucontext_t *actual_landing_frame;
};

int li2_oneshot_initialize(struct li2_oneshot_owner *,const struct li2_step_session *,
                           const struct li2_oneshot_hooks *);
/* Caller installs the pending one-shot route before entering this API. The
   complete owner is preinitialized, private and never copied while active. */
int li2_oneshot_nx(struct li2_oneshot_owner *,const struct li2_oneshot_plan *,
                   int,siginfo_t *,ucontext_t *);
int li2_oneshot_ud(struct li2_oneshot_owner *,int,siginfo_t *,ucontext_t *,
                   struct li2_oneshot_handoff *);
/* Best-effort R/NX cleanup only; never marks restored, releases ownership,
   overwrites the initiating failure, or permits execution/fallback. */
void li2_oneshot_abort_close(struct li2_oneshot_owner *);
/* Root's integration must consume the RESTORED typed handoff, freshly borrow
   original_pc and check kind/bytes/next_pc before effects. It may then mark
   COMPLETE only after the real effect and kernel-frame continuation commit.
   No reset/reuse API is included yet; retain this owner to process exit. */
#endif
