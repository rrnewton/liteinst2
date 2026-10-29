#ifndef LI2_TF_SAME_PAGE_H
#define LI2_TF_SAME_PAGE_H
#include "tf_owner.h"
#include "lifecycle_loader.h"
#if LI2_TF_SAME_PAGE_LEASE != 1 || !defined(LI2_TF_HANDOFF) || \
    !defined(LI2_MAPS_PHASE_REUSE) || !defined(LI2_RSEQ_INACTIVE)
#error "same-page lease requires the fixed TF/maps/rseq composition"
#endif

/* A staged description is not a borrow or an execution permit. Only this
   module's exact private object is accepted at commit/cancel. The old borrow
   remains held, and its actual permission owner remains responsible for RX. */
enum li2_rx_phase { LI2_RX_EMPTY, LI2_RX_STAGING, LI2_RX_STAGED,
    LI2_RX_COMMITTING, LI2_RX_COMMITTED, LI2_RX_CANCELLED };
#ifdef LI2_TF_SEALED_CUSTODY
#include "page_custody.h"
enum li2_custody_kind { LI2_CUSTODY_NONE, LI2_CUSTODY_FRESH, LI2_CUSTODY_RETAINED };
enum { LI2_CUSTODY_MANAGED_SEALED=1 };
struct li2_custody_owner {
    const void *chain;
    const struct li2_step_owner *owner;
    unsigned slot;
    uint64_t generation,event;
};
struct li2_page_custody_receipt {
    unsigned kind,provenance,slot,checks;
    uint64_t epoch,origin_sequence,owner_generation,event;
    uintptr_t chain,owner,session;
    /* Original real acquisition only, never this transfer's maps receipt. */
    struct li2_fetch_map_progress origin;
};
#endif
struct li2_fetch_rx_view {
    unsigned phase,complete;
    int result;
    uint64_t serial,before_sequence,after_sequence;
    uintptr_t pc;
    size_t length;
    long pid,tid;
    unsigned char bytes[15];
    struct li2_fetch_page page;
    struct li2_fetch_backing backing;
    struct li2_fetch_map_progress maps;
#ifdef LI2_TF_SEALED_CUSTODY
    unsigned maps_observed;
    struct li2_page_custody_receipt custody;
#endif
};
int li2_lifecycle_fetch_rx_stage(const struct li2_fetch_ref *,uintptr_t,
                                const struct li2_fetch_rx_view **);
int li2_lifecycle_fetch_rx_commit(const struct li2_fetch_ref *,
                                 const struct li2_fetch_rx_view *,struct li2_fetch_ref *);
int li2_lifecycle_fetch_rx_cancel(const struct li2_fetch_ref *,const struct li2_fetch_rx_view *);
const struct li2_fetch_rx_view *li2_lifecycle_fetch_rx_progress(void);
#ifdef LI2_TF_SEALED_CUSTODY
int li2_lifecycle_fetch_rx_stage_custody(const struct li2_fetch_ref *,uintptr_t,
    const struct li2_custody_owner *,const struct li2_fetch_rx_view **);
int li2_lifecycle_fetch_rx_commit_custody(const struct li2_fetch_ref *,
    const struct li2_fetch_rx_view *,const struct li2_custody_owner *,struct li2_fetch_ref *);
int li2_lifecycle_fetch_rx_publish_custody(const struct li2_fetch_ref *,
    const struct li2_fetch_rx_view *,const struct li2_custody_owner *);
#endif

/* This is a permission lease over multiple separately observed instructions.
   Original open_* fields still describe the one real opening. No successor
   creates an open/close/release receipt. The final original close owns them. */
enum li2_lease_phase { LI2_LEASE_EMPTY, LI2_LEASE_CHECKING, LI2_LEASE_TRANSFERRING,
    LI2_LEASE_RUNNING, LI2_LEASE_MISS, LI2_LEASE_CLOSED };
struct li2_tf_same_page {
    unsigned phase,origin_active,slot;
    uint64_t candidates,misses,transfers,closed_leases;
    uint64_t owner_generation,origin_event,origin_borrow,completed_event;
    struct li2_step_request opening,previous;
    struct li2_step_frame opening_frame,previous_before;
    struct li2_fetch_progress previous_fetch;
    struct li2_fetch_rx_view transfer;
    struct li2_decoded next;
    struct li2_tf_classification classification;
};
#endif
