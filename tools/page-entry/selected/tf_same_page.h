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
};
int li2_lifecycle_fetch_rx_stage(const struct li2_fetch_ref *,uintptr_t,
                                const struct li2_fetch_rx_view **);
int li2_lifecycle_fetch_rx_commit(const struct li2_fetch_ref *,
                                 const struct li2_fetch_rx_view *,struct li2_fetch_ref *);
int li2_lifecycle_fetch_rx_cancel(const struct li2_fetch_ref *,const struct li2_fetch_rx_view *);
const struct li2_fetch_rx_view *li2_lifecycle_fetch_rx_progress(void);

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
