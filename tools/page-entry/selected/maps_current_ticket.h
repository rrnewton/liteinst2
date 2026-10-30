#ifndef LI2_MAPS_CURRENT_TICKET_H
#define LI2_MAPS_CURRENT_TICKET_H
#include "lifecycle_loader.h"
#if !defined(LI2_MAPS_CURRENT_TF) || LI2_MAPS_CURRENT_TF != 1 || \
    !defined(LI2_MAPS_MAINTAINED) || LI2_MAPS_MAINTAINED != 1 || \
    !defined(LI2_TF_SEALED_CUSTODY) || LI2_TF_SEALED_CUSTODY != 1
#error "current-view TF description requires the explicit maintained custody profile"
#endif
/* A protected singleton query identity, not a page/source/execution permit.
   Every table writer is the existing invalidating parser or mprotect projector.
   Another query, phase change, pending frontier probe, RAW transaction, poison
   or consumption makes this reference stale. No query may cross app execution.
   Physical baseline and current query are deliberately separate observations. */
enum { LI2_MAPS_CURRENT_UNAVAILABLE=1 };
struct li2_maps_current_owner;
struct li2_maps_current_ref {
    const struct li2_maps_current_owner *owner;
    uint64_t serial;
};
struct li2_maps_current_view {
    uint32_t version,complete;
    int result;
    long detail;
    uint64_t serial,query_serial;
    uintptr_t table,stack_first,stack_end;
    size_t rows;
    struct li2_fetch_map_progress physical,query;
};
/* One outstanding reference. These return old fetch errors, except the
   explicit unavailable result before publication when reuse is retired/off.
   Acquisition runs the unchanged checked query, including differential I/O.
   Once that query begins, out retains its actual success/failure prefix; only
   a successful complete result supplies a nonzero consumable reference. */
int li2_maps_current_acquire(struct li2_maps_current_ref *,
                             const struct li2_maps_current_view **);
int li2_maps_current_validate(const struct li2_maps_current_ref *,
                              const struct li2_maps_current_view *);
/* No RAW; consumes even a stale matching reference, without erasing evidence. */
int li2_maps_current_release(const struct li2_maps_current_ref *);
#endif
