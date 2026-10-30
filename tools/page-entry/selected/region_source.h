#ifndef LI2_REGION_SOURCE_H
#define LI2_REGION_SOURCE_H
#include "lifecycle_loader.h"
#include "region_plan.h"

/* A reusable description, NOT a held borrow or execution authority. Equality
   includes the complete 4096 actual bytes, entry, allocation/generation,
   full page/VMA identity and the original sealed-backing identity fields.
   No fetch owner or borrow sequence is part of this cache key. Generated
   placement and the decoder/planner policy belong to the caller's cache key
   as well; equality here alone is not a complete generated-image lookup. */
struct li2_region_source_key {
    uintptr_t entry;
    struct li2_fetch_page page;
    struct li2_fetch_backing backing;
    unsigned char bytes[LI2_REGION_PAGE];
};
/* A fresh admission ticket. Retaining key across release does not retain this
   ticket's validity. All validation uses the CURRENT borrow, never the cache
   entry's old borrow. ready is published only after the entire snapshot. */
struct li2_region_source {
    unsigned ready;
    struct li2_fetch_ref borrow;
    struct li2_region_source_key key;
};

/* Caller owns complete, aligned, initially zero output storage disjoint from
   source/module/cache/plan storage; it protects that storage from application
   writes before this call. The exact requested-15 fetch is already held.
   Clean unsupported geometry/backing returns 0 with ready still 0, before new
   I/O or source reads. Otherwise every old fetch check is retained, followed
   by a full SEALED R/NX page read and exact join to the original 15 bytes.
   The old borrow remains held on EVERY return. Nonzero is terminal for this
   attempted source extension, not a clean fallback or permission to release
   an executing generated image. No fetch15/unroll39 storage is enlarged. */
int li2_lifecycle_region_source(const struct li2_fetch_ref *,struct li2_region_source *);

/* Pure description equality. It performs no live validation and grants no
   permission, retention or decoder/source authority. */
int li2_region_source_key_equal(const struct li2_region_source_key *,
                                const struct li2_region_source_key *);

/* Caller has independently validated the COMPLETE immutable typed plan with
   li2_region_plan_validate under the decoder's serialized arena contract.
   This function adds source authority only: join its whole snapshot/entry,
   check every distinct external exit (1..8), and revalidate this exact fresh
   borrow, full live R/NX page, backing and bytes. All exits must be outside
   the selected prefix and inside this same page. It neither decodes nor
   grants a legal-entry, generated mapping, rseq or fault-resumption permit. */
int li2_lifecycle_region_validate(const struct li2_fetch_ref *,
                                  const struct li2_region_source *,
                                  const struct li2_region_plan *);

/* Runtime ownership prerequisites are mandatory through retirement:
   - LI2_RUN_CACHE_REUSE=1 supplies the existing lifecycle quiet interlock.
   - One genuine NX ingress, singleton/no-debug/no-CET/blocked-async session;
     no pending step/run/native/pair/oneshot/REP/RX-transfer/custody owner.
     Install the distinct pending route BEFORE publication or returning RAW;
     its earliest preentry must reject nested/unexpected events terminally.
   - Keep the SAME fetch held and the WHOLE original page R/NX. Preserve the
     existing controller fetch interlock before dispatch/fork/legacy admission
     and mutations. Do not give another TF/permission owner this borrow.
   - Revalidate at least before generated RX, after RX immediately before
     redirect, and on exit. Revoke/synchronize/query generated RX closed,
     revalidate source, then release via the unchanged fetch_release. Only
     then dispatch the original exit or start a new borrow. Any partial/error
     path retains truthful ownership and closes generated RX before terminal
     cleanup; no fallback after redirection and no retry with a fresh ticket.
   This API makes no permission changes and adds no independent lifecycle
   lock. Direct lifecycle_admit is NOT internally fetch-interlocked: its
   existing documented caller-side exclusion remains a required premise. */
_Static_assert(LI2_REGION_PAGE==4096U,"region source page");
_Static_assert(LI2_REGION_EXITS==8U,"region source exit bound");
#endif
