#ifndef LI2_LINKED_PREEDGE_PLAN_H
#define LI2_LINKED_PREEDGE_PLAN_H
#include "linked_plan.h"
#if !defined(LI2_LINKED_PREEDGE) || LI2_LINKED_PREEDGE != 1 || !defined(LI2_LINKED_EPOCH)
#error "pre-edge planning requires the distinct opt-in linked profile"
#endif
#ifdef LI2_LINK_GRAPH_OBSERVE
#error "the original first-refusal observer is not a pre-edge profile"
#endif
#define LI2_PREEDGE_VERSION 2U
#define LI2_PREEDGE_HEADS 64U
#define LI2_PREEDGE_EXITS 8U
#define LI2_PREEDGE_MAPS (2U*LI2_PREEDGE_HEADS)
enum li2_preedge_frontier {
    LI2_PREEDGE_NONE=0, LI2_PREEDGE_UNSUPPORTED=1, LI2_PREEDGE_PAGE_CUT=2,
    LI2_PREEDGE_INVALID=UINT32_MAX
};
/* A separate type and ABI: neither an old plan cast nor a version alternative
   accepted by the old API. All limits and the complete image remain bounded. */
struct li2_preedge_plan {
    uint32_t version,bytes,ready,heads,exits,maps,longest_path,reserved;
    uint32_t source_bytes,image_bytes,decoder_calls,decoder_result;
    uintptr_t page,entry,generated;
    unsigned char source[LI2_REGION_PAGE],image[LI2_REGION_PAGE];
    struct li2_span_decoded original[LI2_PREEDGE_HEADS];
    struct li2_span_decoded frontier[LI2_PREEDGE_EXITS];
    struct li2_region_head head[LI2_PREEDGE_HEADS];
    uintptr_t exit_pc[LI2_PREEDGE_EXITS];
    struct li2_region_pc map[LI2_PREEDGE_MAPS];
    uint32_t frontier_kind[LI2_PREEDGE_EXITS];
};
/* The descriptor must be the actual complete decode of the retained source,
   authenticated by cold whole-plan reconstruction and immutable publication.
   This pure classifier grants no source, permission or execution authority. */
unsigned li2_preedge_frontier_kind(uintptr_t,const struct li2_span_decoded *);
/* Deterministic BFS and full decoder/image reconstruction retain the v1
   policy and bounds. A valid unsupported instruction is still an unsupported
   frontier. A ready instruction is a PAGE_CUT only when at least one of its
   actual NEXT/JMP/Jcc successors leaves this source page. The WHOLE instruction
   is excluded: a Jcc cut includes both outcomes, without predicting flags.
   A cut at entry is MISS. Every cut PC and its full instruction are in-page;
   truncated/straddling instructions still refuse. Intervals include all cut
   instructions in overlap checks. No cut is invented for cycle/capacity errors.
   The emitted subgraph must remain acyclic, with at least one emitted head.

   Generated edges target the ORIGINAL IN-PAGE CUT PC, never its outside target.
   The owner must hold the whole source R/NX until generated revoke/sync/query,
   then release. Thus the real original-page NX occurs before any cut effect.
   The old source/fault/full-state/NONE/live-rseq/mask/TLS/ownership obligations
   remain mandatory. This planner alone supplies none of those authorities. */
int li2_preedge_plan_page(uintptr_t,const unsigned char *,uintptr_t,uintptr_t,
                           struct li2_preedge_plan *);
int li2_preedge_plan_validate(const struct li2_preedge_plan *);
_Static_assert(sizeof(struct li2_preedge_plan)==40744,"pre-edge v2 ABI");
_Static_assert(sizeof(struct li2_preedge_plan)<65536,"bounded full reconstruction");
_Static_assert(LI2_PREEDGE_HEADS==LI2_LINK_HEADS && LI2_PREEDGE_EXITS==LI2_LINK_EXITS &&
               LI2_PREEDGE_MAPS==LI2_LINK_MAPS,"unchanged planner limits");
#endif
