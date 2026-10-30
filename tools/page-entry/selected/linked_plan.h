#ifndef LI2_LINKED_PLAN_H
#define LI2_LINKED_PLAN_H
#include "region_plan.h"

#ifdef LI2_LINK_GRAPH_OBSERVE
#if LI2_LINK_GRAPH_OBSERVE != 1 || !defined(LI2_LINKED_EPOCH) || !defined(LI2_LINKED_NATIVE_HINT) || defined(LI2_LINKED_EPOCH_CAPTURE)
#error "graph observation requires the distinct release-only native-hint profile"
#endif
enum li2_link_graph_reason {
    LI2_LG_INITIAL, LI2_LG_PAGE, LI2_LG_QUEUE, LI2_LG_OVERLAP,
    LI2_LG_EXITS, LI2_LG_HEADS, LI2_LG_EMPTY, LI2_LG_NO_FRONTIER,
    LI2_LG_PRIMARY, LI2_LG_FALLTHROUGH, LI2_LG_KAHN_STALL,
    LI2_LG_DISTANCE, LI2_LG_INCOMING, LI2_LG_REASON_COUNT
};
/* Diagnostic counts have no planning, source or execution authority. */
struct li2_link_graph_observation {
    uint64_t overflow,reasons[LI2_LG_REASON_COUNT];
};
const struct li2_link_graph_observation *li2_link_graph_observation(void);
_Static_assert(LI2_LG_REASON_COUNT==13,"exact first-refusal categories");
_Static_assert(sizeof(struct li2_link_graph_observation)==112,"bounded observation");
#endif

/* A new graph contract. No old contiguous span/region description is cast. */
#define LI2_LINK_VERSION 1U
#define LI2_LINK_HEADS 64U
#define LI2_LINK_EXITS 8U
#define LI2_LINK_MAPS (2U*LI2_LINK_HEADS)
struct li2_link_plan {
    uint32_t version,ready,heads,exits,maps,longest_path;
    uint32_t source_bytes,image_bytes,decoder_calls,decoder_result;
    uintptr_t page,entry,generated;
    unsigned char source[LI2_REGION_PAGE],image[LI2_REGION_PAGE];
    struct li2_span_decoded original[LI2_LINK_HEADS];
    struct li2_span_decoded frontier[LI2_LINK_EXITS];
    struct li2_region_head head[LI2_LINK_HEADS];
    uintptr_t exit_pc[LI2_LINK_EXITS];
    struct li2_region_pc map[LI2_LINK_MAPS];
};
/* Follow reachable direct edges in deterministic breadth-first order, taken
   before fallthrough. Gaps are never decoded merely because they lie between
   two heads. Every discovered head is selected; >64 heads, >8 valid unsupported
   frontiers, any overlap, invalid/truncated decode, cycle or cross-page edge
   refuses the whole graph. No frontier is invented to hide a supported cycle
   or capacity overflow. Each path ends at an actual unsupported same-page head.

   Each NEXT/Jcc has an explicit emitted E9 continuation, avoiding any source-
   order assumption. RIP CPU-read/LEA operands preserve the original absolute
   target or refuse exact disp32 reach. Every emitted instruction is redecoded;
   all effects and the whole 4096-byte CC-padded image are authenticated.
   Synthetic E9 rows name their unexecuted original successor, with length0.
   All pointer, serialized decoder and pure-description obligations of the
   existing planners apply. There is no execution or source authority here. */
int li2_link_plan_page(uintptr_t,const unsigned char *,uintptr_t,uintptr_t,
                       struct li2_link_plan *);
int li2_link_plan_validate(const struct li2_link_plan *);
_Static_assert(sizeof(struct li2_link_plan)==40704,"linked graph ABI");
_Static_assert(sizeof(struct li2_link_plan)<65536,"bounded cold rebuild");
#endif
