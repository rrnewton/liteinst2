#ifndef LI2_LINKED_PLAN_H
#define LI2_LINKED_PLAN_H
#include "region_plan.h"

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
