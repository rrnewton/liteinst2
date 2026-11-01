#ifndef LI2_LOOP_ENVELOPE_H
#define LI2_LOOP_ENVELOPE_H
#include "scalar_read_decode.h"
#include "linked_mov_guard.h"

/* A separate pure proposal format, NOT a PF11 plan, compact, lease, entry,
   emission, recovery or cancellation permit. No installed profile uses it. */
#define LI2_LE_VERSION 12U
#define LI2_LE_PAGE 4096U
#define LI2_LE_HEADS 128U
#define LI2_LE_MEMBER_HEADS 64U
#define LI2_LE_BOUNDARIES 8U
#define LI2_LE_SOURCES 2U

enum li2_le_result {
    LI2_LE_OK=0,LI2_LE_NO_ENVELOPE=1,LI2_LE_ARGUMENT=3600,
    LI2_LE_DECODER,LI2_LE_DISCOVERY_LIMIT,LI2_LE_CORRUPT
};
enum li2_le_stop { LI2_LE_UNSUPPORTED=1,LI2_LE_FETCH_END,LI2_LE_JUMP };
enum li2_le_candidate_result {
    LI2_LE_ELIGIBLE=0,LI2_LE_PREFIX=1,LI2_LE_INTERIOR,LI2_LE_UNREACHABLE,
    LI2_LE_NO_EXIT,LI2_LE_EXIT_LIMIT,LI2_LE_LINK_LIMIT
};
enum li2_le_kind { LI2_LE_NONE=1,LI2_LE_MOV=2 };
struct li2_le_decoded {
    struct li2_span_decoded scalar;
    struct li2_mg_store mov;
    uint32_t kind,stop;
};
struct li2_le_head {
    uint64_t pc;
    uint32_t decoded,kind,flow,successors,token[2],external_mask,reserved;
};
struct li2_le_arm { uint64_t target;uint32_t head,arm; };
struct li2_le_link { uint32_t head,arm,target,reserved; };
struct li2_le_candidate {
    uint64_t first,end,latch;
    uint32_t result,heads,exits,links,backwards,stores,source_bytes,reserved;
};
struct li2_le_shape {
    struct li2_le_candidate choice;
    struct li2_le_head head[LI2_LE_HEADS];
    struct li2_le_arm exit[LI2_LE_BOUNDARIES];
    struct li2_le_link link[LI2_LE_BOUNDARIES];
};
struct li2_le_witness {
    uint32_t version,bytes,ready,result;
    uint64_t page[2],entry,stop_pc;
    uint32_t stop,decoded,candidates,eligible;
    unsigned char source[2][LI2_LE_PAGE];
    struct li2_le_decoded node[LI2_LE_HEADS];
    struct li2_le_candidate candidate[LI2_LE_HEADS];
    struct li2_le_shape selected;
};
/* All host objects are valid owned, aligned and mutually disjoint; decoder
   already initialized/sealed and calls serialized. Only supplied held bytes
   are inspected. No live instruction/data address is dereferenced. Pages are
   sorted, distinct, lower canonical, 4KiB aligned. A straddle needs both exact
   adjacent pages. Output tails are zero. Genuine entry is always BFS head0.

   Discovery: physical fallthrough spine; stop after first unsupported/invalid
   or unavailable descriptor, or after an unconditional direct JMP. Each
   backward spine branch to H<=entry proposes [H,next(branch)). Decode prefix
   H..entry exactly; do not recursively propose from prefix branches. Entire
   discovery, including refused and prefix starts, is limited to128. Needing
   a 129th descriptor refuses the whole choice; no earlier candidate escapes.
   Every interval head must be reachable, every internal arm an exact head,
   and only a real branch arm may leave. Individual external arms and actual
   BFS cross-member edges share the eight-boundary limit. Require >=1 exit.
   Rank (exits+links, descending internal backward arms, heads,first,end).
   Unsupported candidates never grant a classified runtime cancellation. */
int li2_le_choose(const uintptr_t[2],const unsigned char[2][LI2_LE_PAGE],uintptr_t,
                  struct li2_le_witness *);
/* Independent source-bound reconstruction, including failed choices. Caller
   supplies separate actual held pages/bytes/entry; the witness's own source
   copy is NOT used as its validating input. Return0 authenticates only this
   pure description; require ready/result separately, and all future owner,
   exclusion/emission/recovery/source-generation gates remain necessary. */
int li2_le_validate(const uintptr_t[2],const unsigned char[2][LI2_LE_PAGE],uintptr_t,
                    const struct li2_le_witness *,struct li2_le_witness *);
_Static_assert(sizeof(uintptr_t)==8,"x86_64 descriptive address width");
_Static_assert(sizeof(struct li2_le_witness)<128U*1024U,"bounded caller-owned witness");
#endif
