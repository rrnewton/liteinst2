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

#ifdef LI2_LINK_FRONTIER_CENSUS
#if LI2_LINK_FRONTIER_CENSUS != 1 || !defined(LI2_LINKED_NATIVE_HINT) || \
    defined(LI2_LINKED_PREEDGE_CAPTURE) || defined(LI2_LINKED_PREEDGE_REUSE_CAPTURE) || \
    defined(LI2_LINKED_PREEDGE_FULL_CAPTURE) || defined(LI2_LINKED_PREEDGE_FAILURE_CAPTURE) || \
    defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_EPOCH)
#error "frontier census is a distinct release-only pre-edge observer"
#endif
#define LI2_LFC_CODES 4936U /* Exact locked iced-x86 1.21.0 Code population. */
#define LI2_LFC_CHANNELS 6U
/* Cold BFS encounters (unsupported/cut), root MISS (unsupported/cut), and
   actually completed generated exits (unsupported/cut). These are different
   denominators: internal candidate frontiers need not execute. */
enum li2_lfc_reason {
    LI2_LG_INITIAL,LI2_LG_PAGE,LI2_LG_QUEUE,LI2_LG_OVERLAP,LI2_LG_EXITS,
    LI2_LG_HEADS,LI2_LG_EMPTY,LI2_LG_NO_FRONTIER,LI2_LG_PRIMARY,
    LI2_LG_FALLTHROUGH,LI2_LG_KAHN_STALL,LI2_LG_DISTANCE,LI2_LG_INCOMING,
    LI2_LFC_REASONS
};
struct li2_lfc_code {
    uint64_t count[LI2_LFC_CHANNELS],different[LI2_LFC_CHANNELS];
    uint32_t length,step;
    unsigned char encoding[16]; /* First actual encoding, not an effect claim. */
};
struct li2_frontier_census {
    uint64_t overflow,invalid,started,returned,results[8],reasons[LI2_LFC_REASONS];
    uint64_t totals[LI2_LFC_CHANNELS],rsp_mov[LI2_LFC_CHANNELS];
    struct li2_lfc_code codes[LI2_LFC_CODES];
};
static inline void li2_lfc_add(struct li2_frontier_census *c,uint64_t *v) {
    if(*v==UINT64_MAX)c->overflow=1;else ++*v;
}
static inline void li2_lfc_observe(struct li2_frontier_census *c,unsigned channel,
                                  const struct li2_span_decoded *d) {
    if(!c)return;
    const struct li2_decoded *a=&d->decoded;
    if(channel>=LI2_LFC_CHANNELS || a->decode_status!=LI2_VALID ||
       !a->length || a->length>15 || a->code>=LI2_LFC_CODES) {
        c->invalid=1;return;
    }
    struct li2_lfc_code *v=&c->codes[a->code];
    if(!v->length) {
        v->length=a->length;v->step=a->step_disposition;
        for(unsigned i=0;i<a->length;i++)v->encoding[i]=a->bytes[i];
    }
    unsigned different=v->length!=a->length || v->step!=a->step_disposition;
    for(unsigned i=0;i<a->length;i++)if(v->encoding[i]!=a->bytes[i])different=1;
    li2_lfc_add(c,&c->totals[channel]);li2_lfc_add(c,&v->count[channel]);
    if(different)li2_lfc_add(c,&v->different[channel]);
    /* This existing decoder tag covers only its recognized MOV-to-SP/ESP/RSP
       forms. Refused descriptors carry no general GPR-effect information. */
    if(a->step_disposition==LI2_STEP_RSP_WRITE)li2_lfc_add(c,&c->rsp_mov[channel]);
}
int li2_preedge_plan_page_observed(uintptr_t,const unsigned char *,uintptr_t,
    uintptr_t,struct li2_preedge_plan *,struct li2_frontier_census *);
_Static_assert(sizeof(struct li2_lfc_code)==120,"bounded Code histogram cell");
_Static_assert(sizeof(struct li2_frontier_census)==592616,"bounded protected census");
#endif

_Static_assert(sizeof(struct li2_preedge_plan)==40744,"pre-edge v2 ABI");
_Static_assert(sizeof(struct li2_preedge_plan)<65536,"bounded full reconstruction");
_Static_assert(LI2_PREEDGE_HEADS==LI2_LINK_HEADS && LI2_PREEDGE_EXITS==LI2_LINK_EXITS &&
               LI2_PREEDGE_MAPS==LI2_LINK_MAPS,"unchanged planner limits");
#endif
