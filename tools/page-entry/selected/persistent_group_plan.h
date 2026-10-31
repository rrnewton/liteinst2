#ifndef LI2_PERSISTENT_GROUP_PLAN_H
#define LI2_PERSISTENT_GROUP_PLAN_H
#include "persistent_plan.h"
#if !defined(LI2_PERSISTENT_GROUP) || LI2_PERSISTENT_GROUP != 1
#error "distinct two-member persistent group required"
#endif
#define LI2_PG_VERSION 1U
#define LI2_PG_MEMBERS 2U
#define LI2_PG_HEADS (LI2_PG_MEMBERS*LI2_PE_HEADS)
#define LI2_PG_BOUNDARIES LI2_PE_EXITS
#define LI2_PG_CODE_EXTENTS 3U
#define LI2_PG_CODE_PAGES 17U
#define LI2_PG_STUB_BYTES LI2_REGION_PAGE
#define LI2_PG_SLOT_BYTES LI2_REGION_PAGE
enum li2_pg_status { LI2_PG_OK=0,LI2_PG_MISS=1,LI2_PG_ARGUMENT=2800,
    LI2_PG_DECODER,LI2_PG_BOUNDARY,LI2_PG_GRAPH,LI2_PG_RELOCATION,LI2_PG_CORRUPT };
enum li2_pg_edge_kind { LI2_PG_CAPACITY_LINK=1 };
enum li2_pg_map_kind { LI2_PG_COPIED=1,LI2_PG_BRANCH,LI2_PG_EDGE,LI2_PG_GUARD,LI2_PG_LINK };
#define LI2_PG_COMMITTED_EDGE 4U
struct li2_pg_layout { uintptr_t generated[2],stubs,slots,spill; };
struct li2_pg_edge {
    uint32_t kind,source_head,successor,target_head;
    uintptr_t original_target,generated_target,stub,slot;
};
/* Global index i has exactly one member i/64 and local index i%64. Head
   successors are global indices0..127 or real unsupported exits128..135.
   Two code images and the stub image are distinct actual extents. The common
   table/source are retained once. No old plan is cast to this type. */
struct li2_pg_plan {
    uint32_t version,bytes,ready,result,heads,exits,stores,source_bytes;
    uint32_t source_mask,decoder_result,guard_result,reserved;
    uint32_t member_heads[2],links,reserved2;
    uintptr_t page[2],entry;
    struct li2_pg_layout layout;
    unsigned char source[2][LI2_REGION_PAGE];
    unsigned char image[2][LI2_PE_IMAGE_BYTES],stub_image[LI2_PG_STUB_BYTES];
    struct li2_pe_head head[LI2_PG_HEADS];
    struct li2_span_decoded original[LI2_PG_HEADS],frontier[LI2_PG_BOUNDARIES];
    struct li2_mg_store store_original[LI2_PG_HEADS];
    uintptr_t exit_pc[LI2_PG_BOUNDARIES];
    struct li2_pg_edge edge[LI2_PG_BOUNDARIES];
    struct li2_mg_table table;
    struct li2_mg_plan guard[LI2_PG_HEADS];
};
enum li2_pg_reason {
    LI2_PGD_NONE=0,LI2_PGD_ROOT_UNSUPPORTED,LI2_PGD_SOURCE_INVALID,
    LI2_PGD_SOURCE_TRUNCATED,LI2_PGD_SOURCE_OVERLAP,LI2_PGD_OUTSIDE_PAIR,
    LI2_PGD_HEAD_LIMIT,LI2_PGD_EXIT_LIMIT,LI2_PGD_QUEUE_LIMIT,LI2_PGD_NO_EXIT,
    LI2_PGD_RIP_REACH,LI2_PGD_BRANCH_REACH,LI2_PGD_FALLTHROUGH_REACH,
    LI2_PGD_GUARD_RIP_REACH,LI2_PGD_GUARD_FOLLOW_REACH,LI2_PGD_ROOT_SELECTED,
    LI2_PGD_SINGLE_MEMBER,LI2_PGD_LINK_LIMIT,LI2_PGD_REASON_COUNT
};
enum li2_pg_site { LI2_PGD_NO_SITE=0,LI2_PGD_SOURCE=1,LI2_PGD_EMIT=2 };
struct li2_pg_miss { uint32_t version,status,reason,site;uintptr_t pc;uint64_t detail; };
struct li2_pg_recovered {
    uint64_t gpr[16],flags,original_pc;
    uint32_t member,head,link,kind,phase,complete;
};
/* Pure cold reconstruction only. All host buffers are valid aligned and
   disjoint. Layout's two8-page images,1-page stubs,1-page slots,32-byte spill,
   table and both complete source pages are disjoint lower-canonical ranges.
   Exactly two nonempty members, A64/B1..64; shared links+exits<=8. Complete
   global decoding/overlap/successor proof precedes emission. A real owner
   must authenticate source/table/code/slots and one shared rseq lifetime. */
int li2_pg_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *);
int li2_pg_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *);
/* Immediate protected-output consistency, never independent source authority.
   Exact selected-root independent decode/refusal contract is retained. */
int li2_pg_miss_valid(const struct li2_pg_plan *,const struct li2_pg_miss *,int);
/* -1 malformed geometry,0 impossible original rel32 exit,1 not ruled out.
   Pure necessary-only advisory; no mapped memory or authority. */
int li2_pg_placement(uintptr_t,const struct li2_pg_layout *);
_Static_assert(sizeof(struct li2_pg_layout)==40,"three code extents and private data");
_Static_assert(sizeof(struct li2_pg_edge)==48,"exact directed original edge");
_Static_assert(sizeof(struct li2_pg_miss)==32,"separate protected diagnosis");
_Static_assert(sizeof(struct li2_pg_recovered)==168,"member or committed edge recovery");
_Static_assert(sizeof(struct li2_pg_plan)==981312,"exact separate two-member full description");
_Static_assert(sizeof(struct li2_pg_plan)<1024U*1024U,"bounded two-member cold scratch");
_Static_assert(LI2_PG_CODE_PAGES==2U*(LI2_PE_IMAGE_BYTES/LI2_REGION_PAGE)+1U,"17 code pages");
#endif
