#ifndef LI2_PERSISTENT_GROUP_PLAN_H
#define LI2_PERSISTENT_GROUP_PLAN_H
#include "persistent_plan.h"
#if !defined(LI2_PERSISTENT_GROUP) || LI2_PERSISTENT_GROUP != 1
#error "distinct two-member persistent group required"
#endif
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
#include "linked_jmp_dispatch.h"
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
#define LI2_PG_VERSION 3U
#else
#define LI2_PG_VERSION 2U
#endif
/* New profile semantics; old group and persistent kinds remain unchanged. */
enum li2_pg_instruction_kind { LI2_PG_DISPATCH=3 };
union li2_pg_instruction { struct li2_mg_store mov;struct li2_jd_descriptor dispatch; };
union li2_pg_guard {
    struct li2_mg_plan mov;
    struct li2_jd_plan dispatch;
    unsigned char bytes[sizeof(struct li2_mg_plan)];
};
_Static_assert(sizeof(union li2_pg_instruction)==sizeof(struct li2_mg_store),"typed original width");
_Static_assert(sizeof(union li2_pg_guard)==sizeof(struct li2_mg_plan),"typed full recovery width");
_Static_assert(_Alignof(union li2_pg_instruction)==_Alignof(struct li2_mg_store),"typed original alignment");
_Static_assert(_Alignof(union li2_pg_guard)==_Alignof(struct li2_mg_plan),"typed full recovery alignment");
#else
#define LI2_PG_VERSION 1U
#endif
#define LI2_PG_MEMBERS 2U
#define LI2_PG_HEADS (LI2_PG_MEMBERS*LI2_PE_HEADS)
#define LI2_PG_BOUNDARIES LI2_PE_EXITS
#define LI2_PG_CODE_EXTENTS 3U
#define LI2_PG_CODE_PAGES 17U
#define LI2_PG_STUB_BYTES LI2_REGION_PAGE
#define LI2_PG_SLOT_BYTES LI2_REGION_PAGE
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
_Static_assert(LI2_JD_HEADS==LI2_PG_HEADS && LI2_JD_MEMBER_HEADS==LI2_PE_HEADS,"same immutable row partition");
_Static_assert(LI2_JD_SLOT_BYTES==LI2_PE_SLOT_BYTES && LI2_JD_IMAGE_BYTES==LI2_PE_IMAGE_BYTES,"same actual generated target geometry");
#endif
enum li2_pg_status { LI2_PG_OK=0,LI2_PG_MISS=1,LI2_PG_ARGUMENT=2800,
    LI2_PG_DECODER,LI2_PG_BOUNDARY,LI2_PG_GRAPH,LI2_PG_RELOCATION,LI2_PG_CORRUPT };
enum li2_pg_edge_kind { LI2_PG_CAPACITY_LINK=1 };
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
enum li2_pg_map_kind { LI2_PG_COPIED=1,LI2_PG_BRANCH,LI2_PG_EDGE,LI2_PG_GUARD,LI2_PG_LINK,LI2_PG_DISPATCH_MAP };
#else
enum li2_pg_map_kind { LI2_PG_COPIED=1,LI2_PG_BRANCH,LI2_PG_EDGE,LI2_PG_GUARD,LI2_PG_LINK };
#endif
#define LI2_PG_COMMITTED_EDGE 4U
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
struct li2_pg_layout { uintptr_t generated[2],stubs,slots,spill,directory; };
#else
struct li2_pg_layout { uintptr_t generated[2],stubs,slots,spill; };
#endif
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
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
    union li2_pg_instruction instruction[LI2_PG_HEADS];
#else
    struct li2_mg_store store_original[LI2_PG_HEADS];
#endif
    uintptr_t exit_pc[LI2_PG_BOUNDARIES];
    struct li2_pg_edge edge[LI2_PG_BOUNDARIES];
    struct li2_mg_table table;
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
    union li2_pg_guard guard[LI2_PG_HEADS];
#else
    struct li2_mg_plan guard[LI2_PG_HEADS];
#endif
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
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
/* Version2 retains one or two nonempty members,1..128 total heads, with the
   same two complete source pages and17-page generated owner. DISPATCH has
   no static successor; its typed exit is the exact original JMP before any
   effect. All links plus real exits still share the unchanged eight slots.
   Immutable original[] and table offsets are common to full/compact plans;
   the live owner must bind the actual protected row address and generation. */
#else
/* Pure cold reconstruction only. All host buffers are valid aligned and
   disjoint. Layout's two8-page images,1-page stubs,1-page slots,32-byte spill,
   table and both complete source pages are disjoint lower-canonical ranges.
   Exactly two nonempty members, A64/B1..64; shared links+exits<=8. Complete
   global decoding/overlap/successor proof precedes emission. A real owner
   must authenticate source/table/code/slots and one shared rseq lifetime. */
#endif
int li2_pg_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *);
int li2_pg_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *);
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
/* Descriptive row binding only, never a source/generation permit. table is
   the eventual actual common table; checked subtraction retains the compiled
   root and full immutable original[] order without changing layout ABI. */
int li2_pg_dispatch_binding(const uintptr_t[2],const struct li2_pg_layout *,
    uintptr_t,unsigned,unsigned,struct li2_jd_binding *);
#endif
/* Immediate protected-output consistency, never independent source authority.
   Exact selected-root independent decode/refusal contract is retained. */
int li2_pg_miss_valid(const struct li2_pg_plan *,const struct li2_pg_miss *,int);
/* -1 malformed geometry,0 impossible original rel32 exit,1 not ruled out.
   Pure necessary-only advisory; no mapped memory or authority. */
int li2_pg_placement(uintptr_t,const struct li2_pg_layout *);
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
_Static_assert(sizeof(struct li2_pg_layout)==48,"three code extents plus sealed domain directory");
#else
_Static_assert(sizeof(struct li2_pg_layout)==40,"three code extents and private data");
#endif
_Static_assert(sizeof(struct li2_pg_edge)==48,"exact directed original edge");
_Static_assert(sizeof(struct li2_pg_miss)==32,"separate protected diagnosis");
_Static_assert(sizeof(struct li2_pg_recovered)==168,"member or committed edge recovery");
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
_Static_assert(sizeof(struct li2_pg_plan)==981320,"exact domain-aware full description");
#else
_Static_assert(sizeof(struct li2_pg_plan)==981312,"exact separate two-member full description");
#endif
_Static_assert(sizeof(struct li2_pg_plan)<1024U*1024U,"bounded two-member cold scratch");
_Static_assert(LI2_PG_CODE_PAGES==2U*(LI2_PE_IMAGE_BYTES/LI2_REGION_PAGE)+1U,"17 code pages");
#endif
