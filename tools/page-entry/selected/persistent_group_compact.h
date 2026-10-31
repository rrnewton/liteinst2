#ifndef LI2_PERSISTENT_GROUP_COMPACT_H
#define LI2_PERSISTENT_GROUP_COMPACT_H
#include "persistent_group_plan.h"
#include "persistent_compact.h"
#define LI2_PG_COMPACT_VERSION 1U
struct li2_pg_compact {
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
    struct li2_pe_guard_record guard[LI2_PG_HEADS];
};
int li2_pg_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pg_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pg_compact_guard(const struct li2_pg_compact *,unsigned member,unsigned head,struct li2_mg_plan *);
/* Authenticate actual immutable group and raw savedPC before calling. Select
   image/stub from that PC before spill reads; link start maps the committed
   original edge to target-before with no spill access. Interior/padding PCs
   refuse. Donor recovery owns its protected scratch and never replays a store.
   link==UINT32_MAX for an image; member/head==UINT32_MAX for a link. */
int li2_pg_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_mg_plan *,struct li2_pg_recovered *);
_Static_assert(sizeof(struct li2_pg_compact)==353600,"exact shared group image/source/table primary");
_Static_assert(sizeof(struct li2_pg_compact)<96U*LI2_REGION_PAGE,"bounded shared immutable group primary");
#endif
