#ifndef LI2_PERSISTENT_GROUP_COMPACT_H
#define LI2_PERSISTENT_GROUP_COMPACT_H
#include "persistent_group_plan.h"
#include "persistent_compact.h"
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
#ifdef LI2_ADD_GUARD
#define LI2_PG_COMPACT_VERSION 4U
#else
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
#define LI2_PG_COMPACT_VERSION 3U
#else
#define LI2_PG_COMPACT_VERSION 2U
#endif
#endif
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
#undef LI2_PG_COMPACT_VERSION
#define LI2_PG_COMPACT_VERSION 5U
#endif
#ifdef LI2_PERSISTENT_CALL_DISPATCH
#undef LI2_PG_COMPACT_VERSION
#define LI2_PG_COMPACT_VERSION 6U
/* The full CALL record's literal_offset is exactly504 and reserved[3] are
   exactly zero. Reconstruction plus whole1600-byte comparison proves them;
   no mutable field or boundary row is omitted. Keep the old89-page proof. */
struct li2_pg_call_record {
    uint32_t version,ready,result,image_bytes,boundaries,push_offset,transfer_offset,miss_offset;
    uint32_t scratch_regs[4];
    struct li2_mg_boundary boundary[LI2_CD_BOUNDARIES];
};
_Static_assert(sizeof(struct li2_pg_call_record)==1584,"exact reconstructed CALL compact record");
#endif
union li2_pg_guard_record { struct li2_pe_guard_record mov;struct li2_jd_record dispatch;
#ifdef LI2_PERSISTENT_CALL_DISPATCH
    struct li2_pg_call_record call;
#endif
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
    struct li2_dd_record direct;
#endif
#ifdef LI2_ADD_GUARD
    struct li2_ag_record add;
#endif
};
_Static_assert(sizeof(union li2_pg_guard_record)==sizeof(struct li2_pe_guard_record),"typed compact recovery width");
_Static_assert(_Alignof(union li2_pg_guard_record)==_Alignof(struct li2_pe_guard_record),"typed compact recovery alignment");
#else
#define LI2_PG_COMPACT_VERSION 1U
#endif
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
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
    union li2_pg_instruction instruction[LI2_PG_HEADS];
#else
    struct li2_mg_store store_original[LI2_PG_HEADS];
#endif
    uintptr_t exit_pc[LI2_PG_BOUNDARIES];
    struct li2_pg_edge edge[LI2_PG_BOUNDARIES];
    struct li2_mg_table table;
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
    union li2_pg_guard_record guard[LI2_PG_HEADS];
#else
    struct li2_pe_guard_record guard[LI2_PG_HEADS];
#endif
};
int li2_pg_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pg_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pg_compact_guard(const struct li2_pg_compact *,unsigned member,unsigned head,struct li2_mg_plan *);
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
/* Materialize only an authenticated DISPATCH head into protected scratch.
   The full slot tail is zero, the retained code tail is CC, and the original
   descriptor/common row binding remain typed. No decoder or cell read. */
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
int li2_pg_compact_direct(const struct li2_pg_compact *,unsigned,unsigned,struct li2_dd_plan *);
/* Exact selected ordinary exit; -1 absent, -2 malformed/ambiguous. Both
   typed external arms at one original PC remain distinct tokens. */
int li2_pg_compact_exit(const struct li2_pg_compact *,uintptr_t,uint64_t);
#endif
int li2_pg_compact_dispatch(const struct li2_pg_compact *,unsigned,unsigned,struct li2_jd_plan *);
#ifdef LI2_PERSISTENT_CALL_DISPATCH
int li2_pg_compact_call(const struct li2_pg_compact *,unsigned,unsigned,struct li2_cd_plan *);
#endif
#ifdef LI2_ADD_GUARD
int li2_pg_compact_add(const struct li2_pg_compact *,unsigned,unsigned,struct li2_ag_plan *);
#endif
_Static_assert(offsetof(struct li2_pg_compact,original)==offsetof(struct li2_pg_plan,original),"same immutable original row offset");
_Static_assert(offsetof(struct li2_pg_compact,table)==offsetof(struct li2_pg_plan,table),"same actual common table offset");
#endif
/* Authenticate actual immutable group and raw savedPC before calling. Select
   image/stub from that PC before spill reads; link start maps the committed
   original edge to target-before with no spill access. Interior/padding PCs
   refuse. Donor recovery owns its protected scratch and never replays a store.
   link==UINT32_MAX for an image; member/head==UINT32_MAX for a link. */
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
int li2_pg_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],union li2_pg_guard *,struct li2_pg_recovered *);
#else
int li2_pg_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_mg_plan *,struct li2_pg_recovered *);
#endif
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
#ifdef LI2_PERSISTENT_CALL_DISPATCH
_Static_assert(sizeof(struct li2_pg_compact)==353616,"exact CALL-aware compact primary");
#else
_Static_assert(sizeof(struct li2_pg_compact)==353608,"exact domain-aware compact primary");
#endif
#else
_Static_assert(sizeof(struct li2_pg_compact)==353600,"exact shared group image/source/table primary");
#endif
_Static_assert(sizeof(struct li2_pg_compact)<96U*LI2_REGION_PAGE,"bounded shared immutable group primary");
#endif
