#ifndef LI2_LOOP_CACHED_DIRECT_CONTEXT_H
#define LI2_LOOP_CACHED_DIRECT_CONTEXT_H
#include <stdint.h>
#include "loop_translation_arena.h"
#include "persistent_active_domain.h"
#include "linked_loop_direct.h"
#if !defined(LI2_LOOP_CACHED_DIRECT_CONTEXT) || LI2_LOOP_CACHED_DIRECT_CONTEXT != 1 || \
    !defined(LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_BINDING_VERSION) || \
    LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_BINDING_VERSION != 1
#error "cached DIRECT contexts require their distinct complete binding"
#endif
#if defined(LI2_LOOP_TRANSLATION_ARENA_CAPACITY) || defined(LI2_LOOP_TRANSLATION_ARENA_PROGRAM)
#error "the first cached DIRECT context uses the original twelve-node profile"
#endif
#define LI2_LCX_VERSION 1U
#define LI2_LCX_DIRECTORY_VERSION 2U
#define LI2_LCX_AUXILIARY UINT32_C(0x80000000)
/* This schema shares only the emitter's searched byte layout with JD version1.
   ordinal is an actual head for ordinary rows, or AUXILIARY|auxiliary_index.
   No auxiliary row is cast to an ordinary head or changes an owner's headlist. */
struct li2_lcx_row {
    uintptr_t pc,generated;
    uint64_t generation;
    uint32_t slot,ordinal;
};
struct li2_lcx_directory {
    uint64_t version,count,serial,reserved;
    struct li2_lcx_row row[LI2_JD_DOMAIN_HEADS];
};
struct li2_lcx_tail {
    uint32_t version,source_page,source_offset,reserved;
    struct li2_span_decoded original;
    struct li2_pgs_target target;
};
/* A proposal names an actual external arm in an actual owner. It is a hint
   until that member's pair has passed the unchanged fresh PGX/source checks. */
struct li2_lcx_route {
    uint32_t from_member,from_head,arm,owner_member;
};
/* Immutable for an execution lease; no lease serial or replaceable binding
   generation is embedded in generated code. The separate sealed capability
   binds these exact values to the current union. */
struct li2_lcx_image {
    struct li2_lcx_tail tail;
    struct li2_dd_aux_plan plan;
};
struct li2_lcx_capability {
    struct li2_lcx_route route;
    struct li2_pgd_ref from,owner,target;
    uintptr_t original,generated,target_generated;
    uint32_t auxiliary,target_head,arm,reserved;
};
/* Supplied from the actual controller's publication type and page-rounded
   allocation, never inferred from a compact-plan pointer. Runtime must bind
   these constants to PE_PROOF_BYTES and offsetof(pe_payload, source/plan). */
struct li2_lcx_publication_layout {
    size_t bytes,key_offset,plan_offset;
};
struct li2_lcx_lease {
    struct li2_pg_token token;
    uintptr_t code,spill,directory;
    struct li2_lcx_publication_layout publication;
    uint32_t version,count,members,reserved;
    struct li2_lcx_capability capability[LI2_DD_AUX_SLOTS];
};
/* Pure reconstruction from already authenticated immutable values. No helper
   here grants memory, source, rseq, entry, permission or recovery authority.
   Tail discovery also serves as an advisory pre-lease candidate check. */
int li2_lcx_tail_value(const struct li2_pg_source_key *,const struct li2_pg_compact *,
    uintptr_t,struct li2_lcx_tail *);
int li2_lcx_image_value(const struct li2_pgd_member *,uintptr_t,uintptr_t,uintptr_t,unsigned,
    struct li2_lcx_image *);
int li2_lcx_lease_value(const struct li2_pgd_view *,const struct li2_lcx_route *,
    const struct li2_lcx_image *,unsigned,uintptr_t,uintptr_t,
    const struct li2_lcx_publication_layout *,
    struct li2_lcx_lease *,struct li2_lcx_directory *);
_Static_assert(sizeof(struct li2_lcx_row)==sizeof(struct li2_jd_domain_row),
    "same searched row stride; distinct tagged schema");
_Static_assert(offsetof(struct li2_lcx_directory,row)==32 &&
    offsetof(struct li2_lcx_row,pc)==0 && offsetof(struct li2_lcx_row,generated)==8,
    "unchanged searched offsets in shared emitter");
_Static_assert(sizeof(struct li2_lcx_directory)==sizeof(struct li2_jd_domain_directory),
    "the original directory extent and 256-row bound remain");
#endif
