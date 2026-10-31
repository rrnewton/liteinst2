#ifndef LI2_PERSISTENT_COMPACT_H
#define LI2_PERSISTENT_COMPACT_H
#include "persistent_plan.h"
#define LI2_PE_COMPACT_VERSION 1U
#define LI2_PE_PROOF_SLOT_BYTES (45U*LI2_REGION_PAGE)
/* Every recovery row retains its exact original six uint32_t fields. Only
   data already present in the common primary is omitted: original descriptor,
   table and code image. Generated/spill/successor derive from the actual head.
   This is a distinct ready-only immutable payload, never a donor type alias. */
struct li2_pe_guard_record {
    uint32_t version,ready,result,image_bytes,boundaries,store_offset,reject_offset,reserved;
    uint32_t scratch_regs[4];
    struct li2_mg_boundary boundary[LI2_MG_BOUNDARIES];
};
struct li2_pe_compact {
    uint32_t version,bytes,ready,result,heads,exits,stores,source_bytes;
    uint32_t source_mask,decoder_result,guard_result,reserved;
    uintptr_t page[LI2_PE_SOURCES],entry,generated,spill;
    unsigned char source[LI2_PE_SOURCES][LI2_REGION_PAGE];
    unsigned char image[LI2_PE_IMAGE_BYTES];
    struct li2_pe_head head[LI2_PE_HEADS];
    struct li2_span_decoded original[LI2_PE_HEADS],frontier[LI2_PE_EXITS];
    struct li2_mg_store store_original[LI2_PE_HEADS];
    uintptr_t exit_pc[LI2_PE_EXITS];
    struct li2_mg_table table;
    struct li2_pe_guard_record guard[LI2_PE_HEADS];
};
/* Cold only. First run the unchanged full-plan reconstruction, then require
   every materialized guard to equal all6488 donor bytes. Failed/partial cold
   plans remain in their original representation and are never made ready.
   All three valid aligned host buffers must be disjoint. */
int li2_pe_compact_build(const struct li2_pe_plan *,struct li2_pe_plan *,struct li2_pe_compact *);
/* Fresh source/decoder/emitter reconstruction and whole compact equality.
   Explicit caller-owned cold buffers; never a warm entry or recovery proof. */
int li2_pe_compact_validate(const struct li2_pe_compact *,struct li2_pe_plan *,struct li2_pe_compact *);
/* Pure exact materialization, after actual immutable primary authority.
   It does not revalidate the source, registration, table or code permissions.
   No decoder or target-address access. Only an actual MOV head is accepted. */
int li2_pe_compact_guard(const struct li2_pe_compact *,unsigned,struct li2_mg_plan *);
/* Same pure recovery contract as li2_pe_recover. The guard scratch belongs to
   the actual protected RECOVERING owner and is disjoint from primary, raw
   frame, spill and output. No large automatic buffer or mutable plan mirror. */
int li2_pe_compact_recover(const struct li2_pe_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_mg_plan *,struct li2_pe_recovered *);
_Static_assert(sizeof(struct li2_pe_guard_record)==1584,"unpacked exact recovery rows");
_Static_assert(sizeof(struct li2_pe_compact)==182168,"common image/table once");
_Static_assert(sizeof(struct li2_pe_compact)<=LI2_PE_PROOF_SLOT_BYTES,"bounded R/NX primary");
_Static_assert(64U*(LI2_PE_PROOF_SLOT_BYTES+LI2_PE_IMAGE_BYTES)+
    2U*sizeof(struct li2_pe_plan)+sizeof(struct li2_pe_compact)+
    sizeof(struct li2_mg_plan)+LI2_REGION_PAGE<16U*1024U*1024U,
    "code/proof slots plus cold scratch and one active spill, not a capture wire");
#endif
