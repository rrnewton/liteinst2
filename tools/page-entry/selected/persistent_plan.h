#ifndef LI2_PERSISTENT_PLAN_H
#define LI2_PERSISTENT_PLAN_H
#include "region_plan.h"
#include "linked_mov_guard.h"
#define LI2_PE_VERSION 1U
#define LI2_PE_SOURCES 2U
#define LI2_PE_HEADS 64U
#define LI2_PE_EXITS 8U
#define LI2_PE_SLOT_BYTES LI2_MG_CODE_BYTES
#define LI2_PE_IMAGE_BYTES (LI2_PE_HEADS*LI2_PE_SLOT_BYTES)
enum li2_pe_status { LI2_PE_OK=0,LI2_PE_MISS=1,LI2_PE_ARGUMENT=2700,
    LI2_PE_DECODER,LI2_PE_BOUNDARY,LI2_PE_GRAPH,LI2_PE_RELOCATION,LI2_PE_CORRUPT };
enum li2_pe_kind { LI2_PE_NONE=1,LI2_PE_MOV=2 };
enum li2_pe_map_kind { LI2_PE_COPIED=1,LI2_PE_BRANCH,LI2_PE_EDGE,LI2_PE_GUARD };
struct li2_pe_head {
    uint32_t kind,source_page,source_offset,source_length;
    uint32_t successor_count,successors[2],generated_length;
};
/* Distinct pure description: reachable cycles are legal, no longest_path or
   termination claim. All extents/addresses remain descriptive until an actual
   source-set and immutable execution owner authenticates them. */
struct li2_pe_plan {
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
    struct li2_mg_plan guard[LI2_PE_HEADS];
};
struct li2_pe_recovered {
    uint64_t gpr[16],flags,original_pc;
    uint32_t head,kind,phase,complete;
};
/* Serialized initialized/sealed decoder, valid aligned disjoint host buffers.
   Two sorted distinct lower-canonical pages; entry lies in one. Source/code/
   spill/table virtual ranges are disjoint. Only full actual source ownership
   can authorize using these bytes; the supplied table is NOT a registry proof.
   All reachable heads/unsupported exits are decoded, overlap is refused,
   direct successors must lie in the two pages. A straddle requires both exact
   adjacent source pages. At least one real unsupported exit is required;
   it does not prove eventual termination. Whole source/image/unused rows bind.
   Existing NONE and MOV descriptor APIs are called unchanged. */
int li2_pe_plan_pages(const uintptr_t[LI2_PE_SOURCES],
    const unsigned char[LI2_PE_SOURCES][LI2_REGION_PAGE],uintptr_t,uintptr_t,uintptr_t,
    const struct li2_mg_table *,struct li2_pe_plan *);
/* Caller-provided aligned protected scratch avoids a half-MiB signal-stack
   reconstruction. This performs whole fresh reconstruction, never a hot guard. */
int li2_pe_plan_validate(const struct li2_pe_plan *,struct li2_pe_plan *scratch);
/* PURE association/recovery only after actual immutable-generation authority.
   No recursive decoder call at interruption. Raw full frame/siginfo/FP/memory
   must be retained by the owner; internal guard faults remain internal faults.
   Only exact emitted boundaries map, and only initialized dirty spills read.
   No fault completion, replay, resume or source/RX authority is returned. */
int li2_pe_recover(const struct li2_pe_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_pe_recovered *);
_Static_assert(sizeof(struct li2_pe_head)==32,"new typed head");
_Static_assert(sizeof(struct li2_pe_plan)<512U*1024U,"bounded explicit reconstruction buffer");
_Static_assert(LI2_PE_IMAGE_BYTES==32768,"eight-page new image, old image unchanged");
#endif
