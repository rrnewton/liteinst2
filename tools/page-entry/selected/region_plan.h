#ifndef LI2_REGION_PLAN_H
#define LI2_REGION_PLAN_H
#include "region_decode.h"

#define LI2_REGION_PLAN_VERSION 1U
#define LI2_REGION_PAGE 4096U
#define LI2_REGION_BYTES 256U
#define LI2_REGION_HEADS 64U
#define LI2_REGION_BLOCKS 8U
#define LI2_REGION_EXITS 8U
#define LI2_REGION_MAPS (LI2_REGION_HEADS+1U)
enum li2_region_plan_status {
    LI2_REGION_PLAN_OK=0, LI2_REGION_PLAN_MISS=1,
    LI2_REGION_PLAN_ARGUMENT=2400, LI2_REGION_PLAN_DECODER,
    LI2_REGION_PLAN_BOUNDARY, LI2_REGION_PLAN_GRAPH,
    LI2_REGION_PLAN_RELOCATION, LI2_REGION_PLAN_CORRUPT
};
enum li2_region_stop {
    LI2_REGION_STOP_UNSUPPORTED=1, LI2_REGION_STOP_HEADS=2,
    LI2_REGION_STOP_BYTES=3
};
enum li2_region_pc_kind {
    LI2_REGION_PC_COPIED=1, LI2_REGION_PC_BRANCH=2,
    LI2_REGION_PC_EXIT=3
};
/* Successors 0..63 name head indices; 64..71 name exit indices. The two
   JCC edges are ordered taken, fallthrough (duplicates remain two edges). */
struct li2_region_head {
    uint32_t source_offset, source_length, generated_offset, generated_length;
    uint32_t successor_count, successors[2], block;
};
struct li2_region_pc {
    uint32_t version,ready,head_index,kind;
    uint32_t source_offset,source_length,generated_offset,generated_length;
    uintptr_t original_pc,generated_pc;
};
struct li2_region_plan {
    uint32_t version,ready,heads,blocks,exits,maps,longest_path,stop_reason;
    uint32_t source_bytes,image_bytes,decoder_calls,decoder_result;
    uintptr_t page,entry,generated,boundary_pc;
    unsigned char source[LI2_REGION_PAGE],image[LI2_REGION_PAGE];
    struct li2_region_decoded original[LI2_REGION_HEADS],boundary;
    struct li2_region_decoded emitted[LI2_REGION_MAPS];
    struct li2_region_head head[LI2_REGION_HEADS];
    uintptr_t exit_pc[LI2_REGION_EXITS];
    struct li2_region_pc map[LI2_REGION_MAPS];
};

/* PURE DESCRIPTIONS, NOT EXECUTION AUTHORITY. All pointers denote complete
   owned storage; output is aligned and disjoint from the supplied snapshot.
   The initialized, sealed decoder's serialized/nonreentrant contract applies.
   No heap, system call, application-data load or state prediction is used.
   Virtual source/generated pages are aligned, disjoint, finite canonical48
   pages; entry is inside source. Physical mappings/aliases are NOT proved.

   Decode the nonempty contiguous prefix until a valid unsupported instruction
   or the 256-byte/64-head limit. The stop instruction is actually decoded and
   retained, even for a limit stop. Invalid/truncated/missing boundaries refuse.
   A valid boundary must be inside the same page, including after a final JMP.
   Every selected head must be reachable from entry; all internal destinations
   are exact heads; the entire graph is acyclic and every path reaches one of
   at most eight original same-page exits. No subset is selected to hide an
   unreachable head/cycle. At most eight basic blocks and 64 original steps.

   NEXT bytes are copied exactly. JCC/JMP become equivalent near rel32 forms;
   only a last NEXT/JCC receives a synthetic final E9. Every emitted instruction
   is genuinely re-described and its complete effects compared. The whole
   image is 4096 bytes, unused tail CC; no literal, indirect jump, counter or
   scratch-register instruction is introduced. All failures leave ready=0.
   ARGUMENT leaves output untouched when pointer/alignment/alias checks fail.
   A nonzero result is never permission to execute a partial image. */
int li2_region_plan_page(uintptr_t,const unsigned char *,uintptr_t,uintptr_t,
                         struct li2_region_plan *);

/* Rebuilds the COMPLETE description with actual original/emitted decoder
   calls, then compares every byte, including inactive rows and padding.
   Bounded stack workspace is one plan (<64KiB), not persistent authority.
   It has the same decoder serialization prerequisites as planning. */
int li2_region_plan_validate(const struct li2_region_plan *);
/* Validates the complete plan first; returns only exact generated heads.
   Interior/tail/unknown PCs are MISS. A synthetic E9 names the unexecuted
   original boundary, source_length=0 and head_index=its last predecessor.
   Other rows name the exact original instruction. No association grants
   fault completion/resumption or asserts an application instruction ran. */
int li2_region_map_pc(const struct li2_region_plan *,uintptr_t,
                      struct li2_region_pc *);

/* FUTURE OWNER OBLIGATIONS, NOT PROVIDED HERE:
   Authenticate a held immutable full-page source lease, current allocation/
   generation, full bytes, SEALED backing, EOF/seals/stat/VMA/no aliases, and
   every original exit. Keep the whole original page R/NX and exclude other
   RX/mutation owners until generated RX is revoked/synchronized/verified.
   Bind each descriptor to actual NONE/no-write/rseq guards, actual protected
   range/PKRU/full-state/mask/TLS/singleton/no-debug/no-CET ingress contracts.
   Publish the exact whole generated page under protected write-once W^X
   ownership; a plan supplies no generated mapping or seal assertion.
   CPU loads use restored application registers/rights. No handler data
   pre-read, pointer validity/termination assumption or predicted flags is
   supplied. Native qualification must compare every actual GPR/flag (AF
   included), FP, stack and data byte. Fault/nested/unexpected events retain
   actual full frames and exact PC mapping and remain terminal in this scope.
   No old fetch15/unroll39, STEP, WholeFunctionRequest, owner, cap, comparator,
   failed cohort or source admission rule is replaced or widened. */
_Static_assert(sizeof(uintptr_t)==8,"region x86-64 description");
_Static_assert(sizeof(struct li2_region_head)==32,"region head layout");
_Static_assert(sizeof(struct li2_region_pc)==48,"region map layout");
_Static_assert(sizeof(struct li2_region_plan)==53024,"region plan layout");
_Static_assert(sizeof(struct li2_region_plan)<65536,"bounded plan workspace");
#endif
