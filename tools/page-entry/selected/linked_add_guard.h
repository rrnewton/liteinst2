#ifndef LI2_LINKED_ADD_GUARD_H
#define LI2_LINKED_ADD_GUARD_H
#include "linked_mov_guard.h"
#define LI2_AG_VERSION 1U
#define LI2_AG_CODE_BYTES 512U
#define LI2_AG_BOUNDARIES 64U
#define LI2_AG_STATUS UINT64_C(0x8d5)
#define LI2_AG_READ_WRITE 3U
/* One descriptive Code: Add_rm64_r64. This is neither a MOV store nor an
   execution/write permit. The existing interval-table authority is reused. */
struct li2_ag_descriptor {
    struct li2_mg_tf tf;unsigned char bytes[16];
    uint64_t displacement,rip_target,flags_written;
    uint32_t version,ready,refusal,available,width_bytes,memory_access,source_reg,base;
    uint32_t index,scale,rip_relative,displacement_offset,displacement_bytes,modrm_offset,opcode_offset,reserved;
};
uint32_t li2_decoder_add_rmw(uint64_t,const unsigned char *,size_t,struct li2_ag_descriptor *);
enum li2_ag_status { LI2_AG_OK=0,LI2_AG_ARGUMENT=3601,LI2_AG_DECODER=3602,
    LI2_AG_FORM=3603,LI2_AG_RELOCATION=3604,LI2_AG_CAPACITY=3605,LI2_AG_CORRUPT=3606 };
enum li2_ag_flags { LI2_AG_PHYSICAL=0,LI2_AG_AH_PHYSICAL_OF=1,LI2_AG_AH_AL=2 };
enum li2_ag_phase { LI2_AG_BEFORE=0,LI2_AG_RMW=1,LI2_AG_AFTER=2,LI2_AG_REJECT=3 };
/* State before this emitted instruction. RMW has not retired; AFTER carries
   the actual new status flags and guest memory. No recovery replays the ADD. */
struct li2_ag_boundary { uint32_t offset,length,spill_valid,dirty,flags,phase; };
struct li2_ag_plan {
    uint32_t version,ready,result,image_bytes,boundaries,rmw_offset,reject_offset,reserved;
    uint64_t generated,spill,successor;
    uint32_t scratch_regs[4];
    struct li2_ag_descriptor original;
    struct li2_mg_table table;
    struct li2_ag_boundary boundary[LI2_AG_BOUNDARIES];
    unsigned char image[LI2_AG_CODE_BYTES];
};
struct li2_ag_record {
    uint32_t version,ready,result,image_bytes,boundaries,rmw_offset,reject_offset,reserved;
    uint32_t scratch_regs[4];
    struct li2_ag_boundary boundary[LI2_AG_BOUNDARIES];
};
struct li2_ag_recovered { uint64_t gpr[16],flags,original_pc;uint32_t phase,complete; };
/* Owned/disjoint host buffers. Eventual addresses are descriptive; emit and
   validate dereference no target. Per-execution EA is checked in emitted code.
   The caller authenticates the complete private/source/rseq interval table,
   source/alias custody, and private spill authority before generated entry. */
int li2_ag_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,uintptr_t,
    const struct li2_mg_table *,struct li2_ag_plan *);
int li2_ag_validate(const struct li2_ag_plan *);
/* Caller authenticates immutable plan/epoch/raw PC/frame and initialized
   protected spill first. Fault metadata/RF remain actual; memory is untouched. */
int li2_ag_recover(const struct li2_ag_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_ag_recovered *);
_Static_assert(sizeof(struct li2_ag_descriptor)==144,"one-Code RMW descriptor");
_Static_assert(offsetof(struct li2_ag_descriptor,version)==80,"RMW descriptor fields");
_Static_assert(sizeof(struct li2_ag_boundary)==24,"exact RMW boundary state");
_Static_assert(sizeof(struct li2_ag_plan)==6488,"typed full RMW guard budget");
_Static_assert(sizeof(struct li2_ag_record)==1584,"typed compact RMW guard budget");
_Static_assert(sizeof(struct li2_ag_recovered)==152,"logical RMW integer frame");
#endif
