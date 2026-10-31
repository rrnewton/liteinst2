#ifndef LI2_LINKED_MOV_GUARD_H
#define LI2_LINKED_MOV_GUARD_H
#include "decoder.h"
#define LI2_MG_VERSION 1U
#define LI2_MG_RANGES 131U
#define LI2_MG_CODE_BYTES 512U
#define LI2_MG_BOUNDARIES 64U
#define LI2_MG_STATUS UINT64_C(0x8d5)
/* A distinct descriptive profile. None of these objects grant write/RX,
   source, registration, lifecycle, spill or recovery authority. */
struct li2_mg_tf { uint64_t pc,next_pc;uint32_t abi_version,policy,code,length,flow,family; };
struct li2_mg_store {
    struct li2_mg_tf tf;unsigned char bytes[16];
    uint64_t displacement,rip_target,immediate;
    uint32_t version,ready,refusal,available,width_bytes,source_kind,source_reg,base;
    uint32_t index,scale,rip_relative,displacement_offset,displacement_bytes,modrm_offset,opcode_offset,reserved;
};
uint32_t li2_decoder_mov_store(uint64_t,const unsigned char *,size_t,struct li2_mg_store *);
struct li2_mg_range { uint64_t first,end; };
struct li2_mg_node { uint64_t first,end,left,right; };
struct li2_mg_table {
    uint32_t version,ready,count,height;uint64_t address,root;
    struct li2_mg_node node[LI2_MG_RANGES];
};
enum li2_mg_status { LI2_MG_OK=0,LI2_MG_ARGUMENT=2601,LI2_MG_DECODER=2602,
    LI2_MG_FORM=2603,LI2_MG_RELOCATION=2604,LI2_MG_CAPACITY=2605,LI2_MG_CORRUPT=2606 };
enum li2_mg_flags { LI2_MG_PHYSICAL=0,LI2_MG_AH_PHYSICAL_OF=1,LI2_MG_AH_AL=2 };
enum li2_mg_phase { LI2_MG_BEFORE=0,LI2_MG_STORE=1,LI2_MG_AFTER=2,LI2_MG_REJECT=3 };
/* State BEFORE this instruction; current faulting stores have not retired.
   Bits0..3 name scratch_regs[] and fixed spill[0..3]. All unused rows are0. */
struct li2_mg_boundary { uint32_t offset,length,spill_valid,dirty,flags,phase; };
struct li2_mg_plan {
    uint32_t version,ready,result,image_bytes,boundaries,store_offset,reject_offset,reserved;
    uint64_t generated,spill,successor;
    uint32_t scratch_regs[4]; /* RAX,A,E,T, distinct; no RSP/operand clobber. */
    struct li2_mg_store original;
    struct li2_mg_table table;
    struct li2_mg_boundary boundary[LI2_MG_BOUNDARIES];
    unsigned char image[LI2_MG_CODE_BYTES];
};
struct li2_mg_recovered { uint64_t gpr[16],flags,original_pc;uint32_t phase,complete; };
/* All host pointers are valid aligned owned/disjoint buffers. Addresses are
   descriptive eventual addresses; no target address is dereferenced here. */
int li2_mg_table_build(const struct li2_mg_range *,size_t,uintptr_t,struct li2_mg_table *);
int li2_mg_table_validate(const struct li2_mg_table *);
int li2_mg_interval_allowed(const struct li2_mg_table *,uint64_t,unsigned);
int li2_mg_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,uintptr_t,
                const struct li2_mg_table *,struct li2_mg_plan *);
int li2_mg_validate(const struct li2_mg_plan *);
/* Pure boundary reconstruction. Caller must first authenticate actual epoch,
   full sealed plan and exact raw PC, raw frame and protected spill extent.
   It reads ONLY initialized dirty spills; RF/trap metadata stays raw. */
int li2_mg_recover(const struct li2_mg_plan *,uintptr_t,const uint64_t[16],uint64_t,
                   const uint64_t[4],struct li2_mg_recovered *);
_Static_assert(sizeof(struct li2_mg_store)==144,"four-Code descriptor");
_Static_assert(offsetof(struct li2_mg_store,version)==80,"store descriptor fields");
_Static_assert(sizeof(struct li2_mg_node)==32,"constant interval node");
_Static_assert(sizeof(struct li2_mg_table)==4224,"bounded interval table");
_Static_assert(sizeof(struct li2_mg_boundary)==24,"exact boundary state");
_Static_assert(sizeof(struct li2_mg_plan)==6488,"guard image and recovery ABI");
_Static_assert(sizeof(struct li2_mg_recovered)==152,"logical integer frame");
#endif
