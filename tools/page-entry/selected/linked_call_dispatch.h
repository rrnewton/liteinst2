#ifndef LI2_LINKED_CALL_DISPATCH_H
#define LI2_LINKED_CALL_DISPATCH_H
#include "linked_jmp_dispatch.h"
#if !defined(LI2_PERSISTENT_CALL_DISPATCH) || LI2_PERSISTENT_CALL_DISPATCH != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
#error "typed register CALL requires the explicit active-domain dispatch profile"
#endif
#define LI2_CD_VERSION 1U
#define LI2_CD_SLOT_BYTES 512U
#define LI2_CD_BOUNDARIES 64U
#define LI2_CD_STACK_SPAN_BYTES 512U /* Proposed owner-authorized guest span, not metadata size. */
#define LI2_CD_WINDOW_PAGE 4096U
/* Complete owner-held page, R during the activation; zero unused bytes. Owner
   validates actual version/owner/activation serial and all mapping, ordinary
   RAM, prospective-window, full protected registry/source/rseq disjointness
   BEFORE the first private spill. Numeric bounds alone grant no authority.
   The owner proves overflow-free PAGE <= first, first+8 <= end < 2^47,
   fixed end-first=512 and its extra upper8-byte disjoint envelope. PUSH is
   permitted only for first+8 <= RSP <= end. No guest data is read by
   this descriptor or by a failed lookup. */
struct li2_cd_window { uint64_t version,owner,serial,first,end,reserved[3]; };
struct li2_cd_descriptor {
    struct li2_decoded decoded;
    struct li2_tf_classification tf;
    uint32_t version,ready,refusal,available,target,reserved[3];
};
enum li2_cd_status { LI2_CD_OK=0,LI2_CD_ARGUMENT=4601,LI2_CD_DECODER=4602,
    LI2_CD_FORM=4603,LI2_CD_RELOCATION=4604,LI2_CD_CAPACITY=4605,LI2_CD_CORRUPT=4606 };
/* PUSH identifies its BEFORE boundary, including a faulting store. COMMITTED
   is reached only after the real PUSH: RSP is already decremented, the return
   word was stored once, and replaying the original CALL is forbidden. */
enum li2_cd_phase { LI2_CD_BEFORE=0,LI2_CD_CELL_READY=1,LI2_CD_PUSH=2,LI2_CD_COMMITTED=3 };
struct li2_cd_record {
    uint32_t version,ready,result,image_bytes,boundaries,push_offset,transfer_offset,miss_offset;
    uint32_t literal_offset,reserved[3];
    uint32_t scratch_regs[4];
    struct li2_mg_boundary boundary[LI2_CD_BOUNDARIES];
};
struct li2_cd_binding {
    uintptr_t rows,image[2];uint32_t heads,head;
    uintptr_t directory,window;
};
struct li2_cd_plan {
    struct li2_cd_record record;
    struct li2_cd_descriptor original;
    uintptr_t generated,spill;
    struct li2_cd_binding binding;
    unsigned char image[LI2_CD_SLOT_BYTES];
};
struct li2_cd_recovered {
    uint64_t gpr[16],flags,original_pc,original_rsp,return_pc;
    uint32_t phase,complete;
};
/* Whole canonical FF D0..D7 / 41 FF D0..D7 only. The sealed decoder's full
   decoded/TF CALL and implicit write-footprint results must agree. */
int li2_cd_describe(uintptr_t,const unsigned char *,size_t,struct li2_cd_descriptor *);
int li2_cd_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,
    const struct li2_cd_binding *,struct li2_cd_plan *);
int li2_cd_validate(const struct li2_cd_plan *);
/* Caller authenticates exact saved PC, plan/generation and directory/window
   lifetime first. Plan/raw/spill/output are distinct live aligned owned buffers.
   The original source remains NX, so a miss reaches the actual owner drain
   and ordinary-CALL route; it never executes source while the domain is held.
   Only initialized dirty spills are read; no guest memory or
   private target-cell read. COMMITTED recovers original target from the still
   unchanged operand (original RSP = actual RSP+8 for CALL RSP). This is a typed
   effect result, never a successful internal-fault or owner-drain permit. */
int li2_cd_recover(const struct li2_cd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_cd_recovered *);
_Static_assert(sizeof(struct li2_cd_window)==64,"complete activation window value");
_Static_assert(offsetof(struct li2_cd_window,first)==24 && offsetof(struct li2_cd_window,end)==32,"emitted window fields");
_Static_assert(sizeof(struct li2_cd_descriptor)==144,"separate canonical CALL descriptor");
_Static_assert(sizeof(struct li2_cd_record)==1600,"bounded typed CALL recovery rows");
_Static_assert(sizeof(struct li2_cd_binding)==48,"domain and independent window binding");
_Static_assert(sizeof(struct li2_cd_plan)==2320,"bounded CALL adapter");
_Static_assert(sizeof(struct li2_mg_plan)==6488 && sizeof(struct li2_cd_plan)<=sizeof(struct li2_mg_plan),"fits unchanged complete group guard capacity");
_Static_assert(sizeof(struct li2_cd_recovered)==168,"full logical integer and stack-effect state");
#endif
