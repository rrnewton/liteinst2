#ifndef LI2_LINKED_RET_DISPATCH_H
#define LI2_LINKED_RET_DISPATCH_H
#include "linked_jmp_dispatch.h"
#if !defined(LI2_PERSISTENT_RET_DISPATCH) || LI2_PERSISTENT_RET_DISPATCH != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
#error "typed C3 RET requires its explicit active-domain dispatch profile"
#endif
#define LI2_RD_VERSION 1U
#define LI2_RD_SLOT_BYTES 512U
#define LI2_RD_BOUNDARIES 64U
#define LI2_RD_WINDOW_PAGE 4096U
/* Supplied authority, not a numeric permission oracle. Before the first private
   spill the owner must authenticate actual owner/activation/generation, complete
   mapping/ordinary-RAM provenance, and the full protected/source/rseq disjoint
   envelope. The immutable window page is R/NX throughout the activation.
   PAGE <= first <= end, end-first=512, end+8 < 2^47 without overflow.
   Only first <= original RSP <= end reaches the one guest load. This contract
   does NOT prove the loaded value stable and never permits reading it twice. */
struct li2_rd_window { uint64_t version,owner,serial,first,end,reserved[3]; };
struct li2_rd_descriptor {
    struct li2_decoded decoded;
    struct li2_tf_classification tf;
    uint32_t version,ready,refusal,available,reserved[4];
};
enum li2_rd_status { LI2_RD_OK=0,LI2_RD_ARGUMENT=4701,LI2_RD_DECODER=4702,
    LI2_RD_FORM=4703,LI2_RD_RELOCATION=4704,LI2_RD_CAPACITY=4705,LI2_RD_CORRUPT=4706 };
/* All rows describe BEFORE the named machine instruction. LOAD has no completed
   guest read. LOADED has target in scratch3; SAVED and later have it at spill+40.
   COMMIT precedes flags-neutral RSP+8; COMMITTED follows it exactly once.
   LOADED_MISS is a distinct actual NX landing, never original-C3 replay. */
enum li2_rd_phase { LI2_RD_BEFORE=0,LI2_RD_LOAD=1,LI2_RD_LOADED=2,
    LI2_RD_SAVED=3,LI2_RD_CELL_READY=4,LI2_RD_COMMIT=5,
    LI2_RD_COMMITTED=6,LI2_RD_LOADED_MISS=7 };
struct li2_rd_record {
    uint32_t version,ready,result,image_bytes,boundaries,load_offset,save_offset,commit_offset;
    uint32_t transfer_offset,miss_offset,loaded_miss_offset,reserved;
    uint32_t scratch_regs[4];
    struct li2_mg_boundary boundary[LI2_RD_BOUNDARIES];
};
struct li2_rd_binding {
    uintptr_t rows,image[2];uint32_t heads,head;
    uintptr_t directory,window,loaded_miss;
};
struct li2_rd_plan {
    struct li2_rd_record record;
    struct li2_rd_descriptor original;
    uintptr_t generated,spill;
    struct li2_rd_binding binding;
    unsigned char image[LI2_RD_SLOT_BYTES];
};
struct li2_rd_recovered {
    uint64_t gpr[16],flags,original_pc,original_rsp,target;
    uint32_t phase,complete,target_valid,reserved;
};
/* Canonical unprefixed C3 only; actual sealed decoder, TF RET and WRITE_NONE.
   WRITE_NONE describes no guest store, never a safe or completed guest read. */
int li2_rd_describe(uintptr_t,const unsigned char *,size_t,struct li2_rd_descriptor *);
int li2_rd_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,
    const struct li2_rd_binding *,struct li2_rd_plan *);
int li2_rd_validate(const struct li2_rd_plan *);
/* Caller authenticates exact actual PC/event, whole plan/generation, active
   directory and window before these pure reconstructions. Distinct live aligned
   owned plan/raw/spill/output buffers are required. The six-word private spill
   contains four original GPRs, generated target at+32 and loaded target at+40.
   Only initialized dirty spills and the phase-initialized target are read.
   Recovery never reads guest stack or uses the generated target as authority.
   COMMITTED keeps the actual incremented RSP and original target by value.
   Fault/event equivalence is not supplied by a numeric recovered state. */
int li2_rd_recover(const struct li2_rd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[6],struct li2_rd_recovered *);
/* Distinct entrypoint for actual execution reaching binding.loaded_miss. The
   owner must prove that exact NX event belongs to this active RET's completed
   load, copy the result before scratch reset, drain and consume it once. An
   arbitrary supplied generation/head/PC is not that proof. No resumed RET or
   target-fault synthesis is implemented here; original RSP is still unchanged.
   loaded_miss is a unique 8-aligned non-metadata address in the R/NX window page.
   All internal faults and BEFORE misses retain their own original owner path. */
int li2_rd_recover_loaded_miss(const struct li2_rd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[6],struct li2_rd_recovered *);
_Static_assert(sizeof(struct li2_rd_window)==64,"complete supplied window value");
_Static_assert(offsetof(struct li2_rd_window,first)==24 && offsetof(struct li2_rd_window,end)==32,"emitted window fields");
_Static_assert(sizeof(struct li2_rd_descriptor)==144,"separate exact C3 descriptor");
_Static_assert(sizeof(struct li2_rd_record)==1600,"bounded RET recovery rows");
_Static_assert(sizeof(struct li2_rd_binding)==56,"directory/window/distinct loaded landing");
_Static_assert(sizeof(struct li2_rd_plan)==2328,"bounded RET adapter");
_Static_assert(sizeof(struct li2_mg_plan)==6488 && sizeof(struct li2_rd_plan)<=sizeof(struct li2_mg_plan),"unchanged full group guard budget");
_Static_assert(sizeof(struct li2_rd_recovered)==176,"complete typed load/effect result");
#endif
