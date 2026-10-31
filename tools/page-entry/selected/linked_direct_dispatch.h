#ifndef LI2_LINKED_DIRECT_DISPATCH_H
#define LI2_LINKED_DIRECT_DISPATCH_H
#include "linked_jmp_dispatch.h"
#if !defined(LI2_PERSISTENT_DIRECT_FRONTIER) || LI2_PERSISTENT_DIRECT_FRONTIER != 1 || \
    !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1 || \
    !defined(LI2_PERSISTENT_CROSS_PAIR) || LI2_PERSISTENT_CROSS_PAIR != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1
#error "direct frontiers require their distinct two-active cross-pair profile"
#endif
#if defined(LI2_ADD_GUARD) || defined(LI2_PERSISTENT_RETAINED_EIGHT)
#error "direct frontiers do not imply ADD or eight-retained composition"
#endif
#if defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || \
    defined(LI2_PERSISTENT_STARTUP_CAPTURE) || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || \
    defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE)
#error "direct frontiers require a separate typed capture profile"
#endif
#define LI2_DD_VERSION 1U
#define LI2_DD_SLOT_BYTES 512U
#define LI2_DD_BOUNDARIES 64U
/* Whole span stays in original[]. This distinct descriptor cannot be cast to
   register-JMP syntax. Bit/ordinal0 is taken/JMP; ordinal1 is Jcc fallthrough. */
struct li2_dd_descriptor {
    struct li2_decoded decoded;
    uintptr_t target[2];
    uint32_t version,ready,refusal,available,flow,condition,external_mask,reserved;
};
enum li2_dd_status { LI2_DD_OK=0,LI2_DD_ARGUMENT=4501,LI2_DD_DECODER=4502,
    LI2_DD_FORM=4503,LI2_DD_RELOCATION=4504,LI2_DD_CAPACITY=4505,LI2_DD_CORRUPT=4506 };
enum li2_dd_phase { LI2_DD_BEFORE=0,LI2_DD_CELL_READY=1 };
struct li2_dd_record {
    uint32_t version,ready,result,image_bytes,boundaries,hit_offset,miss_offset,reserved;
    uint32_t scratch_regs[4];
    struct li2_mg_boundary boundary[LI2_DD_BOUNDARIES];
};
struct li2_dd_plan {
    struct li2_dd_record record;
    struct li2_dd_descriptor original;
    uintptr_t generated,spill;
    struct li2_jd_binding binding;
    uintptr_t internal[2];
    unsigned char image[LI2_DD_SLOT_BYTES];
};
struct li2_dd_recovered { uint64_t gpr[16],flags,original_pc;uint32_t phase,complete; };
/* Pure value reconstruction; no decoder, memory, source or entry authority. */
int li2_dd_span(const struct li2_span_decoded *,unsigned,struct li2_dd_descriptor *);
int li2_dd_describe(uintptr_t,const unsigned char *,size_t,unsigned,struct li2_dd_descriptor *);
/* Selected arm0/1, or -1 for malformed descriptor. RF/TF never select Jcc. */
int li2_dd_arm(const struct li2_dd_descriptor *,uint64_t);
int li2_dd_emit(uintptr_t,const unsigned char *,size_t,unsigned,uintptr_t,uintptr_t,
    const struct li2_jd_binding *,const uintptr_t[2],struct li2_dd_plan *);
int li2_dd_validate(const struct li2_dd_plan *);
/* Authenticated savedPC and sealed plan first. Only initialized dirty spills
   are read; never the target cell. Every row is original branch-before. */
int li2_dd_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
_Static_assert(sizeof(struct li2_dd_descriptor)==120,"typed direct descriptor");
_Static_assert(sizeof(struct li2_dd_record)==1584,"bounded direct recovery rows");
_Static_assert(sizeof(struct li2_dd_plan)==2288,"bounded direct adapter image");
_Static_assert(sizeof(struct li2_dd_recovered)==152,"complete integer recovery");
#endif
