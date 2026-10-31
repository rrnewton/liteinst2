#ifndef LI2_LINKED_JMP_DISPATCH_H
#define LI2_LINKED_JMP_DISPATCH_H
#include "linked_mov_guard.h"
#include "region_decode.h"
#include "tf_owner.h"
#include "write_footprint.h"
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
#include "linked_jmp_domain.h"
#define LI2_JD_VERSION 2U
#else
#define LI2_JD_VERSION 1U
#endif
#define LI2_JD_HEADS 128U
#define LI2_JD_MEMBER_HEADS 64U
#define LI2_JD_SLOT_BYTES 512U
#define LI2_JD_IMAGE_BYTES (LI2_JD_MEMBER_HEADS*LI2_JD_SLOT_BYTES)
#define LI2_JD_BOUNDARIES 64U
/* Canonical FF E0..E7 / 41 FF E0..E7 only. Complete independent decoded,
   TF and NONE-footprint equality is required; link_none is not widened. */
struct li2_jd_descriptor {
    struct li2_decoded decoded;
    struct li2_tf_classification tf;
    uint32_t version,ready,refusal,available,target,reserved[3];
};
enum li2_jd_status {
    LI2_JD_OK=0,LI2_JD_ARGUMENT=3901,LI2_JD_DECODER=3902,
    LI2_JD_FORM=3903,LI2_JD_RELOCATION=3904,LI2_JD_CAPACITY=3905,
    LI2_JD_CORRUPT=3906
};
/* These are initialization states, not guest-commit states. At EVERY row,
   including FF25, the original JMP has not retired. Its committed target PC
   belongs to the target head's independent authenticated start map. */
enum li2_jd_phase { LI2_JD_BEFORE=0,LI2_JD_CELL_READY=1 };
struct li2_jd_record {
    uint32_t version,ready,result,image_bytes,boundaries,hit_offset,miss_offset,reserved;
    uint32_t scratch_regs[4];
    struct li2_mg_boundary boundary[LI2_JD_BOUNDARIES];
};
/* rows is the eventual immutable original[heads] array, not a host pointer.
   The owner must bind its exact complete authenticated source rows, order,
   unique PCs, member mapping and generation. No descriptor/lookup grants
   source, rseq, code, spill, cell, entry or recovery authority. */
struct li2_jd_binding {
    uintptr_t rows,image[2];
    uint32_t heads,head;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    uintptr_t directory;
#endif
};
struct li2_jd_plan {
    struct li2_jd_record record;
    struct li2_jd_descriptor original;
    uintptr_t generated,spill;
    struct li2_jd_binding binding;
    unsigned char image[LI2_JD_SLOT_BYTES];
};
struct li2_jd_recovered {
    uint64_t gpr[16],flags,original_pc;
    uint32_t phase,complete;
};
int li2_jd_describe(uintptr_t,const unsigned char *,size_t,struct li2_jd_descriptor *);
int li2_jd_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,
                const struct li2_jd_binding *,struct li2_jd_plan *);
/* Cold reconstruction only; never on a warm edge/recovery path. */
int li2_jd_validate(const struct li2_jd_plan *);
/* Authenticate owner/generation/exact savedPC and immutable plan FIRST.
   Raw/spill/output are distinct owned buffers. Only initialized dirty spills
   are read. Spill[4] (cell at+32) is NEVER read during recovery. RF stays raw.
   Internal guard faults do not become successful guest JMP completion. */
int li2_jd_recover(const struct li2_jd_plan *,uintptr_t,const uint64_t[16],uint64_t,
                   const uint64_t[4],struct li2_jd_recovered *);
_Static_assert(sizeof(struct li2_span_decoded)==336 && offsetof(struct li2_span_decoded,decoded)==0,
               "literal immutable original-row stride and PC field");
_Static_assert(sizeof(struct li2_jd_descriptor)==144,"typed descriptor fits old store width");
_Static_assert(sizeof(struct li2_jd_record)==1584,"typed recovery fits old guard width");
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
_Static_assert(sizeof(struct li2_jd_binding)==40,"actual domain directory and local binding");
#else
_Static_assert(sizeof(struct li2_jd_binding)==32,"actual row/image/head binding");
#endif
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
_Static_assert(sizeof(struct li2_jd_plan)==2296,"bounded full domain dispatch emitter");
#else
_Static_assert(sizeof(struct li2_jd_plan)==2288,"bounded full dispatch emitter");
#endif
_Static_assert(sizeof(struct li2_jd_recovered)==152,"logical integer frame");
#endif
