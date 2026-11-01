#ifndef LI2_LOOP_READ_BRIDGE_H
#define LI2_LOOP_READ_BRIDGE_H
#include "loop_envelope.h"

/* Private, unbuilt source candidate. This is a descriptive bridge, not an
   executable plan, a new PF11 row, or a lease/entry/recovery permit.

   Keep the actual old version1 row whenever the old decoder admits it.
   Use version2 only for a newly admitted scalar-read form. This lets a future
   separately versioned consumer reuse unchanged version1 DIRECT/MOV proofs.
   The chooser remains uniformly version2 and is joined by fresh whole rows;
   no caller-supplied descriptor has its version silently rewritten. */
enum li2_lr_result {
    LI2_LR_OK=0,LI2_LR_ARGUMENT=3700,LI2_LR_DECODER,LI2_LR_FORM,LI2_LR_CORRUPT
};
struct li2_lr_node {
    struct li2_span_decoded original;
    struct li2_mg_store mov;
    uint32_t kind,reserved; /* exact LI2_LE_NONE or LI2_LE_MOV */
};

/* Same sealed, serialized decoder arena and immutable source contract as
   scalar_read_describe. Valid owned aligned output must be disjoint from the
   source. OK may contain a genuine old refusal; ready is never inferred.
   After valid nonaliasing arguments, a nonzero result leaves output zero.
   Invalid host/alias arguments return before touching either object. */
int li2_lr_describe(uintptr_t,const unsigned char *,size_t,struct li2_span_decoded *);

/* Reconstruct the supplied row and independently require the appropriate
   no-write theorem. Does not read operand data or turn NONE into no-fault. */
int li2_lr_none(uintptr_t,const unsigned char *,size_t,const struct li2_span_decoded *);

/* Reconstruct one chooser node against the actual owned instruction window,
   then produce the canonical mixed-version row and existing MOV description.
   The caller must separately reconstruct the complete chooser/graph. */
int li2_lr_bridge_node(uintptr_t,const unsigned char *,size_t,
                       const struct li2_le_decoded *,struct li2_lr_node *);
#endif
