#ifndef LI2_LOOP_EFFECTS_BRIDGE_H
#define LI2_LOOP_EFFECTS_BRIDGE_H
#include "loop_effects_envelope.h"
#include "loop_read_bridge.h"

/* Canonical source rows: exact old-v1 first, exact scalar-read-v2 second,
   version3 only for the separately proved register IMUL addition. A chooser
   node is reconstructed from actual source; no caller row is retagged.
   MOV nodes retain actual old descriptor1 or byte descriptor2. Same owned,
   aligned, disjoint host/source/serialized sealed-decoder contract as LR. */
int li2_ler_describe(uintptr_t,const unsigned char *,size_t,struct li2_span_decoded *);
int li2_ler_none(uintptr_t,const unsigned char *,size_t,const struct li2_span_decoded *);
int li2_ler_bridge_node(uintptr_t,const unsigned char *,size_t,
                        const struct li2_le_decoded *,struct li2_lr_node *);
#endif
