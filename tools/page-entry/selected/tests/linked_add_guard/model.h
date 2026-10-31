#ifndef LI2_AG_MODEL_H
#define LI2_AG_MODEL_H
#include "linked_add_guard.h"
struct model_input {uint64_t base;unsigned char bytes[32];uint32_t readable,writable;};
struct model_result {uint64_t first,value,flags,spill[4];unsigned width,writes,rejected,fault,steps,recoveries;unsigned char memory[32],resolved[8];unsigned resolved_mask;};
/* Independent emitted-byte interpreter, with shared spill/table/guest memory.
   Synthetic access faults grant no statement about native split-store effects. */
int model_run(const struct li2_ag_plan *,const uint64_t[16],uint64_t,const struct model_input *,struct model_result *);
#endif
