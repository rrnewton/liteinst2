#ifndef LI2_MG_MODEL_H
#define LI2_MG_MODEL_H
#include "linked_mov_guard.h"
struct model_result { uint64_t first,value;unsigned width,writes,rejected,steps,recoveries; };
/* Byte interpreter for metadata only. It never jumps into emitted memory. */
int model_run(const struct li2_mg_plan *,const uint64_t[16],uint64_t,struct model_result *);
#endif
