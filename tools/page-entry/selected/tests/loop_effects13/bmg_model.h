#ifndef LI2_BMG_MODEL_H
#define LI2_BMG_MODEL_H
#include "linked_byte_mov_guard.h"
struct bmg_model_result { uint64_t first,value;unsigned width,writes,rejected,steps,recoveries; };
int bmg_model_run(const struct li2_mg_plan *,const uint64_t[16],uint64_t,struct bmg_model_result *);
#endif
