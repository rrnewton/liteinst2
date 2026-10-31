#ifndef LI2_JD_MODEL_H
#define LI2_JD_MODEL_H
#include "linked_jmp_dispatch.h"
struct jd_model_result {
    uint64_t target;
    unsigned hit,miss,steps,recoveries,row_reads,cell_writes;
};
/* Byte interpreter only. rows[] is an independent PC oracle, never emitted
   code or a live pointer; the model never jumps into the generated image. */
int jd_model_run(const struct li2_jd_plan *,const uint64_t *,const uint64_t[16],uint64_t,
                 struct jd_model_result *);
#endif
