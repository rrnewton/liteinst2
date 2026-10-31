#ifndef LI2_CALL_DISPATCH_MODEL_H
#define LI2_CALL_DISPATCH_MODEL_H
#include "linked_call_dispatch.h"
struct cd_model_result {
    uint64_t target,return_word,stack_address;
    unsigned steps,recoveries,hit,miss,row_reads,cell_writes,stack_writes;
};
int cd_model_run(const struct li2_cd_plan *,const struct li2_jd_domain_directory *,
    const struct li2_cd_window *,const uint64_t[16],uint64_t,struct cd_model_result *);
#endif
