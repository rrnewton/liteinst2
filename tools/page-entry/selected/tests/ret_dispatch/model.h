#ifndef LI2_RET_DISPATCH_MODEL_H
#define LI2_RET_DISPATCH_MODEL_H
#include "linked_ret_dispatch.h"
struct rd_model_result {
    uint64_t target,loaded_target,original_rsp,final_rsp;
    unsigned steps,recoveries,hit,before_miss,loaded_miss,load_fault;
    unsigned row_reads,cell_writes,target_writes,load_attempts,guest_reads,stack_writes;
};
int rd_model_run(const struct li2_rd_plan *,const struct li2_jd_domain_directory *,
    const struct li2_rd_window *,const uint64_t[16],uint64_t,uint64_t,unsigned,
    struct rd_model_result *);
#endif
