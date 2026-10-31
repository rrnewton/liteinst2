#ifndef LI2_DIRECT_FRONTIER_MODEL_H
#define LI2_DIRECT_FRONTIER_MODEL_H
#include "linked_direct_dispatch.h"
#include "linked_jmp_domain.h"
struct dd_model_result {
    uint64_t target,visited;
    unsigned hit,miss,internal,steps,recoveries,row_reads,cell_writes;
};
/* Independent byte interpreter only. Directory addresses are modeled values,
   never dereferenced host pointers, and emitted code is never executed. */
int dd_model_taken(unsigned,uint64_t);
int dd_model_run(const struct li2_dd_plan *,const struct li2_jd_domain_directory *,
    const uint64_t[16],uint64_t,struct dd_model_result *);
#endif
