#ifndef LI2_FLAG_STACK_STORAGE_H
#define LI2_FLAG_STACK_STORAGE_H
#include "sealed_generation.h"
int li2_lifecycle_flag_stack_query(const struct li2_sealed_identity *,uintptr_t,
    size_t,int,struct li2_sealed_code_query *);
#endif
