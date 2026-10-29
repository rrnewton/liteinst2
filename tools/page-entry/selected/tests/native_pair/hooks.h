#ifndef LI2_NATIVE_PAIR_FIXTURE_HOOKS_H
#define LI2_NATIVE_PAIR_FIXTURE_HOOKS_H
#include <stdint.h>
#define NPF_PREPARED 1U
#define NPF_PUBLISHED 2U
#define NPF_CLOSE_BEFORE 3U
#define NPF_CLOSE_AFTER 4U
#define NPF_CONTROL_BEFORE 5U
#define NPF_CONTROL_AFTER 6U
struct li2_native_pair_owner;
void npf_stage_observe(unsigned,uintptr_t,int);
int npf_control_match(unsigned,unsigned,unsigned,uintptr_t);
void npf_control_values(unsigned,uint64_t,uint64_t,uintptr_t,uintptr_t);
void npf_control_hook(unsigned,uintptr_t);
int npf_inject_sync(void);
const struct li2_native_pair_owner *npf_owner_argument(const struct li2_native_pair_owner *,uintptr_t);
void npf_owner_overflow(uintptr_t);
void npf_rseq_mutate_pin(void);
#endif
