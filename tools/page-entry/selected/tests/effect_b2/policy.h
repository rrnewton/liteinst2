#ifndef LI2_EFFECT_B2_POLICY_H
#define LI2_EFFECT_B2_POLICY_H
#include "selected_effect.h"
/* Exact generated rows from the unchanged independently accepted B2 corpus. */
struct b2_script_row {
    uint64_t kind,width,destination,length,pc,next,flags,after_flags,carry,values[4];
    unsigned char bytes[16];uint64_t before[16],after[16];
};
struct be_policy_context { uint64_t entered,posted; };
extern struct be_policy_context be_policy_context;
int be_policy_callback(const struct li2_effect_input *,void *,struct li2_effect_decision *);
int be_policy_post(const struct li2_effect_input *,const struct li2_effect_result *,void *,struct li2_effect_result *);
#endif
