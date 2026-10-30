/* Included after the unchanged rseq_region.inc, only for completed-generation reuse-certificate mode.
   No plan, descriptor, static NONE result or decoder success is invented. */
#include "rseq_region_live.h"
int li2_rseq_region_live(const ucontext_t *uc,struct li2_rseq_region_live *out) {
    if(!out || out->attempted)return LI2_RSEQ_ARGUMENT;
    out->attempted=1;
    if(ready())return out->result=(int)state.first_error;
    if(!region_rseq_current(uc))return out->result=bad(LI2_RSEQ_STATE,100);
    if(word_zero())return out->result=(int)state.first_error;
    const struct li2_step_session *session=li2_native_pair_progress()->session;
    uint64_t epoch=state.epoch;unsigned registered=state.registered;
    out->session=(uintptr_t)session;out->epoch=epoch;out->registered=registered;
    /* Retain actual current GPR/TLS inputs without fabricating a new physical
       footprint query or changing state.last_footprint to a cached value. */
    registers(uc,&out->registers);
    if(li2_native_pair_progress()->session!=session || state.epoch!=epoch ||
       state.registered!=registered || !region_rseq_current(uc))
        return out->result=bad(LI2_RSEQ_STATE,101);
    if(word_zero())return out->result=(int)state.first_error;
    out->complete=1;return 0;
}
