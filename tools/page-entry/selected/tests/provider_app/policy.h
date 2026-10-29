#ifndef LI2_PROVIDER_APP_POLICY_H
#define LI2_PROVIDER_APP_POLICY_H
#include "../../selected_effect.h"
/* The trusted bootstrap resolves these from its already registered sealed
   object, fresh stat/seals and full ELF. No application pointer fills them.
   Rows are main CPUID/getpid/RDTSC, then DSO CPUID/getpid/RDTSC. */
struct pa_policy_site { uint64_t object_id,file_offset;uint32_t kind,reserved; };
struct pa_policy_context {
    const struct pa_policy_site *sites;
    uint32_t count,scripted,rounds,reserved;
    /* Only these owned statistics may change after publication of the table. */
    uint64_t matched,visits[6];
};
int pa_policy_callback(const struct li2_effect_input *,void *,struct li2_effect_decision *);
#endif
