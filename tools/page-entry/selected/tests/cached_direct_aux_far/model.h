#ifndef LI2_FAR_AUX_TEST_MODEL_H
#define LI2_FAR_AUX_TEST_MODEL_H
#include <stdint.h>
struct model_counts {
    uint64_t models,steps,recoveries,far_adapters,near_equivalences;
    uint64_t mutations,literal_refusals,nonboundary_refusals,refusals;
};
void far_aux_models(struct model_counts *);
uint64_t far_aux_decoder_calls(void);
#endif
