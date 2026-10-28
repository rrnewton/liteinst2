#ifndef LI2_SELECTED_PROVIDER_POLICY_H
#define LI2_SELECTED_PROVIDER_POLICY_H
#include "provider_callback.h"
/* Internal linked policy, not a general plug-in/configuration ABI. */
struct li2_selected_cpuid_input { uint32_t leaf,subleaf,native[4]; };
struct li2_selected_cpuid_result { uint32_t eax,ebx,ecx,edx; };
typedef int (*li2_selected_cpuid_callback)(const struct li2_selected_cpuid_input *,
                                        struct li2_selected_cpuid_result *);
static int li2_policy_mask_random_v1(const struct li2_selected_callback_input *in,
                                   struct li2_selected_script *out) {
    if(!in || !out || in->abi_version!=1 || in->destination>=16 || in->destination==4)
        return LI2_SELECTED_ARGUMENT;
    if(in->kind==LI2_RDPID) {
        if(in->width_bits!=64)return LI2_SELECTED_SCRIPT;
        *out=(struct li2_selected_script){LI2_RDPID,64,0,0,UINT64_C(0xc00dcafe)};
        return 0;
    }
    if((in->kind!=LI2_RDRAND && in->kind!=LI2_RDSEED) ||
       (in->width_bits!=16 && in->width_bits!=32 && in->width_bits!=64))
        return LI2_SELECTED_SCRIPT;
    uint64_t value=in->width_bits==16?UINT64_C(0xbeef):
        in->width_bits==32?UINT64_C(0xface9876):UINT64_C(0xfedcba9876543210);
    unsigned carry=in->kind==LI2_RDRAND;
    *out=(struct li2_selected_script){in->kind,in->width_bits,carry,0,carry?value:0};
    return 0;
}
static int li2_policy_cpuid_mask_v1(const struct li2_selected_cpuid_input *in,
                                  struct li2_selected_cpuid_result *out) {
    if(!in || !out)return LI2_SELECTED_ARGUMENT;
    *out=(struct li2_selected_cpuid_result){in->native[0],in->native[1],in->native[2],in->native[3]};
    if(in->leaf==1)out->ecx&=~(UINT32_C(1)<<30);
    if(in->leaf==7 && !in->subleaf) {
        out->ebx&=~(UINT32_C(1)<<18);
        out->ecx&=~(UINT32_C(1)<<22);
    }
    return 0;
}
#endif
