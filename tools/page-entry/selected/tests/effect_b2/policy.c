#include "be_policy.h"
#include "b2-script.h"
struct be_policy_context be_policy_context;
static int be_input(const struct li2_effect_input *in,unsigned i) {
    if(!in || i>=B2_SCRIPT_ROWS)return 1;
    const struct b2_script_row *r=&b2_script[i];
    if(in->abi_version!=LI2_EFFECT_ABI || in->sequence!=(uint64_t)i+1 ||
       in->before.pc!=r->pc || in->before.logical_flags!=r->flags ||
       in->decoded.pc!=r->pc || in->decoded.next_pc!=r->next ||
       in->decoded.kind!=r->kind || in->decoded.width_bits!=r->width ||
       in->decoded.destination!=r->destination || in->decoded.length!=r->length ||
       in->decoded.available<r->length || in->source_count!=1 ||
       in->source[0].backing!=1 || !in->source[0].object_id ||
       in->source[0].page!=(r->pc&~UINT64_C(4095)) ||
       in->source[0].offset!=in->source[0].page-UINT64_C(0x200400000))return 2;
    for(unsigned j=0;j<r->length;j++)if(in->decoded.bytes[j]!=r->bytes[j])return 3;
    for(unsigned j=0;j<16;j++)if(in->before.gpr[j]!=r->before[j])return 4;
    return 0;
}
int be_policy_callback(const struct li2_effect_input *in,void *context,
                       struct li2_effect_decision *out) {
    struct be_policy_context *p=context;
    if(p!=&be_policy_context || !out || p->entered!=p->posted ||
       p->entered>=B2_SCRIPT_ROWS || be_input(in,(unsigned)p->entered))return 1;
    *out=(struct li2_effect_decision){.action=LI2_EFFECT_NATIVE};
    ++p->entered;return 0;
}
int be_policy_post(const struct li2_effect_input *in,const struct li2_effect_result *native,
                   void *context,struct li2_effect_result *out) {
    struct be_policy_context *p=context;
    if(p!=&be_policy_context || !native || !out || p->entered!=p->posted+1 ||
       p->posted>=B2_SCRIPT_ROWS || be_input(in,(unsigned)p->posted) ||
       native->kind!=in->decoded.kind)return 1;
    const struct b2_script_row *r=&b2_script[p->posted];
    /* The owner retains the actual native result separately before this call.
       No frame, source, permission, input or native-result pointer is written. */
    *out=(struct li2_effect_result){.kind=(uint32_t)r->kind};
    if(r->kind==LI2_CPUID) {
        for(unsigned j=0;j<4;j++)out->cpuid[j]=(uint32_t)r->values[j];
    } else {
        out->value=r->values[0];
        if(r->kind==LI2_RDTSCP)out->aux=(uint32_t)r->values[1];
        if(r->kind==LI2_RDRAND || r->kind==LI2_RDSEED)out->carry=(uint32_t)r->carry;
    }
    ++p->posted;return 0;
}
const struct li2_effect_binding li2_effect_runtime_binding={
    .abi_version=LI2_EFFECT_ABI,.callback=be_policy_callback,
    .post_native=be_policy_post,.context=&be_policy_context
};
