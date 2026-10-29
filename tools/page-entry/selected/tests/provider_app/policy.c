#include "policy.h"
#include "app.h"
int pa_policy_callback(const struct li2_effect_input *in,void *context,
                       struct li2_effect_decision *out) {
    struct pa_policy_context *p=context;
    if(!in || !p || !out || !p->sites || p->count!=6 || p->scripted>1 || p->reserved ||
       (p->rounds!=PA_STATE_ROUNDS && p->rounds!=PA_STRESS_ROUNDS))return 1;
    *out=(struct li2_effect_decision){.action=LI2_EFFECT_NATIVE};
    const unsigned kinds[3]={LI2_CPUID,LI2_SYSCALL,LI2_RDTSC};
    const unsigned char suffix[3]={0xa2,0x05,0x31};
    for(unsigned i=0;i<6;i++) {
        const struct pa_policy_site *s=p->sites+i;
        if(!s->object_id || s->reserved || s->kind!=kinds[i%3] ||
           s->object_id!=p->sites[3*(i/3)].object_id ||
           p->sites[0].object_id==p->sites[3].object_id)return 2;
        for(unsigned j=0;j<i;j++)if(s->object_id==p->sites[j].object_id &&
            s->file_offset==p->sites[j].file_offset)return 3;
    }
    if(in->source_count!=1)return 0;
    const struct li2_effect_source *source=in->source;
    if(in->decoded.pc<source->page || in->decoded.pc-source->page>=4096 ||
       source->offset>UINT64_MAX-(in->decoded.pc-source->page))return 4;
    uint64_t file_offset=source->offset+in->decoded.pc-source->page;
    for(unsigned i=0;i<6;i++) {
        const struct pa_policy_site *s=p->sites+i;
        if(s->object_id!=source->object_id || s->file_offset!=file_offset)continue;
        uint64_t delta=s->file_offset-source->offset;
        if(s->file_offset<source->offset || delta>=4096 || source->page>UINT64_MAX-delta)return 8;
        uint64_t pc=source->page+delta;
        if(pc>UINT64_MAX-5 || in->abi_version!=LI2_EFFECT_ABI ||
           in->decoded.pc!=pc || in->before.pc!=pc ||
           in->decoded.kind!=s->kind || in->decoded.length!=2 || in->decoded.available<5 ||
           in->decoded.next_pc!=pc+2 || in->decoded.bytes[0]!=15 || in->decoded.bytes[1]!=suffix[i%3] ||
           in->decoded.bytes[2]!=144 || in->decoded.bytes[3]!=144 || in->decoded.bytes[4]!=144 ||
           source->backing!=1 || source->reserved || !source->object_id ||
           !source->allocation || !source->generation || in->before.logical_flags!=PA_FLAGS ||
           p->matched>=6U*p->rounds || p->matched%6!=i || p->visits[i]!=p->matched/6)return 5;
        if(i%3==0 && (in->before.gpr[LI2_EFFECT_RAX] || in->before.gpr[LI2_EFFECT_RCX]))return 6;
        if(i%3==1 && in->before.gpr[LI2_EFFECT_RAX]!=39)return 7;
        if(p->scripted) {
            out->action=LI2_EFFECT_SCRIPTED;out->result.kind=s->kind;
            if(i%3==0) {
                const uint32_t values[2][4]={{0x13579bdf,0x2468ace0,0x10203040,0xa5a5a5a5},
                    {0x11223344,0x55667788,0x99aabbcc,0xddeeff00}};
                for(unsigned j=0;j<4;j++)out->result.cpuid[j]=values[i/3][j];
            } else if(i%3==1)out->result.value=i/3?179:173;
            else out->result.value=i/3?UINT64_C(0xfedcba9876543210):UINT64_C(0x1234567887654321);
        }
        p->visits[i]++;p->matched++;return 0;
    }
    return 0;
}
