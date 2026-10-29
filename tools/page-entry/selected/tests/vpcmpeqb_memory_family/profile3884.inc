/* Address/operand setup for the explicit immediate4-only memory profile.
   Capture, native/TF ownership and full comparison stay in the common fixture. */
static uintptr_t vpcub_high,vpcub_low;
static uint64_t vpcub_ea(const struct vpb_case *v,uintptr_t pc,const uint64_t *gpr) {
    if(v->kind==3)return pc+v->length+(uint64_t)v->displacement;
    uint64_t value=v->base>=0?gpr[v->base]:0;
    if(v->index>=0)value+=gpr[v->index]*v->scale;
    return value+(uint64_t)v->displacement;
}
static uint64_t vpcub_actual_ea(const struct sample *s,const struct state *state) {
    uint64_t gpr[16];for(unsigned i=0;i<16;i++)gpr[i]=(uint64_t)state->frame.greg[regs[i]];
    return vpcub_ea(vpb_case(s),s->pc,gpr);
}
static void vpcub_other_memory(void) {
    uintptr_t other=data_page==vpcub_high?vpcub_low:vpcub_high;
    for(size_t i=0;i<PAGE;i++)need(((const unsigned char *)other)[i]==(unsigned char)(i*11+0x59),1260);
}
static const unsigned char *vpcub_operand(const struct sample *s,const struct state *state) {
    if(s->selftest)return NULL;
    const struct vpb_case *v=vpb_case(s);uint64_t ea=vpcub_actual_ea(s,state);
    uintptr_t object=v->kind==3?s->mapping:v->kind==2?subject:data_page;
    size_t extent=v->kind==3?CODE_BYTES:v->kind==2?SUBJECT_BYTES:DATA_BYTES;
    need(ea>=object&&ea-object<=extent&&32<=extent-(ea-object),1266);
    const unsigned char *actual=v->kind==3?s->source:v->kind==2?state->stack:state->data;
    actual+=ea-object;
    need(!memcmp(actual,v64_patterns[v->pattern],32),1265);
    return actual;
}
static void vpb_inputs(struct sample *s) {
    const struct vpb_case *v=vpb_case(s);
    data_page=v->kind==4?vpcub_low:vpcub_high;data_fault=vpcub_high+PAGE;
    inputs(s);vpb_seed();
    fixture_input_flags=UINT64_C(0x247)|((s->id&1)?UINT64_C(0x400):0);
    uintptr_t other=data_page==vpcub_high?vpcub_low:vpcub_high;
    for(size_t i=0;i<PAGE;i++)((unsigned char *)other)[i]=(unsigned char)(i*11+0x59);
    need(v->source<32&&v->destination<8&&v->pattern<3&&v->offset+32<=DATA_BYTES,1193);
    memcpy(vpb_vectors[v->source],vpc_source,32);
    need((vpb_masks[v->destination]>>32)&&vpb_masks[0]&&vpb_masks[v->destination]!=vpc_expected[v->pattern],1214);
    uint64_t target;
    if(v->kind==3)target=s->pc+s->length+(uint64_t)v->displacement;
    else if(v->kind==2) {
        need(v->base==4&&v->index<0&&!v->displacement,1261);target=fixture_seed[4];
    } else {
        target=v->kind==4?v->absolute_target:data_page+v->offset;
        if(v->index>=0) {
            need(v->index<16&&v->index!=4&&v->base!=v->index,1262);
            fixture_seed[v->index]=v->index_value;
        }
        if(v->base>=0) {
            need(v->base<16&&v->base!=4,1263);
            fixture_seed[v->base]=target-(uint64_t)v->displacement-
                (v->index>=0?fixture_seed[v->index]*v->scale:0);
        }
    }
    if(s==&negative_sample&&control==1) {
        need(v64_fault_kind>=1&&v64_fault_kind<=4&&v->base>=0&&v->base!=4,1194);
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ|PROT_WRITE,0,0,0),1195);
        for(size_t i=0;i<PAGE;i++)((unsigned char *)data_fault)[i]=(unsigned char)(i*13+0x5b);
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),1196);
        target=data_fault-(!(v64_fault_kind&1)?16:0);
        fixture_seed[v->base]=target-(uint64_t)v->displacement-
            (v->index>=0?fixture_seed[v->index]*v->scale:0);
    }
    need(vpcub_ea(v,s->pc,fixture_seed)==target,1264);
    if(s!=&negative_sample) {
        if(v->kind==3) {
            need(target>=s->mapping&&target-s->mapping<=CODE_BYTES-32&&
                 !memcmp((const void *)target,v64_patterns[v->pattern],32),1265);
        } else {
            uintptr_t object=v->kind==2?subject:data_page;
            size_t extent=v->kind==2?SUBJECT_BYTES:DATA_BYTES;
            need(target>=object&&target-object<=extent-32,1266);
            memcpy((void *)target,v64_patterns[v->pattern],32);
        }
    }
}
static void vpb_prepare(struct sample *s,unsigned index) {
    need(index<VPB_COUNT,1107);const struct vpb_case *v=&vpb_cases[VPCM_GROUP][index];
    s->id=5000+18*VPCM_GROUP+index;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1108);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1109);
    need(v->tail>=1&&v->tail<=s->length&&(s->length==7||s->length==8||s->length==9||s->length==11||s->length==12),1110);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<s->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->encoding,s->length);
    if(v->kind==3) {
        uint64_t target=s->expected_post+(uint64_t)v->displacement;
        need(target>=s->mapping&&target-s->mapping<=CODE_BYTES-32&&
             (target+32<=s->pc||target>s->expected_post),1267);
        memcpy(s->source+(target-s->mapping),v64_patterns[v->pattern],32);
    }
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1111);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==3884&&
         s->decoded.length==s->length&&!memcmp(s->decoded.bytes,v->encoding,s->length),1112);
}
