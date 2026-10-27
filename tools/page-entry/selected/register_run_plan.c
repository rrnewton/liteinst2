#include "register_run.h"

static void clear(void *value,size_t n) {
    unsigned char *p=value;
    for(size_t i=0;i<n;i++)p[i]=0;
}
static void bytes_copy(unsigned char *to,const unsigned char *from,size_t n) {
    for(size_t i=0;i<n;i++)to[i]=from[i];
}
/* Independent literal parser of the existing canonical NOP/MOV envelope.
   It never accepts a memory operand, SP destination, ignored/repeated prefix
   or any supplied effect descriptor without a real matching decoder result. */
static int literal(const struct li2_decoded *d,struct li2_run_instruction *out) {
    if(d->abi_version!=1 || d->reserved || d->decode_status!=LI2_VALID ||
       d->kind!=LI2_NONE || d->step_disposition!=LI2_STEP_CANDIDATE ||
       !d->length || d->length>15 || d->available<d->length || d->available>15 ||
       d->pc>UINTPTR_MAX-d->length || d->next_pc!=d->pc+d->length)return 0;
    clear(out,sizeof(*out));
    out->code=d->code;out->length=(unsigned char)d->length;
    out->destination=16;out->source=16;
    if(d->length==1 && d->bytes[0]==0x90)return 1;
    size_t at=0;unsigned small=0,rex=0;
    if(d->bytes[at]==0x66){small=1;at++;}
    if(at<d->length && d->bytes[at]>=0x40 && d->bytes[at]<=0x4f)rex=d->bytes[at++];
    if(at<d->length && (d->bytes[at]==0x89 || d->bytes[at]==0x8b)) {
        if((rex&2) || rex==0x40 || (small && (rex&8)) || at+2!=d->length)return 0;
        unsigned op=d->bytes[at++],modrm=d->bytes[at];
        if((modrm&0xc0)!=0xc0)return 0;
        unsigned reg=((modrm>>3)&7)+(rex&4?8:0),rm=(modrm&7)+(rex&1?8:0);
        out->destination=(unsigned char)(op==0x89?rm:reg);
        out->source=(unsigned char)(op==0x89?reg:rm);
        if(out->destination==4)return 0;
        out->width=(unsigned char)(rex&8?64:small?16:32);
        out->effect=LI2_RUN_REGISTER;return 1;
    }
    if((rex && rex!=0x41 && rex!=0x48 && rex!=0x49) || (small && (rex&8)) || at>=d->length)return 0;
    unsigned op=d->bytes[at++];
    if(op<0xb8 || op>0xbf)return 0;
    out->destination=(unsigned char)(op-0xb8+(rex&1?8:0));
    if(out->destination==4)return 0;
    out->width=(unsigned char)(rex&8?64:small?16:32);
    size_t n=out->width/8;
    if(at+n!=d->length)return 0;
    for(size_t i=0;i<n;i++)out->immediate|=(uint64_t)d->bytes[at+i]<<(8*i);
    out->effect=LI2_RUN_IMMEDIATE;return 1;
}

int li2_run_plan_bytes(uintptr_t pc,const unsigned char *source,size_t length,
                        struct li2_run_plan *out) {
    if(!source || !out || !length || length>LI2_RUN_SOURCE_BYTES ||
       pc>UINTPTR_MAX-length)return LI2_RUN_ARGUMENT;
    clear(out,sizeof(*out));out->policy=LI2_RUN_POLICY;out->pc=pc;
    out->source_length=length;bytes_copy(out->source,source,length);
    size_t at=0,count=0;
    struct li2_decoded previous={0};
    struct li2_run_instruction previous_effect={0};
    int have_previous=0,guard_found=0;
    while(at<length) {
        struct li2_decoded d={0};struct li2_run_instruction effect={0};
        uint32_t status=li2_decoder_decode(pc+at,source+at,length-at,&d);
        out->decoder_result=status;
        if(status)return LI2_RUN_DECODE;
        if(d.abi_version!=1 || d.reserved || d.pc!=pc+at || d.available!=length-at)
            return LI2_RUN_DECODE;
        if(d.decode_status==LI2_INVALID || d.decode_status==LI2_TRUNCATED)break;
        if(d.decode_status!=LI2_VALID)return LI2_RUN_DECODE;
        if(!d.length || d.length>length-at || d.next_pc!=d.pc+d.length)
            return LI2_RUN_DECODE;
        for(size_t i=0;i<length-at;i++)if(d.bytes[i]!=source[at+i])return LI2_RUN_DECODE;
        if(!literal(&d,&effect)) {
            /* A valid unqualified/selected instruction is a guard, never run. */
            out->guard=d;guard_found=1;break;
        }
        /* Keep one entire eligible instruction in reserve as a possible guard.
           Only the previous instruction is committed to the copied prefix. */
        if(have_previous) {
            if(count>=LI2_RUN_MAX_INSTRUCTIONS)return LI2_RUN_PLAN;
            previous_effect.offset=(unsigned char)(previous.pc-pc);
            out->instructions[count++]=previous_effect;
            out->run_length=(size_t)(previous.next_pc-pc);
        }
        previous=d;previous_effect=effect;have_previous=1;
        at+=d.length;
    }
    if(guard_found) {
        if(have_previous) {
            if(count>=LI2_RUN_MAX_INSTRUCTIONS)return LI2_RUN_PLAN;
            previous_effect.offset=(unsigned char)(previous.pc-pc);
            out->instructions[count++]=previous_effect;
            out->run_length=(size_t)(previous.next_pc-pc);
        }
    } else if(have_previous) {
        /* End, invalid or truncated tail: last complete instruction is guard. */
        out->guard=previous;guard_found=1;
    }
    out->instruction_count=count;
    if(!guard_found || count<2)return LI2_RUN_SLOW;
    out->stop=pc+out->run_length;
    if(out->guard.pc!=out->stop || !out->guard.length ||
       out->guard.next_pc>pc+length || out->run_length>=length)return LI2_RUN_PLAN;
    bytes_copy(out->generated,source,out->run_length);
    size_t n=out->run_length;
    out->generated[n]=0xff;out->generated[n+1]=0x25;
    for(unsigned i=0;i<8;i++)out->generated[n+6+i]=(unsigned char)((uint64_t)out->stop>>(8*i));
    out->generated_length=n+14;
    if(out->generated_length>LI2_RUN_CODE_BYTES)return LI2_RUN_PLAN;
    return LI2_RUN_OK;
}

int li2_run_expected(const struct li2_run_plan *p,const uint64_t before[16],uint64_t after[16]) {
    if(!p || !before || !after || p->policy!=LI2_RUN_POLICY ||
       p->instruction_count<2 || p->instruction_count>LI2_RUN_MAX_INSTRUCTIONS)
        return LI2_RUN_ARGUMENT;
    for(unsigned i=0;i<16;i++)after[i]=before[i];
    size_t offset=0;
    for(size_t i=0;i<p->instruction_count;i++) {
        const struct li2_run_instruction *a=&p->instructions[i];
        if(a->offset!=offset || !a->length || offset+a->length>p->run_length)return LI2_RUN_PLAN;
        offset+=a->length;
        if(a->effect==LI2_RUN_NOP) {
            if(a->destination!=16 || a->source!=16 || a->width || a->immediate)return LI2_RUN_PLAN;
            continue;
        }
        if(a->destination>=16 || a->destination==4 ||
           (a->width!=16 && a->width!=32 && a->width!=64))return LI2_RUN_PLAN;
        uint64_t value;
        if(a->effect==LI2_RUN_IMMEDIATE) {
            if(a->source!=16)return LI2_RUN_PLAN;
            value=a->immediate;
        } else if(a->effect==LI2_RUN_REGISTER && a->source<16)value=after[a->source];
        else return LI2_RUN_PLAN;
        uint64_t *to=&after[a->destination];
        if(a->width==16)*to=(*to&~UINT64_C(0xffff))|(value&UINT64_C(0xffff));
        else if(a->width==32)*to=value&UINT64_C(0xffffffff);
        else *to=value;
    }
    return offset==p->run_length?LI2_RUN_OK:LI2_RUN_PLAN;
}
