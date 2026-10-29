/* Supplied-input controls only. Not compiled or executed as part of source
   authoring. Link the real sealed decoder, never a decoder stub. These controls
   execute no selected instruction or application and grant no native credit. */
#include "selected_effect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char arena[2*1024*1024] __attribute__((aligned(64)));
static unsigned char before_fp[512], after_fp[512];
static unsigned assertions;
static void need(int ok,int line) {
    ++assertions;
    if(!ok) {fprintf(stderr,"selected_effect control line %d\n",line);exit(1);}
}
#define CHECK(x) need((x),__LINE__)
_Noreturn void li2_decoder_abort(uint32_t code) {
    fprintf(stderr,"actual decoder abort %u\n",code);exit(125);
}
static struct li2_effect_input input(const unsigned char *bytes,size_t size,uint64_t pc) {
    struct li2_effect_input in={.abi_version=LI2_EFFECT_ABI,.sequence=1};
    CHECK(li2_decoder_decode(pc,bytes,size,&in.decoded)==LI2_OK);
    CHECK(in.decoded.decode_status==LI2_VALID);
    in.before.pc=pc;in.before.logical_flags=UINT64_C(0xed7);
    for(unsigned i=0;i<16;i++)in.before.gpr[i]=UINT64_C(0x9100000000000010)+i*17;
    in.before.selectors_observed=3;in.before.selectors[0]=0x33;in.before.selectors[1]=0x2b;
    in.before.xstate=(struct li2_effect_xstate){before_fp,sizeof(before_fp),0,91};
    uint64_t page=pc&~UINT64_C(4095);
    in.source_count=((pc+size-1)&~UINT64_C(4095))==page?1:2;
    in.source[0]=(struct li2_effect_source){page,3,11,7,4096,1,0};
    if(in.source_count==2)in.source[1]=(struct li2_effect_source){page+4096,4,12,8,8192,1,0};
    CHECK(li2_effect_validate_input(&in)==LI2_EFFECT_OK);
    return in;
}
static struct li2_effect_owner fresh(void) {
    struct li2_effect_owner o;memset(&o,0,sizeof(o));return o;
}
static struct li2_effect_state unchanged(const struct li2_effect_input *in) {
    struct li2_effect_state out=in->before;
    out.pc=in->decoded.next_pc;memcpy(after_fp,before_fp,sizeof(after_fp));
    out.xstate.bytes=after_fp;return out;
}
struct callbacks {
    const struct li2_effect_input *expected;
    struct li2_effect_decision decision;
    struct li2_effect_result post_result, seen_native;
    unsigned before_calls,after_calls;
    int before_error,after_error;
};
static int decide(const struct li2_effect_input *in,void *opaque,struct li2_effect_decision *out) {
    struct callbacks *c=opaque;
    /* Exact callback visibility, including every register, flags, fetched byte,
       source identity, selector mask and descriptive immutable FP view. */
    const unsigned char *a=(const void *)in,*b=(const void *)c->expected;
    for(size_t i=0;i<sizeof(*in);i++)if(a[i]!=b[i])return 101;
    ++c->before_calls;*out=c->decision;return c->before_error;
}
static int observe(const struct li2_effect_input *in,const struct li2_effect_result *native,
                   void *opaque,struct li2_effect_result *logical) {
    struct callbacks *c=opaque;
    const unsigned char *a=(const void *)in,*b=(const void *)c->expected;
    for(size_t i=0;i<sizeof(*in);i++)if(a[i]!=b[i])return 102;
    ++c->after_calls;c->seen_native=*native;*logical=c->post_result;return c->after_error;
}
static struct li2_effect_binding binding(struct callbacks *c,int post) {
    return (struct li2_effect_binding){.abi_version=LI2_EFFECT_ABI,.callback=decide,
        .post_native=post?observe:0,.context=c};
}
static void native_outcome(struct li2_effect_owner *o,const struct li2_effect_input *in,
                           const struct li2_effect_binding *b,const struct li2_effect_result *r) {
    CHECK(li2_effect_begin(o,b,in)==LI2_EFFECT_OK);
    CHECK(li2_effect_guarded(o)==LI2_EFFECT_OK);
    CHECK(li2_effect_native_enter(o)==LI2_EFFECT_OK);
    CHECK(li2_effect_native_return(o,r)==LI2_EFFECT_OK);
    CHECK(o->phase==LI2_EFFECT_NATIVE_RETURNED && o->native_returned && !o->post_guards_complete);
    CHECK(!memcmp(&o->native_result,r,sizeof(*r)));
    CHECK(li2_effect_native_outcome(o)==LI2_EFFECT_OK);
}
static void scripted_outcome(struct li2_effect_owner *o,const struct li2_effect_input *in,
                             struct callbacks *c) {
    struct li2_effect_binding b=binding(c,1);
    CHECK(li2_effect_begin(o,&b,in)==LI2_EFFECT_OK);
    CHECK(li2_effect_guarded(o)==LI2_EFFECT_OK);
    CHECK(li2_effect_scripted_outcome(o)==LI2_EFFECT_OK);
    CHECK(c->before_calls==1 && !c->after_calls && !o->native_entered && !o->native_returned);
}
static void class_controls(void) {
    static const unsigned char cpuid[]={0x0f,0xa2},rdtsc[]={0x0f,0x31};
    static const unsigned char rdtscp[]={0x0f,0x01,0xf9},syscall[]={0x0f,0x05};
    static const unsigned char rand16[]={0x66,0x41,0x0f,0xc7,0xf0};
    static const unsigned char rand32[]={0x41,0x0f,0xc7,0xf7};
    static const unsigned char seed64[]={0x49,0x0f,0xc7,0xfb};
    static const unsigned char pid[]={0xf3,0x41,0x0f,0xc7,0xfa};
    const unsigned char *bytes[]={cpuid,rdtsc,rdtscp,syscall,rand16,rand32,seed64,pid};
    const size_t sizes[]={2,2,3,2,5,4,4,5};
    const unsigned kinds[]={LI2_CPUID,LI2_RDTSC,LI2_RDTSCP,LI2_SYSCALL,
        LI2_RDRAND,LI2_RDRAND,LI2_RDSEED,LI2_RDPID};
    const struct li2_effect_result results[]={
        {.kind=LI2_CPUID,.cpuid={0x89abcdef,0x76543210,0xfedcba98,0x13572468}},
        {.kind=LI2_RDTSC,.value=UINT64_C(0x12345678fedcba98)},
        {.kind=LI2_RDTSCP,.value=UINT64_C(0x12345678fedcba98),.aux=0x88776655},
        {.kind=LI2_SYSCALL,.value=7001},
        {.kind=LI2_RDRAND,.carry=1,.value=0xbeef},
        {.kind=LI2_RDRAND,.value=0},
        {.kind=LI2_RDSEED,.carry=1,.value=UINT64_C(0xfedcba9876543210)},
        {.kind=LI2_RDPID,.value=0xc00dcafe}
    };
    for(unsigned i=0;i<8;i++)for(unsigned native=0;native<2;native++) {
        struct li2_effect_input in=input(bytes[i],sizes[i],UINT64_C(0x400100));
        CHECK(in.decoded.kind==kinds[i]);
        if(i==3)in.before.gpr[LI2_EFFECT_RAX]=39;
        struct li2_effect_state out=unchanged(&in);
        /* Independent class expectations; do not derive them through expected(). */
        switch(i) {
        case 0:out.gpr[0]=0x89abcdef;out.gpr[3]=0x76543210;
            out.gpr[1]=0xfedcba98;out.gpr[2]=0x13572468;break;
        case 1:out.gpr[0]=0xfedcba98;out.gpr[2]=0x12345678;break;
        case 2:out.gpr[0]=0xfedcba98;out.gpr[2]=0x12345678;out.gpr[1]=0x88776655;break;
        case 3:out.gpr[0]=7001;out.gpr[1]=in.decoded.next_pc;out.gpr[11]=0xed7;break;
        case 4:CHECK(in.decoded.destination==8 && in.decoded.width_bits==16);
            out.gpr[8]=UINT64_C(0x910000000000beef);out.logical_flags=0x603;break;
        case 5:CHECK(in.decoded.destination==15 && in.decoded.width_bits==32);
            out.gpr[15]=0;out.logical_flags=0x602;break;
        case 6:CHECK(in.decoded.destination==11 && in.decoded.width_bits==64);
            out.gpr[11]=UINT64_C(0xfedcba9876543210);out.logical_flags=0x603;break;
        case 7:CHECK(in.decoded.destination==10 && in.decoded.width_bits==64);
            out.gpr[10]=0xc00dcafe;break;
        }
        struct li2_effect_owner o=fresh();
        struct callbacks c={.expected=&in,.decision={.action=native?LI2_EFFECT_NATIVE:LI2_EFFECT_SCRIPTED}};
        if(native) {
            struct li2_effect_binding b=binding(&c,0);native_outcome(&o,&in,&b,&results[i]);
            CHECK(c.before_calls==1 && !c.after_calls);
        } else {c.decision.result=results[i];scripted_outcome(&o,&in,&c);}
        CHECK(li2_effect_commit(&o,&out)==LI2_EFFECT_OK && o.committed);
        CHECK(li2_effect_begin(&o,&li2_effect_native_binding,&in)==LI2_EFFECT_STATE);
        ++in.sequence;CHECK(li2_effect_begin(&o,&li2_effect_native_binding,&in)==LI2_EFFECT_OK);
    }
}
static void outcome_controls(void) {
    static const unsigned char cpuid[]={0x0f,0xa2},syscall[]={0x0f,0x05};
    struct li2_effect_input in=input(cpuid,2,0x400100);
    const struct li2_effect_result native={.kind=LI2_CPUID,.cpuid={1,2,0xffffffff,4}};
    struct callbacks c={.expected=&in,.decision={.action=LI2_EFFECT_NATIVE},
        .post_result={.kind=LI2_CPUID,.cpuid={1,2,0x7fffffff,4}}};
    struct li2_effect_binding b=binding(&c,1);struct li2_effect_owner o=fresh();
    native_outcome(&o,&in,&b,&native);
    CHECK(c.after_calls==1 && o.post_callback_entered && o.post_callback_returned);
    CHECK(!memcmp(&o.native_result,&native,sizeof(native)) && !memcmp(&c.seen_native,&native,sizeof(native)));
    struct li2_effect_state out=unchanged(&in);
    out.gpr[0]=1;out.gpr[3]=2;out.gpr[1]=0x7fffffff;out.gpr[2]=4;
    CHECK(li2_effect_commit(&o,&out)==LI2_EFFECT_OK);
    /* Every preserved GPR/flag/selector/FP byte remains part of completion. */
    for(unsigned control=0;control<6;control++) {
        o=fresh();native_outcome(&o,&in,&b,&native);out=unchanged(&in);
        out.gpr[0]=1;out.gpr[3]=2;out.gpr[1]=0x7fffffff;out.gpr[2]=4;
        if(control==0)out.gpr[12]^=1;
        if(control==1)out.logical_flags^=0x400;
        if(control==2)out.selectors[1]^=8;
        if(control==3)after_fp[511]^=1;
        if(control==4)out.xstate.bytes=before_fp; /* No self-comparison credit. */
        if(control==5)out.selectors_observed=1;
        CHECK(li2_effect_commit(&o,&out)==LI2_EFFECT_COMMIT && !o.committed);
    }
    o=fresh();c.before_error=19;
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_CALLBACK && o.callback_returned && !o.native_entered);
    c.before_error=0;c.after_error=29;o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_OK && li2_effect_guarded(&o)==0);
    CHECK(li2_effect_native_enter(&o)==0 && li2_effect_native_return(&o,&native)==0);
    CHECK(li2_effect_native_outcome(&o)==LI2_EFFECT_CALLBACK && o.native_returned && o.post_callback_returned);
    CHECK(!memcmp(&o.native_result,&native,sizeof(native)) && !o.committed);
    c.after_error=0;
    for(unsigned nr=0;nr<2;nr++) {
        in=input(syscall,2,0x400100);in.before.gpr[0]=nr?39:9;
        c=(struct callbacks){.expected=&in,.decision={.action=LI2_EFFECT_NATIVE},
            .post_result={.kind=LI2_SYSCALL,.value=777}};b=binding(&c,1);o=fresh();
        const struct li2_effect_result actual={.kind=LI2_SYSCALL,.value=555};
        CHECK(li2_effect_begin(&o,&b,&in)==0 && li2_effect_guarded(&o)==0);
        CHECK(li2_effect_native_enter(&o)==0 && li2_effect_native_return(&o,&actual)==0);
        CHECK(li2_effect_native_outcome(&o)==(nr?LI2_EFFECT_OK:LI2_EFFECT_RESULT));
        CHECK(o.native_result.value==555 && o.native_returned && !o.committed);
        o=fresh();c.decision=(struct li2_effect_decision){.action=LI2_EFFECT_SCRIPTED,
            .result={.kind=LI2_SYSCALL,.value=777}};
        CHECK(li2_effect_begin(&o,&b,&in)==(nr?LI2_EFFECT_OK:LI2_EFFECT_RESULT));
    }
}
static void refusal_controls(void) {
    static const unsigned char cpuid[]={0x0f,0xa2},syscall[]={0x0f,0x05};
    static const unsigned char random[]={0x66,0x0f,0xc7,0xf0};
    struct li2_effect_input in=input(cpuid,2,0x400fff);CHECK(in.source_count==2);
    for(unsigned control=0;control<11;control++) {
        struct li2_effect_input bad=in;
        if(control==0)bad.source_count=1;
        if(control==1)bad.source[1].generation=0;
        if(control==2)bad.decoded.bytes[0]^=1;
        if(control==3)bad.before.logical_flags|=0x100;
        if(control==4)bad.before.selectors[2]=0x2b;
        if(control==5)bad.before.selectors_observed|=0x80;
        if(control==6)bad.decoded.next_pc++;
        if(control==7)bad.source[1].object_id=0;
        if(control==8)bad.source[1].backing=2;
        if(control==9)bad.source[1].backing=3;
        if(control==10)bad.source[1].reserved=1;
        CHECK(li2_effect_validate_input(&bad)!=LI2_EFFECT_OK);
    }
    struct li2_effect_input anonymous=in;
    anonymous.source[1].backing=2;anonymous.source[1].object_id=0;
    CHECK(li2_effect_validate_input(&anonymous)==LI2_EFFECT_OK);
    struct li2_effect_owner o=fresh();
    CHECK(li2_effect_begin(&o,&li2_effect_native_binding,&in)==0);
    CHECK(li2_effect_native_enter(&o)==LI2_EFFECT_STATE && !o.native_entered);
    struct callbacks c={.expected=&in,.decision={.action=LI2_EFFECT_UNCOMPLETED,
        .fault={LI2_EFFECT_REFUSAL,9,-4,0x400fff}}};
    struct li2_effect_binding b=binding(&c,0);o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_NOT_COMPLETED && o.phase==LI2_EFFECT_REJECTED);
    CHECK(!o.native_entered && !o.committed);
    c.decision.fault.origin=LI2_EFFECT_NATIVE_FAULT;o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_RESULT && !o.native_entered);
    o=fresh();CHECK(li2_effect_begin(&o,&li2_effect_native_binding,&in)==0);
    CHECK(li2_effect_guarded(&o)==0 && li2_effect_native_enter(&o)==0);
    const struct li2_effect_fault native_fault={LI2_EFFECT_NATIVE_FAULT,4,2,0x400fff};
    CHECK(li2_effect_native_fault(&o,&native_fault)==LI2_EFFECT_NOT_COMPLETED && !o.native_returned);
    ++in.sequence;CHECK(li2_effect_begin(&o,&li2_effect_native_binding,&in)==LI2_EFFECT_STATE);
    in=input(random,sizeof(random),0x400100);c.expected=&in;
    c.decision=(struct li2_effect_decision){.action=LI2_EFFECT_SCRIPTED,
        .result={.kind=LI2_RDRAND,.value=1}};o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_RESULT); /* CF=0 requires zero result. */
    c.decision.result.carry=1;c.decision.result.value=0x10000;o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_RESULT); /* No width truncation. */
    for(unsigned i=0;i<2;i++) {
        in=input(syscall,2,0x400100);in.before.gpr[0]=i?231:60;o=fresh();
        CHECK(li2_effect_begin(&o,&li2_effect_native_binding,&in)==0 && li2_effect_guarded(&o)==0);
        CHECK(li2_effect_native_enter(&o)==0 && o.phase==LI2_EFFECT_EXIT_ENTERED && o.exit_entered);
        CHECK(!o.native_returned && !o.committed);
        const struct li2_effect_result returned={.kind=LI2_SYSCALL,.value=(uint64_t)-1};
        CHECK(li2_effect_native_return(&o,&returned)==LI2_EFFECT_RESULT && o.native_returned && !o.committed);
    }
    in=input(cpuid,2,0x400100);
    struct li2_effect_script_entry entries[2]={{.pc=0x400100,.kind=LI2_CPUID,
        .decision={.action=LI2_EFFECT_NATIVE}},{.pc=0x400200,.kind=LI2_CPUID,
        .decision={.action=LI2_EFFECT_NATIVE}}};
    struct li2_effect_script script={LI2_EFFECT_ABI,2,entries};
    b=(struct li2_effect_binding){.abi_version=LI2_EFFECT_ABI,
        .callback=li2_effect_script_callback,.context=&script};o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==0);
    entries[1].pc=entries[0].pc;o=fresh();
    CHECK(li2_effect_begin(&o,&b,&in)==LI2_EFFECT_CALLBACK && !o.native_entered);
}
int main(void) {
    for(unsigned i=0;i<sizeof(before_fp);i++)before_fp[i]=(unsigned char)(i*37+11);
    struct li2_decoder_stats before,after;
    CHECK(li2_decoder_initialize(arena,sizeof(arena),&before)==LI2_OK && before.phase==2);
    class_controls();outcome_controls();refusal_controls();
    CHECK(li2_decoder_stats(&after)==LI2_OK && !memcmp(&before,&after,sizeof(before)));
    printf("supplied selected_effect controls: %u assertions\n",assertions);return 0;
}
