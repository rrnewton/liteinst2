/* Full-state memory comparisons: original EVEX512 VPCMPEQB by default;
   explicit VPCM_PROFILE=3884 selects only EVEX256 unsigned NEQ immediate4.
   Capture/compare and genuine failed-read checks remain mandatory. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "write_footprint.h"
#define VPE_PROMOTED_INDICES 42
#define VPE_FIRST_ENCODING 0
#include "tests/vpcmpeqb_register/promotions.inc"
#include "write_footprint.h"
#include "tests/vmovdqu64_family/promotions.inc"
#include "tests/vmovdqu64_family/promotions256.inc"
#ifndef VPCM_PROFILE
#define VPCM_PROFILE 1720
#endif
#if VPCM_PROFILE == 3884
#define VPCM_CODE 3884
#define VPCM_GROUPS 5
#define VPCM_CPU_MASK UINT64_C(0xc0010000)
#define VPCM_OBS_MAGIC UINT64_C(0x31584e435056324c)
#define VPCM_QUERY_MAGIC UINT64_C(0x31514e435056324c)
#define VPCM_LENGTH(v) ((v)->length)
#define VPCM_FAULT_PREFIX (!(v64_fault_kind&1)?16:0)
#define VPCM_FP_PARAMETER ,const unsigned char *operand
#define VPCM_FP_OPERAND(s,before) ,vpcub_operand(s,before)
#include "cases3884.inc"
#elif VPCM_PROFILE == 1720
#define VPCM_CODE 1720
#define VPCM_GROUPS 6
#define VPCM_CPU_MASK UINT64_C(0x40010000)
#define VPCM_OBS_MAGIC UINT64_C(0x31584d435056324c)
#define VPCM_QUERY_MAGIC UINT64_C(0x31514d435056324c)
#define VPCM_LENGTH(v) 6
#define VPCM_FAULT_PREFIX (v64_fault_kind==2?32:0)
#define VPCM_FP_PARAMETER
#define VPCM_FP_OPERAND(s,before)
#include "cases.inc"
#else
#error closed VPCM profile
#endif
#include "write_footprint.h"
#include "../vpcmpeqb_memory/promotions.inc"
#ifndef VPCM_GROUP
#error VPCM_GROUP must select a bounded cohort
#endif
_Static_assert(VPCM_GROUP>=0&&VPCM_GROUP<VPCM_GROUPS,"closed m512 comparison cohorts");
_Static_assert(PAIRS==21,"unchanged original record storage");
#define VPB_COUNT 18U
#define VPB_PAIRS (VPB_COUNT+1)
#define VPB_ACTIVE UINT64_C(0xe7)
unsigned char vpb_vectors[32][64] __attribute__((aligned(64)));
uint64_t vpb_masks[8] __attribute__((aligned(64)));
struct vpb_cpuid { uint64_t leaf,subleaf,a,b,c,d; };
static struct {
    uint64_t magic,version,bytes,group,query_count,checked,xcr0,xsave_bytes;
    struct vpb_cpuid basic[4],component[64];
    uint64_t ids[VPB_PAIRS],bv[VPB_PAIRS][10];
} vpb_observations;
static struct {
    uint64_t kind,checked,operand,address,prefix_bytes,owner_trace;
    uint64_t native_bv[2],owner_bv[2],live_bv[2];
} v64_fault;
static unsigned v64_fault_kind;
static void v64_fault_memory(void) {
    need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ,0,0,0),1190);
    for(size_t i=0;i<PAGE;i++)need(((const unsigned char *)data_fault)[i]==(unsigned char)(i*13+0x5b),1191);
    need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),1192);
}

static void vpb_cpuid(struct vpb_cpuid *out,unsigned leaf,unsigned subleaf) {
    unsigned a=leaf,b,c=subleaf,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));
    *out=(struct vpb_cpuid){leaf,subleaf,a,b,c,d};++vpb_observations.query_count;
}
static void vpb_layout(void) {
    vpb_observations.magic=VPCM_OBS_MAGIC;
    vpb_observations.version=1;vpb_observations.bytes=sizeof(vpb_observations);
    vpb_observations.group=VPCM_GROUP;vpb_observations.xcr0=fixture_xcr0;
    vpb_observations.xsave_bytes=xsave_bytes;
    vpb_cpuid(&vpb_observations.basic[0],0,0);
    need(vpb_observations.basic[0].a>=13,1100);
    vpb_cpuid(&vpb_observations.basic[1],1,0);
    vpb_cpuid(&vpb_observations.basic[2],7,0);
    vpb_cpuid(&vpb_observations.basic[3],13,0);
    need((vpb_observations.basic[1].c&UINT64_C(0x1c000000))==UINT64_C(0x1c000000)&&
         (vpb_observations.basic[2].b&VPCM_CPU_MASK)==VPCM_CPU_MASK,1101);
    uint64_t supported=vpb_observations.basic[3].a|(vpb_observations.basic[3].d<<32);
    need((fixture_xcr0&VPB_ACTIVE)==VPB_ACTIVE&&!(fixture_xcr0&~supported)&&
         !(fixture_xcr0>>63)&&vpb_observations.basic[3].b==xsave_bytes&&
         xsave_bytes<=vpb_observations.basic[3].c,1102);
    /* Every enabled extended component is queried, not just the changed one.
       CPUID standard offsets must be user state, bounded and non-overlapping. */
    for(unsigned i=2;i<63;i++)if(fixture_xcr0&(UINT64_C(1)<<i)) {
        struct vpb_cpuid *q=&vpb_observations.component[i];vpb_cpuid(q,13,i);
        need(q->a&&q->b>=576&&q->b<=xsave_bytes&&q->a<=xsave_bytes-q->b&&!(q->c&1),1103);
        for(unsigned j=2;j<i;j++)if(fixture_xcr0&(UINT64_C(1)<<j)) {
            const struct vpb_cpuid *p=&vpb_observations.component[j];
            need(q->b>=p->b+p->a||p->b>=q->b+q->a,1104);
        }
    }
    need(vpb_observations.component[2].a==256&&vpb_observations.component[5].a==64&&
         vpb_observations.component[6].a==512&&vpb_observations.component[7].a==1024,1105);
}
static void vpb_seed(void) {
    for(unsigned r=0;r<32;r++)for(unsigned i=0;i<64;i++)
        vpb_vectors[r][i]=(unsigned char)(1+(r*17+i*13)%255);
    for(unsigned r=0;r<8;r++)vpb_masks[r]=UINT64_C(0x0123456789abcdef)^
        (UINT64_C(0x1111111111111111)*r);
}
static const struct vpb_case *vpb_case(const struct sample *s) {
    need(s->id>=5000+18*VPCM_GROUP&&s->id<5018+18*VPCM_GROUP,1106);
    return &vpb_cases[VPCM_GROUP][s->id-5000-18*VPCM_GROUP];
}
#if VPCM_PROFILE == 3884
#include "profile3884.inc"
#else
static void vpb_inputs(struct sample *s) {
    inputs(s);vpb_seed();const struct vpb_case *v=vpb_case(s);
    need(v->pattern<3&&v->offset+64<=DATA_BYTES&&v->source<32&&v->destination<8,1193);
    memcpy(vpb_vectors[v->source],vpc_source,64);
    need(vpb_masks[v->destination]!=vpc_expected[v->pattern],1214);
    memcpy((void *)(data_page+v->offset),v64_patterns[v->pattern],64);
    fixture_seed[7]=data_page+v->offset;
    if(s==&negative_sample&&control==1) {
        need(v64_fault_kind==1||v64_fault_kind==2,1194);
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ|PROT_WRITE,0,0,0),1195);
        for(size_t i=0;i<PAGE;i++)((unsigned char *)data_fault)[i]=(unsigned char)(i*13+0x5b);
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),1196);
        fixture_seed[7]=data_fault-(v64_fault_kind==2?32:0);
    }
}
static void vpb_prepare(struct sample *s,unsigned index) {
    need(index<VPB_COUNT,1107);const struct vpb_case *v=&vpb_cases[VPCM_GROUP][index];
    s->id=5000+18*VPCM_GROUP+index;s->length=sizeof(v->encoding);
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1108);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1109);
    need(v->tail>=1&&v->tail<=s->length,1110);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<s->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->encoding,s->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1111);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==1720&&
         s->decoded.length==s->length&&!memcmp(s->decoded.bytes,v->encoding,s->length),1112);
}
#endif
static size_t vpb_offset(unsigned reg,unsigned byte) {
    need(reg<32&&byte<64,1113);
    if(reg>=16)return vpb_observations.component[7].b+(reg-16)*64+byte;
    if(byte<16)return 160+16*reg+byte;
    if(byte<32)return vpb_observations.component[2].b+16*reg+byte-16;
    return vpb_observations.component[6].b+32*reg+byte-32;
}
static uint64_t vpb_header(const unsigned char *fp,size_t n,int kernel) {
    need(n>=576&&n<=FP_CAPACITY,1114);
    for(unsigned i=520;i<576;i++)need(!fp[i],1115); /* XCOMP_BV and reserved bytes. */
    uint64_t bv=word(fp+512);
    uint64_t represented=fixture_xcr0;size_t extent=n;
    if(kernel) {
        need(u32(fp+464)==UINT32_C(0x46505853)&&u32(fp+468)==n&&
             u32(fp+480)>=576&&u32(fp+480)<=n-4&&
             u32(fp+n-4)==UINT32_C(0x46505845),1129);
        represented=word(fp+472);extent=u32(fp+480);
        need(!(represented&~fixture_xcr0),1130);
    } else need(n==xsave_bytes,1131);
    need((represented&VPB_ACTIVE)==VPB_ACTIVE&&(bv&VPB_ACTIVE)==VPB_ACTIVE&&
         !(bv&~represented),1116);
    for(unsigned i=2;i<63;i++)if(represented&(UINT64_C(1)<<i)) {
        const struct vpb_cpuid *q=&vpb_observations.component[i];
        need(q->b<=extent&&q->a<=extent-q->b,1117);
    }
    return bv;
}
static void vpb_inputs_observed(const unsigned char *fp,size_t n,int kernel) {
    (void)vpb_header(fp,n,kernel);
    for(unsigned r=0;r<32;r++)for(unsigned j=0;j<64;j++)
        need(fp[vpb_offset(r,j)]==vpb_vectors[r][j],1118);
    for(unsigned r=0;r<8;r++)need(word(fp+vpb_observations.component[5].b+8*r)==vpb_masks[r],1119);
}
static void vpb_fp_effect(const struct sample *s,const unsigned char *before,
                          const unsigned char *after,size_t n,int kernel VPCM_FP_PARAMETER) {
    vpb_inputs_observed(before,n,kernel);uint64_t a=vpb_header(before,n,kernel),b=vpb_header(after,n,kernel);
    need(a==b,1120); /* Nonzero independently seeded components remain in use. */
    size_t at=vpb_observations.component[5].b; /* Only selected K changes; every ZMM byte unchanged. */
    uint64_t answer=0;
    if(!s->selftest) {
        const struct vpb_case *v=vpb_case(s);at+=8*v->destination;
        /* Recompute equality from the actual captured operands, independently
           of the product classifier and the literal answer table. */
#if VPCM_PROFILE == 3884
        need(operand&&word(before+at)>>32,1215);
        for(unsigned i=0;i<32;i++)if(before[vpb_offset(v->source,i)]!=operand[i])
            answer|=UINT64_C(1)<<i;
        need(!(answer>>32),1216);
#else
        for(unsigned i=0;i<64;i++)if(before[vpb_offset(v->source,i)]==v64_patterns[v->pattern][i])
            answer|=UINT64_C(1)<<i;
#endif
        need(answer==vpc_expected[v->pattern],1213);
    }
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(!s->selftest&&i>=at&&i<at+8)expected=(unsigned char)(answer>>(8*(i-at)));
        need(after[i]==expected,1121);
    }
}
struct vpc_query { uint64_t attempted,result,id,lane; struct li2_write_registers before; struct li2_write_footprint value;
#if VPCM_PROFILE == 3884
    uint64_t ea,object,offset,kind;
#endif
};
static struct { uint64_t magic,version,bytes,group,checked,refusals,reserved[2]; struct vpc_query rows[20][2]; } vpc_queries;
#if VPCM_PROFILE == 3884
_Static_assert(sizeof(struct vpc_query)==256&&sizeof(vpc_queries)==10304,"complete query and EA trailer");
#else
_Static_assert(sizeof(struct vpc_query)==224&&sizeof(vpc_queries)==9024,"complete query trailer");
#endif
static void vpc_query(struct sample *s,unsigned index,unsigned lane_index) {
    need(index<20&&lane_index<2,1190);struct vpc_query *q=&vpc_queries.rows[index][lane_index];
    need(!q->attempted,1191);q->attempted=1;q->id=s->id;q->lane=lane_index;
    const struct state *before=lane_index?&s->step_before:&s->native_before;
    for(unsigned r=0;r<16;r++)q->before.gpr[r]=(uint64_t)before->frame.greg[regs[r]];
    q->before.fs_base=before->fs;q->before.gs_base=before->gs;
    q->result=li2_decoder_write_footprint(s->pc,s->decoded.bytes,s->length,&q->before,&q->value);
    need(!q->result&&q->value.abi_version==1&&q->value.policy==LI2_WRITE_NONE&&
         q->value.code==VPCM_CODE&&q->value.length==VPCM_LENGTH(vpb_case(s))&&q->value.pc==s->pc&&
         q->value.next_pc==s->pc+VPCM_LENGTH(vpb_case(s))&&!q->value.first&&!q->value.end,1192);
#if VPCM_PROFILE == 3884
    const struct vpb_case *v=vpb_case(s);q->kind=v->kind;q->ea=vpcub_ea(v,s->pc,q->before.gpr);
    q->object=v->kind==3?s->mapping:v->kind==2?subject:data_page;q->offset=q->ea-q->object;
    if(s==&negative_sample)need(q->ea==data_fault-VPCM_FAULT_PREFIX,1268);
    else if(v->kind==3)need(q->ea==s->expected_post+(uint64_t)v->displacement,1269);
    else if(v->kind==2)need(q->ea==q->before.gpr[4]&&q->offset==SUBJECT_BYTES/2,1270);
    else need(q->ea==(v->kind==4?v->absolute_target:data_page+v->offset),1271);
#endif
    ++vpc_queries.checked;
}
static void vpb_effects(struct sample *s,unsigned index) {
    need(index<VPB_PAIRS&&vpb_observations.checked==index,1122);
    if(!s->selftest)need(s->owner.classification.policy==1&&s->owner.classification.code==VPCM_CODE&&
        s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_SIMD&&
        s->length==VPCM_LENGTH(vpb_case(s))&&s->expected_post==s->pc+VPCM_LENGTH(vpb_case(s))&&!memcmp(s->decoded.bytes,vpb_case(s)->encoding,VPCM_LENGTH(vpb_case(s))),1123);
    const struct li2_step_frame *frames[]={&s->native_before.frame,&s->native_after.frame,
        &s->step_before.frame,&s->owner.step.before,&s->owner.step.after,&s->step_endpoint.frame};
    for(unsigned i=0;i<6;i++)vpb_observations.bv[index][i]=vpb_header(frames[i]->fp,frames[i]->fp_bytes,1);
    for(unsigned i=0;i<4;i++)vpb_observations.bv[index][6+i]=vpb_header(s->actual_fp[i],xsave_bytes,0);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++)need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
            before->frame.greg[regs[r]]==after->frame.greg[regs[r]]&&
            s->live[2*l].gpr[r]==s->live[2*l+1].gpr[r],1124);
        compare_memory(before,after,1125);
        if(!s->selftest) {
#if VPCM_PROFILE == 3884
            need(!memcmp(vpcub_operand(s,before),vpcub_operand(s,after),32),1197);vpcub_other_memory();
#else
            const struct vpb_case *v=vpb_case(s);
            need((uintptr_t)before->frame.greg[REG_RDI]==data_page+v->offset&&
                 !memcmp(before->data+v->offset,v64_patterns[v->pattern],64)&&
                 !memcmp(after->data+v->offset,v64_patterns[v->pattern],64),1197);
#endif
        }
        vpb_fp_effect(s,before->frame.fp,after->frame.fp,before->frame.fp_bytes,1 VPCM_FP_OPERAND(s,before));
        vpb_fp_effect(s,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,0 VPCM_FP_OPERAND(s,before));
    }
    vpb_fp_effect(s,s->owner.step.before.fp,s->owner.step.after.fp,s->owner.step.before.fp_bytes,1 VPCM_FP_OPERAND(s,&s->step_before));
    need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,1126);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,1127);
    need(actual_protection(s->expected_post,0)==PROT_READ,1128);
    if(!s->selftest){vpc_query(s,index-1,0);vpc_query(s,index-1,1);}
    vpb_observations.ids[index]=s->id;++vpb_observations.checked;
}
/* A failed m512 read has no retired register/memory effect. Preserve the
   unchanged common failed-frame/revoke/sync predicates after these literals. */
static void v64_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        need(s->native_fault&&!s->native_complete&&!s->step_endpoint_seen&&
             s->owner.classification.code==VPCM_CODE&&s->owner.classification.policy==1,1198);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==14&&s->native_after.frame.greg[REG_ERR]==4&&
#if VPCM_PROFILE == 3884
             vpcub_actual_ea(s,&s->native_after)==data_fault-VPCM_FAULT_PREFIX&&
#else
             (uintptr_t)s->native_after.frame.greg[REG_RDI]==fixture_seed[7]&&
#endif
             (uintptr_t)s->native_after.frame.greg[REG_CR2]==data_fault&&
             (uintptr_t)o->after.greg[REG_CR2]==data_fault,1199);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
            s->native_after.frame.greg[regs[i]]&&o->before.greg[regs[i]]==o->after.greg[regs[i]],1200);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             ((uint64_t)o->before.greg[REG_EFL]|LI2_STEP_TF)==(uint64_t)o->after.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             o->before.fp_bytes==o->after.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),1201);
        compare_memory(&s->native_before,&s->native_after,1202);v64_fault_memory();
#if VPCM_PROFILE == 3884
        vpcub_other_memory();
#endif
        need(!memcmp(s->native_before.data,s->step_before.data,DATA_BYTES)&&
             !memcmp(s->native_before.stack,s->step_before.stack,SUBJECT_BYTES),1203);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->native_before.frame.mask==mask&&s->native_after.frame.mask==mask&&
             s->native_before.frame.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS]&&
             o->after.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS],1204);
        need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
             s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),1205);
        const struct li2_step_frame *f[]={&s->native_before.frame,&s->native_after.frame,&o->before,&o->after};
        for(unsigned i=0;i<4;i++) {
            need(f[i]->initialized==f[i]->fp_bytes&&f[i]->mask==mask,1212);
            vpb_inputs_observed(f[i]->fp,f[i]->fp_bytes,1);
        }
        vpb_inputs_observed(s->actual_fp[0],xsave_bytes,0);vpb_inputs_observed(s->actual_fp[1],xsave_bytes,0);
        v64_fault=(typeof(v64_fault)){.kind=v64_fault_kind,.checked=1,
#if VPCM_PROFILE == 3884
            .operand=vpcub_actual_ea(s,&s->native_before),
#else
            .operand=fixture_seed[7],
#endif
            .address=data_fault,.prefix_bytes=VPCM_FAULT_PREFIX,.owner_trace=o->trace_seen,
            .native_bv={vpb_header(f[0]->fp,f[0]->fp_bytes,1),vpb_header(f[1]->fp,f[1]->fp_bytes,1)},
            .owner_bv={vpb_header(f[2]->fp,f[2]->fp_bytes,1),vpb_header(f[3]->fp,f[3]->fp_bytes,1)},
            .live_bv={vpb_header(s->actual_fp[0],xsave_bytes,0),vpb_header(s->actual_fp[1],xsave_bytes,0)}};
    }
    if(control==1&&s==&negative_sample){vpc_query(s,0,0);vpc_query(s,0,1);}
    failure(context,o);
    if(control==1&&s==&negative_sample)
        need(write_all(3,&vpb_observations,sizeof(vpb_observations))&&
             write_all(3,&v64_fault,sizeof(v64_fault))&&
             write_all(3,&vpc_queries,sizeof(vpc_queries))&&
             write_all(3,&vpcm_promotions,sizeof(vpcm_promotions))&&
             write_all(3,&vm64_promotions,sizeof(vm64_promotions))&&
             write_all(3,&vpe_promotions,sizeof(vpe_promotions))&&
              write_all(3,&vm256_promotions,sizeof(vm256_promotions)),1206);
}
static void vpb_pair(struct sample *s,unsigned index) {
    current=s;fixture_target=s->pc;vpb_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
#if VPCM_PROFILE == 3884
    vpcub_other_memory();
#endif
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    if(s==&negative_sample&&control==1)v64_fault_memory();
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3||(s==&negative_sample&&control==1))s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    vpb_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,v64_failure},continue_closed};
    int error=s->selftest?li2_step_arm(&s->owner.step,&session,&hooks.step,&request,1):
                         li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();
    need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);vpb_effects(s,index);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void vpb_refusals(void) {
    for(size_t i=0;i<sizeof(vpb_refused)/sizeof(vpb_refused[0]);i++) {
        const struct vpb_refusal *v=&vpb_refused[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        if(vpe_is_promoted(i)) {
            vpe_promote(i,v->b,v->n,result.decoder_result,&refused_last);
            continue;
        }
        if(vm256_is_promoted(i)) {
            vm256_promote(i,v->b,v->n,result.decoder_result,&refused_last);
            continue;
        }
        if(vm64_is_promoted(i)) {
            vm64_promote(i,v->b,v->n,result.decoder_result,&refused_last);
            continue;
        }
        if(vpcm_is_promoted(i))vpcm_promote(i,v->b,v->n,result.decoder_result,&refused_last);
        else {
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1140+(unsigned)i);
        ++result.refusals;
        }
    }
    vpcm_promotions_complete();
    for(size_t i=0;i<sizeof(vpcm_refused)/sizeof(vpcm_refused[0]);i++) {
        const struct vpb_refusal *v=&vpcm_refused[i];result.failed_refusal=47+66+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1260+(unsigned)i);
        ++result.refusals;
    }
    vm64_promotions_complete();vm256_promotions_complete();
#if VPCM_PROFILE == 3884
    _Static_assert(sizeof(vpcub_refused)/sizeof(vpcub_refused[0])==33,"closed immediate4 neighbors");
    for(size_t i=0;i<33;i++) {
        const struct vpcub_refusal *v=&vpcub_refused[i];result.failed_refusal=47+66+9+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1300+(unsigned)i);
        ++result.refusals;
    }
#endif
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(vm256_promotions)+sizeof(vpe_promotions)+sizeof(vm64_promotions)+sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(vpb_observations)+sizeof(v64_fault)+sizeof(vpc_queries)+sizeof(vpcm_promotions)<16*1024*1024,"unchanged complete record cap");
    _Static_assert(sizeof(vpb_observations)==5000,"literal trailer extent");
    _Static_assert(sizeof(v64_fault)==96,"actual failed-read trailer extent");
    _Static_assert(sizeof(vpb_refused)/sizeof(vpb_refused[0])==66,"closed supplied neighbors");
    _Static_assert(sizeof(vpcm_refused)/sizeof(vpcm_refused[0])==9,"additional canonical-bit refusals");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=VPB_PAIRS;
    need(stack[0]==1,1180);setup(stack);need(!control,1181);vpb_layout();
#if VPCM_PROFILE == 3884
    long low=RAW(SYS_mmap,UINT64_C(0x1ffff000),3*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    need(low==INT64_C(0x1ffff000),1274);vpcub_low=(uintptr_t)low+PAGE;
    need(!RAW(SYS_mprotect,vpcub_low,PAGE,PROT_READ|PROT_WRITE,0,0,0)&&
         actual_protection(vpcub_low-PAGE,0)==PROT_NONE&&actual_protection(vpcub_low+PAGE,0)==PROT_NONE,1275);
#endif
    long guarded=RAW(SYS_mmap,0,3*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(guarded>0,1207);data_page=(uintptr_t)guarded+PAGE;data_fault=data_page+PAGE;
#if VPCM_PROFILE == 3884
    vpcub_high=data_page;
#endif
    need(!RAW(SYS_mprotect,data_page,PAGE,PROT_READ|PROT_WRITE,0,0,0)&&
         actual_protection(data_page-PAGE,0)==PROT_NONE&&actual_protection(data_fault,0)==PROT_NONE,1208);
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_VPCM_CONTROL=";
#if VPCM_PROFILE == 3884
    const char *names[]={"full-read-fault","cross-read-fault","indexed-full-read-fault","indexed-cross-read-fault"};
#else
    const char *names[]={"full-read-fault","cross-read-fault"};
#endif
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&VPCM_GROUP==0,1209);
        for(unsigned j=0;j<sizeof(names)/sizeof(names[0]);j++)if(same(env[i]+sizeof(key)-1,names[j]))v64_fault_kind=j+1;
        need(v64_fault_kind>=1&&v64_fault_kind<=sizeof(names)/sizeof(names[0]),1210);control=1;
    }
    result.control=control;
    vpc_queries.magic=VPCM_QUERY_MAGIC;vpc_queries.version=1;
    vpc_queries.bytes=sizeof(vpc_queries);vpc_queries.group=VPCM_GROUP;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47&&failed==SIZE_MAX&&!decoder_result,1182);
    vpb_refusals();vpe_promotions_complete();need(result.refusals==(VPCM_PROFILE==3884?141:108),1183);
    vpb_seed();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    vpb_effects(&samples[0],0);
    if(control){vpb_prepare(&negative_sample,v64_fault_kind-1);vpb_pair(&negative_sample,1);die(1211);}
    for(unsigned i=0;i<VPB_COUNT;i++){vpb_prepare(&samples[i+1],i);vpb_pair(&samples[i+1],i+1);}
    need(result.completed==VPB_PAIRS&&vpb_observations.checked==VPB_PAIRS&&dump()&&
         write_all(3,&vpb_observations,sizeof(vpb_observations))&&
         write_all(3,&v64_fault,sizeof(v64_fault))&&
             write_all(3,&vpc_queries,sizeof(vpc_queries))&&
             write_all(3,&vpcm_promotions,sizeof(vpcm_promotions))&&
             write_all(3,&vm64_promotions,sizeof(vm64_promotions))&&
             write_all(3,&vpe_promotions,sizeof(vpe_promotions))&&
              write_all(3,&vm256_promotions,sizeof(vm256_promotions)),1184);
#if VPCM_PROFILE == 3884
    output("LI2_VPCMPNEQUB256_TF_PASS pairs=19 comparisons=18 selftest=1 refusal_bytes=141 footprint_queries=36 full_state=19 full_memory=19 upper_k32_zero=18 prior_typed_promotions=14 prior_supplied_none_queries=14 live_endpoints=19\n");
#else
    output("LI2_VPCMPEQB_MEMORY_FAMILY_TF_PASS pairs=19 comparisons=18 selftest=1 old_refusal_bytes=72 memory_refusals=27 new_refusals=9 typed_promotions=5 supplied_none_queries=5 footprint_queries=36 full_state=19 full_memory=19 vm64_typed_promotions=7 vm64_supplied_none_queries=7 live_endpoints=19 vpe_typed_promotions=1 vpe_supplied_none_queries=1 vm256_typed_promotions=1 vm256_supplied_none_queries=1\n");
#endif
    return 0;
}
