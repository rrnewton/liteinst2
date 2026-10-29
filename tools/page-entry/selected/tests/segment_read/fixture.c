/* Canonical MOV r16,Sreg only. The complete native/TF machinery is unchanged. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "write_footprint.h"
#include "cases.inc"
#ifndef SEGMENT_GROUP
#error SEGMENT_GROUP must select one of five closed cohorts
#endif
_Static_assert(SEGMENT_GROUP>=0&&SEGMENT_GROUP<5,"five bounded cohorts");
_Static_assert(PAIRS==21,"unchanged original sample capacity");
#define SEGMENT_COUNT 18U
#define SEGMENT_FIRST (SEGMENT_COUNT*SEGMENT_GROUP)
#define SEGMENT_PAIRS (SEGMENT_COUNT+1)
/* Encoding fields use ES,CS,SS,DS,FS,GS; the unchanged live observer uses
   CS,SS,DS,ES,FS,GS. These are actual selectors, never assumed constants. */
static const unsigned selector_index[6]={3,0,1,2,4,5};
struct segment_query {
    uint64_t attempted,result,id,lane;
    struct li2_write_registers before;
    struct li2_write_footprint value;
    uint64_t selector,actual;
};
static struct {
    uint64_t magic,version,bytes,group,checked,refusals,reserved[2];
    struct segment_query rows[SEGMENT_COUNT][2];
} segment_queries;
_Static_assert(sizeof(struct segment_query)==240&&sizeof(segment_queries)==8704,
               "complete actual-before and literal-result trailer");
static void segment_prepare(struct sample *s,unsigned index) {
    need(index<SEGMENT_COUNT,1100);const struct segment_case *v=&segment_cases[SEGMENT_FIRST+index];
    need(v->selector<6&&v->destination<16&&v->destination!=4&&
         v->length==(v->destination<8?3U:4U)&&v->tail>=1&&v->tail<=v->length,1101);
    s->id=10000+SEGMENT_FIRST+index;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1102);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1103);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<s->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->encoding,s->length);
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1104);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&
         s->decoded.code==287&&s->decoded.length==s->length&&
         !memcmp(s->decoded.bytes,v->encoding,s->length),1105);
}
static void segment_effects(struct sample *s,unsigned index) {
    need(index<SEGMENT_COUNT&&s->checked&&s->id==10000+SEGMENT_FIRST+index,1110);
    const struct segment_case *v=&segment_cases[SEGMENT_FIRST+index];
    need(s->owner.classification.policy==1&&s->owner.classification.code==287&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&
         s->owner.classification.family==LI2_TF_INTEGER&&
         s->expected_post==s->pc+v->length,1111);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        uint64_t selector=s->live[2*l].selectors[selector_index[v->selector]];
        for(unsigned r=0;r<16;r++) {
            uint64_t initial=fixture_seed[r],expected=initial;
            if(r==v->destination)expected=(initial&~UINT64_C(0xffff))|selector;
            need((uint64_t)before->frame.greg[regs[r]]==initial&&
                 s->live[2*l].gpr[r]==initial&&
                 (uint64_t)after->frame.greg[regs[r]]==expected&&
                 s->live[2*l+1].gpr[r]==expected,1112);
        }
        need((fixture_seed[v->destination]&~UINT64_C(0xffff))!=0&&
             s->initial_flags==s->post_flags&&
             s->live[2*l].rflags==s->live[2*l+1].rflags,1113);
        compare_memory(before,after,1114);
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes),1115);
        struct segment_query *q=&segment_queries.rows[index][l];
        need(!q->attempted,1116);q->attempted=1;q->id=s->id;q->lane=l;
        for(unsigned r=0;r<16;r++)q->before.gpr[r]=(uint64_t)before->frame.greg[regs[r]];
        q->before.fs_base=before->fs;q->before.gs_base=before->gs;
        q->selector=selector;q->actual=(uint64_t)after->frame.greg[regs[v->destination]];
        q->result=li2_decoder_write_footprint(s->pc,s->decoded.bytes,s->length,&q->before,&q->value);
        need(!q->result&&q->value.abi_version==1&&q->value.policy==LI2_WRITE_NONE&&
             q->value.code==287&&q->value.length==s->length&&q->value.pc==s->pc&&
             q->value.next_pc==s->expected_post&&!q->value.first&&!q->value.end,1117);
        ++segment_queries.checked;
    }
    need(s->owner.step.before.fp_bytes==s->owner.step.after.fp_bytes&&
         !memcmp(s->owner.step.before.fp,s->owner.step.after.fp,s->owner.step.before.fp_bytes),1118);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,1119);
    need(actual_protection(s->expected_post,0)==PROT_READ,1120);
}
static void segment_refusals(void) {
    for(size_t i=0;i<sizeof(segment_refused)/sizeof(segment_refused[0]);i++) {
        const struct segment_refusal *v=&segment_refused[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->bytes,v->length,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1200+(unsigned)i);
        struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
        for(unsigned r=0;r<16;r++)registers.gpr[r]=UINT64_C(0x1234567800000000)+r*16;
        registers.fs_base=0x12340000;registers.gs_base=0x56780000;
        need(!li2_decoder_write_footprint(0x1000,v->bytes,v->length,&registers,&footprint)&&
             footprint.abi_version==1&&!footprint.policy&&!footprint.first&&!footprint.end,1400);
        ++result.refusals;++segment_queries.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(segment_queries)<16*1024*1024,"unchanged complete record cap");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=SEGMENT_PAIRS;
    need(stack[0]==1,1500);setup(stack);need(!control,1501);
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47&&failed==SIZE_MAX&&!decoder_result,1502);
    segment_queries.magic=UINT64_C(0x315247455332494c);segment_queries.version=1;
    segment_queries.bytes=sizeof(segment_queries);segment_queries.group=SEGMENT_GROUP;
    segment_refusals();need(result.refusals==47+SEGMENT_REFUSALS&&
         segment_queries.refusals==SEGMENT_REFUSALS,1503);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,1504);
    for(unsigned i=0;i<SEGMENT_COUNT;i++) {
        segment_prepare(&samples[i+1],i);run_pair(&samples[i+1]);segment_effects(&samples[i+1],i);
    }
    need(result.completed==SEGMENT_PAIRS&&segment_queries.checked==2*SEGMENT_COUNT&&dump()&&
         write_all(3,&segment_queries,sizeof(segment_queries)),1505);
    output(SEGMENT_PASS);
    return 0;
}
