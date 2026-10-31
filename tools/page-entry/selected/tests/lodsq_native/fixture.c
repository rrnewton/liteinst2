/* Additive canonical LODSQ oracle. The original generic fixture, including
   its four commands and all state/closure comparisons, remains literal. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "tf_entry_route.h"
#include "write_footprint.h"

#define LODSQ_PAIRS 9U
_Static_assert(PAIRS==21 && LODSQ_PAIRS<PAIRS,"original bounded record slots");
static unsigned lodsq_control;
struct lodsq_trailer {
    uint64_t magic,version,bytes,route_checks,footprint_checks;
    uint64_t lodsq_pairs,native_faults,stepped_faults;
};
static struct lodsq_trailer lodsq_evidence;
_Static_assert(sizeof(lodsq_evidence)==64,"bounded additive query counts");
static int lodsq_dump(void) {
    lodsq_evidence.magic=UINT64_C(0x315153444f4c324c);
    lodsq_evidence.version=1;lodsq_evidence.bytes=sizeof(lodsq_evidence);
    return write_all(3,&lodsq_evidence,sizeof(lodsq_evidence));
}
static void lodsq_routes(void) {
    static const unsigned char prefixes[]={0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,
        0xf0,0xf2,0xf3,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};
    const unsigned char canonical[]={0x48,0xad};struct li2_decoded decoded;
    struct li2_tf_classification classification;
    need(!li2_decoder_decode(0x1000,canonical,2,&decoded)&&
         decoded.decode_status==LI2_VALID&&decoded.kind==LI2_NONE&&decoded.code==350&&
         decoded.length==2&&decoded.step_disposition==0&&
         li2_tf_entry_route(&decoded)==LI2_TF_ENTRY_PLAIN,1600);
    need(!li2_decoder_tf_classify(0x1000,canonical,2,&classification)&&
         classification.abi_version==1&&classification.pc==0x1000&&classification.next_pc==0x1002&&
         classification.code==350&&classification.length==2&&classification.policy==1&&
         classification.flow==LI2_TF_FALLTHROUGH&&classification.family==LI2_TF_INTEGER,1601);
    ++lodsq_evidence.route_checks;
    for(size_t i=0;i<sizeof(prefixes);i++) {
        unsigned char bytes[]={prefixes[i],0x48,0xad};
        need(!li2_decoder_decode(0x1000,bytes,3,&decoded)&&
             li2_tf_entry_route(&decoded)==LI2_TF_ENTRY_UNKNOWN,1602);
        need(!li2_decoder_tf_classify(0x1000,bytes,3,&classification)&&
             classification.abi_version==1&&classification.pc==0x1000&&
             !classification.policy&&!classification.flow&&!classification.family,1603);
        ++lodsq_evidence.route_checks;
    }
    need(lodsq_evidence.route_checks==28,1604);
}
static void lodsq_prepare(struct sample *s,unsigned index) {
    need(index<8,1605);s->id=3000+index;s->length=2;s->count=(index&1)?2:1;
    s->endpoint_int3=index&1;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1606);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1607);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-(s->count==2?1:2);
    s->pc=s->mapping+offset;s->expected_post=s->pc+2;
    s->source[offset]=0x48;s->source[offset+1]=0xad;
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0)&&
         !li2_decoder_decode(s->pc,(const void *)s->pc,2,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==350&&
         s->decoded.length==2&&s->decoded.next_pc==s->pc+2&&s->decoded.step_disposition==0&&
         li2_tf_entry_route(&s->decoded)==LI2_TF_ENTRY_PLAIN,1608);
    long data=dispatch(SYS_mmap,0,3*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(data>0,1609);data_page=(uintptr_t)data+PAGE;data_fault=data_page+PAGE;
}
static void lodsq_inputs(struct sample *s) {
    unsigned index=s->id-3000,geometry=index%4,df=index/4;
    static const size_t offsets[4]={64,3,DATA_BYTES-8,0};
    static const uint64_t rcx[4]={0,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x12345678ffffffff)};
    need(index<8&&!dispatch(SYS_mprotect,data_page,DATA_BYTES,PROT_READ|PROT_WRITE,0,0,0),1610);
    inputs(s);fixture_seed[6]=data_page+offsets[geometry];
    fixture_seed[0]=UINT64_C(0xdafefeed00332211)^index;fixture_seed[1]=rcx[geometry];
    fixture_input_flags=UINT64_C(0x247)|(df?UINT64_C(0x400):0);
    if(s==&negative_sample) {
        need(lodsq_control>=1&&lodsq_control<=4,1611);
        fixture_seed[6]=data_fault-(lodsq_control>=3?4:0);
    }
    need(!dispatch(SYS_mprotect,data_page,DATA_BYTES,PROT_READ,0,0,0)&&
         actual_protection(data_page,0)==PROT_READ&&
         actual_protection(data_page-1,0)==PROT_NONE&&actual_protection(data_fault,0)==PROT_NONE,1612);
    struct li2_write_registers r;struct li2_write_footprint f;
    memcpy(r.gpr,fixture_seed,sizeof(r.gpr));
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&r.fs_base,0,0,0,0)&&
         !RAW(SYS_arch_prctl,ARCH_GET_GS,&r.gs_base,0,0,0,0),1613);
    need(!li2_decoder_write_footprint(s->pc,s->decoded.bytes,2,&r,&f)&&
         f.abi_version==1&&f.policy==LI2_WRITE_NONE&&!f.first&&!f.end&&
         f.pc==s->pc&&f.next_pc==s->pc+2&&f.code==350&&f.length==2,1614);
    ++lodsq_evidence.footprint_checks;
}
static void lodsq_effects(struct sample *s) {
    const struct li2_step_owner *o=&s->owner.step;
    unsigned index=s->id-3000,df=index/4;
    need(index<8&&s->length==2&&s->count==((index&1)?2U:1U)&&
         s->pc==s->mapping+PAGE-((index&1)?1:2)&&s->decoded.code==350&&
         s->owner.classification.policy==1&&s->owner.classification.flow==LI2_TF_FALLTHROUGH&&
         s->owner.classification.family==LI2_TF_INTEGER&&s->owner.actual_post_pc==s->pc+2,1615);
    for(unsigned which=0;which<2;which++) {
        const struct state *before=which?&s->step_before:&s->native_before;
        const struct state *after=which?&s->step_endpoint:&s->native_after;
        uintptr_t rsi=(uintptr_t)before->frame.greg[REG_RSI];
        need(rsi>=data_page&&rsi<=data_page+DATA_BYTES-8,1616);
        uint64_t expected=word(before->data+rsi-data_page);
        need(expected!=(uint64_t)before->frame.greg[REG_RAX]&&
             (uint64_t)after->frame.greg[REG_RAX]==expected&&
             (uint64_t)after->frame.greg[REG_RSI]==rsi+(df?(uint64_t)-8:8),1617);
        for(unsigned r=0;r<16;r++)if(r!=0&&r!=6)
            need(before->frame.greg[regs[r]]==after->frame.greg[regs[r]],1618);
        compare_memory(before,after,1619);
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*which],s->actual_fp[2*which+1],xsave_bytes),1620);
        need(s->live[2*which].rflags==s->live[2*which+1].rflags,1621);
    }
    need(s->initial_flags==fixture_input_flags&&s->post_flags==s->initial_flags&&
         o->before.fp_bytes==o->after.fp_bytes&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),1622);
    ++lodsq_evidence.lodsq_pairs;
}
static void lodsq_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    need(s==&negative_sample&&control==1&&lodsq_control>=1&&lodsq_control<=4&&
         s->decoded.code==350&&s->native_fault&&o->phase==LI2_STEP_FAILED&&
         o->first_error==LI2_STEP_FOREIGN_EVENT&&!o->trace_seen&&
         !s->native_complete&&!s->step_endpoint_seen&&!s->owner.continuation_started&&
         !s->owner.continuation_complete,1623);
    for(unsigned r=0;r<16;r++)need(
        s->native_before.frame.greg[regs[r]]==s->native_after.frame.greg[regs[r]]&&
        s->native_before.frame.greg[regs[r]]==s->step_before.frame.greg[regs[r]]&&
        s->step_before.frame.greg[regs[r]]==o->before.greg[regs[r]]&&
        o->before.greg[regs[r]]==o->after.greg[regs[r]],1624);
    need(s->native_before.frame.greg[REG_RIP]==(greg_t)s->pc&&
         s->native_after.frame.greg[REG_RIP]==(greg_t)s->pc&&
         o->before.greg[REG_RIP]==(greg_t)s->pc&&o->after.greg[REG_RIP]==(greg_t)s->pc&&
         o->signal_address==data_fault&&o->after.greg[REG_ERR]==4&&o->after.greg[REG_TRAPNO]==14,1625);
    need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
         (uint64_t)o->before.greg[REG_EFL]==(fixture_input_flags|LI2_STEP_RF)&&
         (uint64_t)o->after.greg[REG_EFL]==(fixture_input_flags|LI2_STEP_RF|LI2_STEP_TF),1626);
    const struct li2_step_frame *frames[]={&s->native_before.frame,&s->native_after.frame,
        &s->step_before.frame,&o->before,&o->after};
    for(unsigned i=0;i<5;i++)need(frames[i]->initialized==frames[i]->fp_bytes&&
        frames[i]->fp_bytes==frames[0]->fp_bytes&&frames[i]->mask==mask&&
        frames[i]->greg[REG_CSGSFS]==frames[0]->greg[REG_CSGSFS]&&
        !memcmp(frames[i]->fp,frames[0]->fp,frames[0]->fp_bytes),1627);
    compare_memory(&s->native_before,&s->native_after,1628);
    compare_memory(&s->native_before,&s->step_before,1629);
    need(!memcmp((void *)subject,s->step_before.stack,SUBJECT_BYTES)&&
         !memcmp((void *)data_page,s->step_before.data,DATA_BYTES)&&
         !memcmp((void *)s->mapping,s->source,sizeof(s->source)),1630);
    unsigned long fs=0,gs=0;
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&fs,0,0,0,0)&&
         !RAW(SYS_arch_prctl,ARCH_GET_GS,&gs,0,0,0,0)&&
         s->native_before.fs==fs&&s->native_after.fs==fs&&s->step_before.fs==fs&&
         s->native_before.gs==gs&&s->native_after.gs==gs&&s->step_before.gs==gs,1631);
    s->live[2]=fixture_live_before;memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);
    need(s->live[2].started==1&&s->live[2].complete==1&&!s->live[2].reserved&&
         !memcmp(s->live[0].gpr,s->live[2].gpr,sizeof(s->live[0].gpr))&&
         s->live[0].rflags==s->live[2].rflags&&
         !memcmp(s->live[0].selectors,s->live[2].selectors,sizeof(s->live[0].selectors))&&
         !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes)&&
         !memcmp(s->actual_fp[0],s->actual_fp[2],xsave_bytes),1632);
    ++lodsq_evidence.native_faults;++lodsq_evidence.stepped_faults;
    /* Every original native/fault-frame/whole-memory/revocation predicate. */
    failure(context,o);need(lodsq_dump(),1633);
}
/* Original pair protocol, only additive inputs/failure/effect hooks differ. */
static void lodsq_pair(struct sample *s) {
    current=s;fixture_target=s->pc;lodsq_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    lodsq_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,lodsq_failure},continue_closed};
    int error=s->selftest?li2_step_arm(&s->owner.step,&session,&hooks.step,&request,1):
                         li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();
    need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);lodsq_effects(s);need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(lodsq_evidence)<16*1024*1024,"original bounded complete record");
    need(stack[0]<128,1634);const char *const *env=(const void *)(stack+stack[0]+2);
    const char prefix[]="LI2_LODSQ_CASE=";const char *choice=0;
    for(size_t i=0;env[i];i++) {
        need(i<1024,1635);
        if(length(env[i])>=sizeof(prefix)-1&&!memcmp(env[i],prefix,sizeof(prefix)-1)) {
            need(!choice,1636);choice=env[i]+sizeof(prefix)-1;
        }
    }
    if(!choice)return li2_unchanged_generic_fixture_main(stack);
    need(stack[0]==1,1637);
    if(same(choice,"positive"))lodsq_control=0;
    else if(same(choice,"none-df0"))lodsq_control=1;
    else if(same(choice,"none-df1"))lodsq_control=2;
    else if(same(choice,"split-df0"))lodsq_control=3;
    else if(same(choice,"split-df1"))lodsq_control=4;
    else die(1638);
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=LODSQ_PAIRS;
    setup(stack);control=lodsq_control?1:0;result.control=lodsq_control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);lodsq_routes();
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(lodsq_control) {
        /* Fault cases use wholly page-ending code; the 8 positives include
           four real two-page 48/ad fetches and four wholly page-ending ones. */
        lodsq_prepare(&negative_sample,(lodsq_control%2==0)?4:0);
        lodsq_pair(&negative_sample);die(1639);
    }
    for(unsigned i=0;i<8;i++){lodsq_prepare(&samples[i+1],i);lodsq_pair(&samples[i+1]);}
    need(result.completed==LODSQ_PAIRS&&lodsq_evidence.lodsq_pairs==8&&
         lodsq_evidence.footprint_checks==16&&!lodsq_evidence.native_faults&&
         !lodsq_evidence.stepped_faults&&dump()&&lodsq_dump(),1640);
    output("LI2_LODSQ_TF_PASS pairs=9 lodsq=8 selftest=1 old_refusal_bytes=47 route_checks=28 footprint_checks=16 full_state=9 full_memory=9 live_endpoints=9\n");
    return 0;
}
