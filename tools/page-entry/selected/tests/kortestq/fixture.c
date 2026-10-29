/* Exact KORTESTQ: all eight mask registers in both source roles.
   Complete original native/TF flags and state remain compared. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#include "write_footprint.h"
#define VTN_PROMOTED_INDICES 0,1,2,3,4,5,6,7,11,12
#include "tests/vptestnmb_family/promotions.inc"
#ifndef KORTESTQ_GROUP
#error KORTESTQ_GROUP must select a bounded cohort
#endif
_Static_assert(KORTESTQ_GROUP>=0&&KORTESTQ_GROUP<5,"five bounded KORTESTQ cohorts");
_Static_assert(PAIRS==21,"unchanged original record storage");
#define VPB_COUNT 16U
#define KORTESTQ_FIRST (16U*KORTESTQ_GROUP)
#define VPB_PAIRS (VPB_COUNT+1)
#define VPB_ACTIVE UINT64_C(0xe7)
unsigned char vpb_vectors[32][64] __attribute__((aligned(64)));
uint64_t vpb_masks[8] __attribute__((aligned(64)));
struct vpb_cpuid { uint64_t leaf,subleaf,a,b,c,d; };
static struct {
    uint64_t magic,version,bytes,group,query_count,checked,xcr0,xsave_bytes;
    struct vpb_cpuid basic[4],component[64];
    uint64_t ids[17],bv[17][10];
} vpb_observations;

static void vpb_cpuid(struct vpb_cpuid *out,unsigned leaf,unsigned subleaf) {
    unsigned a=leaf,b,c=subleaf,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));
    *out=(struct vpb_cpuid){leaf,subleaf,a,b,c,d};++vpb_observations.query_count;
}
static void vpb_layout(void) {
    vpb_observations.magic=UINT64_C(0x315852425056324c); /* existing17-pair vector layout */
    vpb_observations.version=1;vpb_observations.bytes=sizeof(vpb_observations);
    vpb_observations.group=KORTESTQ_GROUP;vpb_observations.xcr0=fixture_xcr0;
    vpb_observations.xsave_bytes=xsave_bytes;
    vpb_cpuid(&vpb_observations.basic[0],0,0);
    need(vpb_observations.basic[0].a>=13,1100);
    vpb_cpuid(&vpb_observations.basic[1],1,0);
    vpb_cpuid(&vpb_observations.basic[2],7,0);
    vpb_cpuid(&vpb_observations.basic[3],13,0);
    need((vpb_observations.basic[1].c&UINT64_C(0x1c000000))==UINT64_C(0x1c000000)&&
         (vpb_observations.basic[2].b&UINT64_C(0xc0010100))==UINT64_C(0xc0010100),1101); /* actual F/BW/VL and BMI2 */
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
    need(s->id>=9000+KORTESTQ_FIRST&&s->id<9000+KORTESTQ_FIRST+VPB_COUNT,1106);
    return &vpb_cases[s->id-9000];
}
static void vpb_inputs(struct sample *s) {
    inputs(s);vpb_seed();const struct vpb_case *v=vpb_case(s);
    need(v->role<16&&v->first<8&&v->second<8&&
         (v->first!=v->second||v->first_value==v->second_value),1132);
    vpb_masks[v->first]=v->first_value;vpb_masks[v->second]=v->second_value;
    fixture_input_flags=v->initial_flags;
}
static void vpb_prepare(struct sample *s,unsigned index) {
    need(index<VPB_COUNT,1107);const struct vpb_case *v=&vpb_cases[KORTESTQ_FIRST+index];
    s->id=9000+KORTESTQ_FIRST+index;s->length=sizeof(v->encoding);
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
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==1935&&
         s->decoded.length==s->length&&!memcmp(s->decoded.bytes,v->encoding,s->length),1112);
}
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
                          const unsigned char *after,size_t n,int kernel) {
    (void)s;vpb_inputs_observed(before,n,kernel);
    uint64_t a=vpb_header(before,n,kernel),b=vpb_header(after,n,kernel);
    need(a==b,1120);
    for(size_t i=0;i<n;i++)need(after[i]==before[i],1121);
}
struct vpc_query { uint64_t attempted,result,id,lane; struct li2_write_registers before; struct li2_write_footprint value; };
static struct { uint64_t magic,version,bytes,group,checked,refusals,reserved[2]; struct vpc_query rows[16][2]; } vpc_queries;
_Static_assert(sizeof(struct vpc_query)==224&&sizeof(vpc_queries)==7232,"complete query trailer");
static void vpc_query(struct sample *s,unsigned index,unsigned lane_index) {
    need(index<VPB_COUNT&&lane_index<2,1190);struct vpc_query *q=&vpc_queries.rows[index][lane_index];
    need(!q->attempted,1191);q->attempted=1;q->id=s->id;q->lane=lane_index;
    const struct state *before=lane_index?&s->step_before:&s->native_before;
    for(unsigned r=0;r<16;r++)q->before.gpr[r]=(uint64_t)before->frame.greg[regs[r]];
    q->before.fs_base=before->fs;q->before.gs_base=before->gs;
    q->result=li2_decoder_write_footprint(s->pc,s->decoded.bytes,s->length,&q->before,&q->value);
    need(!q->result&&q->value.abi_version==1&&q->value.policy==LI2_WRITE_NONE&&
         q->value.code==1935&&q->value.length==5&&q->value.pc==s->pc&&
         q->value.next_pc==s->pc+5&&!q->value.first&&!q->value.end,1192);
    ++vpc_queries.checked;
}
static void vpb_effects(struct sample *s,unsigned index) {
    need(index<VPB_PAIRS&&vpb_observations.checked==index,1122);
    if(!s->selftest)need(s->owner.classification.policy==1&&s->owner.classification.code==1935&&
        s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_INTEGER&&
        s->length==5&&s->expected_post==s->pc+5&&!memcmp(s->decoded.bytes,vpb_case(s)->encoding,5),1123);
    const struct li2_step_frame *frames[]={&s->native_before.frame,&s->native_after.frame,
        &s->step_before.frame,&s->owner.step.before,&s->owner.step.after,&s->step_endpoint.frame};
    for(unsigned i=0;i<6;i++)vpb_observations.bv[index][i]=vpb_header(frames[i]->fp,frames[i]->fp_bytes,1);
    for(unsigned i=0;i<4;i++)vpb_observations.bv[index][6+i]=vpb_header(s->actual_fp[i],xsave_bytes,0);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        uint64_t defined=0;
        if(!s->selftest) {
            const struct vpb_case *v=vpb_case(s);
            uint64_t first=word(before->frame.fp+vpb_observations.component[5].b+8*v->first);
            uint64_t second=word(before->frame.fp+vpb_observations.component[5].b+8*v->second);
            uint64_t value=first|second;
            defined=(value==UINT64_MAX?1:0)|(value?0:0x40);
            need(first==v->first_value&&second==v->second_value&&
                 value==v->expected_or&&defined==v->defined_flags,1133);
        }
        for(unsigned r=0;r<16;r++) {
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
                 s->live[2*l].gpr[r]==fixture_seed[r]&&
                 (uint64_t)after->frame.greg[regs[r]]==fixture_seed[r]&&
                 s->live[2*l+1].gpr[r]==fixture_seed[r],1124);
        }
        if(!s->selftest) {
            uint64_t initial=s->live[2*l].rflags,actual=s->live[2*l+1].rflags;
            need(initial==vpb_case(s)->initial_flags&&
                 actual==((initial&~UINT64_C(0x8d5))|defined),1126);
        }
        compare_memory(before,after,1125);
        if(!s->selftest)vpc_query(s,index-1,l);
        vpb_fp_effect(s,before->frame.fp,after->frame.fp,before->frame.fp_bytes,1);
        vpb_fp_effect(s,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,0);
    }
    vpb_fp_effect(s,s->owner.step.before.fp,s->owner.step.after.fp,s->owner.step.before.fp_bytes,1);
    if(s->selftest)need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,1126);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,1127);
    need(actual_protection(s->expected_post,0)==PROT_READ,1128);
    vpb_observations.ids[index]=s->id;++vpb_observations.checked;
}
static void vpb_pair(struct sample *s,unsigned index) {
    current=s;fixture_target=s->pc;vpb_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    vpb_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,failure},continue_closed};
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
static unsigned promoted_count;
static void promoted_encoding(const struct vpb_refusal *v) {
    static const unsigned char exact[]={0x62,0xb2,0x75,0x40,0x26,0xc1};
    need(v->n==sizeof(exact)&&!memcmp(v->b,exact,sizeof(exact))&&
         !result.decoder_result&&refused_last.abi_version==1&&
         refused_last.pc==0x1000&&refused_last.next_pc==0x1006&&
         refused_last.policy==1&&refused_last.flow==LI2_TF_FALLTHROUGH&&
         refused_last.family==LI2_TF_SIMD&&refused_last.code==2785&&refused_last.length==6,1194);
    struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
    need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
         footprint.abi_version==1&&footprint.policy==LI2_WRITE_NONE&&
         footprint.code==2785&&footprint.length==6&&footprint.pc==0x1000&&
         footprint.next_pc==0x1006&&!footprint.first&&!footprint.end,1195);
    ++promoted_count;
}
static void vpb_refusals(void) {
    for(size_t i=0;i<sizeof(vpb_refused)/sizeof(vpb_refused[0]);i++) {
        const struct vpb_refusal *v=&vpb_refused[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        if(vtn_is_promoted(i)) {
            vtn_promote(i,v->b,v->n,result.decoder_result,&refused_last);
        } else if(i==17) {
            promoted_encoding(v);
        } else {
            need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
                 !refused_last.policy&&!refused_last.flow&&!refused_last.family,1140+(unsigned)i);
            struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
            need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
                 footprint.abi_version==1&&!footprint.policy&&!footprint.first&&!footprint.end,1193);
            ++vpc_queries.refusals;++result.refusals;
        }
    }
    result.failed_refusal=SIZE_MAX;
}
static void vpx_refusals(void) {
    for(size_t i=0;i<sizeof(vpx_refused)/sizeof(vpx_refused[0]);i++) {
        const struct vpx_refusal *v=&vpx_refused[i];result.failed_refusal=47+73+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1200+(unsigned)i);
        struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
        need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
             footprint.abi_version==1&&!footprint.policy&&!footprint.first&&!footprint.end,1238);
        ++vpc_queries.refusals;++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
static void bzhi_refusals(void) {
    for(size_t i=0;i<sizeof(bzhi_refused)/sizeof(bzhi_refused[0]);i++) {
        const struct bzhi_refusal *v=&bzhi_refused[i];result.failed_refusal=47+73+37+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1300+(unsigned)i);
        struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
        for(unsigned r=0;r<16;r++)registers.gpr[r]=UINT64_C(0x1234567800000000)+r*16;
        registers.fs_base=0x12340000;registers.gs_base=0x56780000;
        need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
             footprint.abi_version==1&&!footprint.policy&&!footprint.first&&!footprint.end,1332);
        ++vpc_queries.refusals;++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
static void kortestq_refusals(void) {
    for(size_t i=0;i<sizeof(kortestq_refused)/sizeof(kortestq_refused[0]);i++) {
        const struct kortestq_refusal *v=&kortestq_refused[i];result.failed_refusal=47+73+37+31+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1400+(unsigned)i);
        struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
        for(unsigned r=0;r<16;r++)registers.gpr[r]=UINT64_C(0x1234567800000000)+r*16;
        registers.fs_base=0x12340000;registers.gs_base=0x56780000;
        need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
             footprint.abi_version==1&&!footprint.policy&&!footprint.first&&!footprint.end,1430);
        ++vpc_queries.refusals;++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(vtn_promotions)+sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(vpb_observations)+sizeof(vpc_queries)<16*1024*1024,"unchanged complete record cap");
    _Static_assert(sizeof(vpb_observations)==4824,"literal trailer extent");
    _Static_assert(sizeof(vpx_refused)/sizeof(vpx_refused[0])==37,"closed VPXORQ neighbors");
    _Static_assert(sizeof(vpb_refused)/sizeof(vpb_refused[0])==73,"closed supplied neighbors");
    _Static_assert(sizeof(bzhi_refused)/sizeof(bzhi_refused[0])==31,"closed BZHI neighbors");
    _Static_assert(sizeof(kortestq_refused)/sizeof(kortestq_refused[0])==29,"closed KORTESTQ neighbors");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=VPB_PAIRS;
    need(stack[0]==1,1180);setup(stack);need(!control,1181);vpb_layout();
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47&&failed==SIZE_MAX&&!decoder_result,1182);
    vpc_queries.magic=UINT64_C(0x315158565056324c);vpc_queries.version=1;
    vpc_queries.bytes=sizeof(vpc_queries);vpc_queries.group=KORTESTQ_GROUP;
    vpb_refusals();need(result.refusals==109&&vpc_queries.refusals==62&&promoted_count==1,1183);
    vpx_refusals();need(result.refusals==146&&vpc_queries.refusals==99&&promoted_count==1,1239);
    bzhi_refusals();need(result.refusals==177&&vpc_queries.refusals==130&&promoted_count==1,1333);
    kortestq_refusals();need(result.refusals==206&&vpc_queries.refusals==159&&promoted_count==1,1431);
    vtn_promotions_complete();
    vpb_seed();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    vpb_effects(&samples[0],0);
    for(unsigned i=0;i<VPB_COUNT;i++){vpb_prepare(&samples[i+1],i);vpb_pair(&samples[i+1],i+1);}
    need(result.completed==VPB_PAIRS&&vpb_observations.checked==VPB_PAIRS&&dump()&&
         vpc_queries.checked==2*VPB_COUNT&&write_all(3,&vpb_observations,sizeof(vpb_observations))&&
         write_all(3,&vpc_queries,sizeof(vpc_queries))&&
         write_all(3,&vtn_promotions,sizeof(vtn_promotions)),1184);
    static const char *const passed[5]={
        "LI2_KORTESTQ_TF_PASS group=0 pairs=17 kortestq=16 selftest=1 old_refusal_bytes=177 new_refusal_bytes=29 promoted_encoding_checks=1 promoted_footprint_queries=1 footprint_queries=32 full_state=17 full_memory=17 live_endpoints=17 vtn_typed_promotions=10 vtn_supplied_none_queries=10\n",
        "LI2_KORTESTQ_TF_PASS group=1 pairs=17 kortestq=16 selftest=1 old_refusal_bytes=177 new_refusal_bytes=29 promoted_encoding_checks=1 promoted_footprint_queries=1 footprint_queries=32 full_state=17 full_memory=17 live_endpoints=17 vtn_typed_promotions=10 vtn_supplied_none_queries=10\n",
        "LI2_KORTESTQ_TF_PASS group=2 pairs=17 kortestq=16 selftest=1 old_refusal_bytes=177 new_refusal_bytes=29 promoted_encoding_checks=1 promoted_footprint_queries=1 footprint_queries=32 full_state=17 full_memory=17 live_endpoints=17 vtn_typed_promotions=10 vtn_supplied_none_queries=10\n",
        "LI2_KORTESTQ_TF_PASS group=3 pairs=17 kortestq=16 selftest=1 old_refusal_bytes=177 new_refusal_bytes=29 promoted_encoding_checks=1 promoted_footprint_queries=1 footprint_queries=32 full_state=17 full_memory=17 live_endpoints=17 vtn_typed_promotions=10 vtn_supplied_none_queries=10\n",
        "LI2_KORTESTQ_TF_PASS group=4 pairs=17 kortestq=16 selftest=1 old_refusal_bytes=177 new_refusal_bytes=29 promoted_encoding_checks=1 promoted_footprint_queries=1 footprint_queries=32 full_state=17 full_memory=17 live_endpoints=17 vtn_typed_promotions=10 vtn_supplied_none_queries=10\n",
    };
    output(passed[KORTESTQ_GROUP]);
    return 0;
}
