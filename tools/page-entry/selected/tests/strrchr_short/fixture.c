/* Three exact short-return leaves, independently compared at original PC. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "write_footprint.h"
#define VPE_PROMOTED_INDICES 0,1,2,3
#define VPE_FIRST_ENCODING 1
#include "tests/vpcmpeqb_register/promotions.inc"
#include "tests/bmi1_register/promotions.inc"
#ifndef SHORT_GROUP
#error SHORT_GROUP must select a bounded cohort
#endif
#include "cases.inc"
_Static_assert(SHORT_GROUP>=0&&SHORT_GROUP<3,"three closed cohorts");
_Static_assert(PAIRS==21,"unchanged original record storage");
#define VPB_ACTIVE UINT64_C(0xe7)
unsigned char vpb_vectors[32][64] __attribute__((aligned(64)));
uint64_t vpb_masks[8] __attribute__((aligned(64)));
struct vpb_cpuid { uint64_t leaf,subleaf,a,b,c,d; };
static struct {
    uint64_t magic,version,bytes,group,query_count,checked,xcr0,xsave_bytes;
    struct vpb_cpuid basic[4],component[64];
    uint64_t ids[21],bv[21][10];
} vpb_observations;

static void vpb_cpuid(struct vpb_cpuid *out,unsigned leaf,unsigned subleaf) {
    unsigned a=leaf,b,c=subleaf,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));
    *out=(struct vpb_cpuid){leaf,subleaf,a,b,c,d};++vpb_observations.query_count;
}
static void vpb_layout(void) {
    vpb_observations.magic=UINT64_C(0x315452485356324c);
    vpb_observations.version=1;vpb_observations.bytes=sizeof(vpb_observations);
    vpb_observations.group=SHORT_GROUP;vpb_observations.xcr0=fixture_xcr0;
    vpb_observations.xsave_bytes=xsave_bytes;
    vpb_cpuid(&vpb_observations.basic[0],0,0);
    need(vpb_observations.basic[0].a>=13,1100);
    vpb_cpuid(&vpb_observations.basic[1],1,0);
    vpb_cpuid(&vpb_observations.basic[2],7,0);
    vpb_cpuid(&vpb_observations.basic[3],13,0);
    need((vpb_observations.basic[1].c&UINT64_C(0x1c000000))==UINT64_C(0x1c000000)&&
         (vpb_observations.basic[2].b&UINT64_C(0x40010008))==UINT64_C(0x40010008),1101);
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
    need(s->id>=8000+20*SHORT_GROUP&&s->id<8000+20*SHORT_GROUP+VPB_COUNT,1106);
    return &vpb_cases[SHORT_GROUP][s->id-8000-20*SHORT_GROUP];
}
static void vpb_inputs(struct sample *s) {
    inputs(s);vpb_seed();const struct vpb_case *v=vpb_case(s);
    need(v->pattern<(SHORT_GROUP==0?3U:4U),1132);
    if(SHORT_GROUP==0) {
        for(unsigned j=0;j<64;j++) {
            unsigned char x=(unsigned char)(j*13+7);
            vpb_vectors[17][j]=x;
            vpb_vectors[16][j]=(v->input&(UINT64_C(1)<<j))?x:(unsigned char)(x^0xa5);
        }
        vpb_masks[1]=~v->expected;
    } else if(SHORT_GROUP==1) {vpb_masks[1]=v->input;fixture_seed[0]=~v->input;}
    else fixture_seed[6]=v->input;
}
static void vpb_prepare(struct sample *s,unsigned index) {
    need(index<VPB_COUNT,1107);const struct vpb_case *v=&vpb_cases[SHORT_GROUP][index];
    s->id=8000+20*SHORT_GROUP+index;s->length=sizeof(vpb_encoding);
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1108);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1109);
    need(v->tail>=1&&v->tail<=s->length,1110);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<s->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,vpb_encoding,s->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1111);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==SHORT_CODE&&
         s->decoded.length==s->length&&!memcmp(s->decoded.bytes,vpb_encoding,s->length),1112);
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
    vpb_inputs_observed(before,n,kernel);uint64_t a=vpb_header(before,n,kernel),b=vpb_header(after,n,kernel);
    need(a==b,1120); /* Other K and ZMM values keep all seeded components non-init. */
    size_t at=vpb_observations.component[5].b+8;uint64_t expected=word(before+at);
    if(!s->selftest&&SHORT_GROUP==0) {
        expected=0;
        for(unsigned j=0;j<64;j++)if(before[vpb_offset(17,j)]==before[vpb_offset(16,j)])expected|=UINT64_C(1)<<j;
        need(expected==vpb_case(s)->expected&&word(before+at)!=expected,1133);
    }
    if(!s->selftest&&SHORT_GROUP==1)need(expected==vpb_case(s)->input,1134);
    for(size_t i=0;i<n;i++) {
        unsigned char v=before[i];
        if(!s->selftest&&SHORT_GROUP==0&&i>=at&&i<at+8)v=(unsigned char)(expected>>(8*(i-at)));
        need(after[i]==v,1121);
    }
}
static void vpb_effects(struct sample *s,unsigned index) {
    need(index<VPB_PAIRS&&vpb_observations.checked==index,1122);
    if(!s->selftest)need(s->owner.classification.policy==1&&s->owner.classification.code==SHORT_CODE&&
        s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==SHORT_FAMILY&&
        s->length==sizeof(vpb_encoding)&&s->expected_post==s->pc+sizeof(vpb_encoding)&&
        !memcmp(s->decoded.bytes,vpb_encoding,sizeof(vpb_encoding)),1123);
    const struct li2_step_frame *frames[]={&s->native_before.frame,&s->native_after.frame,
        &s->step_before.frame,&s->owner.step.before,&s->owner.step.after,&s->step_endpoint.frame};
    for(unsigned i=0;i<6;i++)vpb_observations.bv[index][i]=vpb_header(frames[i]->fp,frames[i]->fp_bytes,1);
    for(unsigned i=0;i<4;i++)vpb_observations.bv[index][6+i]=vpb_header(s->actual_fp[i],xsave_bytes,0);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++) {
            uint64_t expected=fixture_seed[r];
            if(!s->selftest&&((SHORT_GROUP==1&&r==0)||(SHORT_GROUP==2&&r==6)))expected=vpb_case(s)->expected;
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
                 s->live[2*l].gpr[r]==fixture_seed[r]&&
                 (uint64_t)after->frame.greg[regs[r]]==expected&&s->live[2*l+1].gpr[r]==expected,1124);
        }
        compare_memory(before,after,1125);
        vpb_fp_effect(s,before->frame.fp,after->frame.fp,before->frame.fp_bytes,1);
        vpb_fp_effect(s,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,0);
    }
    vpb_fp_effect(s,s->owner.step.before.fp,s->owner.step.after.fp,s->owner.step.before.fp_bytes,1);
    if(s->selftest||SHORT_GROUP!=2)need(s->initial_flags==s->post_flags&&
        s->live[0].rflags==s->live[1].rflags&&s->live[2].rflags==s->live[3].rflags,1126);
    else {
        const struct vpb_case *v=vpb_case(s);
        need(v->expected==((v->input-1)^v->input),1135);
        uint64_t defined=(v->expected>>63?0x80:0)|(v->input==0?1:0);
        /* Independently assert only defined CF/SF/ZF/OF. The unchanged compare()
           still requires the entire actual native/TF flags including AF/PF. */
        need((s->post_flags&UINT64_C(0x8c1))==defined&&
             s->live[1].rflags==s->post_flags&&s->live[3].rflags==s->post_flags,1136);
    }
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
#include "tests/kmovq/register_promotions.inc"
#include "tests/kmovq_register/promotions32.inc"
static void old_kmov_refusals(void) {
    for(size_t i=0;i<sizeof(vpb_refused)/sizeof(vpb_refused[0]);i++) {
        const struct vpb_refusal *v=&vpb_refused[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        if(i<5){kmr_promote(v,(unsigned)i);continue;}
        if(kd32_is_promoted(i)) {
            kd32_promote(i,v->b,v->n,result.decoder_result,&refused_last);
            continue;
        }
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1140+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
static void vpb_refusals(void) {
    old_kmov_refusals();
    for(size_t i=0;i<SHORT_EXTRA_REFUSALS;i++) {
        const struct vpb_refusal *v=&short_refused[i];result.failed_refusal=80+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        if(bmi_is_promoted(i)) {
            bmi_promote(i,v->b,v->n,result.decoder_result,&refused_last);
            continue;
        } else if(vpe_is_promoted(i)) {
            vpe_promote(i,v->b,v->n,result.decoder_result,&refused_last);
            continue;
        }
        if(i==9||i==10){kmr_promote(v,(unsigned)i-4);continue;}
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1250+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(kd32_promotions)+sizeof(bmi_promotions)+sizeof(vpe_promotions)+sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(vpb_observations)<16*1024*1024,"unchanged complete record cap");
    _Static_assert(sizeof(vpb_observations)==5176,"literal trailer extent");
    _Static_assert(sizeof(vpb_refused)/sizeof(vpb_refused[0])==33,"closed supplied neighbors");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=VPB_PAIRS;
    need(stack[0]==1,1180);setup(stack);need(!control,1181);vpb_layout();
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47&&failed==SIZE_MAX&&!decoder_result,1182);
    vpb_refusals();vpe_promotions_complete();bmi_promotions_complete();kd32_promotions_complete();need(result.refusals==66+SHORT_EXTRA_REFUSALS&&kmr_promoted==7,1183);
    vpb_seed();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    vpb_effects(&samples[0],0);
    for(unsigned i=0;i<VPB_COUNT;i++){vpb_prepare(&samples[i+1],i);vpb_pair(&samples[i+1],i+1);}
    need(result.completed==VPB_PAIRS&&vpb_observations.checked==VPB_PAIRS&&dump()&&
         write_all(3,&vpb_observations,sizeof(vpb_observations))&&
             write_all(3,&vpe_promotions,sizeof(vpe_promotions))&&write_all(3,&bmi_promotions,sizeof(bmi_promotions))&&
             write_all(3,&kd32_promotions,sizeof(kd32_promotions)),1184);
    output(SHORT_GROUP==0?"LI2_SHORT_LEAF_PASS group=0 pairs=19 promoted_encoding_checks=7 promoted_footprint_queries=7 vpe_typed_promotions=4 vpe_supplied_none_queries=4 bmi_typed_promotions=2 bmi_supplied_none_queries=2 kd32_typed_promotions=1 kd32_supplied_none_queries=1\n":SHORT_GROUP==1?"LI2_SHORT_LEAF_PASS group=1 pairs=21 promoted_encoding_checks=7 promoted_footprint_queries=7 vpe_typed_promotions=4 vpe_supplied_none_queries=4 bmi_typed_promotions=2 bmi_supplied_none_queries=2 kd32_typed_promotions=1 kd32_supplied_none_queries=1\n":"LI2_SHORT_LEAF_PASS group=2 pairs=21 promoted_encoding_checks=7 promoted_footprint_queries=7 vpe_typed_promotions=4 vpe_supplied_none_queries=4 bmi_typed_promotions=2 bmi_supplied_none_queries=2 kd32_typed_promotions=1 kd32_supplied_none_queries=1\n");
    return 0;
}
