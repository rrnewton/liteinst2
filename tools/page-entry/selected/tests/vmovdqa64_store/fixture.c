/* Canonical EVEX512 W1 aligned VMOVDQA64 store/reverse-copy. Literal semantics,
   unchanged complete native/TF comparisons and genuine failed writes. */
#ifndef VQA64S_CODE
#define VQA64S_CODE 1838
#endif
#if VQA64S_CODE!=1838 && VQA64S_CODE!=1847
#error closed store family selector
#endif
#define fixture_main li2_unchanged_generic_fixture_main
static unsigned store_fault_error,qa_alignment_fault;
#include "common.inc"
#undef fixture_main
#include "write_footprint.h"
#define VPE_PROMOTED_INDICES 42
#define VPE_FIRST_ENCODING 0
#include "tests/vpcmpeqb_register/promotions.inc"
#include "write_footprint.h"
#include "tests/vmovdqu64_family/promotions.inc"
#include "tests/vmovdqu64_family/promotions256.inc"
#if VQA64S_CODE==1838
#include "cases.inc"
#else
#include "cases1847.inc"
#endif
#define VDQ_STORE_PROMOTED_INDICES 16,5
#include "tests/vmovdqu64_store/promotions.inc"
#include "tests/vmovdqu128_store/refusals.inc"
#include "write_footprint.h"
#include "tests/vmovdqu128/promotions.inc"
#include "tests/vpcmpeqb_memory/promotions.inc"
#ifndef VQA64S_GROUP
#error VQA64S_GROUP must select a bounded cohort
#endif
#if VQA64S_CODE==1838
#define VPB_GROUPS 10
#define VPB_TOTAL 161U
#define VPB_ID 14000U
#define VPB_FAULT_ID 14200U
#define VPB_FAULTS 8U
#define VPB_PP 0xfd
#define VPB_OBSERVATIONS_MAGIC UINT64_C(0x315341363456324c)
#define VPB_QUERY_MAGIC UINT64_C(0x315741363456324c)
#define VPB_MEMORY_MAGIC UINT64_C(0x314d41363456324c)
#define VPB_RANGE_MAGIC UINT64_C(0x315241363456324c)
#define VPB_CONTROL "LI2_VQA64S_CONTROL="
#define VPB_LABEL "LI2_VMOVDQA64_STORE_TF_PASS"
#define VPB_REFUSALS "150"
#else
#define VPB_GROUPS 11
#define VPB_TOTAL 178U
#define VPB_ID 16000U
#define VPB_FAULT_ID 16200U
#define VPB_FAULTS 10U
#define VPB_PP 0xfe
#define VPB_OBSERVATIONS_MAGIC UINT64_C(0x315355363456324c)
#define VPB_QUERY_MAGIC UINT64_C(0x315755363456324c)
#define VPB_MEMORY_MAGIC UINT64_C(0x314d55363456324c)
#define VPB_RANGE_MAGIC UINT64_C(0x315255363456324c)
#define VPB_CONTROL "LI2_VQU64S_CONTROL="
#define VPB_LABEL "LI2_VMOVDQU64_STORE_TF_PASS"
#define VPB_REFUSALS "182"
#endif
#define VPB_START (VQA64S_GROUP==10?161U:16U*VQA64S_GROUP)
_Static_assert(VQA64S_GROUP>=0&&VQA64S_GROUP<VPB_GROUPS,"closed selected store cohort");
_Static_assert(PAIRS==21,"unchanged original record storage");
#define VPB_COUNT (16U+(VQA64S_GROUP>=9))
#define VPB_PAIRS (VPB_COUNT+1)
#define VPB_ACTIVE UINT64_C(0xe7)
unsigned char vpb_vectors[32][64] __attribute__((aligned(64)));
uint64_t vpb_masks[8] __attribute__((aligned(64)));
struct vpb_cpuid { uint64_t leaf,subleaf,a,b,c,d; };
static struct {
    uint64_t magic,version,bytes,group,query_count,checked,xcr0,xsave_bytes;
    struct vpb_cpuid basic[4],component[64];
    uint64_t ids[19],bv[19][10]; /* Keep old complete trailer storage. */
} vpb_observations;
static struct {
    uint64_t kind,checked,operand,address,prefix_bytes,owner_trace;
    uint64_t native_bv[2],owner_bv[2],live_bv[2];
} v64_fault;
static unsigned v64_fault_kind;

static void vpb_cpuid(struct vpb_cpuid *out,unsigned leaf,unsigned subleaf) {
    unsigned a=leaf,b,c=subleaf,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));
    *out=(struct vpb_cpuid){leaf,subleaf,a,b,c,d};++vpb_observations.query_count;
}
static void vpb_layout(void) {
    vpb_observations.magic=VPB_OBSERVATIONS_MAGIC;
    vpb_observations.version=1;vpb_observations.bytes=sizeof(vpb_observations);
    vpb_observations.group=VQA64S_GROUP;vpb_observations.xcr0=fixture_xcr0;
    vpb_observations.xsave_bytes=xsave_bytes;
    vpb_cpuid(&vpb_observations.basic[0],0,0);
    need(vpb_observations.basic[0].a>=13,1100);
    vpb_cpuid(&vpb_observations.basic[1],1,0);
    vpb_cpuid(&vpb_observations.basic[2],7,0);
    vpb_cpuid(&vpb_observations.basic[3],13,0);
    need((vpb_observations.basic[1].c&UINT64_C(0x1c000000))==UINT64_C(0x1c000000)&&
         (vpb_observations.basic[2].b&UINT64_C(0x40010000))==UINT64_C(0x40010000),1101);
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
/* Literal memory expectations never use a post-execution byte as an input. */
struct store_memory_row {
    uint64_t id,attempted[4],complete[4],pages[2],ea,failed,changed[2];
    unsigned char image[4][2][PAGE];
};
_Static_assert(sizeof(struct store_memory_row)==32888&&offsetof(struct store_memory_row,image)==120,"complete literal memory record layout");
static struct { uint64_t magic,version,bytes,checked,reserved[4];
    struct store_memory_row rows[18]; } store_memory;
struct store_region { uintptr_t page; };
static struct store_region store_regions[40];
static unsigned store_region_count;
static uintptr_t vqa64s_high,vqa64s_low,store_target,store_pages[2];
static unsigned store_index;
static uintptr_t store_restricted[2];
static int store_restricted_prot[2];
static unsigned store_restricted_count;
#if VQA64S_CODE==1838
static const struct vpb_case store_fault_cases[8]={
#define STORE_FAULT(n) {.name=n,.length=6,.tail=6,.dest=-1,.src=0,.kind=1,.base=7,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfd,0x48,0x7f,0x07}}
    STORE_FAULT("full-noaccess"),STORE_FAULT("full-readonly"),STORE_FAULT("cross-alignment"),
#undef STORE_FAULT
#define INDEX_FAULT(n) {.name=n,.length=7,.tail=7,.dest=-1,.src=0,.kind=1,.base=7,.index=1,.scale=2,.index_value=37,.encoding={0x62,0xf1,0xfd,0x48,0x7f,0x04,0x4f}}
    INDEX_FAULT("indexed-cross-alignment"),INDEX_FAULT("indexed-readonly"),
#undef INDEX_FAULT
    {.name="stack-readonly",.length=7,.tail=7,.dest=-1,.src=0,.kind=2,.base=4,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfd,0x48,0x7f,0x04,0x24}},
    {.name="base-source",.length=6,.tail=6,.dest=-1,.src=0,.kind=1,.base=7,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfd,0x48,0x7f,0x07}},
    {.name="rip-source",.length=10,.tail=10,.dest=-1,.src=0,.kind=3,.base=-1,.index=-1,.scale=1,.displacement=-3840,.encoding={0x62,0xf1,0xfd,0x48,0x7f,0x05,0x00,0xf1,0xff,0xff}}
};
#else
static const struct vpb_case store_fault_cases[10]={
#define STORE_FAULT(n) {.name=n,.length=6,.tail=6,.dest=-1,.src=0,.kind=1,.base=7,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x07}}
    STORE_FAULT("full-noaccess"),STORE_FAULT("full-readonly"),STORE_FAULT("cross-noaccess"),
#undef STORE_FAULT
#define INDEX_FAULT(n) {.name=n,.length=7,.tail=7,.dest=-1,.src=0,.kind=1,.base=7,.index=1,.scale=2,.index_value=37,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x04,0x4f}}
    {.name="cross-readonly",.length=6,.tail=6,.dest=-1,.src=0,.kind=1,.base=7,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x07}},
    INDEX_FAULT("indexed-readonly"),
#undef INDEX_FAULT
    {.name="stack-readonly",.length=7,.tail=7,.dest=-1,.src=0,.kind=2,.base=4,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x04,0x24}},
    {.name="base-source",.length=6,.tail=6,.dest=-1,.src=0,.kind=1,.base=7,.index=-1,.scale=1,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x07}},
    {.name="rip-source",.length=10,.tail=10,.dest=-1,.src=0,.kind=3,.base=-1,.index=-1,.scale=1,.displacement=-3840,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x05,0x00,0xf1,0xff,0xff}},
    {.name="indexed-cross-noaccess",.length=7,.tail=7,.dest=-1,.src=0,.kind=1,.base=7,.index=1,.scale=2,.index_value=37,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x04,0x4f}},
    {.name="indexed-cross-readonly",.length=7,.tail=7,.dest=-1,.src=0,.kind=1,.base=7,.index=1,.scale=2,.index_value=37,.encoding={0x62,0xf1,0xfe,0x48,0x7f,0x04,0x4f}}
};
#endif
/* Exact per-family fault regions; later indexed cases are never source writes. */
enum store_fault_region { STORE_DATA=1,STORE_STACK,STORE_BASE_SOURCE,STORE_RIP_SOURCE };
struct store_fault_spec { unsigned region,offset,protection,error,alignment; };
#if VQA64S_CODE==1838
static const struct store_fault_spec store_fault_specs[8]={
    {STORE_DATA,PAGE,PROT_NONE,6,0},{STORE_DATA,PAGE,PROT_READ,7,0},
    {STORE_DATA,PAGE-32,PROT_NONE,7,1},{STORE_DATA,PAGE-32,PROT_NONE,7,1},
    {STORE_DATA,PAGE,PROT_READ,7,0},{STORE_STACK,PAGE,PROT_READ,7,0},
    {STORE_BASE_SOURCE,256,PROT_READ|PROT_EXEC,7,0},{STORE_RIP_SOURCE,256,PROT_READ|PROT_EXEC,7,0}
};
#else
static const struct store_fault_spec store_fault_specs[10]={
    {STORE_DATA,PAGE,PROT_NONE,6,0},{STORE_DATA,PAGE,PROT_READ,7,0},
    {STORE_DATA,PAGE-32,PROT_NONE,6,0},{STORE_DATA,PAGE-32,PROT_READ,7,0},
    {STORE_DATA,PAGE,PROT_READ,7,0},{STORE_STACK,PAGE,PROT_READ,7,0},
    {STORE_BASE_SOURCE,256,PROT_READ|PROT_EXEC,7,0},{STORE_RIP_SOURCE,256,PROT_READ|PROT_EXEC,7,0},
    {STORE_DATA,PAGE-32,PROT_NONE,6,0},{STORE_DATA,PAGE-32,PROT_READ,7,0}
};
#endif
static const struct store_fault_spec *store_fault_spec(void) {
    need(v64_fault_kind>=1&&v64_fault_kind<=VPB_FAULTS,1194);
    return &store_fault_specs[v64_fault_kind-1];
}
static const struct vpb_case *vpb_case(const struct sample *s) {
    if(s==&negative_sample){need(s->id>VPB_FAULT_ID&&s->id<=VPB_FAULT_ID+VPB_FAULTS,1106);return &store_fault_cases[s->id-VPB_FAULT_ID-1];}
    need(s->id>=VPB_ID&&s->id<VPB_ID+VPB_TOTAL,1106);return &vpb_cases[s->id-VPB_ID];
}
static uint64_t vqa64s_ea(const struct vpb_case *v,uintptr_t pc,const uint64_t *gpr) {
    if(v->dest>=0)return 0;
    if(v->kind==3)return pc+v->length+(uint64_t)v->displacement;
    uint64_t value=v->base>=0?gpr[v->base]:0;
    if(v->index>=0)value+=gpr[v->index]*v->scale;
    return value+(uint64_t)v->displacement;
}
static uint64_t vqa64s_actual_ea(const struct sample *s,const struct state *state) {
    uint64_t gpr[16];for(unsigned i=0;i<16;i++)gpr[i]=(uint64_t)state->frame.greg[regs[i]];
    return vqa64s_ea(vpb_case(s),s->pc,gpr);
}
static unsigned char store_baseline(uintptr_t at) {
    if(at>=subject&&at<subject+SUBJECT_BYTES)return (unsigned char)((at-subject)*29+11);
    if(at>=vqa64s_high&&at<vqa64s_high+PAGE)return (unsigned char)((at-vqa64s_high)*17+3);
    return (unsigned char)((at%PAGE)*11+0x59);
}
static void store_add(uintptr_t page) {
    need(page&&!(page%PAGE)&&store_region_count<40,1280);
    for(unsigned i=0;i<store_region_count;i++)need(store_regions[i].page!=page,1281);
    need(!RAW(SYS_mprotect,page,PAGE,PROT_READ|PROT_WRITE,0,0,0),1282);
    store_regions[store_region_count++].page=page;
}
static void store_permissions(int inspect) {
    for(unsigned i=0;i<store_restricted_count;i++)
        need(!RAW(SYS_mprotect,store_restricted[i],PAGE,
             inspect?PROT_READ:store_restricted_prot[i],0,0,0),1283);
}
static void store_restrict(uintptr_t page,int prot) {
    need(store_restricted_count<2&&!(page%PAGE),1284);
    store_restricted[store_restricted_count]=page;
    store_restricted_prot[store_restricted_count++]=prot;
    need(!RAW(SYS_mprotect,page,PAGE,prot,0,0,0),1285);
    need(actual_protection(page,0)==prot,1286);
}
static unsigned char store_before_byte(const struct sample *s,uintptr_t at) {
    if(at>=s->mapping&&at<s->mapping+CODE_BYTES)return s->source[at-s->mapping];
    if(store_target&&at>=store_target&&at-store_target<64)
        return (unsigned char)(v64_patterns[vpb_case(s)->pattern][at-store_target]^0xff);
    return store_baseline(at);
}
static void store_memory_observe(struct sample *s,unsigned phase) {
    need(store_index<18&&phase<4,1287);struct store_memory_row *m=&store_memory.rows[store_index];
    need(!m->attempted[phase],1288);m->attempted[phase]=1;
    if(!phase){m->id=s->id;m->pages[0]=store_pages[0];m->pages[1]=store_pages[1];
        m->ea=store_target;m->failed=s==&negative_sample;}
    need(m->id==s->id&&m->pages[0]==store_pages[0]&&m->pages[1]==store_pages[1]&&m->ea==store_target,1289);
    store_permissions(1);
    for(unsigned p=0;p<2;p++)memcpy(m->image[phase][p],(const void *)store_pages[p],PAGE);
    const struct vpb_case *v=vpb_case(s);uint64_t changed=0;
    for(unsigned p=0;p<2;p++)for(size_t i=0;i<PAGE;i++) {
        uintptr_t at=store_pages[p]+i;unsigned char before=store_before_byte(s,at),actual=m->image[phase][p][i];
        unsigned inside=store_target&&at>=store_target&&at-store_target<64;
        if(!(phase&1)||!inside)need(actual==before,1290);
        else if(!m->failed)need(actual==v64_patterns[v->pattern][at-store_target],1291);
        else if(qa_alignment_fault)need(actual==before,1292);
        else need(actual==before||actual==v64_patterns[v->pattern][at-store_target],1292);
        if((phase&1)&&actual!=before)changed|=UINT64_C(1)<<(at-store_target);
    }
    /* Every active and inactive writable arena is checked immediately after
       each lane, including pages not represented by the active two-page view. */
    for(unsigned p=0;p<store_region_count;p++)for(size_t i=0;i<PAGE;i++) {
        uintptr_t at=store_regions[p].page+i;unsigned char before=store_before_byte(s,at),actual=*(const unsigned char *)at;
        unsigned inside=store_target&&at>=store_target&&at-store_target<64;
        if(!(phase&1)||!inside)need(actual==before,1293);
        else if(!m->failed)need(actual==v64_patterns[v->pattern][at-store_target],1294);
        else if(qa_alignment_fault)need(actual==before,1295);
        else need(actual==before||actual==v64_patterns[v->pattern][at-store_target],1295);
    }
    need(!memcmp((const void *)s->mapping,s->source,CODE_BYTES),1296);
    store_permissions(0);m->complete[phase]=1;
    if(phase&1)m->changed[phase/2]=changed;
    if(phase==3){need(!memcmp(m->image[0],m->image[2],sizeof(m->image[0]))&&
        !memcmp(m->image[1],m->image[3],sizeof(m->image[1]))&&m->changed[0]==m->changed[1],1297);
        ++store_memory.checked;}
}
static void vpb_inputs(struct sample *s) {
    const struct vpb_case *v=vpb_case(s);data_page=vqa64s_high;data_fault=vqa64s_high+PAGE;
    for(unsigned i=0;i<store_restricted_count;i++)need(!RAW(SYS_mprotect,store_restricted[i],PAGE,PROT_READ|PROT_WRITE,0,0,0),1298);
    store_restricted_count=0;inputs(s);vpb_seed();
    fixture_input_flags=UINT64_C(0x247)|((s->id&1)?UINT64_C(0x400):0);
    need(v->src>=0&&v->src<32&&v->dest<32&&v->pattern<3,1193);
    memcpy(vpb_vectors[v->src],v64_patterns[v->pattern],64);
    for(unsigned p=0;p<store_region_count;p++)for(size_t i=0;i<PAGE;i++) {
        uintptr_t at=store_regions[p].page+i;*(unsigned char *)at=store_baseline(at);
    }
    uintptr_t target=0;store_pages[0]=vqa64s_high;store_pages[1]=vqa64s_high+PAGE;
    if(v->dest<0) {
        if(v->kind==3) {target=s->pc+s->length+(uint64_t)v->displacement;
            store_pages[0]=s->mapping-3*PAGE;store_pages[1]=s->mapping+4*PAGE;}
        else if(v->kind==2) {need(v->base==4&&v->index<0,1261);
            target=fixture_seed[4]+(uint64_t)v->displacement;store_pages[0]=subject;store_pages[1]=subject+PAGE;}
        else {target=v->kind==4?v->absolute_target:vqa64s_high+(uint64_t)v->offset;
            if(v->kind==4){store_pages[0]=vqa64s_low;store_pages[1]=vqa64s_low+PAGE;}
            if(v->index>=0){need(v->index<16&&v->index!=4&&v->base!=v->index,1262);fixture_seed[v->index]=v->index_value;}
            if(v->base>=0){need(v->base<16&&v->base!=4,1263);
                fixture_seed[v->base]=target-(uint64_t)v->displacement-(v->index>=0?fixture_seed[v->index]*v->scale:0);}
        }
    }
    const struct store_fault_spec *fault=s==&negative_sample?store_fault_spec():0;
    if(fault) {
        need(control==1,1194);
        if(fault->region==STORE_DATA){target=vqa64s_high+fault->offset;
            fixture_seed[7]=target-(v->index>=0?fixture_seed[v->index]*v->scale:0);}
        else if(fault->region==STORE_STACK)target=fixture_seed[4];
        else {need(fault->region==STORE_BASE_SOURCE||fault->region==STORE_RIP_SOURCE,1390);
            target=s->mapping+fault->offset;store_pages[0]=s->mapping;store_pages[1]=s->mapping+PAGE;
            if(fault->region==STORE_BASE_SOURCE)fixture_seed[7]=target;}
    }
    store_target=target;need(vqa64s_ea(v,s->pc,fixture_seed)==target,1264);
    if(VQA64S_CODE==1838&&target)need((target&63)==(qa_alignment_fault?32:0),1361);
    if(target&&!(fault&&(fault->region==STORE_BASE_SOURCE||fault->region==STORE_RIP_SOURCE))) {
        unsigned covered=0;
        for(unsigned j=0;j<64;j++) {unsigned own=0;for(unsigned p=0;p<store_region_count;p++) {
            own+=target+j>=store_regions[p].page&&target+j-store_regions[p].page<PAGE;}
            need(own==1,1299);*(unsigned char *)(target+j)=(unsigned char)(v64_patterns[v->pattern][j]^0xff);++covered;}
        need(covered==64,1300);
    }
    if(fault){
        store_fault_error=fault->error;
        if(fault->region==STORE_DATA)store_restrict(vqa64s_high+PAGE,(int)fault->protection);
        else if(fault->region==STORE_STACK)store_restrict(subject+PAGE,(int)fault->protection);
        data_fault=fault->region==STORE_DATA?vqa64s_high+PAGE:target;
    }
}
static void vpb_prepare(struct sample *s,unsigned index) {
    need(index<=VPB_TOTAL,1107);
    s->id=index==VPB_TOTAL?VPB_FAULT_ID+v64_fault_kind:VPB_ID+index;
    const struct vpb_case *v=vpb_case(s);s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,10*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1108);s->mapping=(uintptr_t)reserved+4*PAGE;
    store_add(s->mapping-3*PAGE);store_add(s->mapping+4*PAGE);
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1109);
    need(v->tail>=1&&v->tail<=s->length&&(s->length==6||s->length==7||s->length==8||s->length==10||s->length==11),1110);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<s->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->encoding,s->length);
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1111);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==VQA64S_CODE&&
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
    vpb_inputs_observed(before,n,kernel);uint64_t a=vpb_header(before,n,kernel),b=vpb_header(after,n,kernel);
    need(a==b,1120); /* Nonzero independently seeded components remain in use. */
    const struct vpb_case *v=s->selftest?0:vpb_case(s);
    const unsigned char *literal=!v?0:v->src>=0?vpb_vectors[v->src]:v64_patterns[v->pattern];
    unsigned destination=v&&v->dest>=0?(unsigned)v->dest:0;
    size_t xmm=vpb_offset(destination,0),ymm=vpb_offset(destination,16),zmm=vpb_offset(destination,32);
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(!s->selftest&&v->dest>=0) {
            if(i>=xmm&&i<xmm+16)expected=literal[i-xmm];
            else if(i>=ymm&&i<ymm+16)expected=literal[16+i-ymm];
            else if(i>=zmm&&i<zmm+32)expected=literal[32+i-zmm];
        }
        need(after[i]==expected,1121);
    }
}
struct vpc_query { uint64_t attempted,result,id,lane; struct li2_write_registers before;
    struct li2_write_footprint value; uint64_t ea,object,offset,kind; };
static struct { uint64_t magic,version,bytes,group,checked,refusals,reserved[2]; struct vpc_query rows[20][2]; } vpc_queries;
_Static_assert(sizeof(struct vpc_query)==256&&sizeof(vpc_queries)==10304,"complete query and EA trailer");
static void vpc_query(struct sample *s,unsigned index,unsigned lane_index) {
    need(index<20&&lane_index<2,1190);struct vpc_query *q=&vpc_queries.rows[index][lane_index];
    need(!q->attempted,1191);q->attempted=1;q->id=s->id;q->lane=lane_index;
    const struct state *before=lane_index?&s->step_before:&s->native_before;
    const struct vpb_case *v=vpb_case(s);
    for(unsigned r=0;r<16;r++)q->before.gpr[r]=(uint64_t)before->frame.greg[regs[r]];
    q->before.fs_base=before->fs;q->before.gs_base=before->gs;
    q->result=li2_decoder_write_footprint(s->pc,s->decoded.bytes,s->length,&q->before,&q->value);
    q->kind=v->kind;q->ea=vqa64s_ea(v,s->pc,q->before.gpr);
    need(!q->result&&q->value.abi_version==1&&q->value.code==VQA64S_CODE&&
         q->value.length==s->length&&q->value.pc==s->pc&&q->value.next_pc==s->pc+s->length,1192);
    if(v->dest>=0)need(!q->ea&&q->value.policy==LI2_WRITE_NONE&&!q->value.first&&!q->value.end,1272);
    else {
        q->object=store_pages[0];q->offset=q->ea-q->object;
        need(q->ea==store_target&&q->ea<=UINT64_MAX-64&&q->value.policy==LI2_WRITE_RANGE&&
             q->value.first==q->ea&&q->value.end==q->ea+64,1268);
        if(v->kind==3)need(q->ea==s->expected_post+(uint64_t)v->displacement,1269);
        if(v->kind==2)need(q->ea==q->before.gpr[4]+(uint64_t)v->displacement,1270);
        if(v->index>=0)need(q->before.gpr[v->index]==v->index_value,1271);
    }
    ++vpc_queries.checked;
}

/* New7F-specific exclusions are additional to every retained6F neighbor. */
static const struct store_refusal { unsigned n; unsigned char b[10]; } store_refused[]={
    {6,{0x62,0xe2,0xfd,0x48,0x7f,0xf}},
    {6,{0x62,0xe3,0xfd,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0x7d,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xf5,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xfc,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xff,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x49,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x4a,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x4f,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0xc8,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0xc9,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x58,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x8,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x28,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x68,0x7f,0xf}},
    {6,{0x62,0xe1,0xfd,0x40,0x7f,0xf}},
    {7,{0x66,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0x67,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0xf3,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0xf2,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0x2e,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0x64,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0x65,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0xf0,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {7,{0x48,0x62,0xe1,0xfd,0x48,0x7f,0xf}},
    {1,{0x62}},
    {2,{0x62,0xe1}},
    {3,{0x62,0xe1,0xfd}},
    {4,{0x62,0xe1,0xfd,0x48}},
    {5,{0x62,0xe1,0xfd,0x48,0x7f}},
    {6,{0x62,0xe1,0xfd,0x48,0x7f,0x4}},
    {9,{0x62,0xe1,0xfd,0x48,0x7f,0x5,0x0,0x0,0x0}},
};
#if VQA64S_CODE==1847
static const struct store_refusal store_unaligned_refused[]={
    {6,{0x62,0xe2,0xfe,0x48,0x7f,0xf}},
    {6,{0x62,0xe3,0xfe,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0x7e,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xf6,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xfc,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xff,0x48,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x49,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x4a,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x4f,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0xc8,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0xc9,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x58,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x8,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x28,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x68,0x7f,0xf}},
    {6,{0x62,0xe1,0xfe,0x40,0x7f,0xf}},
    {7,{0x66,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0x67,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0xf3,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0xf2,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0x2e,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0x64,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0x65,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0xf0,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {7,{0x48,0x62,0xe1,0xfe,0x48,0x7f,0xf}},
    {1,{0x62}},
    {2,{0x62,0xe1}},
    {3,{0x62,0xe1,0xfe}},
    {4,{0x62,0xe1,0xfe,0x48}},
    {5,{0x62,0xe1,0xfe,0x48,0x7f}},
    {6,{0x62,0xe1,0xfe,0x48,0x7f,0x4}},
    {9,{0x62,0xe1,0xfe,0x48,0x7f,0x5,0x0,0x0,0x0}},
};
static void store_unaligned_refusals_check(void) {
    _Static_assert(sizeof(store_unaligned_refused)/sizeof(store_unaligned_refused[0])==32,"closed1847 unsafe neighbors;1838 remains positive");
    for(size_t i=0;i<32;i++) {
        const struct store_refusal *v=&store_unaligned_refused[i];result.failed_refusal=179+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1420+(unsigned)i);
        struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
        need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
             footprint.abi_version==1&&footprint.policy==LI2_WRITE_UNSUPPORTED&&
             !footprint.first&&!footprint.end,1460+(unsigned)i);
        ++vpc_queries.refusals;++result.refusals;
    }
    need(result.refusals==182&&vpc_queries.refusals==64,1499);result.failed_refusal=SIZE_MAX;
}
#endif
static void store_refusals_check(void) {
    for(size_t i=0;i<sizeof(store_refused)/sizeof(store_refused[0]);i++) {
        const struct store_refusal *v=&store_refused[i];result.failed_refusal=146+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        if(i==5&&vdq_store_is_promoted(i)){vdq_store_promote(i,v->b,v->n,result.decoder_result,&refused_last);continue;}
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1320+(unsigned)i);
        struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
        need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
             footprint.abi_version==1&&footprint.policy==LI2_WRITE_UNSUPPORTED&&
             !footprint.first&&!footprint.end,1380+(unsigned)i);
        ++vpc_queries.refusals;++result.refusals;
    }
    need(result.refusals==150&&vpc_queries.refusals==32,1338);result.failed_refusal=SIZE_MAX;
}
static struct { uint64_t magic,version,bytes,checked;struct vpc_query rows[3]; } store_ranges;
static void store_range_controls(void) {
    static const uint64_t first[3]={UINT64_MAX-64,UINT64_MAX-63,UINT64_MAX-7};
    static const unsigned char encoding[6]={0x62,0xf1,VPB_PP,0x48,0x7f,0x06};
    store_ranges.magic=VPB_RANGE_MAGIC;store_ranges.version=1;store_ranges.bytes=sizeof(store_ranges);
    for(unsigned i=0;i<3;i++) {
        struct vpc_query *q=&store_ranges.rows[i];q->attempted=1;q->id=i;q->before.gpr[6]=first[i];
        q->result=li2_decoder_write_footprint(0x1000,encoding,6,&q->before,&q->value);
        need(!q->result&&q->value.abi_version==1&&q->value.code==VQA64S_CODE&&q->value.length==6&&
             q->value.pc==0x1000&&q->value.next_pc==0x1006,1340);
        if(!i)need(q->value.policy==LI2_WRITE_RANGE&&q->value.first==first[i]&&q->value.end==UINT64_MAX,1341);
        else need(q->value.policy==LI2_WRITE_UNSUPPORTED&&!q->value.first&&!q->value.end,1342);
        ++store_ranges.checked;
    }
}

static void vpb_effects(struct sample *s,unsigned index) {
    need(index<VPB_PAIRS&&vpb_observations.checked==index,1122);
    if(!s->selftest)need(s->owner.classification.policy==1&&s->owner.classification.code==VQA64S_CODE&&
        s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_SIMD&&
        s->length==vpb_case(s)->length&&s->expected_post==s->pc+s->length&&!memcmp(s->decoded.bytes,vpb_case(s)->encoding,s->length),1123);
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
        if(s->selftest||vpb_case(s)->dest>=0)compare_memory(before,after,1125);
        /* All memory destinations are checked byte-for-byte by the independent
           literal and native/TF snapshots before either lane can be reseeded. */
        vpb_fp_effect(s,before->frame.fp,after->frame.fp,before->frame.fp_bytes,1);
        vpb_fp_effect(s,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,0);
    }
    vpb_fp_effect(s,s->owner.step.before.fp,s->owner.step.after.fp,s->owner.step.before.fp_bytes,1);
    need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,1126);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,1127);
    need(actual_protection(s->expected_post,0)==PROT_READ,1128);
    if(!s->selftest){vpc_query(s,index-1,0);vpc_query(s,index-1,1);}
    vpb_observations.ids[index]=s->id;++vpb_observations.checked;
}
/* A failed aligned64 write retains its actual complete memory outcome. Preserve the
   unchanged common failed-frame/revoke/sync predicates after these literals. */
static void v64_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        need(s->native_fault&&!s->native_complete&&!s->step_endpoint_seen&&
             s->owner.classification.code==VQA64S_CODE&&s->owner.classification.policy==1,1198);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==(qa_alignment_fault?13:14)&&
             s->native_after.frame.greg[REG_ERR]==(qa_alignment_fault?0:store_fault_error)&&
             vqa64s_actual_ea(s,&s->native_after)==store_target,1199);
        if(qa_alignment_fault)need(s->native_after.frame.greg[REG_CR2]==s->native_before.frame.greg[REG_CR2]&&
             o->after.greg[REG_CR2]==o->before.greg[REG_CR2]&&
             o->after.greg[REG_CR2]==s->native_after.frame.greg[REG_CR2],1362);
        else need((uintptr_t)s->native_after.frame.greg[REG_CR2]==data_fault&&
             (uintptr_t)o->after.greg[REG_CR2]==data_fault,1362);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
            s->native_after.frame.greg[regs[i]]&&o->before.greg[regs[i]]==o->after.greg[regs[i]],1200);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             ((uint64_t)o->before.greg[REG_EFL]|LI2_STEP_TF)==(uint64_t)o->after.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             o->before.fp_bytes==o->after.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),1201);
        store_memory_observe(s,3);
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
        v64_fault=(typeof(v64_fault)){.kind=v64_fault_kind,.checked=1,.operand=vqa64s_ea(vpb_case(s),s->pc,fixture_seed),
            .address=data_fault,.prefix_bytes=data_fault-store_target,.owner_trace=o->trace_seen,
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
             write_all(3,&v128_promotions,sizeof(v128_promotions))&&
             write_all(3,&store_memory,sizeof(store_memory))&&
             write_all(3,&store_ranges,sizeof(store_ranges))&&
             write_all(3,&vpcm_promotions,sizeof(vpcm_promotions))&&
             write_all(3,&vm64_promotions,sizeof(vm64_promotions))&&
             write_all(3,&vpe_promotions,sizeof(vpe_promotions))&&
              write_all(3,&vm256_promotions,sizeof(vm256_promotions))&&
              write_all(3,&vdq_store_promotions,sizeof(vdq_store_promotions)),1206);
}
static void vpb_pair(struct sample *s,unsigned index) {
    current=s;store_index=s==&negative_sample?17:index;fixture_target=s->pc;vpb_inputs(s);
    store_memory_observe(s,0);borrow(s);lane=0;native_phase=0;fixture_enter();
    store_memory_observe(s,1);
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);

    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3||(s==&negative_sample&&control==1))s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    vpb_inputs(s);store_memory_observe(s,2);borrow(s);
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
    store_memory_observe(s,3);compare(s);vpb_effects(s,index);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void vpb_refusals(void) {
    for(size_t i=0;i<sizeof(vpb_refused)/sizeof(vpb_refused[0]);i++) {
        const struct vpb_refusal *v=&vpb_refused[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        if(i==16&&vdq_store_is_promoted(i)){vdq_store_promote(i,v->b,v->n,result.decoder_result,&refused_last);continue;}
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
        if(vpcm_is_promoted(i)) {
            vpcm_promote(i,v->b,v->n,result.decoder_result,&refused_last);
        } else if(v128_is_promoted(i)) {
            v128_promote(i,v->b,v->n,result.decoder_result,&refused_last);
        } else {
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1140+(unsigned)i);
        ++result.refusals;
        }
    }
    v128_promotions_complete();
    vpcm_promotions_complete();
    vm64_promotions_complete();vm256_promotions_complete();result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(vdq_store_promotions)+sizeof(vm256_promotions)+sizeof(vpe_promotions)+sizeof(vm64_promotions)+sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(vpb_observations)+sizeof(v64_fault)+sizeof(vpc_queries)+sizeof(v128_promotions)+sizeof(store_memory)+sizeof(store_ranges)+sizeof(vpcm_promotions)<16*1024*1024,"unchanged complete record cap");
    _Static_assert(sizeof(store_refused)/sizeof(store_refused[0])==33,"closed1838 neighbors");
    _Static_assert(sizeof(vpb_observations)==5000,"literal trailer extent");
    _Static_assert(sizeof(v64_fault)==96,"actual failed-write trailer extent");
    _Static_assert(sizeof(vpb_refused)/sizeof(vpb_refused[0])==99,"closed supplied neighbors");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=VPB_PAIRS;
    need(stack[0]==1,1180);setup(stack);need(!control,1181);vpb_layout();
    long low=RAW(SYS_mmap,UINT64_C(0x1ffff000),4*PAGE,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    need(low==INT64_C(0x1ffff000),1274);vqa64s_low=(uintptr_t)low+PAGE;
    store_add(subject);store_add(subject+PAGE);store_add(vqa64s_low);store_add(vqa64s_low+PAGE);
    need(actual_protection(vqa64s_low-PAGE,0)==PROT_NONE&&actual_protection(vqa64s_low+2*PAGE,0)==PROT_NONE,1275);
    long guarded=RAW(SYS_mmap,0,4*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(guarded>0,1207);data_page=(uintptr_t)guarded+PAGE;vqa64s_high=data_page;data_fault=data_page+PAGE;
    store_add(vqa64s_high);store_add(vqa64s_high+PAGE);
    need(actual_protection(data_page-PAGE,0)==PROT_NONE&&actual_protection(data_page+2*PAGE,0)==PROT_NONE,1208);
    store_memory.magic=VPB_MEMORY_MAGIC;store_memory.version=1;store_memory.bytes=sizeof(store_memory);
    const char *const *env=(const void *)(stack+3);const char key[]=VPB_CONTROL;
    /* Names and opcode rows share the exact family fault descriptor. */
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&VQA64S_GROUP==0,1209);
        for(unsigned j=0;j<VPB_FAULTS;j++)if(same(env[i]+sizeof(key)-1,store_fault_cases[j].name))v64_fault_kind=j+1;
        need(v64_fault_kind>=1&&v64_fault_kind<=VPB_FAULTS,1210);control=1;
    }
    result.control=control;qa_alignment_fault=control?store_fault_spec()->alignment:0;
    vpc_queries.magic=VPB_QUERY_MAGIC;vpc_queries.version=1;
    vpc_queries.bytes=sizeof(vpc_queries);vpc_queries.group=VQA64S_GROUP;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47&&failed==SIZE_MAX&&!decoder_result,1182);
    vpb_refusals();vpe_promotions_complete();need(result.refusals==118&&v128_promotions.completed==13&&vpcm_promotions.completed==5,1183);
    store_refusals_check();vdq_store_promotions_complete();
#if VQA64S_CODE==1847
    store_unaligned_refusals_check();
#endif
    store_range_controls();
    vpb_seed();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    vpb_effects(&samples[0],0);
    if(control){vpb_prepare(&negative_sample,VPB_TOTAL);vpb_pair(&negative_sample,1);die(1211);}
    for(unsigned i=0;i<VPB_COUNT;i++){vpb_prepare(&samples[i+1],VPB_START+i);vpb_pair(&samples[i+1],i+1);}
    need(result.completed==VPB_PAIRS&&vpb_observations.checked==VPB_PAIRS&&store_memory.checked==VPB_COUNT&&dump()&&
         write_all(3,&vpb_observations,sizeof(vpb_observations))&&
         write_all(3,&v64_fault,sizeof(v64_fault))&&
             write_all(3,&vpc_queries,sizeof(vpc_queries))&&
             write_all(3,&v128_promotions,sizeof(v128_promotions))&&
             write_all(3,&store_memory,sizeof(store_memory))&&
             write_all(3,&store_ranges,sizeof(store_ranges))&&
             write_all(3,&vpcm_promotions,sizeof(vpcm_promotions))&&
             write_all(3,&vm64_promotions,sizeof(vm64_promotions))&&
             write_all(3,&vpe_promotions,sizeof(vpe_promotions))&&
              write_all(3,&vm256_promotions,sizeof(vm256_promotions))&&
              write_all(3,&vdq_store_promotions,sizeof(vdq_store_promotions)),1184);
    if(VPB_COUNT==17)output(VPB_LABEL " pairs=18 moves=17 selftest=1 refusal_bytes=" VPB_REFUSALS " promoted_bytes=13 supplied_none_queries=12 supplied_range_queries=1 vpcm_promoted_bytes=5 vpcm_supplied_none_queries=5 footprint_queries=34 full_state=18 full_memory=18 vm64_typed_promotions=7 vm64_supplied_none_queries=7 live_endpoints=18 vpe_typed_promotions=1 vpe_supplied_none_queries=1 vm256_typed_promotions=1 vm256_supplied_none_queries=1 vdq_store_typed_promotions=2 vdq_store_supplied_range_queries=2\n");
    else output(VPB_LABEL " pairs=17 moves=16 selftest=1 refusal_bytes=" VPB_REFUSALS " promoted_bytes=13 supplied_none_queries=12 supplied_range_queries=1 vpcm_promoted_bytes=5 vpcm_supplied_none_queries=5 footprint_queries=32 full_state=17 full_memory=17 vm64_typed_promotions=7 vm64_supplied_none_queries=7 live_endpoints=17 vpe_typed_promotions=1 vpe_supplied_none_queries=1 vm256_typed_promotions=1 vm256_supplied_none_queries=1 vdq_store_typed_promotions=2 vdq_store_supplied_range_queries=2\n");
    return 0;
}
