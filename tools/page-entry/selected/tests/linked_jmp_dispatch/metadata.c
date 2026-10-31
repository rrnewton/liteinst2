/* Pure descriptor/emitter/byte-model oracle; no generated instruction runs. */
#include "model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_decoder_stats initialized;
static unsigned descriptors,models,refusals,corruptions,api_controls,recovery_controls,relocations;
static unsigned injection;
static const uintptr_t PC=UINT64_C(0x400f18),SPILL=UINT64_C(0x10040000);
static const struct li2_jd_binding binding={UINT64_C(0x700000000000),
    {UINT64_C(0x10000000),UINT64_C(0x10020000)},128,69};
static uint64_t rows[LI2_JD_HEADS];
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __real_li2_decoder_tf_classify(uint64_t,const unsigned char *,size_t,struct li2_tf_classification *);
uint32_t __real_li2_decoder_write_footprint(uint64_t,const unsigned char *,size_t,const struct li2_write_registers *,struct li2_write_footprint *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *out) {
    uint32_t e=__real_li2_decoder_decode(pc,b,n,out);if(pc!=PC || !injection)return e;
    if(injection==1)return LI2_BUSY;
    if(injection==2)out->code^=1;
    if(injection==3)out->kind=LI2_RDTSC;
    if(injection==4)out->destination=0;
    if(injection==5)out->width_bits=64;
    if(injection==6)out->step_disposition=LI2_STEP_CANDIDATE;
    if(injection==7)out->bytes[15]=1;
    if(injection==8)out->reserved=1;
    return e;
}
uint32_t __wrap_li2_decoder_tf_classify(uint64_t pc,const unsigned char *b,size_t n,struct li2_tf_classification *out) {
    uint32_t e=__real_li2_decoder_tf_classify(pc,b,n,out);if(pc!=PC || !injection)return e;
    if(injection==9)return LI2_BUSY;
    if(injection==10)out->policy=2;
    if(injection==11)out->family=LI2_TF_CALL;
    if(injection==12)out->flow=LI2_TF_FALLTHROUGH;
    return e;
}
uint32_t __wrap_li2_decoder_write_footprint(uint64_t pc,const unsigned char *b,size_t n,
        const struct li2_write_registers *r,struct li2_write_footprint *out) {
    uint32_t e=__real_li2_decoder_write_footprint(pc,b,n,r,out);if(pc!=PC || !injection)return e;
    if(injection==13)return LI2_BUSY;
    if(injection==14)out->policy=LI2_WRITE_RANGE;
    if(injection==15)out->first=1;
    if(injection==16)out->end=1;
    if(injection==17)out->next_pc++;
    return e;
}
static uint64_t status(unsigned n) {
    static const unsigned bit[]={0,2,4,6,7,11};uint64_t f=UINT64_C(0x202)|((uint64_t)(n&1)<<10)|((uint64_t)(n&2)<<20);
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bit[i];return f;
}
static unsigned encode(unsigned reg,unsigned char b[15],int full) {
    memset(b,0x90,15);unsigned n=0;if(reg>=8)b[n++]=0x41;
    b[n++]=0xff;b[n++]=(unsigned char)(0xe0+(reg&7));return full?15:n;
}
static uintptr_t generated(const struct li2_jd_binding *b) { return b->image[b->head/64]+(b->head%64)*512U; }
static void run(const struct li2_jd_plan *p,uint64_t target,uint64_t flags) {
    uint64_t r[16];for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234000000000000)+UINT64_C(0x100010001)*i;
    r[p->original.target]=target;struct jd_model_result out;
    assert(!jd_model_run(p,rows,r,flags,&out));
    unsigned found=LI2_JD_HEADS;
    for(unsigned i=0;i<p->binding.heads;i++)if(rows[i]==target) { assert(found==LI2_JD_HEADS);found=i; }
    assert(out.recoveries==out.steps && out.steps<=2048);
    if(found<LI2_JD_HEADS) {
        assert(out.hit==1 && !out.miss && out.cell_writes==1 && out.row_reads==found+1);
        assert(out.target==p->binding.image[found/64]+(found%64)*512U);
    } else assert(!out.hit && out.miss==1 && !out.cell_writes && out.row_reads==p->binding.heads && out.target==PC);
    ++models;
}
static void specimens(void) {
    for(unsigned reg=0;reg<16;reg++) {
        struct li2_jd_plan p;unsigned char b[15];unsigned n=encode(reg,b,0);
        assert(!li2_jd_emit(PC,b,n,generated(&binding),SPILL,&binding,&p));
        assert(!li2_jd_validate(&p) && p.original.target==reg && p.original.available==n);
        assert(p.record.boundaries==38 && p.record.image_bytes==224 && p.record.miss_offset==123 && p.record.hit_offset==218);
        assert(p.original.decoded.code==765 && p.original.tf.policy==1 && p.original.tf.family==LI2_TF_BRANCH);
        ++descriptors;
        const uint64_t targets[]={rows[0],rows[64],rows[127],rows[69],UINT64_MAX};
        for(unsigned f=0;f<64;f++)for(unsigned i=0;i<5;i++)run(&p,targets[i],status(f));
        const uint64_t edges[]={rows[0],rows[63],rows[64],rows[127],rows[69],rows[0]+1,
            rows[127]+1,PC+n,0,UINT64_MAX,binding.image[0]+512,binding.rows};
        for(unsigned i=0;i<12;i++)run(&p,edges[i],status(reg));
        n=encode(reg,b,1);assert(!li2_jd_emit(PC,b,n,generated(&binding),SPILL,&binding,&p));
        assert(!li2_jd_validate(&p) && p.original.available==15 && p.original.decoded.bytes[14]==0x90);
        run(&p,rows[64],status(63-reg));++descriptors;
        /* Register-independent NONE is checked against varied actual registers,
           including RSP. There is no implicit-stack permission assumption. */
        struct li2_write_registers actual={0};
        for(unsigned i=0;i<16;i++)actual.gpr[i]=UINT64_MAX-i;
        struct li2_write_footprint fp={0},want={.pc=PC,.next_pc=PC+(reg>=8?3:2),
            .abi_version=1,.policy=LI2_WRITE_NONE,.code=765,.length=reg>=8?3:2};
        assert(!li2_decoder_write_footprint(PC,b,n,&actual,&fp) && !memcmp(&fp,&want,sizeof fp));
    }
}
static void rejected_forms(void) {
    static const unsigned char bytes[][5]={
        {0xff},{0xff,0xd0},{0xff,0xe8},{0xff,0x20},{0x48,0xff,0xe0},{0x40,0xff,0xe0},
        {0x66,0xff,0xe0},{0xf2,0xff,0xe0},{0xf3,0xff,0xe0},{0x2e,0xff,0xe0},
        {0x67,0xff,0xe0},{0x41,0x41,0xff,0xe0},{0x41,0xff},{0x41,0xff,0x20},
        {0x90},{0xc3},{0xe9,0,0,0,0}
    };
    static const unsigned length[]={1,2,2,2,3,3,3,3,3,3,3,4,2,3,1,1,5};
    for(unsigned i=0;i<sizeof length/sizeof length[0];i++) {
        struct li2_jd_descriptor d;assert(li2_jd_describe(PC,bytes[i],length[i],&d)==LI2_JD_FORM && !d.ready);++refusals;
    }
    unsigned char b[16]={0xff,0xe0};struct li2_jd_descriptor d;
    assert(li2_jd_describe(PC,b,0,&d)==LI2_JD_ARGUMENT && !d.ready);++refusals;
    assert(li2_jd_describe(PC,b,16,&d)==LI2_JD_ARGUMENT && !d.ready);++refusals;
    assert(li2_jd_describe(PC,0,2,&d)==LI2_JD_ARGUMENT && !d.ready);++refusals;
    assert(li2_jd_describe(UINT64_C(0x7fffffffffff),b,2,&d)==LI2_JD_ARGUMENT && !d.ready);++refusals;
    for(unsigned i=1;i<=17;i++) {
        injection=i;int e=li2_jd_describe(PC,b,2,&d);
        assert(e==((i==1 || i==9 || i==13)?LI2_JD_DECODER:LI2_JD_FORM) && !d.ready);
        ++api_controls;
    }
    injection=0;
}
static void bad_bindings(void) {
    unsigned char b[15];unsigned n=encode(0,b,0);struct li2_jd_plan p;
    for(unsigned i=0;i<11;i++) {
        struct li2_jd_binding wrong=binding;uintptr_t spill=SPILL;
        if(i==0)wrong.heads=0;
        if(i==1)wrong.heads=129;
        if(i==2)wrong.head=128;
        if(i==3)wrong.rows++;
        if(i==4)wrong.rows=UINT64_C(0x7ffffffff000);
        if(i==5)wrong.rows=wrong.image[0];
        if(i==6)wrong.image[1]=wrong.image[0];
        if(i==7)wrong.image[0]++;
        if(i==8)spill=wrong.rows;
        if(i==9)spill=wrong.image[1];
        if(i==10)spill++;
        assert(li2_jd_emit(PC,b,n,generated(&binding),spill,&wrong,&p)==LI2_JD_ARGUMENT && !p.record.ready);++refusals;
    }
    assert(li2_jd_emit(PC,b,n,generated(&binding)+1,SPILL,&binding,&p)==LI2_JD_ARGUMENT && !p.record.ready);++refusals;
    assert(li2_jd_emit(PC,b,n,generated(&binding),UINT64_C(0x600000000000),&binding,&p)==LI2_JD_RELOCATION && !p.record.ready);++relocations;
    struct li2_jd_binding high=binding;high.image[0]=UINT64_C(0x100000000);high.image[1]=UINT64_C(0x100020000);
    uintptr_t g=generated(&high),s=UINT64_C(0x100040000),next=g+128;
    const uintptr_t targets[]={next+UINT32_C(0x7fffffff),next-UINT32_C(0x80000000),
        next+UINT64_C(0x80000000),next-UINT64_C(0x80000001)};
    for(unsigned i=0;i<4;i++) {
        int e=li2_jd_emit(targets[i],b,n,g,s,&high,&p);
        assert(e==(i<2?0:LI2_JD_RELOCATION) && p.record.ready==(i<2));++relocations;
    }
}
static void corrupted_plans(void) {
    unsigned char b[15];unsigned n=encode(0,b,0);struct li2_jd_plan p,q;
    assert(!li2_jd_emit(PC,b,n,generated(&binding),SPILL,&binding,&p));
    for(unsigned i=0;i<24;i++) {
        q=p;
        if(i==0)q.original.target=1;
        if(i==1)q.original.decoded.code++;
        if(i==2)q.original.decoded.bytes[15]=1;
        if(i==3)q.original.tf.family=LI2_TF_CALL;
        if(i==4)q.original.reserved[2]=1;
        if(i==5)q.record.ready=0;
        if(i==6)q.record.result=LI2_JD_FORM;
        if(i==7)q.record.reserved=1;
        if(i==8)q.record.image_bytes--;
        if(i==9)q.record.boundaries--;
        if(i==10)q.record.hit_offset++;
        if(i==11)q.record.miss_offset++;
        if(i==12)q.record.scratch_regs[1]=0;
        if(i==13)q.record.boundary[0].spill_valid=1;
        if(i==14)q.record.boundary[9].dirty=0;
        if(i==15)q.record.boundary[9].flags=LI2_MG_PHYSICAL;
        if(i==16)q.record.boundary[37].phase=LI2_JD_BEFORE;
        if(i==17)q.record.boundary[63].length=1;
        if(i==18)q.binding.rows+=8;
        if(i==19)q.binding.heads--;
        if(i==20)q.binding.image[0]+=4096;
        if(i==21)q.generated++;
        if(i==22)q.spill+=8;
        if(i==23)q.image[223]^=1;
        assert(li2_jd_validate(&q)==LI2_JD_CORRUPT);++corruptions;
    }
    uint64_t raw[16]={0},spills[4]={0};struct li2_jd_recovered recovered;
    for(unsigned at=0;at<512;at++) {
        unsigned found=0;for(unsigned i=0;i<p.record.boundaries;i++)found|=p.record.boundary[i].offset==at;
        if(!found) { assert(li2_jd_recover(&p,p.generated+at,raw,0,spills,&recovered)==LI2_JD_CORRUPT);++recovery_controls; }
    }
    assert(li2_jd_recover(&p,p.generated-1,raw,0,spills,&recovered)==LI2_JD_ARGUMENT);++recovery_controls;
    for(unsigned i=0;i<6;i++) {
        q=p;
        if(i==0)q.record.boundary[0].dirty=1;
        if(i==1)q.record.boundary[0].spill_valid=16;
        if(i==2)q.record.boundary[0].flags=3;
        if(i==3)q.record.boundary[0].phase=2;
        if(i==4)q.record.scratch_regs[1]=4;
        if(i==5)q.record.boundary[1].offset=0;
        assert(li2_jd_recover(&q,q.generated,raw,0,spills,&recovered)==LI2_JD_CORRUPT);++recovery_controls;
    }
    raw[0]=2;
    assert(li2_jd_recover(&p,p.generated+p.record.boundary[9].offset,raw,0,spills,&recovered)==LI2_JD_CORRUPT);++recovery_controls;
}
int main(void) {
    assert(!li2_decoder_initialize(arena,sizeof arena,&initialized));
    for(unsigned i=0;i<128;i++)rows[i]=UINT64_C(0x400000)+(i/64)*4096+(i%64)*4;
    rows[binding.head]=PC;
    specimens();rejected_forms();bad_bindings();corrupted_plans();
    assert(descriptors==32 && models==5328 && refusals==33 && api_controls==17 && relocations==5 &&
           corruptions==24 && recovery_controls==482);
    struct li2_decoder_stats final;assert(!li2_decoder_stats(&final));
    assert(final.phase==2 && !final.first_fatal_reason && final.allocation_calls==initialized.allocation_calls &&
           final.deallocation_calls==initialized.deallocation_calls);
    printf("resident-jmp-pure descriptors=%u models=%u refusals=%u api=%u relocation=%u corruptions=%u recovery=%u descriptor_bytes=%zu record_bytes=%zu plan_bytes=%zu\n",
        descriptors,models,refusals,api_controls,relocations,corruptions,recovery_controls,
        sizeof(struct li2_jd_descriptor),sizeof(struct li2_jd_record),sizeof(struct li2_jd_plan));
    return 0;
}
