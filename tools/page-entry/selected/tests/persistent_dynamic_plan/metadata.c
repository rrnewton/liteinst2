/* Pure description only. No emitted code, guest instruction or owner executes.
   Test wrappers deliberately inject impossible metadata into the real decoder/
   guard results to prove it remains terminal, never an ordinary cancellation. */
#include "persistent_dynamic_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pe_plan actual,old,scratch;
static struct li2_pe_dynamic_miss miss;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static uintptr_t code,spill;
static unsigned inject,positive,classified,terminal,corruptions;
uint32_t __real_li2_decoder_span_describe(uint64_t,const unsigned char *,size_t,struct li2_span_decoded *);
uint32_t __wrap_li2_decoder_span_describe(uint64_t pc,const unsigned char *b,size_t n,struct li2_span_decoded *d) {
    uint32_t r=__real_li2_decoder_span_describe(pc,b,n,d);
    if(r)return r;
    int emitted=pc>=code && pc-code<LI2_PE_IMAGE_BYTES;
    if(inject==1 && !emitted)return LI2_BUSY;
    if(inject==2 && !emitted)d->decoded.length=0;
    if(inject==3 && emitted)d->decoded.length=0;
    if(inject==4 && !emitted && d->relocation==LI2_SPAN_RIP_DISP32)d->displacement_bytes=1;
    if(inject==5 && emitted) {d->ready=0;d->refusal=LI2_REGION_UNSUPPORTED;}
    if(inject==7 && !emitted && d->decoded.decode_status!=LI2_VALID)d->refusal=LI2_REGION_EFFECTS;
    if(inject==8 && !emitted) {struct li2_decoded original=d->decoded;memset(d,0,sizeof *d);d->decoded=original;d->version=1;d->refusal=LI2_REGION_EFFECTS;}
    return 0;
}
int __real_li2_mg_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,uintptr_t,const struct li2_mg_table *,struct li2_mg_plan *);
int __wrap_li2_mg_emit(uintptr_t pc,const unsigned char *b,size_t n,uintptr_t g,uintptr_t s,uintptr_t next,const struct li2_mg_table *t,struct li2_mg_plan *out) {
    int r=__real_li2_mg_emit(pc,b,n,g,s,next,t,out);
    if(inject==6 && !r) {out->ready=0;out->result=LI2_MG_RELOCATION;return LI2_MG_RELOCATION;}
    return r;
}
static void put32(unsigned char *b,int64_t v) {assert(v>=INT32_MIN && v<=INT32_MAX);uint32_t u=(uint32_t)v;for(unsigned i=0;i<4;i++)b[i]=(unsigned char)(u>>(8*i));}
static void rel(unsigned at,unsigned length,unsigned displacement,uintptr_t target) {put32(source[0]+at+displacement,(int64_t)target-(int64_t)(pages[0]+at+length));}
static void empty(void) {memset(source,0xcc,sizeof source);code=0x10000000;spill=code+LI2_PE_IMAGE_BYTES;inject=0;}
static void loop(void) {
    empty();static const unsigned char a[]={0x48,0x89,7,0x48,0x83,0xc0,1,0x48,0x39,0xc8,0x0f,0x82,0,0,0,0,0xc3};
    static const unsigned char b[]={0x48,0x83,0xc7,8,0xe9,0,0,0,0};
    memcpy(source[0]+0x100,a,sizeof a);memcpy(source[1]+0x100,b,sizeof b);rel(0x10a,6,2,pages[1]+0x100);
    put32(source[1]+0x105,(int64_t)(pages[0]+0x100)-(int64_t)(pages[1]+0x109));
}
static void add_ret(void) {empty();static const unsigned char b[]={0x48,0x83,0xc0,1,0xc3};memcpy(source[0]+0x100,b,sizeof b);}
static void rip(void) {empty();static const unsigned char b[]={0x48,0x8b,5,0,0,0,0,0xc3};memcpy(source[0]+0x100,b,sizeof b);}
static void compare(uintptr_t entry,unsigned reason,int status) {
    int a=li2_pe_plan_pages_dynamic(pages,source,entry,code,spill,&table,&actual,&miss);
    int b=li2_pe_plan_pages(pages,source,entry,code,spill,&table,&old);
    assert(a==status && b==status && !memcmp(&actual,&old,sizeof actual));
    assert(miss.version==1 && miss.status==(unsigned)status && miss.reason==reason);
    if(!status) {
        const struct li2_pe_dynamic_miss zero={.version=1};assert(!memcmp(&miss,&zero,sizeof miss));
        assert(actual.ready==1 && !li2_pe_plan_validate(&actual,&scratch) && !memcmp(&actual,&scratch,sizeof actual));++positive;
    } else if(reason) {
        assert(!actual.ready && li2_pe_dynamic_miss_valid(&actual,&miss,status));++classified;
        struct li2_pe_dynamic_miss bad=miss;bad.version^=1;assert(!li2_pe_dynamic_miss_valid(&actual,&bad,status));++corruptions;
        bad=miss;bad.status^=1;assert(!li2_pe_dynamic_miss_valid(&actual,&bad,status));++corruptions;
        bad=miss;bad.site=0;assert(!li2_pe_dynamic_miss_valid(&actual,&bad,status));++corruptions;
        bad=miss;bad.pc=0;assert(!li2_pe_dynamic_miss_valid(&actual,&bad,status));++corruptions;
    } else {
        const struct li2_pe_dynamic_miss zero={.version=1,.status=(unsigned)status};assert(!memcmp(&miss,&zero,sizeof miss));++terminal;
    }
    if(!reason)assert(!li2_pe_dynamic_miss_valid(&actual,&miss,status));
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before) && before.phase==2 && !before.first_fatal_reason);
    const struct li2_mg_range range={0x70000008,0x70000010};assert(!li2_mg_table_build(&range,1,0x70002000,&table));
    loop();compare(pages[0]+0x100,0,0);add_ret();compare(pages[0]+0x100,0,0);
    empty();source[0][0x100]=0xc3;compare(pages[0]+0x100,LI2_PED_ROOT_UNSUPPORTED,LI2_PE_MISS);
    empty();source[0][0x100]=0x0f;source[0][0x101]=4;compare(pages[0]+0x100,LI2_PED_SOURCE_INVALID,LI2_PE_BOUNDARY);
    empty();source[1][4095]=0x0f;compare(pages[1]+4095,LI2_PED_SOURCE_TRUNCATED,LI2_PE_BOUNDARY);
    empty();source[0][0x100]=0x0f;source[0][0x101]=0x85;rel(0x100,6,2,pages[0]+0x107);
    source[0][0x106]=0x48;source[0][0x107]=0x89;source[0][0x108]=0xc0;source[0][0x109]=0xc3;
    compare(pages[0]+0x100,LI2_PED_SOURCE_OVERLAP,LI2_PE_GRAPH);
    empty();source[0][0x100]=0xe9;rel(0x100,5,1,pages[1]+4096);compare(pages[0]+0x100,LI2_PED_OUTSIDE_PAIR,LI2_PE_GRAPH);
    empty();for(unsigned i=0;i<65;i++) {unsigned a=0x100+4*i;source[0][a]=0x48;source[0][a+1]=0x83;source[0][a+2]=0xc0;source[0][a+3]=1;}
    source[0][0x100+65*4]=0xc3;compare(pages[0]+0x100,LI2_PED_HEAD_LIMIT,LI2_PE_GRAPH);
    empty();for(unsigned i=0;i<9;i++) {unsigned a=0x100+6*i;source[0][a]=0x0f;source[0][a+1]=0x85;rel(a,6,2,pages[0]+0x500+i);source[0][0x500+i]=0xc3;}
    source[0][0x100+9*6]=0xc3;compare(pages[0]+0x100,LI2_PED_EXIT_LIMIT,LI2_PE_GRAPH);
    /* Binary discovery tree: each block's Jcc queues one new child and the
       following JMP queues another. All targets lie in-pair; queue72 fills
       before64 decoded heads or8 frontiers. */
    empty();for(unsigned i=0;i<128;i++) {unsigned a=0x100+16*i;source[0][a]=0x0f;source[0][a+1]=0x85;rel(a,6,2,pages[0]+0x100+16*(2*i+1));source[0][a+6]=0xe9;rel(a+6,5,1,pages[0]+0x100+16*(2*i+2));}
    compare(pages[0]+0x100,LI2_PED_QUEUE_LIMIT,LI2_PE_GRAPH);
    empty();source[0][0x100]=0xe9;rel(0x100,5,1,pages[0]+0x100);compare(pages[0]+0x100,LI2_PED_NO_EXIT,LI2_PE_GRAPH);
    rip();code=UINT64_C(0x600000000000);spill=code+LI2_PE_IMAGE_BYTES;compare(pages[0]+0x100,LI2_PED_RIP_REACH,LI2_PE_RELOCATION);
    empty();source[0][0x100]=0x0f;source[0][0x101]=0x85;rel(0x100,6,2,pages[0]+0x110);source[0][0x106]=source[0][0x110]=0xc3;
    code=UINT64_C(0x600000000000);spill=code+LI2_PE_IMAGE_BYTES;compare(pages[0]+0x100,LI2_PED_BRANCH_REACH,LI2_PE_RELOCATION);
    add_ret();code=UINT64_C(0x600000000000);spill=code+LI2_PE_IMAGE_BYTES;compare(pages[0]+0x100,LI2_PED_FALLTHROUGH_REACH,LI2_PE_RELOCATION);
    empty();static const unsigned char rs[]={0x48,0x89,5,0,0,0,0,0xc3};memcpy(source[0]+0x100,rs,sizeof rs);
    code=UINT64_C(0x600000000000);spill=code+LI2_PE_IMAGE_BYTES;compare(pages[0]+0x100,LI2_PED_GUARD_RIP_REACH,LI2_PE_RELOCATION);
    empty();source[0][0x100]=0x48;source[0][0x101]=0x89;source[0][0x102]=7;source[0][0x103]=0xc3;
    code=UINT64_C(0x600000000000);spill=code+LI2_PE_IMAGE_BYTES;compare(pages[0]+0x100,LI2_PED_GUARD_FOLLOW_REACH,LI2_PE_RELOCATION);
    add_ret();inject=1;compare(pages[0]+0x100,0,LI2_PE_DECODER);
    add_ret();inject=2;compare(pages[0]+0x100,0,LI2_PE_BOUNDARY);
    add_ret();inject=3;compare(pages[0]+0x100,0,LI2_PE_BOUNDARY);
    rip();inject=4;compare(pages[0]+0x100,0,LI2_PE_RELOCATION);
    add_ret();inject=5;compare(pages[0]+0x100,0,LI2_PE_DECODER);
    loop();inject=6;compare(pages[0]+0x100,0,LI2_PE_RELOCATION);
    empty();source[0][0x100]=0x0f;source[0][0x101]=4;inject=7;compare(pages[0]+0x100,0,LI2_PE_BOUNDARY);
    add_ret();inject=8;compare(pages[0]+0x100,0,LI2_PE_MISS);
    loop();spill=UINT64_C(0x200000000);compare(pages[0]+0x100,0,LI2_PE_RELOCATION);
    loop();spill=code+16;compare(pages[0]+0x100,0,LI2_PE_ARGUMENT);
    assert(!li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    assert(positive==2 && classified==14 && terminal==10 && corruptions==56);
    printf("{\"schema\":1,\"positives\":2,\"classified\":14,\"terminal\":10,\"corruptions\":56,\"whole_old_plans_equal\":26,\"postseal_equal\":1,\"emitted_execution\":0}\n");
    return 0;
}
