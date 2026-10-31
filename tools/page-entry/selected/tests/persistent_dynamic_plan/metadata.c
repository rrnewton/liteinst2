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
static unsigned placement_cases,placement_ready;
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
        assert(li2_pe_dynamic_placement(entry,code)==1);++placement_cases;++placement_ready;
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
/* Literal aligned geometry cases, separate from the actual emitter cases
   below. The interval is deliberately conservative: overlap is possible,
   not admission; image end is an instruction-end bound, not a readable PC. */
static void placement_geometry(void) {
    static const struct {uintptr_t entry,generated;int expected;} cases[]={
        {0x400100,0x10000000,1}, {0x400000,0x401000,1},
        {0x400ff1,0x10000000,1}, {0x400ff2,0x10000000,-1},
        {0,0x10000000,-1}, {0xfff,0x10000000,-1},
        {0x1000,0x1000,1}, {0x400100,0,-1},
        {0x400100,0x10000001,-1}, {0x400100,UINTPTR_MAX,-1},
        {UINTPTR_MAX,0x10000000,-1},
        {UINT64_C(0x800000000000),0x10000000,-1},
        {0x400100,UINT64_C(0x800000000000),-1},
        {UINT64_C(0x7ffffffff000),0x10000000,-1},
        {UINT64_C(0x7fffffffeff1),UINT64_C(0x7fffffff8000),1},
        {UINT64_C(0x7fffffffeff2),UINT64_C(0x7fffffff8000),-1},
        {0x400100,UINT64_C(0x7fffffff9000),-1},
        /* Closest aligned gaps straddling the negative signed boundary. */
        {0x400100,0x80401000,1}, {0x400100,0x80402000,0},
        /* Positive reach uses image END, with its asymmetric signed limit. */
        {0x90007100,0x10000000,1}, {0x90008100,0x10000000,0},
        {0x10008100,0x10000000,1}, {0x10009100,0x10000000,1},
        /* The real helper region versus low/high/near hypothetical banks. */
        {UINT64_C(0x200001010),0x413ca000,0},
        {UINT64_C(0x200001010),UINT64_C(0x7f7d68a71000),0},
        {UINT64_C(0x200001010),UINT64_C(0x200010000),1}
    };
    for(unsigned i=0;i<sizeof cases/sizeof cases[0];i++) {
        assert(li2_pe_dynamic_placement(cases[i].entry,cases[i].generated)==cases[i].expected);
        ++placement_cases;
    }
}
/* These are actual unchanged old and classified planner calls. No generated
   instruction executes. Every ready image still round-trips the old full
   validator; exact reach is established by emitted target/next-PC geometry. */
static void placement_plan(const uintptr_t pair[2],uintptr_t entry,int status,int possible) {
    int a=li2_pe_plan_pages_dynamic(pair,source,entry,code,spill,&table,&actual,&miss);
    int b=li2_pe_plan_pages(pair,source,entry,code,spill,&table,&old);
    assert(a==status && b==status && !memcmp(&actual,&old,sizeof actual));
    assert(li2_pe_dynamic_placement(entry,code)==possible);++placement_cases;
    if(!status) {
        const struct li2_pe_dynamic_miss zero={.version=1};
        assert(possible==1 && actual.ready==1 && !memcmp(&miss,&zero,sizeof miss));
        assert(!li2_pe_plan_validate(&actual,&scratch) && !memcmp(&actual,&scratch,sizeof actual));
        ++placement_ready;
    } else assert(!actual.ready && li2_pe_dynamic_miss_valid(&actual,&miss,status));
}
static void placement_jump(uintptr_t first,uintptr_t generated,unsigned frontier,int status,int possible,int64_t delta) {
    empty();const uintptr_t pair[2]={first,first+4096};code=generated;spill=code+LI2_PE_IMAGE_BYTES;
    source[0][0x100]=0xe9;put32(source[0]+0x101,(int64_t)frontier-0x105);
    source[frontier/4096][frontier%4096]=0xc3;
    assert((int64_t)(first+frontier)-(int64_t)(code+5)==delta);
    placement_plan(pair,first+0x100,status,possible);
    assert(actual.heads==1 && actual.exits==1 && actual.exit_pc[0]==first+frontier);
    if(!status)assert(actual.head[0].generated_length==5 && actual.image[0]==0xe9);
    else assert(miss.reason==LI2_PED_BRANCH_REACH);
}
static void placement_emit_edges(void) {
    /* Real JMP disp32 endpoints and the immediately adjacent bytes. */
    placement_jump(0x400000,0x80400000,4,LI2_PE_RELOCATION,1,INT64_C(-2147483649));
    placement_jump(0x400000,0x80400000,5,0,1,INT64_C(-2147483648));
    placement_jump(0x400000,0x80400000,6,0,1,INT64_C(-2147483647));
    placement_jump(0x90000000,0x10000000,3,0,1,INT64_C(2147483646));
    placement_jump(0x90000000,0x10000000,4,0,1,INT64_C(2147483647));
    placement_jump(0x90000000,0x10000000,5,LI2_PE_RELOCATION,1,INT64_C(2147483648));
    /* Actual last pair byte, both sides of the aligned interval threshold. */
    placement_jump(0x400000,0x80401000,8191,0,1,INT64_C(-2147479558));
    placement_jump(0x400000,0x80402000,8191,LI2_PE_RELOCATION,0,INT64_C(-2147483654));
    /* First-head emission can still fail when the whole-image bound permits. */
    placement_jump(0x90007000,0x10000000,5,LI2_PE_RELOCATION,1,INT64_C(2147512320));
    placement_jump(0x90008000,0x10000000,5,LI2_PE_RELOCATION,0,INT64_C(2147516416));
    /* Low M remains a real post-close root miss, not a placement decline. */
    empty();source[0][0x100]=0x41;source[0][0x101]=0xff;source[0][0x102]=0xe1;
    placement_plan(pages,pages[0]+0x100,LI2_PE_MISS,1);
    assert(miss.reason==LI2_PED_ROOT_UNSUPPORTED);
}
static void placement_old_positives(void) {
    /* Same three source fixtures, registry, code and spill as the independent
       persistent_plan component; its original assertions remain untouched. */
    const uintptr_t old_spill=0x10010000,table_at=0x10012000;
    const struct li2_mg_range ranges[]={
        {pages[0],pages[1]+4096},{0x10000000,0x10000000+LI2_PE_IMAGE_BYTES},
        {old_spill,old_spill+4096},{table_at,table_at+8192},{0x70000008,0x70000010}};
    assert(!li2_mg_table_build(ranges,sizeof ranges/sizeof ranges[0],table_at,&table));
    loop();spill=old_spill;placement_plan(pages,pages[0]+0x100,0,1);
    assert(actual.heads==6 && actual.stores==1 && actual.source_bytes==25 && actual.exits==1);
    static const unsigned char first32[]={0x89,0x07,0x48,0x83,0xc0,1,
        0x48,0x39,0xc8,0x0f,0x82,0,0,0,0,0xc3};
    memcpy(source[0]+0x100,first32,sizeof first32);rel(0x109,6,2,pages[1]+0x100);
    placement_plan(pages,pages[0]+0x100,0,1);
    assert(actual.heads==6 && actual.stores==1 && actual.source_bytes==24 && actual.exits==1 && actual.store_original[0].width_bytes==4);
    empty();spill=old_spill;source[0][0xff0]=0xe9;rel(0xff0,5,1,pages[0]+0xffe);
    source[0][0xffe]=0x48;source[0][0xfff]=0x89;source[1][0]=0x47;source[1][1]=8;source[1][2]=0xc3;
    placement_plan(pages,pages[0]+0xff0,0,1);
    assert(actual.heads==2 && actual.stores==1 && actual.source_bytes==9 && actual.exits==1 && actual.source_mask==3);
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
    placement_geometry();placement_emit_edges();placement_old_positives();
    assert(placement_cases==42 && placement_ready==10);
    assert(!li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    assert(positive==2 && classified==14 && terminal==10 && corruptions==56);
    printf("{\"schema\":1,\"positives\":2,\"classified\":14,\"terminal\":10,\"corruptions\":56,\"whole_old_plans_equal\":26,\"postseal_equal\":1,\"emitted_execution\":0,\"placement_cases\":42,\"placement_ready\":10}\n");
    return 0;
}
