/* Pure component. Addresses below are descriptions, never executable mappings.
   No registered/source/lifecycle authority or hardware state is supplied. */
#include "persistent_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pe_plan plan,scratch,changed;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static const uintptr_t code=0x10000000,spill=0x10010000,table_at=0x10012000;
static unsigned positives,refusals,corruptions,recoveries;
static void put32(unsigned char *b,uint32_t n) {
    for(unsigned i=0;i<4;i++)b[i]=(unsigned char)(n>>(i*8));
}
static void rel(unsigned page,unsigned offset,unsigned length,unsigned position,uintptr_t target) {
    int64_t d=(int64_t)target-(int64_t)(pages[page]+offset+length);
    assert(d>=INT32_MIN && d<=INT32_MAX);
    put32(source[page]+offset+position,(uint32_t)d);
}
static void empty(void) { memset(source,0xcc,sizeof source); }
static void loop(void) {
    empty();
    /* Store; increment value; compare; taken crosses page, fallthrough RET.
       Second page advances the destination and jumps back to the actual store. */
    static const unsigned char first[]={0x48,0x89,0x07,0x48,0x83,0xc0,1,
        0x48,0x39,0xc8,0x0f,0x82,0,0,0,0,0xc3};
    static const unsigned char second[]={0x48,0x83,0xc7,8,0xe9,0,0,0,0};
    memcpy(source[0]+0x100,first,sizeof first);
    memcpy(source[1]+0x100,second,sizeof second);
    rel(0,0x10a,6,2,pages[1]+0x100);
    rel(1,0x104,5,1,pages[0]+0x100);
}
static void accepted(uintptr_t entry,unsigned heads,unsigned stores,unsigned bytes,unsigned exits) {
    assert(li2_pe_plan_pages(pages,source,entry,code,spill,&table,&plan)==LI2_PE_OK);
    assert(plan.ready==1 && plan.result==0 && plan.version==LI2_PE_VERSION &&
        plan.bytes==sizeof plan && plan.heads==heads && plan.stores==stores &&
        plan.source_bytes==bytes && plan.exits==exits);
    assert(!memcmp(plan.source,source,sizeof source));
    assert(!li2_pe_plan_validate(&plan,&scratch));
    assert(!memcmp(&plan,&scratch,sizeof plan));
    ++positives;
}
static void recovery(void) {
    uint64_t raw[16],saved[4];
    for(unsigned i=0;i<16;i++)raw[i]=UINT64_C(0x1234000000000000)+17*i;
    for(unsigned i=0;i<4;i++)saved[i]=UINT64_C(0xaabb000000000000)+31*i;
    const uint64_t flags=UINT64_C(0x102d7); /* actual RF and all six status bits */
    struct li2_pe_recovered out;
    for(unsigned i=0;i<plan.heads;i++) {
        const struct li2_pe_head *h=&plan.head[i];
        const struct li2_span_decoded *d=&plan.original[i];
        uintptr_t base=code+(uintptr_t)i*LI2_PE_SLOT_BYTES;
        if(h->kind==LI2_PE_MOV) {
            const struct li2_mg_plan *g=&plan.guard[i];
            for(unsigned j=0;j<g->boundaries;j++) {
                /* Supply a source-consistent packed-flag shape, with poisoned
                   old spills. Pure API comparison does not claim execution. */
                uint64_t actual[16];memcpy(actual,raw,sizeof actual);
                if(g->boundary[j].flags)actual[0]=(actual[0]&~UINT64_C(0xffff))|
                    ((flags&UINT64_C(0xd5))<<8)|((flags>>11)&1);
                struct li2_mg_recovered old;
                assert(!li2_mg_recover(g,base+g->boundary[j].offset,actual,flags,saved,&old));
                assert(!li2_pe_recover(&plan,base+g->boundary[j].offset,actual,flags,saved,&out));
                assert(out.complete==1 && out.head==i && out.kind==LI2_PE_GUARD &&
                    out.phase==old.phase && out.original_pc==old.original_pc && out.flags==old.flags);
                assert(!memcmp(out.gpr,old.gpr,sizeof out.gpr));
                assert((out.flags&UINT64_C(0x10000))==(flags&UINT64_C(0x10000)));
                ++recoveries;
            }
        } else {
            assert(!li2_pe_recover(&plan,base,raw,flags,saved,&out));
            assert(out.complete==1 && out.original_pc==d->decoded.pc && out.phase==LI2_MG_BEFORE &&
                out.flags==flags && !memcmp(out.gpr,raw,sizeof raw));
            ++recoveries;
            if(d->flow!=LI2_REGION_JMP) {
                unsigned offset=d->flow==LI2_REGION_NEXT?h->source_length:6;
                assert(!li2_pe_recover(&plan,base+offset,raw,flags,saved,&out));
                assert(out.complete==1 && out.original_pc==d->decoded.next_pc && out.phase==LI2_MG_AFTER &&
                    out.kind==LI2_PE_EDGE && out.flags==flags && !memcmp(out.gpr,raw,sizeof raw));
                ++recoveries;
            }
        }
        assert(li2_pe_recover(&plan,base+1,raw,flags,saved,&out)==LI2_PE_MISS && !out.complete);
        assert(li2_pe_recover(&plan,base+h->generated_length,raw,flags,saved,&out)==LI2_PE_MISS && !out.complete);
        refusals+=2;
    }
    assert(li2_pe_recover(&plan,code+LI2_PE_IMAGE_BYTES,raw,flags,saved,&out)==LI2_PE_MISS);
    ++refusals;
    changed=plan;changed.head[0].successors[0]=63;
    assert(li2_pe_recover(&changed,code,raw,flags,saved,&out)==LI2_PE_CORRUPT && !out.complete);
    ++corruptions;
    changed=plan;changed.guard[0].boundary[0].dirty=1;
    assert(li2_pe_recover(&changed,code,raw,flags,saved,&out)==LI2_PE_CORRUPT && !out.complete);
    ++corruptions;
    changed=plan;changed.guard[0].boundary[1].offset=0;
    assert(li2_pe_recover(&changed,code,raw,flags,saved,&out)==LI2_PE_CORRUPT && !out.complete);
    ++corruptions;
}
static void corrupt(void) {
    /* Whole reconstruction checks source, edge topology, actual emitted image,
       immutable guard/recovery table and unused space, not counts alone. */
    const size_t offsets[]={offsetof(struct li2_pe_plan,source)+0x100,
        offsetof(struct li2_pe_plan,image)+LI2_PE_SLOT_BYTES-1,
        offsetof(struct li2_pe_plan,head)+offsetof(struct li2_pe_head,successors),
        offsetof(struct li2_pe_plan,original)+offsetof(struct li2_span_decoded,flags_read),
        offsetof(struct li2_pe_plan,frontier)+offsetof(struct li2_span_decoded,ready),
        offsetof(struct li2_pe_plan,guard)+offsetof(struct li2_mg_plan,store_offset),
        offsetof(struct li2_pe_plan,guard)+offsetof(struct li2_mg_plan,boundary),
        offsetof(struct li2_pe_plan,guard)+63*sizeof(struct li2_mg_plan),
        offsetof(struct li2_pe_plan,table)+offsetof(struct li2_mg_table,root)};
    for(unsigned i=0;i<sizeof offsets/sizeof offsets[0];i++) {
        changed=plan;((unsigned char *)&changed)[offsets[i]]^=1;
        assert(li2_pe_plan_validate(&changed,&scratch)==LI2_PE_CORRUPT);
        ++corruptions;
    }
}
static void cases(void) {
    loop();accepted(pages[0]+0x100,6,1,25,1);
    assert(plan.source_mask==3 && plan.exit_pc[0]==pages[0]+0x110);
    assert(plan.head[5].successors[0]==0 && plan.original[5].flow==LI2_REGION_JMP);
    recovery();corrupt();
    /* Original MOV width/form remains exact. */
    static const unsigned char first32[]={0x89,0x07,0x48,0x83,0xc0,1,
        0x48,0x39,0xc8,0x0f,0x82,0,0,0,0,0xc3};
    memcpy(source[0]+0x100,first32,sizeof first32);
    rel(0,0x109,6,2,pages[1]+0x100);
    accepted(pages[0]+0x100,6,1,24,1);
    assert(plan.store_original[0].width_bytes==4);
    /* An actual contiguous two-source straddle. Entry is earlier than4081;
       source holding must still independently authorize both complete pages. */
    empty();source[0][0xff0]=0xe9;rel(0,0xff0,5,1,pages[0]+0xffe);
    source[0][0xffe]=0x48;source[0][0xfff]=0x89;source[1][0]=0x47;source[1][1]=8;source[1][2]=0xc3;
    accepted(pages[0]+0xff0,2,1,9,1);assert(plan.source_mask==3);
    /* Closed cycle is refused for absent actual frontier; no termination
       theorem or 'every graph failure is a cycle' classification is inferred. */
    empty();source[0][0x100]=0xe9;rel(0,0x100,5,1,pages[0]+0x100);
    assert(li2_pe_plan_pages(pages,source,pages[0]+0x100,code,spill,&table,&plan)==LI2_PE_GRAPH && !plan.ready);++refusals;
    empty();source[0][0x100]=0xe9;rel(0,0x100,5,1,pages[1]+4096);
    assert(li2_pe_plan_pages(pages,source,pages[0]+0x100,code,spill,&table,&plan)==LI2_PE_GRAPH && !plan.ready);++refusals;
    empty();source[0][0x100]=0xc3;
    assert(li2_pe_plan_pages(pages,source,pages[0]+0x100,code,spill,&table,&plan)==LI2_PE_MISS && !plan.ready);++refusals;
    empty();source[0][0x100]=0x0f;source[0][0x101]=0x85;rel(0,0x100,6,2,pages[0]+0x107);
    source[0][0x106]=0x48;source[0][0x107]=0x89;source[0][0x108]=0xc0;source[0][0x109]=0xc3;
    assert(li2_pe_plan_pages(pages,source,pages[0]+0x100,code,spill,&table,&plan)==LI2_PE_GRAPH && !plan.ready);++refusals;
    loop();
    assert(li2_pe_plan_pages(pages,source,pages[0]+0x100,code,UINT64_C(0x200000000),&table,&plan)==LI2_PE_RELOCATION && !plan.ready);++refusals;
    assert(li2_pe_plan_pages(pages,source,pages[0]+0x100,code,code+16,&table,&plan)==LI2_PE_ARGUMENT && !plan.ready);++refusals;
}
int main(void) {
    struct li2_decoder_stats before,after;
    assert(!li2_decoder_initialize(arena,sizeof arena,&before) && before.phase==2 && !before.first_fatal_reason);
    const struct li2_mg_range ranges[]={
        {pages[0],pages[1]+4096},{code,code+LI2_PE_IMAGE_BYTES},
        {spill,spill+4096},{table_at,table_at+8192},{0x70000008,0x70000010}};
    assert(!li2_mg_table_build(ranges,sizeof ranges/sizeof ranges[0],table_at,&table));
    cases();
    assert(!li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    assert(positives==3 && refusals==19 && corruptions==12 && recoveries==46);
    printf("{\"schema\":1,\"positives\":%u,\"refusals\":%u,\"corruptions\":%u,\"recoveries\":%u,\"postseal_equal\":1}\n",
        positives,refusals,corruptions,recoveries);
    return 0;
}
