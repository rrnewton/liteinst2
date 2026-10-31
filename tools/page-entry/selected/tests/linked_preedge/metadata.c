/* Supplied-byte planner component only: no guest instruction execution,
   source lease, generated permission, live frame or rseq authority. */
#include "linked_preedge_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[2*1024*1024];
static struct li2_decoder_stats initial;
static struct li2_preedge_plan candidate,corrupt,saved;
static struct li2_link_plan previous;
static unsigned char page[4096];
static const uintptr_t BASE=UINT64_C(0x100000000),GENERATED=UINT64_C(0x100010000);
static unsigned cases,corruptions,jcc_outcomes;
static void stable(void) {
    struct li2_decoder_stats actual;
    assert(!li2_decoder_stats(&actual) && !memcmp(&actual,&initial,sizeof actual));
}
static void reset(void) { memset(page,0xcc,sizeof page); }
static void mov(unsigned at) { page[at]=0x89;page[at+1]=0xdb; }
static void branch(unsigned at,unsigned target) {
    page[at]=0xe9;int32_t delta=(int32_t)target-(int32_t)(at+5);
    memcpy(page+at+1,&delta,4);
}
static void plans(unsigned entry,int now,int old) {
    int a=li2_preedge_plan_page(BASE,page,BASE+entry,GENERATED,&candidate);
    int b=li2_link_plan_page(BASE,page,BASE+entry,GENERATED,&previous);
    assert(a==now && b==old && candidate.ready==(unsigned)!now && previous.ready==(unsigned)!old);
    assert(candidate.version==2 && candidate.bytes==40744 && !candidate.reserved);
    assert(previous.version==1);
    if(!a)assert(!li2_preedge_plan_validate(&candidate));
    if(!b)assert(!li2_link_plan_validate(&previous));
    cases++;stable();
}
static void unchanged_unsupported(void) {
    assert(candidate.heads==previous.heads && candidate.exits==previous.exits &&
        candidate.maps==previous.maps && candidate.longest_path==previous.longest_path &&
        candidate.source_bytes==previous.source_bytes && candidate.image_bytes==previous.image_bytes &&
        candidate.decoder_calls==previous.decoder_calls && candidate.decoder_result==previous.decoder_result &&
        candidate.page==previous.page && candidate.entry==previous.entry && candidate.generated==previous.generated);
#define SAME(member) assert(!memcmp(&candidate.member,&previous.member,sizeof candidate.member))
    SAME(source);SAME(image);SAME(original);SAME(frontier);SAME(head);SAME(exit_pc);SAME(map);
#undef SAME
    for(unsigned i=0;i<8;i++)assert(candidate.frontier_kind[i]==(i<candidate.exits?LI2_PREEDGE_UNSUPPORTED:0));
}
static void cut(unsigned pc,unsigned flow) {
    assert(candidate.heads==1 && candidate.exits==1 && candidate.maps==2 &&
        candidate.longest_path==1 && candidate.source_bytes==2 && candidate.image_bytes==7 &&
        candidate.frontier_kind[0]==LI2_PREEDGE_PAGE_CUT && candidate.exit_pc[0]==BASE+pc);
    const struct li2_span_decoded *d=&candidate.frontier[0];
    assert(d->ready==1 && !d->refusal && d->flow==flow && d->decoded.pc==BASE+pc);
    assert(candidate.head[0].successor_count==1 && candidate.head[0].successors[0]==64);
    assert(candidate.map[0].source_length==2 && candidate.map[0].original_pc==candidate.entry &&
        candidate.map[1].source_length==0 && candidate.map[1].original_pc==BASE+pc &&
        candidate.map[1].kind==LI2_REGION_PC_EXIT && candidate.image[2]==0xe9);
    int32_t delta;memcpy(&delta,candidate.image+3,4);
    assert((uintptr_t)((int64_t)(GENERATED+7)+delta)==BASE+pc);
    for(unsigned i=7;i<4096;i++)assert(candidate.image[i]==0xcc);
    for(unsigned i=1;i<8;i++)assert(!candidate.frontier_kind[i]);
    if(flow==LI2_REGION_JCC) {
        /* Both actual original outcomes are deferred. This is a static
           descriptor check, not claimed native execution of either outcome. */
        for(unsigned taken=0;taken<2;taken++) {
            uintptr_t next=taken?d->target:d->decoded.next_pc;
            assert(next!=candidate.exit_pc[0]);jcc_outcomes++;
        }
    }
}
static void refused(void) {
    assert(li2_preedge_plan_validate(&corrupt)==LI2_REGION_PLAN_CORRUPT);
    corruptions++;stable();
}
static void mutations(void) {
    corrupt=saved;corrupt.version=1;refused();
    corrupt=saved;corrupt.bytes=sizeof(struct li2_link_plan);refused();
    corrupt=saved;corrupt.reserved=1;refused();
    corrupt=saved;corrupt.frontier_kind[0]=LI2_PREEDGE_NONE;refused();
    corrupt=saved;corrupt.frontier_kind[0]=LI2_PREEDGE_UNSUPPORTED;refused();
    corrupt=saved;corrupt.frontier_kind[0]=99;refused();
    corrupt=saved;corrupt.frontier_kind[7]=LI2_PREEDGE_PAGE_CUT;refused();
    corrupt=saved;corrupt.frontier_kind[0]=LI2_PREEDGE_UNSUPPORTED;
    corrupt.frontier[0].ready=0;corrupt.frontier[0].refusal=1;refused();
    corrupt=saved;corrupt.frontier[0].target=BASE+32;
    corrupt.frontier[0].operands[0].immediate=BASE+32;refused();
    corrupt=saved;corrupt.exit_pc[0]=saved.frontier[0].target;refused();
    corrupt=saved;corrupt.frontier[0].decoded.bytes[0]^=1;refused();
    corrupt=saved;corrupt.image[4095]^=1;refused();
    corrupt=saved;corrupt.map[0].original_pc++;refused();
    corrupt=saved;corrupt.head[0].successors[0]=0;refused();
    corrupt=saved;corrupt.head[0].generated_length=1;refused();
    corrupt=saved;corrupt.original[0].gpr_write^=1;refused();
    corrupt=saved;corrupt.maps=0;refused();
    corrupt=saved;corrupt.source[1]=0xda;refused(); /* Valid different MOV. */
}
int main(void) {
    assert(!li2_decoder_initialize(arena,sizeof arena,&initial));
    assert(initial.abi_version==1 && initial.phase==2 && !initial.first_fatal_reason &&
        !initial.reserved && initial.arena_bytes==sizeof arena && initial.retained_high_water &&
        initial.retained_high_water<=sizeof arena);
    reset();mov(0);page[2]=0x90;
    plans(0,0,0);unchanged_unsupported();
    reset();mov(0);branch(2,4096);
    plans(0,0,LI2_REGION_PLAN_GRAPH);cut(2,LI2_REGION_JMP);
    reset();mov(0);page[2]=0x75;page[3]=0xf8; /* Taken leaves; fallthrough stays. */
    plans(0,0,LI2_REGION_PLAN_GRAPH);cut(2,LI2_REGION_JCC);saved=candidate;
    reset();mov(4092);page[4094]=0x75;page[4095]=0x80; /* Fallthrough leaves. */
    plans(4092,0,LI2_REGION_PLAN_GRAPH);cut(4094,LI2_REGION_JCC);
    reset();mov(4092);page[4094]=0x31;page[4095]=0xc0; /* Whole XOR ends at page end. */
    plans(4092,0,LI2_REGION_PLAN_GRAPH);cut(4094,LI2_REGION_NEXT);
    /* XOR eax,eax has constant flag effects; no flag is in the dynamic-written
       category. This entire descriptor is a cut, not an emitted effect. */
    assert(candidate.frontier[0].flags_read==0 && candidate.frontier[0].flags_written==0 &&
        candidate.frontier[0].flags_set==0x44 && candidate.frontier[0].flags_cleared==0x881 &&
        candidate.frontier[0].flags_undefined==0x10 && candidate.original[0].flags_read==0 &&
        candidate.original[0].flags_written==0 && candidate.original[0].flags_set==0 &&
        candidate.original[0].flags_cleared==0 && candidate.original[0].flags_undefined==0);
    reset();branch(0,4096);plans(0,LI2_REGION_PLAN_MISS,LI2_REGION_PLAN_GRAPH);
    reset();mov(4092);page[4094]=0x48;page[4095]=0xb8;
    plans(4092,LI2_REGION_PLAN_BOUNDARY,LI2_REGION_PLAN_BOUNDARY);
    reset();mov(0);page[2]=0x75;page[3]=0xfc;page[4]=0x90;
    plans(0,LI2_REGION_PLAN_GRAPH,LI2_REGION_PLAN_GRAPH); /* Cycle plus frontier. */
    reset();branch(0,0);plans(0,LI2_REGION_PLAN_GRAPH,LI2_REGION_PLAN_GRAPH);
    reset();static const unsigned char overlap[]={0x74,3,0x48,0xb8,0,0x89,0xdb,0,0,0,0,0,0x90};
    memcpy(page,overlap,sizeof overlap);plans(0,LI2_REGION_PLAN_GRAPH,LI2_REGION_PLAN_GRAPH);
    reset();for(unsigned i=0;i<65;i++)branch(16*i,16*(i+1));page[16*65]=0x90;
    plans(0,LI2_REGION_PLAN_GRAPH,LI2_REGION_PLAN_GRAPH);
    for(unsigned exits=8;exits<=9;exits++) {
        reset();for(unsigned i=0;i<exits-1;i++) {
            unsigned at=6*i,target=0x800+16*i;
            page[at]=0x0f;page[at+1]=0x84;int32_t delta=(int32_t)target-(int32_t)(at+6);
            memcpy(page+at+2,&delta,4);page[target]=0x90;
        }
        page[6*(exits-1)]=0x90;
        plans(0,exits==8?0:LI2_REGION_PLAN_GRAPH,exits==8?0:LI2_REGION_PLAN_GRAPH);
        if(exits==8)unchanged_unsupported();
    }
    mutations();assert(cases==13 && corruptions==18 && jcc_outcomes==4);stable();
    printf("{\"schema\":2,\"plan_bytes\":40744,\"cases\":13,\"corruptions\":18,"
        "\"jcc_outcome_descriptions\":4,\"max_heads\":64,\"max_frontiers\":8,"
        "\"max_maps\":128,\"postseal_equal\":1,\"native_execution\":0}\n");
    return 0;
}
