/* Additive component for the new linked API. The existing scalar metadata
   source, expected descriptors, populations and assertions remain unchanged.
   Supplied instruction bytes are decoded here, never executed. */
#include "linked_rseq.h"
#include <assert.h>
#include <string.h>
static unsigned independent_calls, varied_calls, independent_refusals;
static uint32_t metadata_write_footprint(uint64_t pc,const unsigned char *bytes,
        size_t length,const struct li2_write_registers *state,struct li2_write_footprint *out) {
    uint32_t result=li2_decoder_write_footprint(pc,bytes,length,state,out);
    struct li2_write_footprint linked;
    memset(&linked,0xa5,sizeof linked);
    assert(!result && !li2_decoder_link_none(pc,bytes,length,&linked));
    assert(linked.policy==LI2_WRITE_NONE && !memcmp(out,&linked,sizeof linked));
    independent_calls++;
    static const uint64_t values[]={0,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffff)};
    for(unsigned trial=0;trial<4;trial++) {
        struct li2_write_registers varied;
        for(unsigned i=0;i<16;i++)varied.gpr[i]=values[(trial+i)%4];
        varied.fs_base=values[trial];varied.gs_base=values[(trial+1)%4];
        struct li2_write_footprint actual;
        memset(&actual,0xa5,sizeof actual);
        assert(!li2_decoder_write_footprint(pc,bytes,length,&varied,&actual));
        assert(!memcmp(&actual,&linked,sizeof actual));varied_calls++;
    }
    return result;
}
static uint32_t metadata_span_describe(uint64_t pc,const unsigned char *bytes,
        size_t length,struct li2_span_decoded *out) {
    uint32_t result=li2_decoder_span_describe(pc,bytes,length,out);
    if(result || !out->ready) {
        struct li2_write_footprint linked,zero={0};
        memset(&linked,0xa5,sizeof linked);
        assert(li2_decoder_link_none(pc,bytes,length,&linked)==result);
        if(result)assert(!memcmp(&linked,&zero,sizeof linked));
        else assert(linked.policy==LI2_WRITE_UNSUPPORTED && !linked.first && !linked.end);
        independent_refusals++;
    }
    return result;
}
#define li2_decoder_write_footprint metadata_write_footprint
#define li2_decoder_span_describe metadata_span_describe
#define main scalar_metadata_main
#include "../scalar_span/metadata.c"
#undef main
#undef li2_decoder_span_describe
#undef li2_decoder_write_footprint

static struct li2_link_plan linked_plan,corrupted;
static unsigned graph_checks;
static unsigned char linked_page[4096];
static const uintptr_t BASE=UINT64_C(0x100000000);
static void jump(unsigned at,unsigned target) {
    linked_page[at]=0xe9;
    int32_t delta=(int32_t)target-(int32_t)(at+5);
    memcpy(linked_page+at+1,&delta,4);
}
static void graph(int expected,unsigned entry) {
    int actual=li2_link_plan_page(BASE,linked_page,BASE+entry,BASE+4096,&linked_plan);
    assert(actual==expected && linked_plan.ready==(unsigned)!expected);
    if(!expected)assert(!li2_link_plan_validate(&linked_plan));
    graph_checks++;stats();
}
static void graph_boundaries(void) {
    /* More than the old256-byte contiguous bound, with unreachable CC gaps.
       Every reachable supported head must remain in the graph. */
    memset(linked_page,0xcc,sizeof linked_page);
    for(unsigned i=0;i<64;i++)jump(0x100+16*i,0x100+16*(i+1));
    linked_page[0x500]=0x90;
    graph(0,0x100);
    assert(linked_plan.heads==64 && linked_plan.exits==1 && linked_plan.maps==64 &&
           linked_plan.source_bytes==320 && linked_plan.longest_path==64 && linked_plan.exit_pc[0]==BASE+0x500);
    for(unsigned i=0;i<64;i++) {
        assert(linked_plan.original[i].decoded.pc==BASE+0x100+16*i);
        assert(linked_plan.head[i].successors[0]==(i==63?64:i+1));
    }
    static const size_t corrupt_offsets[]={
        offsetof(struct li2_link_plan,heads),offsetof(struct li2_link_plan,exits),
        offsetof(struct li2_link_plan,maps),offsetof(struct li2_link_plan,longest_path),
        offsetof(struct li2_link_plan,source_bytes),offsetof(struct li2_link_plan,image_bytes),
        offsetof(struct li2_link_plan,decoder_calls),offsetof(struct li2_link_plan,entry),
        offsetof(struct li2_link_plan,source)+0x103,
        offsetof(struct li2_link_plan,image)+4095,
        offsetof(struct li2_link_plan,original)+sizeof(struct li2_span_decoded)-1,
        offsetof(struct li2_link_plan,frontier),offsetof(struct li2_link_plan,head),
        offsetof(struct li2_link_plan,exit_pc),offsetof(struct li2_link_plan,map)
    };
    for(unsigned i=0;i<sizeof corrupt_offsets/sizeof corrupt_offsets[0];i++) {
        corrupted=linked_plan;((unsigned char *)&corrupted)[corrupt_offsets[i]]^=1;
        assert(li2_link_plan_validate(&corrupted)==LI2_REGION_PLAN_CORRUPT);graph_checks++;
    }
    jump(0x500,0x510);linked_page[0x510]=0x90;
    graph(LI2_REGION_PLAN_GRAPH,0x100); /* Actual65th supported head. */
    for(unsigned frontiers=8;frontiers<=9;frontiers++) {
        memset(linked_page,0xcc,sizeof linked_page);
        for(unsigned i=0;i<frontiers-1;i++) {
            unsigned at=0x100+6*i,target=0x800+16*i;
            linked_page[at]=0x0f;linked_page[at+1]=0x84;
            int32_t delta=(int32_t)target-(int32_t)(at+6);
            memcpy(linked_page+at+2,&delta,4);linked_page[target]=0x90;
        }
        linked_page[0x100+6*(frontiers-1)]=0x90;
        graph(frontiers==8?0:LI2_REGION_PLAN_GRAPH,0x100);
        if(frontiers==8)assert(linked_plan.exits==8 && linked_plan.heads==7 && linked_plan.maps==14);
    }
    memset(linked_page,0xcc,sizeof linked_page);jump(0x100,0x100);
    graph(LI2_REGION_PLAN_GRAPH,0x100);
    memset(linked_page,0xcc,sizeof linked_page);jump(0x100,0x1000);
    graph(LI2_REGION_PLAN_GRAPH,0x100);
    memset(linked_page,0xcc,sizeof linked_page);
    /* Both paths decode; the taken head overlaps the fallthrough immediate. */
    static const unsigned char interior[]={0x74,3,0x48,0xb8,0,0x89,0xdb,0,0,0,0,0,0x90};
    memcpy(linked_page+0x100,interior,sizeof interior);
    graph(LI2_REGION_PLAN_GRAPH,0x100);
    memset(linked_page,0xcc,sizeof linked_page);jump(0x100,4095);linked_page[4095]=0x0f;
    graph(LI2_REGION_PLAN_BOUNDARY,0x100);
    stats();
}
int main(void) {
    assert(!scalar_metadata_main());
    assert(independent_calls==1283 && varied_calls==5132 && independent_refusals==26);
    assert(li2_decoder_link_none(PC,(const unsigned char *)"\x89\xdb",2,NULL)==LI2_BAD_ARGUMENT);
    independent_refusals++;
    graph_boundaries();assert(graph_checks==23);stats();
    printf("{\"schema\":1,\"linked_code_forms\":131,\"independent_calls\":%u,"
           "\"varied_register_calls\":%u,\"independent_refusals\":%u,\"graph_checks\":%u,"
           "\"max_heads\":64,\"max_frontiers\":8,\"selected_bytes\":320,\"postseal_equal\":1}\n",
           independent_calls,varied_calls,independent_refusals,graph_checks);
    return 0;
}
