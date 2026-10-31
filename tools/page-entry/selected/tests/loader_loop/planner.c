/* Whole pinned loader pages: all alternate branches and genuine frontiers.
   Descriptive planner component only; no generated or guest execution. */
#include "persistent_group_compact.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static unsigned char source[2][4096];
static struct li2_pg_plan plan,scratch;
static struct li2_pg_compact compact,rebuilt;
static struct li2_mg_table table;
static unsigned failures;
static void expected_graph(unsigned offset,uintptr_t bias) {
    static const unsigned first[]={0x10040,0x10021,0x1171e,0x10118,0x100a0,0x1008e,0x1009d};
    static const unsigned second[]={0x11d7a,0x10313,0x100a0,0x10c2c};
    const unsigned *frontier=offset==0x1002e?first:second;
    unsigned count=offset==0x1002e?7:4,heads=offset==0x1002e?53:27,stores=offset==0x1002e?2:5;
#ifdef LI2_ADD_GUARD
    if(offset==0x1002e){--count;++heads;++stores;}
#endif
    assert(plan.heads==heads && plan.exits==count && plan.stores==stores && !plan.links);
    unsigned found=0,adds=0;
    for(unsigned j=0;j<(offset==0x1002e?7U:4U);j++) {
#ifdef LI2_ADD_GUARD
        if(offset==0x1002e && frontier[j]==0x10021)continue;
#endif
        unsigned n=0;for(unsigned k=0;k<plan.exits;k++)n+=plan.exit_pc[k]==bias+frontier[j];
        assert(n==1);++found;
    }
    assert(found==plan.exits);
    for(unsigned i=0;i<plan.heads;i++) {
#ifdef LI2_ADD_GUARD
        if(plan.head[i].kind==LI2_PG_ADD) {
            assert(offset==0x1002e && plan.original[i].decoded.pc==bias+0x10021);
            assert(plan.head[i].successor_count==1 && plan.head[i].successors[0]<plan.heads);
            assert(plan.original[plan.head[i].successors[0]].decoded.pc==bias+0x10025);
            struct li2_ag_plan actual;
            assert(!li2_pg_compact_add(&compact,i/64,i%64,&actual));
            assert(!memcmp(&actual,&plan.guard[i].add,sizeof actual));
            assert(!li2_ag_validate(&actual));++adds;
        }
#endif
        const struct li2_pe_head *h=&plan.head[i];
        for(unsigned j=0;j<h->successor_count;j++) {
            unsigned t=h->successors[j];
            assert(t<plan.heads || (t>=LI2_PG_HEADS && t-LI2_PG_HEADS<plan.exits));
        }
    }
#ifdef LI2_ADD_GUARD
    assert(adds==(unsigned)(offset==0x1002e));
#else
    assert(adds==0);
#endif
}
static void one(uintptr_t bias,unsigned offset,const uintptr_t pages[2],const struct li2_pg_layout *layout) {
    struct li2_pg_miss miss;
    int result=li2_pg_plan_pages(pages,source,bias+offset,layout,&table,&plan,&miss);
    assert(plan.version==LI2_PG_VERSION && plan.bytes==sizeof plan && plan.result==(unsigned)result);
    assert(!memcmp(plan.page,pages,sizeof plan.page) && plan.entry==bias+offset);
    assert(!memcmp(plan.source,source,sizeof source) && !memcmp(&plan.layout,layout,sizeof *layout));
    assert(plan.heads<=LI2_PG_HEADS && plan.exits<=LI2_PG_BOUNDARIES);
    int valid=li2_pg_miss_valid(&plan,&miss,result),pv=-1,cb=-1,cv=-1;
    if(!result) {
        const struct li2_pg_miss empty={.version=LI2_PG_VERSION};
        assert(plan.ready==1 && !memcmp(&miss,&empty,sizeof miss));
        pv=li2_pg_plan_validate(&plan,&scratch);
        cb=li2_pg_compact_build(&plan,&scratch,&compact);
        if(!cb)cv=li2_pg_compact_validate(&compact,&scratch,&rebuilt);
    }
    printf("{\"root_offset\":%u,\"root_pc\":%llu,\"result\":%d,\"ready\":%u,"
        "\"decoder_result\":%u,\"guard_result\":%u,\"heads\":%u,\"member_heads\":[%u,%u],"
        "\"stores\":%u,\"links\":%u,\"exits\":%u,\"source_bytes\":%u,\"source_mask\":%u,"
        "\"miss\":{\"version\":%u,\"status\":%u,\"reason\":%u,\"site\":%u,\"pc\":%llu,\"detail\":%llu},"
        "\"miss_valid\":%d,\"plan_validate\":%d,\"compact_build\":%d,\"compact_validate\":%d,\"head_rows\":[",
        offset,(unsigned long long)(bias+offset),result,plan.ready,plan.decoder_result,plan.guard_result,
        plan.heads,plan.member_heads[0],plan.member_heads[1],plan.stores,plan.links,plan.exits,
        plan.source_bytes,plan.source_mask,miss.version,miss.status,miss.reason,miss.site,
        (unsigned long long)miss.pc,(unsigned long long)miss.detail,valid,pv,cb,cv);
    for(unsigned i=0;i<plan.heads;i++) {
        const struct li2_pe_head *h=&plan.head[i];const struct li2_span_decoded *d=&plan.original[i];
        printf("%s[%llu,%u,%u,%u,%u,%llu,%u,%u,%u]",i?",":"",(unsigned long long)d->decoded.pc,
            d->decoded.length,h->kind,d->decoded.code,d->flow,(unsigned long long)d->target,
            h->successor_count,h->successors[0],h->successors[1]);
    }
    printf("],\"frontier_rows\":[");
    for(unsigned i=0;i<plan.exits;i++) {
        const struct li2_span_decoded *d=&plan.frontier[i];
        printf("%s[%llu,%u,%u,%u,%u,%u]",i?",":"",(unsigned long long)d->decoded.pc,
            d->decoded.length,d->decoded.kind,d->decoded.code,d->ready,d->refusal);
    }
    printf("]}\n");assert(!fflush(stdout));
    /* Report the actual failed result first; never convert terminal failure to a miss. */
    failures|=result!=0 || pv!=0 || cb!=0 || cv!=0;
    if(!failures)expected_graph(offset,bias);
}
int main(int argc,char **argv) {
    assert(argc==3);char *end=0;unsigned long long raw=strtoull(argv[2],&end,16);
    assert(end && !*end && raw>=4096 && !(raw&4095) && raw<UINT64_C(0x800000000000)-0x4000000);
    uintptr_t bias=(uintptr_t)raw,pages[2]={bias+0x10000,bias+0x11000};
    FILE *f=fopen(argv[1],"rb");assert(f);
    assert(fread(source,1,sizeof source,f)==sizeof source && fgetc(f)==EOF && !ferror(f));assert(!fclose(f));
    /* Supplied disjoint lower-canonical near placement, never a mapping claim. */
    uintptr_t image=bias+0x1000000,proof=bias+0x1800000;
    const struct li2_pg_layout layout={{image,image+0x8000},image+0x10000,image+0x11000,
        image+0x12000,bias+0x1400000};
    const struct li2_mg_range ranges[]={
        {pages[0],pages[1]+4096},{image,image+0x13000},
        {layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES},
        {proof,proof+((sizeof compact+4095)&~(size_t)4095)},
        {bias+0x1c00008,bias+0x1c00010}};
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    assert(!li2_mg_table_build(ranges,5,proof+offsetof(struct li2_pg_compact,table),&table));
    assert(li2_pg_placement(pages[0],&layout)==1);
    one(bias,0x1002e,pages,&layout);one(bias,0x102c8,pages,&layout);
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        before.allocation_calls==after.allocation_calls && before.deallocation_calls==after.deallocation_calls);
    return failures?1:0;
}
