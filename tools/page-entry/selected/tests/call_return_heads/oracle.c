/* Pure held-pair graph/compact and unchanged CALL/RET byte models. Numeric
   directories below do not establish live owner, mapping or stack authority. */
#include "persistent_group_compact.h"
#include "tests/call_dispatch/model.h"
#include "tests/ret_dispatch/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#if !defined(LI2_PERSISTENT_CALL_RETURN_HEADS) || LI2_PERSISTENT_CALL_RETURN_HEADS != 1
#error "explicit return-head component required"
#endif
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch;
static struct li2_pg_compact compact,rebuilt,bad;
static struct li2_mg_table table;
static struct li2_jd_domain_directory directory;
static unsigned char source[2][4096];
static uintptr_t pages[2];
static struct li2_pg_layout layout;
static unsigned plans,pairs,rsp_misses,boundaries,deduplications,capacities,refusals,corruptions;
static void put32(unsigned char *p,uint32_t v) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));
}
static void put(unsigned at,const unsigned char *p,unsigned n) {
    assert(at<=8192 && n<=8192-at);
    for(unsigned i=0;i<n;i++)source[(at+i)/4096][(at+i)%4096]=p[i];
}
static uintptr_t pc(unsigned at) {
    assert(at<8192);return pages[at/4096]+at%4096;
}
static void geometry(uintptr_t delta,unsigned gap) {
    pages[0]=delta+0x400000;pages[1]=pages[0]+(gap?0x3000:0x1000);
    layout=(struct li2_pg_layout){.generated={delta+0x10000000,delta+0x10008000},
        .stubs=delta+0x10010000,.slots=delta+0x10011000,.spill=delta+0x10012000,
        .directory=delta+0x70000000,.window=delta+0x70010000,.ret_miss=delta+0x70010040};
    const uintptr_t proof=delta+0x30000000;
    struct li2_mg_range ranges[]={{pages[0],pages[0]+4096},{pages[1],pages[1]+4096},
        {layout.generated[0],layout.spill+4096},{proof,proof+0x100000},
        {layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES},{layout.window,layout.window+4096}};
    assert(!li2_mg_table_build(ranges,6,proof+offsetof(struct li2_pg_compact,table),&table));
    memset(source,0xcc,sizeof source);
}
static unsigned call(unsigned at,unsigned reg) {
    unsigned char b[3];unsigned n=0;
    if(reg>=8)b[n++]=0x41;
    b[n++]=0xff;b[n++]=(unsigned char)(0xd0+(reg&7));put(at,b,n);return n;
}
static void branch(unsigned at,unsigned target) {
    unsigned char b[6]={0x0f,0x85};put32(b+2,(uint32_t)(pc(target)-pc(at)-6));put(at,b,6);
}
static void jump(unsigned at,unsigned target) {
    unsigned char b[5]={0xe9};put32(b+1,(uint32_t)(pc(target)-pc(at)-5));put(at,b,5);
}
static void prove(unsigned root,unsigned heads,unsigned exits,unsigned stores,unsigned links) {
    struct li2_pg_miss miss,empty={.version=8};
    assert(!li2_pg_plan_pages(pages,source,pc(root),&layout,&table,&full,&miss));
    assert(!memcmp(&miss,&empty,sizeof miss) && full.version==8 && full.ready==1 && !full.result &&
        full.heads==heads && full.exits==exits && full.stores==stores && full.links==links &&
        !memcmp(full.source,source,sizeof source) && !memcmp(full.page,pages,sizeof pages) &&
        !memcmp(&full.layout,&layout,sizeof layout) && !memcmp(&full.table,&table,sizeof table));
    assert(!li2_pg_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_pg_compact_build(&full,&scratch,&compact) && compact.version==8);
    assert(!li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
    for(unsigned i=0;i<full.heads;i++) {
        for(unsigned j=0;j<i;j++)assert(full.original[i].decoded.pc!=full.original[j].decoded.pc);
        if(full.head[i].kind==LI2_PG_CALL) {
            struct li2_cd_plan g;uint64_t literal;
            assert(!li2_pg_compact_call(&compact,i/64,i%64,&g) && !memcmp(&g,&full.guard[i].call,sizeof g));
            memcpy(&literal,g.image+504,8);
            assert(!li2_cd_validate(&g) && literal==full.original[i].decoded.next_pc &&
                !full.head[i].successor_count && !full.head[i].successors[0] && !full.head[i].successors[1] &&
                !memcmp(g.image,compact.image[i/64]+512*(i%64),512));
            unsigned exits_at_call=0;
            for(unsigned j=0;j<full.exits;j++)if(full.exit_pc[j]==g.original.decoded.pc) {
                assert(!memcmp(&full.frontier[j],&full.original[i],sizeof full.frontier[j]));++exits_at_call;
            }
            assert(exits_at_call==1);
        }
    }
    ++plans;
}
static void reject(unsigned root,int result,unsigned reason,uint64_t detail) {
    struct li2_pg_miss miss;
    assert(li2_pg_plan_pages(pages,source,pc(root),&layout,&table,&full,&miss)==result &&
        !full.ready && full.result==(unsigned)result && miss.reason==reason &&
        miss.detail==detail && li2_pg_miss_valid(&full,&miss,result));
    ++refusals;
}
static void rows(void) {
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=73;directory.count=full.heads;
    for(unsigned i=0;i<full.heads;i++)directory.row[i]=(struct li2_jd_domain_row){
        .pc=full.original[i].decoded.pc,.generated=layout.generated[i/64]+512*(i%64),
        .generation=91,.slot=0,.head=i};
}
static void roundtrips(void) {
    for(unsigned where=0;where<3;where++)for(unsigned reg=0;reg<16;reg++) {
        geometry(where==2?UINT64_C(0x500000000000):0,0);
        unsigned n=reg>=8?3:2,at=where==1?4096-n:0x200,root=at-6,next=at+n;
        branch(root,0x300);put(0x300,(const unsigned char *)"\xc3",1);assert(call(at,reg)==n);
        put(next,(const unsigned char *)"\x48\x83\xc0\x01\xff\xe3",6);
        prove(root,5,3,1,0);
        assert(full.head[1].kind==LI2_PG_RET && full.head[2].kind==LI2_PG_CALL &&
            full.original[3].decoded.pc==pc(next) && full.original[3].decoded.length==4 &&
            full.head[3].successor_count==1 && full.head[3].successors[0]==4 &&
            full.head[4].kind==LI2_PG_DISPATCH && full.source_mask==(where==1?3U:1U));
        rows();struct li2_cd_plan c;struct li2_rd_plan r;
        assert(!li2_pg_compact_call(&compact,0,2,&c) && !li2_pg_compact_ret(&compact,0,1,&r));
        uint64_t gpr[16];for(unsigned i=0;i<16;i++)gpr[i]=UINT64_C(0x1234567800000000)+0x101*i;
        gpr[4]=0x60000100;if(reg!=4)gpr[reg]=pc(0x300);
        struct li2_cd_window cw={.version=1,.owner=0x72000000,.serial=73,.first=gpr[4]-256,.end=gpr[4]+256};
        struct cd_model_result co;assert(!cd_model_run(&c,&directory,&cw,gpr,0xed7,&co));
        if(reg==4) {
            /* A real stack address is not a directory PC. Do not fabricate
               source/stack overlap to turn CALL RSP into an owner hit. */
            assert(co.miss && !co.hit && !co.stack_writes && !co.cell_writes && co.target==pc(at));++rsp_misses;
        } else {
            assert(co.hit && !co.miss && co.stack_writes==1 && co.cell_writes==1 &&
                co.return_word==pc(next) && co.stack_address==gpr[4]-8 && co.target==directory.row[1].generated);
            const uint64_t original_rsp=gpr[4];gpr[4]=co.stack_address;
            struct li2_rd_window rw={.version=1,.owner=cw.owner,.serial=cw.serial,.first=cw.first,.end=cw.end};
            struct rd_model_result ro;assert(!rd_model_run(&r,&directory,&rw,gpr,0xed7,co.return_word,1,&ro));
            assert(ro.hit && !ro.before_miss && !ro.loaded_miss && !ro.load_fault && ro.load_attempts==1 &&
                ro.guest_reads==1 && ro.target_writes==1 && ro.cell_writes==1 && !ro.stack_writes &&
                ro.target==directory.row[3].generated && ro.original_rsp==co.stack_address && ro.final_rsp==original_rsp);
            ++pairs;
        }
    }
}
static void qualified_boundaries(void) {
    for(unsigned where=0;where<3;where++)for(unsigned reg=0;reg<16;reg++) {
        geometry(where==1?UINT64_C(0x500000000000):0,where==2);
        unsigned n=reg>=8?3:2,at=(where==2?4096:8192)-n;
        assert(call(at,reg)==n);prove(at,1,1,1,0);
        uintptr_t next=pc(at)+n;
        assert(full.original[0].decoded.next_pc==next && full.original[0].decoded.available==n &&
            full.source_bytes==n && full.source_mask==(where==2?1U:2U));
        for(unsigned i=0;i<2;i++)assert(next<pages[i] || next-pages[i]>=4096);
        ++boundaries;
    }
    geometry(0,0);call(8189,0);put(8191,(const unsigned char *)"\xc3",1);prove(8189,2,2,1,0);
    assert(full.original[1].decoded.pc==pc(8191) && full.original[1].decoded.available==1);++boundaries;
    geometry(0,0);call(8189,0);put(8191,(const unsigned char *)"\x0f",1);
    reject(8189,LI2_PG_BOUNDARY,LI2_PGD_SOURCE_TRUNCATED,1);
    assert(full.heads==1 && full.exits==1);
    geometry(0,0);call(8188,0);put(8190,(const unsigned char *)"\x31\xc0",2);
    reject(8188,LI2_PG_GRAPH,LI2_PGD_OUTSIDE_PAIR,pages[1]+4096);
}
static void duplicates_and_overlap(void) {
    geometry(0,0);call(0x200,0);put(0x202,(const unsigned char *)"\xeb\xfc",2);prove(0x200,2,1,1,0);
    assert(full.head[1].successor_count==1 && full.head[1].successors[0]==0);++deduplications;
    for(unsigned reg=0;reg<=8;reg+=8) {
        geometry(0,0);unsigned n=reg?3:2;branch(0x200,0x206+n);call(0x206,reg);
        put(0x206+n,(const unsigned char *)"\xc3",1);prove(0x200,3,2,1,0);
        assert(full.original[1].decoded.pc==pc(0x206+n) && full.head[1].kind==LI2_PG_RET &&
            full.head[2].kind==LI2_PG_CALL);++deduplications;
    }
    geometry(0,0);branch(0x200,0x209);call(0x206,0);
    put(0x208,(const unsigned char *)"\x48\x83\xc0\x01\xc3",5);
    reject(0x200,LI2_PG_GRAPH,LI2_PGD_SOURCE_OVERLAP,pc(0x209));
}
/* Preorder source layout; both real JCC children enter the existing BFS.
   Depth7 fills its unchanged136-cell queue; depth6 with backedges exhausts
   the unchanged shared link+exit budget before emission. */
static unsigned tree(unsigned index,unsigned depth,unsigned leaves_return) {
    unsigned at=0x202+6*index;
    if(!depth) {
        if(leaves_return)put(at,(const unsigned char *)"\xc3",1);else jump(at,0x200);
        return index+1;
    }
    unsigned right=index+(1U<<depth);branch(at,0x202+6*right);
    assert(tree(index+1,depth-1,leaves_return)==right);
    return tree(right,depth-1,leaves_return);
}
static void limits(void) {
    const unsigned lengths[]={62,63,126,127};
    for(unsigned k=0;k<4;k++) {
        unsigned n=lengths[k];geometry(0,0);call(0x200,0);
        for(unsigned i=0;i<n;i++)put(0x202+4*i,(const unsigned char *)"\x48\x83\xc0\x01",4);
        put(0x202+4*n,(const unsigned char *)"\xc3",1);
        if(n==127)reject(0x200,LI2_PG_GRAPH,LI2_PGD_HEAD_LIMIT,128);
        else {prove(0x200,n+2,2,1,n>=63);++capacities;}
    }
    for(unsigned n=8;n<=9;n++) {
        geometry(0,0);for(unsigned i=0;i<n;i++)call(0x200+2*i,0);jump(0x200+2*n,0x200);
        if(n==8) {prove(0x200,9,8,8,0);++capacities;}
        else reject(0x200,LI2_PG_GRAPH,LI2_PGD_EXIT_LIMIT,8);
    }
    geometry(0,0);call(0x200,0);assert(tree(0,7,1)==255);
    reject(0x200,LI2_PG_GRAPH,LI2_PGD_QUEUE_LIMIT,136);
    geometry(0,0);call(0x200,0);assert(tree(0,6,0)==127);
    reject(0x200,LI2_PG_GRAPH,LI2_PGD_LINK_LIMIT,8);
}
static void corruptions_and_scope(void) {
    geometry(0,0);call(0x200,0);put(0x202,(const unsigned char *)"\xc3",1);prove(0x200,2,2,1,0);
    for(unsigned i=0;i<8;i++) {
        bad=compact;
        if(i==0)bad.heads=1;
        if(i==1)bad.head[1].source_offset++;
        if(i==2)bad.original[1].decoded.next_pc++;
        if(i==3)bad.source[0][0x202]=0x90;
        if(i==4)bad.image[0][512]^=1;
        if(i==5)bad.image[0][504]^=1;
        if(i==6)bad.head[0].successor_count=1;
        if(i==7)bad.version=7;
        assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
    const unsigned char forms[][5]={{0xe8,0,0,0,0},{0xff,0x10,0,0,0}};
    for(unsigned i=0;i<2;i++) {
        geometry(0,0);put(0x200,forms[i],5);struct li2_pg_miss miss;
        int e=li2_pg_plan_pages(pages,source,pc(0x200),&layout,&table,&full,&miss);
        assert(e==LI2_PG_MISS && !full.ready && miss.reason==LI2_PGD_ROOT_UNSUPPORTED &&
            li2_pg_miss_valid(&full,&miss,e));++refusals;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    roundtrips();qualified_boundaries();duplicates_and_overlap();limits();corruptions_and_scope();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(plans==105 && pairs==45 && rsp_misses==3 && boundaries==49 && deduplications==3 &&
        capacities==4 && refusals==9 && corruptions==8);
    printf("call-return-heads plans=%u pairs=%u rsp_misses=%u boundaries=%u deduplications=%u capacities=%u refusals=%u corruptions=%u\n",
        plans,pairs,rsp_misses,boundaries,deduplications,capacities,refusals,corruptions);
    return 0;
}
