/* Finite pure planner + actual generated-byte model. No generated execution. */
#include "persistent_block_plan.h"
#include "tests/persistent_direct_frontier/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch,old,bad_full;
static struct li2_pg_compact compact,rebuilt,bad;
static struct li2_dd_plan recovery,materialized;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static const struct li2_pg_layout layout={{0x10000000,0x10008000},0x10010000,0x10011000,0x10012000,0x30000000};
static unsigned plans,models,misses,corruptions,old_checks,selectors,interiors,copied,links;
static uint64_t calls,typed,steps;
static const struct li2_pg_compact *current;
static unsigned nested;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *d) {
    ++calls;return __real_li2_decoder_decode(pc,b,n,d);
}
int __real_li2_dd_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_dd_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    uint64_t before=calls;
    int e=__real_li2_dd_recover(p,pc,r,flags,spill,out);assert(calls==before);
    if(current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_pb_compact_recover(current,pc,r,flags,spill,&recovery,&got));nested=0;
        unsigned i=current->heads-1;
        assert(calls==before && got.complete==1 && got.member==i/64 && got.head==i%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_DIRECT_MAP && got.phase==LI2_DD_BEFORE &&
            got.original_pc==out->original_pc && got.flags==out->flags &&
            !memcmp(got.gpr,out->gpr,sizeof got.gpr) && !memcmp(&recovery,p,sizeof recovery));
        ++typed;
    }
    return e;
}
static void put32(unsigned char *p,int64_t n) {
    assert(n>=INT32_MIN && n<=INT32_MAX);uint32_t x=(uint32_t)n;
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(x>>(8*i));
}
static void at(unsigned offset,const unsigned char *b,unsigned n) {
    assert(offset<8192 && n<=8192-offset);
    for(unsigned i=0;i<n;i++)source[(offset+i)/4096][(offset+i)%4096]=b[i];
}
static void reset(void) {memset(source,0xcc,sizeof source);}
static void prefix(unsigned count) {
    const unsigned char x[]={0x31,0xc0};
    for(unsigned i=0;i<count;i++)at(0x200+i*2,x,2);
}
static void branch(unsigned offset,unsigned length,unsigned condition,uintptr_t target) {
    unsigned char b[6]={0};
    if(condition==16)b[0]=length==2?0xeb:0xe9;
    else if(length==2)b[0]=(unsigned char)(0x70+condition);
    else {b[0]=0x0f;b[1]=(unsigned char)(0x80+condition);}
    int64_t delta=(int64_t)target-(int64_t)(pages[0]+offset+length);
    if(length==2) {assert(delta>=INT8_MIN && delta<=INT8_MAX);b[1]=(unsigned char)delta;}
    else put32(b+length-4,delta);
    at(offset,b,length);
}
static void accept(uintptr_t entry,unsigned heads,unsigned exits,unsigned capacity_links) {
    struct li2_pg_miss miss,zero={.version=LI2_PB_VERSION};
    assert(!li2_pb_plan_pages(pages,source,entry,&layout,&table,&full,&miss));
    assert(!memcmp(&miss,&zero,sizeof miss) && full.version==LI2_PB_VERSION && full.ready==1 &&
        full.heads==heads && full.exits==exits && full.links==capacity_links && !full.stores &&
        !memcmp(full.source,source,sizeof source));
    assert(!li2_pb_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_pb_compact_build(&full,&scratch,&compact) && !li2_pb_compact_validate(&compact,&scratch,&rebuilt) &&
        !memcmp(&compact,&rebuilt,sizeof compact));
    assert(li2_pg_plan_validate(&full,&scratch)==LI2_PG_CORRUPT &&
        li2_pg_compact_validate(&compact,&scratch,&rebuilt)==LI2_PG_CORRUPT);
    ++plans;
}
static uint64_t flags_for(unsigned value) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((value>>i)&1)<<bits[i];return f;
}
static void model(void) {
    unsigned i=compact.heads-1;const struct li2_dd_plan *p=&full.guard[i].direct;
    assert(!li2_pb_compact_direct(&compact,i/64,i%64,&materialized) && !memcmp(p,&materialized,sizeof *p) &&
        !li2_dd_validate(p) && !p->internal[0] && !p->internal[1]);
    uint64_t r[16],spill[4]={UINT64_MAX,0xdead,0xbeef,0x1234};
    for(unsigned j=0;j<16;j++)r[j]=UINT64_C(0x1234567800000000)+0x101*j;
    current=&compact;uint64_t visited=0;
    for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<3;mode++) {
        struct li2_jd_domain_directory dir={.version=1,.serial=40};
        unsigned arms=p->original.flow==LI2_REGION_JCC?2U:1U;
        for(unsigned arm=0;arm<arms;arm++) {
            uintptr_t pc=p->original.target[arm]+(mode==1?1U:0U);
            if(dir.count && dir.row[0].pc==pc)continue;
            unsigned j=(unsigned)dir.count++;
            dir.row[j]=(struct li2_jd_domain_row){pc,0x50000000+512*j,7,j,j};
        }
        if(mode==2)dir.count=0;
        struct dd_model_result out;uint64_t flags=flags_for(f);
        unsigned arm=arms==1?0U:(dd_model_taken(p->original.condition,flags)?0U:1U);
        assert(li2_pb_compact_exit(&compact,p->original.decoded.pc,flags)==(int)arm);++selectors;
        assert(!dd_model_run(p,&dir,r,flags,&out) && !out.internal && out.steps==out.recoveries);
        if(mode==0) {
            unsigned j=0;while(j<dir.count && dir.row[j].pc!=p->original.target[arm])++j;
            assert(j<dir.count && out.hit==1 && !out.miss && out.target==dir.row[j].generated && out.cell_writes==1);
        } else assert(out.miss==1 && !out.hit && !out.cell_writes && out.target==p->original.decoded.pc);
        visited|=out.visited;steps+=out.steps;++models;
    }
    current=0;
    assert(visited==((UINT64_C(1)<<p->record.boundaries)-1));
    for(unsigned offset=0;offset<512;offset++) {
        unsigned boundary=0;
        for(unsigned j=0;j<p->record.boundaries;j++)boundary|=offset==p->record.boundary[j].offset;
        if(!boundary) {
            struct li2_pg_recovered out;
            assert(li2_pb_compact_recover(&compact,p->generated+offset,r,flags_for(63),spill,&recovery,&out)==LI2_PG_MISS);
            ++interiors;
        }
    }
    for(unsigned j=0;j<i;j++)for(unsigned after=0;after<2;after++) {
        struct li2_pg_recovered out;uintptr_t pc=layout.generated[j/64]+512*(j%64);
        if(after)pc+=compact.head[j].source_length;
        assert(!li2_pb_compact_recover(&compact,pc,r,flags_for(63),spill,&recovery,&out) &&
            out.complete==1 && out.original_pc==(after?compact.original[j].decoded.next_pc:compact.original[j].decoded.pc) &&
            out.phase==(after?LI2_MG_AFTER:LI2_MG_BEFORE) && out.flags==flags_for(63) &&
            !memcmp(out.gpr,r,sizeof r));++copied;
    }
    if(compact.links) {
        struct li2_pg_recovered out;
        assert(!li2_pb_compact_recover(&compact,layout.stubs,r,flags_for(63),spill,&recovery,&out) &&
            out.complete==1 && out.kind==LI2_PG_LINK && out.phase==LI2_PG_COMMITTED_EDGE &&
            out.original_pc==compact.original[64].decoded.pc && out.flags==flags_for(63) && !memcmp(out.gpr,r,sizeof r));++links;
    }
}
static void positives(void) {
    for(unsigned c=0;c<16;c++)for(unsigned near=0;near<2;near++) {
        reset();prefix(1);branch(0x202,near?6:2,c,0x400280);accept(0x400200,2,2,0);model();
    }
    for(unsigned near=0;near<2;near++) {
        reset();prefix(1);branch(0x202,near?5:2,16,0x400280);accept(0x400200,2,1,0);model();
    }
    reset();branch(0x200,2,16,0x400200);accept(0x400200,1,1,0);model();
    struct li2_pg_miss miss;
    assert(li2_pg_plan_pages(pages,source,0x400200,&layout,&table,&old,&miss)==LI2_PG_GRAPH &&
        miss.reason==LI2_PGD_NO_EXIT && !old.ready);++old_checks;
    reset();prefix(1);branch(0x202,2,16,0x400200);accept(0x400200,2,1,0);model();
    reset();branch(0x200,2,4,0x400202);accept(0x400200,1,2,0);model();
    assert(compact.instruction[0].direct.target[0]==compact.instruction[0].direct.target[1] &&
        compact.head[0].successors[0]==128 && compact.head[0].successors[1]==129);
    reset();const unsigned char x[]={0x31,0xc0};at(4093,x,2);branch(4095,5,16,0x402100);
    accept(0x400ffd,2,1,0);assert(compact.source_mask==3 && compact.source_bytes==7);model();
    const unsigned n[3]={63,64,127};
    for(unsigned j=0;j<3;j++) {
        reset();prefix(n[j]);branch(0x200+n[j]*2,5,16,0x500000);
        accept(0x400200,n[j]+1,1,j?1:0);model();
        assert(!li2_pg_plan_pages(pages,source,0x400200,&layout,&table,&old,&miss) &&
            old.version==LI2_PG_VERSION && old.heads==full.heads && old.exits==full.exits && old.links==full.links &&
            !li2_pg_plan_validate(&old,&scratch));++old_checks;
    }
    reset();
    for(unsigned j=0;j<8;j++)branch(8176+2*j,2,j,0x402020);
    accept(0x401ff0,1,2,0);model();
    assert(li2_pg_plan_pages(pages,source,0x401ff0,&layout,&table,&old,&miss)==LI2_PG_GRAPH &&
        miss.reason==LI2_PGD_EXIT_LIMIT && li2_pg_miss_valid(&old,&miss,LI2_PG_GRAPH) && !old.ready);++old_checks;
    reset();prefix(1);const unsigned char store[]={0x48,0x89,7};at(0x202,store,sizeof store);
    accept(0x400200,1,1,0);assert(compact.exit_pc[0]==0x400202 && !compact.frontier[0].ready);
    assert(!li2_pg_plan_pages(pages,source,0x400200,&layout,&table,&old,&miss) && old.heads==2 && old.stores==1);++old_checks;
    reset();prefix(1);const unsigned char syscall[]={0x0f,0x05};at(0x202,syscall,2);
    accept(0x400200,1,1,0);assert(compact.exit_pc[0]==0x400202 && compact.frontier[0].decoded.kind==LI2_SYSCALL);
}
static void refuse(const uintptr_t pair[2],uintptr_t entry,int status,unsigned reason) {
    struct li2_pg_miss miss;
    assert(li2_pb_plan_pages(pair,source,entry,&layout,&table,&full,&miss)==status && !full.ready &&
        miss.reason==reason && !li2_pb_miss_validate(&full,&miss,status,&scratch));++misses;
}
static void negatives(void) {
    reset();prefix(128);branch(0x300,5,16,0x500000);refuse(pages,0x400200,LI2_PG_GRAPH,LI2_PGD_HEAD_LIMIT);
    reset();prefix(1);branch(0x202,2,16,0x400201);refuse(pages,0x400200,LI2_PG_GRAPH,LI2_PGD_SOURCE_OVERLAP);
    reset();prefix(1);branch(0x202,2,16,0x400203);refuse(pages,0x400200,LI2_PG_GRAPH,LI2_PGD_SOURCE_OVERLAP);
    const unsigned char refused[][5]={{0x48,0x89,7},{0xe8,0,0,0,0},{0xc3},{0xff,0xe0},{0x0f,0x05}};
    for(unsigned j=0;j<5;j++) {
        reset();at(0x200,refused[j],5);
        refuse(pages,0x400200,LI2_PG_MISS,j==4?LI2_PGD_ROOT_SELECTED:LI2_PGD_ROOT_UNSUPPORTED);
    }
    reset();const unsigned char xor[]={0x31,0xc0};at(8190,xor,2);refuse(pages,0x401ffe,LI2_PG_GRAPH,LI2_PGD_OUTSIDE_PAIR);
    const uintptr_t gap[2]={0x400000,0x402000};reset();source[0][4095]=0xe9;
    refuse(gap,0x400fff,LI2_PG_BOUNDARY,LI2_PGD_SOURCE_TRUNCATED);
    reset();branch(0x200,2,16,0x400280);
    struct li2_pg_layout far=layout;far.generated[0]+=0x80000000;far.generated[1]+=0x80000000;
    far.stubs+=0x80000000;far.slots+=0x80000000;far.spill+=0x80000000;
    struct li2_pg_miss miss;
    assert(li2_pb_plan_pages(pages,source,0x400200,&far,&table,&full,&miss)==LI2_PG_RELOCATION &&
        !full.ready && full.guard_result==LI2_DD_RELOCATION &&
        !li2_pb_miss_validate(&full,&miss,LI2_PG_RELOCATION,&scratch));++misses;
}
static void corrupt(void) {
    reset();prefix(1);branch(0x202,2,4,0x400280);accept(0x400200,2,2,0);
    for(unsigned k=0;k<16;k++) {
        bad=compact;
        if(k==0)bad.version=LI2_PG_COMPACT_VERSION;
        if(k==1)bad.heads++;
        if(k==2)bad.head[1].successors[1]=bad.head[1].successors[0];
        if(k==3)bad.instruction[1].direct.external_mask=1;
        if(k==4)bad.instruction[1].direct.target[0]++;
        if(k==5)bad.frontier[1].decoded.pc++;
        if(k==6)bad.original[0].decoded.bytes[0]^=1;
        if(k==7)bad.source[0][0x200]^=1;
        if(k==8)bad.image[0][512]^=1;
        if(k==9)bad.image[1][32767]^=1;
        if(k==10)bad.stub_image[4095]^=1;
        if(k==11)bad.guard[1].direct.boundary[0].dirty=1;
        if(k==12)bad.guard[127].mov.boundary[0].offset=1;
        if(k==13)bad.table.node[130].left^=1;
        if(k==14)bad.instruction[127].mov.bytes[0]=1;
        if(k==15)bad.stores=1;
        assert(li2_pb_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
    for(unsigned k=0;k<5;k++) {
        bad_full=full;
        if(k==0)bad_full.version=LI2_PG_VERSION;
        if(k==1)bad_full.guard[1].direct.internal[0]=layout.generated[0];
        if(k==2)bad_full.guard[1].direct.image[511]=1;
        if(k==3)bad_full.source[0][0x200]^=1;
        if(k==4)bad_full.original[127].decoded.reserved=1;
        assert(li2_pb_plan_validate(&bad_full,&scratch)==LI2_PG_CORRUPT);++corruptions;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    const struct li2_mg_range ranges[4]={{0x400000,0x403000},{0x10000000,0x10013000},
        {0x30000000,0x30003000},{0x40000000,0x40060000}};
    assert(!li2_mg_table_build(ranges,4,0x40000000+offsetof(struct li2_pg_compact,table),&table));
    positives();negatives();corrupt();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(plans==45 && models==8064 && selectors==8064 && misses==11 && corruptions==21 && old_checks==6 && links==2);
    assert(typed==2*steps && steps>models && copied==580 && interiors==19848);
    printf("{\"version\":10,\"plans\":%u,\"models\":%u,\"selectors\":%u,\"misses\":%u,\"corruptions\":%u,\"old_checks\":%u,\"capacity_links\":%u,\"typed_recoveries\":%llu,\"steps\":%llu,\"copied_boundaries\":%u,\"interiors\":%u,\"emitted_execution\":0,\"owner_credit\":0}\n",
        plans,models,selectors,misses,corruptions,old_checks,links,(unsigned long long)typed,(unsigned long long)steps,copied,interiors);
    return 0;
}
