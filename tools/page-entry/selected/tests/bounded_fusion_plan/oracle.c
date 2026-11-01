/* Pure component puzzle: actual decoder/emitter, unchanged independent byte
   models. No generated/native execution, source lease, or owner credit. */
#include "persistent_fused_plan.h"
#include "persistent_block_plan.h"
/* Select the real pure runtime miss classifier in this component TU only.
   These prerequisites instantiate no owner and grant no cancellation token. */
#define LI2_PERSISTENT_FUSED_RUNTIME 1
#define LI2_PERSISTENT_RETAINED_TWO 1
#define LI2_PERSISTENT_SUBENTRY 1
#define LI2_PERSISTENT_UNREGISTERED 1
#include "persistent_fused_runtime.h"
#undef LI2_PERSISTENT_UNREGISTERED
#undef LI2_PERSISTENT_SUBENTRY
#undef LI2_PERSISTENT_RETAINED_TWO
#undef LI2_PERSISTENT_FUSED_RUNTIME
#include "tests/persistent_direct_frontier/model.h"
#include "tests/linked_mov_guard/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch,old;
static struct li2_pg_compact compact,rebuilt,bad;
static union li2_pg_guard recovery;
static struct li2_dd_plan direct;
static struct li2_mg_plan guard;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static const struct li2_pg_layout layout={{0x10000000,0x10008000},0x10010000,0x10011000,0x10012000,0x30000000};
static unsigned plans,misses,corruptions,old_checks,direct_models,mov_models,copied,interiors;
static uint64_t calls,typed_direct,typed_mov,direct_steps,mov_boundaries;
static const struct li2_pg_compact *current;
static unsigned current_head,nested;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *out) {
    ++calls;return __real_li2_decoder_decode(pc,b,n,out);
}
int __real_li2_dd_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_dd_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    uint64_t before=calls;int e=__real_li2_dd_recover(p,pc,r,flags,spill,out);assert(calls==before);
    if(current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_pf_compact_recover(current,pc,r,flags,spill,&recovery,&got));nested=0;
        assert(calls==before && got.complete==1 && got.member==current_head/64 && got.head==current_head%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_DIRECT_MAP && got.phase==LI2_DD_BEFORE &&
            got.original_pc==out->original_pc && got.flags==out->flags && !memcmp(got.gpr,out->gpr,sizeof got.gpr) &&
            !memcmp(&recovery.direct,p,sizeof *p));++typed_direct;
    }
    return e;
}
int __real_li2_mg_recover(const struct li2_mg_plan *,uintptr_t,const uint64_t[16],uint64_t,const uint64_t[4],struct li2_mg_recovered *);
int __wrap_li2_mg_recover(const struct li2_mg_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_mg_recovered *out) {
    uint64_t before=calls;int e=__real_li2_mg_recover(p,pc,r,flags,spill,out);assert(calls==before);
    if(current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_pf_compact_recover(current,pc,r,flags,spill,&recovery,&got));nested=0;
        assert(calls==before && got.complete==1 && got.member==current_head/64 && got.head==current_head%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_GUARD && got.phase==out->phase &&
            got.original_pc==out->original_pc && got.flags==out->flags && !memcmp(got.gpr,out->gpr,sizeof got.gpr) &&
            !memcmp(&recovery.mov,p,sizeof *p));++typed_mov;
    }
    return e;
}
static void reset(void) {memset(source,0xcc,sizeof source);}
static void at(unsigned offset,const unsigned char *b,unsigned n) {
    assert(offset<8192 && n<=8192-offset);
    for(unsigned i=0;i<n;i++)source[(offset+i)/4096][(offset+i)%4096]=b[i];
}
static void branch(unsigned offset,unsigned condition,uintptr_t target) {
    unsigned char b[6]={0x0f,(unsigned char)(0x80+condition)};
    const unsigned n=condition==16?5:6;if(condition==16)b[0]=0xe9;
    int64_t delta=(int64_t)target-(int64_t)(pages[0]+offset+n);assert(delta>=INT32_MIN && delta<=INT32_MAX);
    for(unsigned j=0;j<4;j++)b[n-4+j]=(unsigned char)((uint32_t)delta>>(8*j));at(offset,b,n);
}
static uint64_t flags_for(unsigned v) {
    const unsigned bits[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((v>>i)&1)<<bits[i];return f;
}
static void accept(uintptr_t entry,unsigned heads,unsigned exits,unsigned stores,unsigned links) {
    struct li2_pg_miss miss,empty={.version=11};
    assert(!li2_pf_plan_pages(pages,source,entry,&layout,&table,&full,&miss));
    assert(!memcmp(&miss,&empty,sizeof miss) && full.version==11 && full.ready==1 && full.heads==heads &&
        full.exits==exits && full.stores==stores && full.links==links && full.original[0].decoded.pc==entry);
    assert(!li2_pf_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_pf_compact_build(&full,&scratch,&compact) && !li2_pf_compact_validate(&compact,&scratch,&rebuilt) &&
        !memcmp(&compact,&rebuilt,sizeof compact));
    assert(li2_pg_plan_validate(&full,&scratch)==LI2_PG_CORRUPT && li2_pb_plan_validate(&full,&scratch)==LI2_PG_CORRUPT &&
        li2_pg_compact_validate(&compact,&scratch,&rebuilt)==LI2_PG_CORRUPT &&
        li2_pb_compact_validate(&compact,&scratch,&rebuilt)==LI2_PG_CORRUPT);old_checks+=4;++plans;
}
static void refuse(uintptr_t entry,int result,unsigned reason) {
    struct li2_pg_miss miss;
    assert(li2_pf_plan_pages(pages,source,entry,&layout,&table,&full,&miss)==result && miss.reason==reason && !full.ready);
    assert(!li2_pf_miss_validate(&full,&miss,result,&scratch));
    if(reason==LI2_PGD_EXIT_LIMIT) {
        /* The existing nine-Jcc puzzle stays a refused plan. It may only
           authorize the caller's separate genuine HELD cancellation. */
        assert(result==LI2_PG_GRAPH && full.exits==8 && miss.detail==8 &&
            li2_pfr_miss_valid(&full,&miss,result,&scratch));
        assert(!full.ready && li2_pf_plan_validate(&full,&scratch)==LI2_PG_CORRUPT &&
            li2_pf_compact_build(&full,&scratch,&compact)==LI2_PG_CORRUPT);
        for(unsigned i=0;i<6;i++) {
            struct li2_pg_miss altered=miss;
            if(i==0)altered.version^=1;
            if(i==1)altered.status^=1;
            if(i==2)altered.reason^=1;
            if(i==3)altered.site^=1;
            if(i==4)altered.pc^=1;
            if(i==5)altered.detail^=1;
            assert(!li2_pfr_miss_valid(&full,&altered,result,&scratch));
        }
        for(unsigned i=0;i<7;i++) {
            old=full;
            if(i==0)old.ready=1;
            if(i==1)old.result^=1;
            if(i==2)--old.exits;
            if(i==3)old.source[0][0x200]^=1;
            if(i==4)--old.heads;
            if(i==5)old.decoder_result=1;
            if(i==6)old.table.node[0].first^=1;
            assert(!li2_pfr_miss_valid(&old,&miss,result,&scratch));
        }
        assert(!li2_pfr_miss_valid(&full,&miss,LI2_PG_MISS,&scratch) &&
            !li2_pfr_miss_valid(&full,&miss,0,&scratch));
    } else if(reason==LI2_PFD_BACKWARD_UNSUPPORTED) {
        /* Same source and GRAPH/unready outcome as the existing backedge
           puzzle. Only this exact refused shape gets the new diagnosis. */
        assert(result==LI2_PG_GRAPH && full.heads==1 && full.exits==2 && !full.stores &&
            !full.links && full.source_bytes==6 && miss.site==LI2_PGD_SOURCE &&
            miss.pc==entry && miss.detail==pages[0]+0xf0 && full.head[0].successors[0]==LI2_PG_HEADS+1 &&
            full.exit_pc[1]==miss.detail && full.frontier[1].decoded.pc==miss.detail &&
            !full.frontier[1].ready && li2_pfr_miss_valid(&full,&miss,result,&scratch));
        assert(!full.ready && li2_pf_plan_validate(&full,&scratch)==LI2_PG_CORRUPT &&
            li2_pf_compact_build(&full,&scratch,&compact)==LI2_PG_CORRUPT);
        for(unsigned i=0;i<6;i++) {
            struct li2_pg_miss altered=miss;
            if(i==0)altered.version^=1;
            if(i==1)altered.status^=1;
            if(i==2)altered.reason^=1;
            if(i==3)altered.site^=1;
            if(i==4)altered.pc^=1;
            if(i==5)altered.detail^=1;
            assert(!li2_pfr_miss_valid(&full,&altered,result,&scratch));
        }
        for(unsigned i=0;i<13;i++) {
            old=full;
            if(i==0)old.ready=1;
            if(i==1)old.result^=1;
            if(i==2)--old.exits;
            if(i==3)old.source[0][0x100]^=1;
            if(i==4)--old.heads;
            if(i==5)old.decoder_result=1;
            if(i==6)old.table.node[0].first^=1;
            if(i==7)old.head[0].successors[0]^=1;
            if(i==8)old.exit_pc[1]^=1;
            if(i==9)old.frontier[1].decoded.pc^=1;
            if(i==10)old.frontier[1].ready=1;
            if(i==11)old.original[0].target^=1;
            if(i==12)old.source[0][0xf0]^=1;
            assert(!li2_pfr_miss_valid(&old,&miss,result,&scratch));
        }
        /* Exercise the separate internal-JMP marking site with a genuine
           planner invocation. It adds no counted puzzle or accepted graph. */
        unsigned char saved[6];memcpy(saved,source[0]+0x100,sizeof saved);
        branch(0x100,16,pages[0]+0xf0);
        struct li2_pg_miss jump_miss;
        assert(li2_pf_plan_pages(pages,source,entry,&layout,&table,&old,&jump_miss)==LI2_PG_GRAPH &&
            old.version==LI2_PF_VERSION && old.result==LI2_PG_GRAPH && !old.ready &&
            old.heads==1 && old.exits==1 && !old.stores && !old.links && old.source_bytes==5 &&
            old.original[0].flow==LI2_REGION_JMP && old.head[0].kind==LI2_PE_NONE &&
            old.head[0].successors[0]==LI2_PG_HEADS && old.exit_pc[0]==pages[0]+0xf0 &&
            old.frontier[0].decoded.pc==old.exit_pc[0] && !old.frontier[0].ready &&
            jump_miss.version==LI2_PF_VERSION && jump_miss.status==LI2_PG_GRAPH &&
            jump_miss.reason==LI2_PFD_BACKWARD_UNSUPPORTED && jump_miss.site==LI2_PGD_SOURCE &&
            jump_miss.pc==entry && jump_miss.detail==pages[0]+0xf0);
        assert(!li2_pf_miss_validate(&old,&jump_miss,LI2_PG_GRAPH,&scratch) &&
            li2_pfr_miss_valid(&old,&jump_miss,LI2_PG_GRAPH,&scratch));
        assert(li2_pf_plan_validate(&old,&scratch)==LI2_PG_CORRUPT &&
            li2_pf_compact_build(&old,&scratch,&compact)==LI2_PG_CORRUPT);
        memcpy(source[0]+0x100,saved,sizeof saved);
        assert(!memcmp(source,full.source,sizeof source));
        struct li2_pg_miss unclassified=miss;
        unclassified.reason=LI2_PGD_NONE;unclassified.site=0;unclassified.pc=0;unclassified.detail=0;
        assert(!li2_pfr_miss_valid(&full,&unclassified,result,&scratch));
        unclassified=miss;unclassified.reason=LI2_PGD_ROOT_UNSUPPORTED;
        assert(!li2_pfr_miss_valid(&full,&unclassified,result,&scratch));
        assert(!li2_pfr_miss_valid(&full,&miss,LI2_PG_MISS,&scratch) &&
            !li2_pfr_miss_valid(&full,&miss,0,&scratch));
    } else if(reason==LI2_PGD_NONE || reason==LI2_PGD_NO_EXIT) {
        /* Unclassified backward closure and a no-exit cycle remain fatal. */
        assert(!li2_pfr_miss_valid(&full,&miss,result,&scratch));
    }
    miss.detail^=1;assert(li2_pf_miss_validate(&full,&miss,result,&scratch)==LI2_PG_CORRUPT);++misses;
}
static void loop(unsigned entry) {
    /* Literal unchanged relocation loop, translated only by source base. */
    const unsigned char bytes[]={0x48,0x8b,0x10,0x4c,0x01,0xe2,0x83,0x78,0x08,0x08,
        0x0f,0x85,0x50,0x02,0x00,0x00,0x48,0x8b,0x48,0x10,0x48,0x83,0xc0,0x18,
        0x4c,0x01,0xe1,0x48,0x89,0x0a,0x48,0x39,0xd8,0x72,0xdd};
    const unsigned order[3][10]={{0x66,0x6a,0x70,0x74,0x78,0x7b,0x7e,0x81,0x60,0x63},
        {0x78,0x7b,0x7e,0x81,0x60,0x63,0x66,0x6a,0x70,0x74},
        {0x7e,0x81,0x60,0x63,0x66,0x6a,0x70,0x74,0x78,0x7b}};
    reset();at(0x60,bytes,sizeof bytes);accept(pages[0]+order[entry][0],10,2,1,0);
    assert(full.source_bytes==35 && full.source_mask==1);
    struct li2_pg_miss old_miss;
    assert(!li2_pb_plan_pages(pages,source,full.entry,&layout,&table,&old,&old_miss) && old.version==10 && !old.stores);
    if(entry==1)assert(old.heads==1 && old.exits==1 && old.exit_pc[0]==pages[0]+0x7b);
    else assert(old.heads==2 && old.exits==2 && old.head[1].kind==LI2_PG_DIRECT && old.instruction[1].direct.external_mask==3);
    ++old_checks;
    for(unsigned i=0;i<10;i++)assert(full.original[i].decoded.pc==pages[0]+order[entry][i]);
    for(unsigned i=0;i<10;i++)if(full.head[i].kind==LI2_PG_DIRECT) {
        const struct li2_dd_descriptor *d=&full.instruction[i].direct;
        assert(d->external_mask==(d->decoded.pc==pages[0]+0x6a?1U:2U));
        assert(d->target[0]==pages[0]+(d->decoded.pc==pages[0]+0x6a?0x2c0:0x60));
    }
    uint64_t r[16],spill[4]={0x1234,0x5678,0x9abc,0xdef0};
    for(unsigned j=0;j<16;j++)r[j]=UINT64_C(0x1234567800000000)+0x101*j;
    for(unsigned i=0;i<10;i++) {
        current=&compact;current_head=i;const struct li2_pe_head *h=&compact.head[i];
        if(h->kind==LI2_PG_DIRECT) {
            assert(!li2_pf_compact_direct(&compact,i/64,i%64,&direct) && !memcmp(&direct,&full.guard[i].direct,sizeof direct));
            uint64_t visited=0;
            for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<3;mode++) {
                uint64_t flags=flags_for(f);unsigned arm=dd_model_taken(direct.original.condition,flags)?0:1;
                struct li2_jd_domain_directory dir={.version=1,.serial=40};
                for(unsigned a=0;a<2;a++)if(direct.original.external_mask&(1U<<a))
                    dir.row[dir.count++]=(struct li2_jd_domain_row){direct.original.target[a]+(mode==1),0x50000000,7,0,0};
                if(mode==2)dir.count=0;
                struct dd_model_result out;assert(!dd_model_run(&direct,&dir,r,flags,&out));
                int selected=li2_pf_compact_exit(&compact,direct.original.decoded.pc,flags);
                if(direct.original.external_mask&(1U<<arm)) {
                    assert(selected==(int)(h->successors[arm]-LI2_PG_HEADS));
                    if(mode==0)assert(out.hit && !out.miss && !out.internal && out.target==0x50000000 && out.cell_writes==1);
                    else assert(out.miss && !out.hit && !out.internal && out.target==direct.original.decoded.pc && !out.cell_writes);
                } else assert(selected==-1 && out.internal && !out.hit && !out.miss && out.target==direct.internal[arm] && !out.cell_writes);
                assert(out.steps==out.recoveries);visited|=out.visited;direct_steps+=out.steps;++direct_models;
            }
            assert(direct.record.boundaries<64 && visited==((UINT64_C(1)<<direct.record.boundaries)-1));
        } else if(h->kind==LI2_PE_MOV) {
            assert(!li2_pf_compact_guard(&compact,i/64,i%64,&guard) && !memcmp(&guard,&full.guard[i].mov,sizeof guard));
            const uintptr_t address[5]={0x50000000,0x400000,0x10000000,0x30000000,0x40000000};
            for(unsigned f=0;f<64;f++)for(unsigned a=0;a<5;a++) {
                r[2]=address[a];r[1]=UINT64_C(0xfedcba9876543210);struct model_result out;
                assert(!model_run(&guard,r,flags_for(f),&out));
                if(!a)assert(out.writes==1 && !out.rejected && out.first==address[a] && out.width==8 && out.value==r[1]);
                else assert(!out.writes && out.rejected);
                assert(out.steps==out.recoveries+out.writes);mov_boundaries+=out.recoveries;++mov_models;
            }
        }
        current=0;
        for(unsigned offset=0;offset<512;offset++) {
            unsigned boundary=0;
            if(h->kind==LI2_PG_DIRECT)for(unsigned j=0;j<full.guard[i].direct.record.boundaries;j++)boundary|=offset==full.guard[i].direct.record.boundary[j].offset;
            else if(h->kind==LI2_PE_MOV)for(unsigned j=0;j<full.guard[i].mov.boundaries;j++)boundary|=offset==full.guard[i].mov.boundary[j].offset;
            else boundary=offset==0 || offset==h->source_length;
            struct li2_pg_recovered out;uintptr_t pc=layout.generated[i/64]+512*(i%64)+offset;
            if(!boundary) {assert(li2_pf_compact_recover(&compact,pc,r,flags_for(63),spill,&recovery,&out)==LI2_PG_MISS);++interiors;}
            else if(h->kind==LI2_PE_NONE) {
                assert(!li2_pf_compact_recover(&compact,pc,r,flags_for(63),spill,&recovery,&out) && out.complete==1 &&
                    out.original_pc==(offset?compact.original[i].decoded.next_pc:compact.original[i].decoded.pc) &&
                    out.phase==(offset?LI2_MG_AFTER:LI2_MG_BEFORE) && out.flags==flags_for(63) && !memcmp(out.gpr,r,sizeof r));++copied;
            }
        }
    }
}
static void puzzles(void) {
    const unsigned char mov[]={0x48,0x89,0xd8},ret[]={0xc3},call[]={0xe8,0,0,0,0},indirect[]={0xff,0xe0},movsxd[]={0x4d,0x63,0xd1},add_mem[]={0x48,0x01,0x08};
    reset();at(0x100,mov,sizeof mov);branch(0x103,4,pages[0]+0x100);accept(pages[0]+0x100,2,1,0,0);
    assert(compact.instruction[1].direct.external_mask==2 && compact.head[1].successors[0]==0);
    reset();branch(0x100,4,pages[0]-8);accept(pages[0]+0x100,1,2,0,0); /* target cut, unsupported fallthrough */
    assert(compact.instruction[0].direct.external_mask==1);
    reset();branch(8192-6,4,pages[1]+4096);accept(pages[1]+4096-6,1,2,0,0);
    assert(compact.instruction[0].direct.external_mask==3 && compact.head[0].successors[0]!=compact.head[0].successors[1]);
    reset();branch(0x100,16,pages[0]+0x200);accept(pages[0]+0x100,1,1,0,0);
    reset();at(0x100,mov,sizeof mov);branch(0x103,16,pages[0]+0x100);refuse(pages[0]+0x100,LI2_PG_GRAPH,LI2_PGD_NO_EXIT);
    reset();at(0x100,mov,sizeof mov);branch(0x103,4,pages[0]+0x101);refuse(pages[0]+0x100,LI2_PG_GRAPH,LI2_PGD_SOURCE_OVERLAP);
    reset();branch(0x100,4,pages[0]+0xf0);refuse(pages[0]+0x100,LI2_PG_GRAPH,LI2_PFD_BACKWARD_UNSUPPORTED); /* refused graph, exact PF diagnosis */
    reset();for(unsigned i=0;i<129;i++)at(0x200+3*i,mov,sizeof mov);refuse(pages[0]+0x200,LI2_PG_GRAPH,LI2_PGD_HEAD_LIMIT);
    reset();for(unsigned i=0;i<9;i++)branch(0x200+6*i,4,pages[0]+0x900);refuse(pages[0]+0x200,LI2_PG_GRAPH,LI2_PGD_EXIT_LIMIT);
    reset();for(unsigned i=0;i<65;i++)at(0x200+3*i,mov,sizeof mov);branch(0x200+65*3,4,pages[0]+0x200);
    accept(pages[0]+0x200,66,1,0,2);
    const unsigned char *unknown[5]={ret,call,indirect,movsxd,add_mem};const unsigned sizes[5]={1,5,2,3,3};
    for(unsigned i=0;i<5;i++) {
        reset();at(0x100,unknown[i],sizes[i]);refuse(pages[0]+0x100,LI2_PG_MISS,LI2_PGD_ROOT_UNSUPPORTED);
        reset();at(0x100,mov,sizeof mov);at(0x103,unknown[i],sizes[i]);accept(pages[0]+0x100,1,1,0,0);
        assert(compact.exit_pc[0]==pages[0]+0x103 && compact.frontier[0].decoded.pc==pages[0]+0x103 && !compact.frontier[0].ready);
    }
}
static void corrupt(void) {
    loop(0);
    for(unsigned i=0;i<14;i++) {
        bad=compact;
        if(i==0)bad.version=10;
        if(i==1)bad.entry=pages[0]+0x60;
        if(i==2)bad.instruction[1].direct.external_mask=3;
        if(i==3)bad.guard[1].direct.boundary[0].offset^=1;
        if(i==4)bad.head[7].successors[0]=0;
        if(i==5)bad.image[0][511]^=1;
        if(i==6)bad.source[0][0x60]^=1;
        if(i==7)bad.head[5].kind=LI2_PG_DISPATCH;
        if(i==8)bad.guard[5].mov.store_offset^=1;
        if(i==9)bad.table.node[0].first^=1;
        if(i==10)bad.instruction[5].mov.width_bytes=4;
        if(i==11)bad.original[0].decoded.reserved=1;
        if(i==12)bad.stores=0;
        if(i==13)bad.instruction[127].mov.bytes[0]=1;
        assert(li2_pf_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    const struct li2_mg_range ranges[4]={{0x400000,0x403000},{0x10000000,0x10013000},{0x30000000,0x30003000},{0x40000000,0x40060000}};
    assert(!li2_mg_table_build(ranges,4,0x40000000+offsetof(struct li2_pg_compact,table),&table));
    loop(0);loop(1);loop(2);puzzles();corrupt();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(plans==14 && misses==10 && corruptions==14 && old_checks==60 && direct_models==1536 && mov_models==1280 && copied==56);
    assert(typed_direct==2*direct_steps && typed_mov==2*mov_boundaries && interiors>0);
    printf("{\"version\":11,\"plans\":%u,\"misses\":%u,\"corruptions\":%u,\"old_version_refusals\":%u,\"direct_models\":%u,\"mov_models\":%u,\"typed_direct\":%llu,\"typed_mov\":%llu,\"copied_boundaries\":%u,\"interiors\":%u,\"emitted_execution\":0,\"owner_credit\":0}\n",
        plans,misses,corruptions,old_checks,direct_models,mov_models,(unsigned long long)typed_direct,(unsigned long long)typed_mov,copied,interiors);
    return 0;
}
