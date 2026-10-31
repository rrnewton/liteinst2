/* Actual decoder/planner/compact plus the frozen byte interpreter. No
   generated instruction or guest memory executes; supplied numeric bindings
   are not owner/window/lifetime authority. Old integration gates are separate. */
#include "persistent_group_compact.h"
#include "tests/call_dispatch/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch,bad_full;
static struct li2_pg_compact compact,rebuilt,bad_compact;
static union li2_pg_guard recovered_guard;
static struct li2_mg_table table;
static struct li2_jd_domain_directory directory;
static unsigned char source[2][4096];
static uintptr_t pages[2];
static struct li2_pg_layout layout;
static unsigned plans,models,wrapped,refusals,corruptions,geometry,capacities,interiors;
static unsigned current_head,nested;
static const struct li2_pg_compact *current;
int __real_li2_cd_recover(const struct li2_cd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_cd_recovered *);
int __wrap_li2_cd_recover(const struct li2_cd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_cd_recovered *out) {
    int e=__real_li2_cd_recover(p,pc,r,flags,spill,out);
    if(current && !nested) {
        struct li2_pg_recovered logical;nested=1;
        assert(!e && !li2_pg_compact_recover(current,pc,r,flags,spill,&recovered_guard,&logical));nested=0;
        assert(logical.complete==1 && logical.kind==LI2_PG_CALL_MAP && logical.phase==out->phase &&
            logical.member==current_head/64 && logical.head==current_head%64 && logical.link==UINT32_MAX &&
            logical.original_pc==out->original_pc && logical.flags==out->flags &&
            !memcmp(logical.gpr,out->gpr,sizeof logical.gpr) &&
            !memcmp(&recovered_guard.call,p,sizeof *p));++wrapped;
    }
    return e;
}
static uint64_t get64(const unsigned char *p) {
    uint64_t x=0;for(unsigned i=0;i<8;i++)x|=(uint64_t)p[i]<<(8*i);return x;
}
static void put32(unsigned char *p,uint32_t v) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i)); }
static void geometry_at(uintptr_t delta) {
    pages[0]=delta+0x400000;pages[1]=delta+0x401000;
    layout=(struct li2_pg_layout){.generated={delta+0x10000000,delta+0x10008000},
        .stubs=delta+0x10010000,.slots=delta+0x10011000,.spill=delta+0x10012000,
        .directory=UINT64_C(0x700000000000),.window=UINT64_C(0x700000004000)};
    const uintptr_t proof=delta+0x30000000;
    struct li2_mg_range ranges[]={
        {pages[0],pages[1]+4096},{layout.generated[0],layout.spill+4096},
        {proof,proof+0x100000},{layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES},
        {layout.window,layout.window+4096},{0x70000008,0x70000010}};
    assert(!li2_mg_table_build(ranges,sizeof ranges/sizeof ranges[0],proof+offsetof(struct li2_pg_compact,table),&table));
    memset(source,0xcc,sizeof source);
}
static unsigned call_bytes(unsigned char *out,unsigned reg) {
    unsigned n=0;if(reg>=8)out[n++]=0x41;out[n++]=0xff;out[n++]=(unsigned char)(0xd0+(reg&7));return n;
}
static void prove(uintptr_t root,unsigned heads,unsigned exits,unsigned stores,unsigned links) {
    struct li2_pg_miss miss,empty={.version=6};
    assert(!li2_pg_plan_pages(pages,source,root,&layout,&table,&full,&miss) && !memcmp(&miss,&empty,sizeof miss));
    assert(full.heads==heads && full.exits==exits && full.stores==stores && full.links==links &&
        full.version==6 && full.layout.window==layout.window);
    assert(!li2_pg_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_pg_compact_build(&full,&scratch,&compact));
    assert(!li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
    for(unsigned i=0;i<heads;i++)if(full.head[i].kind==LI2_PG_CALL) {
        union li2_pg_guard materialized;memset(&materialized,0,sizeof materialized);
        assert(!li2_pg_compact_call(&compact,i/64,i%64,&materialized.call));
        const struct li2_cd_plan *p=&materialized.call;
        assert(!memcmp(&materialized,&full.guard[i],sizeof materialized) && !li2_cd_validate(p));
        assert(p->record.image_bytes==248 && p->record.boundaries==46 && p->record.literal_offset==504 &&
            !p->record.reserved[0] && !p->record.reserved[1] && !p->record.reserved[2] &&
            p->binding.head==i && p->binding.heads==heads && p->binding.window==layout.window &&
            !full.head[i].successor_count && !full.head[i].successors[0] && !full.head[i].successors[1]);
        assert(!memcmp(p->image,&compact.image[i/64][512*(i%64)],512));
        assert(get64(p->image+504)==full.original[i].decoded.next_pc);
        for(unsigned j=248;j<504;j++)assert(p->image[j]==0);
    }
    ++plans;
}
static uint64_t flags_for(unsigned f) {
    static const unsigned bits[]={0,2,4,6,7,11};uint64_t out=0x602;
    for(unsigned i=0;i<6;i++)out|=(uint64_t)((f>>i)&1)<<bits[i];return out;
}
static void model(unsigned head,unsigned flags,unsigned mode) {
    const struct li2_cd_plan *p=&full.guard[head].call;uint64_t r[16];
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234567800000000)+0x101*i;
    r[4]=0x800200;const uint64_t target=p->original.target==4?r[4]:0x900200;r[p->original.target]=target;
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=40;directory.count=1;
    directory.row[0]=(struct li2_jd_domain_row){.pc=target,.generated=layout.generated[1],.generation=2,.slot=1,.head=0};
    struct li2_cd_window window={.version=1,.owner=0x1234,.serial=40,.first=r[4]-256,.end=r[4]+256};
    if(mode==1)directory.row[0].pc++;
    if(mode==2) {window.first=r[4]-7;window.end=window.first+512;}
    if(mode==3) {window.end=r[4]-1;window.first=window.end-512;}
    current=&compact;current_head=head;struct cd_model_result out;const unsigned prior_wrapped=wrapped;
    assert(!cd_model_run(p,&directory,&window,r,flags_for(flags),&out));current=0;
    static const unsigned expected_steps[]={36,36,19,22},expected_wrapped[]={150,146,95,104};
    assert(out.steps==expected_steps[mode] && out.recoveries==out.steps && wrapped-prior_wrapped==expected_wrapped[mode]);
    if(mode)assert(out.miss==1 && !out.hit && !out.cell_writes && !out.stack_writes && out.target==p->original.decoded.pc);
    else assert(out.hit==1 && !out.miss && out.cell_writes==1 && out.stack_writes==1 &&
        out.stack_address==r[4]-8 && out.return_word==p->original.decoded.next_pc && out.target==directory.row[0].generated);
    ++models;
}
static void canonical(void) {
    for(unsigned where=0;where<3;where++)for(unsigned reg=0;reg<16;reg++) {
        geometry_at(where==2?UINT64_C(0x500000000000):0);
        unsigned n=reg>=8?3:2;unsigned offset=where?8192-n:0x200;
        assert(call_bytes(source[offset/4096]+offset%4096,reg)==n);
        prove(pages[0]+offset,1,1,1,0);
        assert(full.head[0].kind==LI2_PG_CALL && full.instruction[0].call.target==reg && full.source_bytes==n &&
            full.exit_pc[0]==pages[0]+offset && !memcmp(&full.frontier[0],&full.original[0],sizeof full.frontier[0]) &&
            full.original[0].decoded.available==(where?n:15));
        if(where)assert(full.original[0].decoded.next_pc==pages[1]+4096);
        if(where==2)assert(get64(compact.image[0]+504)>UINT32_MAX);
        if(!where) {for(unsigned f=0;f<64;f++)model(0,f,0);for(unsigned m=1;m<=3;m++)model(0,0,m);}
        else model(0,0,0);
    }
}
static void member_and_capacity(void) {
    geometry_at(0);
    for(unsigned i=0;i<64;i++)memcpy(source[0]+0x200+4*i,"\x48\x83\xc0\x01",4);
    call_bytes(source[0]+0x300,11);prove(pages[0]+0x200,65,1,1,1);model(64,63,0);
    for(unsigned count=8;count<=9;count++) {
        geometry_at(0);
        for(unsigned i=0;i<count-1;i++) {
            unsigned at=0x200+6*i,to=0x400+4*i;
            source[0][at]=0x0f;source[0][at+1]=0x85;put32(source[0]+at+2,to-at-6);
            call_bytes(source[0]+to,i);
        }
        call_bytes(source[0]+0x200+6*(count-1),count-1);
        if(count==8)prove(pages[0]+0x200,15,8,8,0);
        else {
            struct li2_pg_miss miss;int e=li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss);
            assert(e==LI2_PG_GRAPH && !full.ready && miss.reason==LI2_PGD_EXIT_LIMIT &&
                miss.site==LI2_PGD_SOURCE && miss.detail==8 && li2_pg_miss_valid(&full,&miss,e));
        }
        ++capacities;
    }
}
static void rejected_forms(void) {
    static const unsigned char forms[][6]={{0x66,0x90},{0xe8,0,0,0,0},{0xc3},
        {0xff,0x10},{0x48,0xff,0xd0},{0x66,0xff,0xd0}};
    for(unsigned i=0;i<sizeof forms/sizeof forms[0];i++) {
        geometry_at(0);memcpy(source[0]+0x200,forms[i],sizeof forms[i]);struct li2_pg_miss miss;
        int e=li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss);
        assert(e==LI2_PG_MISS && !full.ready && miss.reason==LI2_PGD_ROOT_UNSUPPORTED &&
            miss.pc==pages[0]+0x200 && li2_pg_miss_valid(&full,&miss,e));++refusals;
    }
}
static void bad_geometry(void) {
    geometry_at(0);call_bytes(source[0]+0x200,0);const struct li2_pg_layout good=layout;
    const uintptr_t windows[]={0,good.window+1,UINT64_C(0x800000000000),pages[0],pages[1],
        good.generated[0],good.generated[1],good.stubs,good.slots,good.spill,good.directory,0x30000000};
    for(unsigned i=0;i<sizeof windows/sizeof windows[0];i++) {
        layout=good;layout.window=windows[i];struct li2_pg_miss miss;
        int e=li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss);
        assert(e==(i==11?LI2_PG_CORRUPT:LI2_PG_ARGUMENT) && !full.ready);++geometry;
    }
    layout=good;
}
static void corrupt(void) {
    geometry_at(0);call_bytes(source[0]+0x200,0);prove(pages[0]+0x200,1,1,1,0);
    for(unsigned i=0;i<9;i++) {
        bad_full=full;
        if(i==0)bad_full.guard[0].call.record.literal_offset=496;
        if(i==1)bad_full.guard[0].call.record.reserved[0]=1;
        if(i==2)bad_full.guard[0].call.record.reserved[1]=1;
        if(i==3)bad_full.guard[0].call.record.reserved[2]=1;
        if(i==4)bad_full.guard[0].call.image[504]^=1;
        if(i==5)bad_full.image[0][511]^=1;
        if(i==6)bad_full.image[0][300]=0xcc;
        if(i==7)bad_full.guard[0].bytes[sizeof(struct li2_cd_plan)]=1;
        if(i==8)bad_full.head[0].successor_count=1;
        assert(li2_pg_compact_build(&bad_full,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
    for(unsigned i=0;i<8;i++) {
        bad_compact=compact;
        if(i==0)bad_compact.image[0][504]^=1;
        if(i==1)bad_compact.image[0][511]^=1;
        if(i==2)bad_compact.image[0][300]=0xcc;
        if(i==3)bad_compact.guard[0].call.transfer_offset++;
        if(i==4)bad_compact.guard[0].call.boundary[45].phase=LI2_CD_BEFORE;
        if(i==5)bad_compact.instruction[0].call.target++;
        if(i==6)bad_compact.layout.window=layout.directory;
        if(i==7)bad_compact.original[0].decoded.bytes[15]=1;
        assert(li2_pg_compact_validate(&bad_compact,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
    uint64_t raw[16]={0},spill[4]={0};struct li2_pg_recovered out;
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;const struct li2_cd_record *r=&full.guard[0].call.record;
        for(unsigned i=0;i<r->boundaries;i++)found|=r->boundary[i].offset==offset;
        if(!found) {assert(li2_pg_compact_recover(&compact,layout.generated[0]+offset,raw,0,spill,&recovered_guard,&out)==LI2_PG_MISS);++interiors;}
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    canonical();member_and_capacity();rejected_forms();bad_geometry();corrupt();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(plans==51 && models==1105 && refusals==6 && geometry==12 && capacities==2 && corruptions==17 && interiors==466);
    assert(wrapped==164070); /* Every interpreter recovery also traverses the real compact API. */
    printf("call-dispatch-plan plans=%u models=%u refusals=%u geometry=%u capacities=%u corruptions=%u interiors=%u compact_recoveries=%u\n",
        plans,models,refusals,geometry,capacities,corruptions,interiors,wrapped);
    return 0;
}
