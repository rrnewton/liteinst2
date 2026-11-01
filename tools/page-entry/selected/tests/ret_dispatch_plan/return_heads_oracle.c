/* Pure cold planner/compact integration with the unchanged RET byte model.
   No guest or generated code executes; this does not establish owner custody. */
#include "persistent_group_compact.h"
#include "tests/ret_dispatch/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch,bad_full;
static struct li2_pg_compact compact,rebuilt,bad;
static union li2_pg_guard guard;
static struct li2_mg_table table;
static struct li2_jd_domain_directory directory;
static unsigned char source[2][4096];
static uintptr_t pages[2];
static struct li2_pg_layout layout;
static unsigned plans,models,wrapped,loaded,refusals,geometry,capacities,corruptions,interiors,landings,arguments;
static unsigned far_plans,far_corruptions;
static unsigned current_head,nested,seen[LI2_RD_BOUNDARIES];
static const struct li2_pg_compact *current;
int __real_li2_rd_recover(const struct li2_rd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[6],struct li2_rd_recovered *);
int __real_li2_rd_recover_loaded_miss(const struct li2_rd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[6],struct li2_rd_recovered *);
int __wrap_li2_rd_recover(const struct li2_rd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[6],struct li2_rd_recovered *out) {
    int e=__real_li2_rd_recover(p,pc,r,flags,spill,out);
    if(current && !nested) {
        struct li2_rd_recovered logical;assert(!e);nested=1;
        assert(!li2_pg_compact_recover_ret(current,current_head/64,current_head%64,pc,r,flags,spill,&logical));nested=0;
        assert(!memcmp(&logical,out,sizeof logical));
        for(unsigned i=0;i<p->record.boundaries;i++)if(pc==p->generated+p->record.boundary[i].offset)seen[i]=1;
        struct li2_pg_recovered old;
        assert(li2_pg_compact_recover(current,pc,r,flags,spill,&guard,&old)==LI2_PG_CORRUPT && !old.complete);
        ++wrapped;
    }
    return e;
}
int __wrap_li2_rd_recover_loaded_miss(const struct li2_rd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[6],struct li2_rd_recovered *out) {
    int e=__real_li2_rd_recover_loaded_miss(p,pc,r,flags,spill,out);
    if(current && !nested) {
        unsigned head;struct li2_rd_plan actual;struct li2_rd_recovered logical;assert(!e);nested=1;
        assert(li2_pg_compact_ret_loaded_miss(current,pc,&head)==1 && head==current_head);
        assert(!li2_pg_compact_ret(current,head/64,head%64,&actual) && !memcmp(p,&actual,sizeof actual));
        assert(!__real_li2_rd_recover_loaded_miss(&actual,pc,r,flags,spill,&logical) && !memcmp(&logical,out,sizeof logical));
        assert(logical.target_valid==1 && logical.phase==LI2_RD_LOADED_MISS && logical.original_rsp==r[4]);
        assert(li2_pg_compact_exit(current,pc,flags)==-1);nested=0;++loaded;
    }
    return e;
}
static void put32(unsigned char *p,uint32_t v) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i)); }
static void geometry_at(uintptr_t delta,unsigned slot) {
    pages[0]=delta+0x400000;pages[1]=delta+0x401000;
    layout=(struct li2_pg_layout){.generated={delta+0x10000000,delta+0x10008000},
        .stubs=delta+0x10010000,.slots=delta+0x10011000,.spill=delta+0x10012000,
        .directory=delta+0x70000000,.window=delta+0x70010000,
        .ret_miss=delta+0x70010040+slot*LI2_PG_HEADS*8};
    const uintptr_t proof=delta+0x30000000;
    struct li2_mg_range ranges[]={{pages[0],pages[1]+4096},{layout.generated[0],layout.spill+4096},
        {proof,proof+0x100000},{layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES},
        {layout.window,layout.window+4096}};
    assert(!li2_mg_table_build(ranges,5,proof+offsetof(struct li2_pg_compact,table),&table));
    memset(source,0xcc,sizeof source);
}
static void prove(uintptr_t root,unsigned heads,unsigned exits,unsigned links) {
    struct li2_pg_miss miss,empty={.version=LI2_PG_VERSION};
    assert(!li2_pg_plan_pages(pages,source,root,&layout,&table,&full,&miss) && !memcmp(&miss,&empty,sizeof miss));
    assert(full.version==LI2_PG_VERSION && full.heads==heads && full.exits==exits && !full.stores && full.links==links);
    assert(!li2_pg_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_pg_compact_build(&full,&scratch,&compact));
    assert(!li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
    for(unsigned i=0;i<heads;i++)if(full.head[i].kind==LI2_PG_RET) {
        union li2_pg_guard actual;memset(&actual,0,sizeof actual);
        assert(!li2_pg_compact_ret(&compact,i/64,i%64,&actual.ret) && !memcmp(&actual,&full.guard[i],sizeof actual));
        const struct li2_rd_plan *p=&actual.ret;
        assert(!li2_rd_validate(p) && p->record.image_bytes==285 && p->record.boundaries==53 &&
            p->record.load_offset==68 && p->record.save_offset==72 && p->record.loaded_miss_offset==190 &&
            p->record.miss_offset==227 && p->record.commit_offset==274 && p->record.transfer_offset==279 &&
            p->binding.loaded_miss==layout.ret_miss+i*8 && p->binding.head==i && p->binding.heads==heads &&
            !full.head[i].successor_count && !full.head[i].successors[0] && !full.head[i].successors[1]);
        assert(!memcmp(p->image,&compact.image[i/64][512*(i%64)],512));
        for(unsigned j=285;j<504;j++)assert(!p->image[j]);
        uint64_t literal=0;memcpy(&literal,p->image+504,8);assert(literal==p->binding.loaded_miss);
        unsigned found;assert(li2_pg_compact_ret_loaded_miss(&compact,p->binding.loaded_miss,&found)==1 && found==i);
        assert(li2_pg_compact_exit(&compact,p->original.decoded.pc,0x202)>=0 &&
            li2_pg_compact_exit(&compact,p->binding.loaded_miss,0x202)==-1);
    }
    ++plans;
}
static uint64_t flags_for(unsigned f,unsigned df) {
    static const unsigned bits[]={0,2,4,6,7,11};uint64_t out=0x202|((uint64_t)df<<10);
    for(unsigned i=0;i<6;i++)out|=(uint64_t)((f>>i)&1)<<bits[i];return out;
}
static void model(unsigned head,unsigned f,unsigned df,unsigned mode) {
    const struct li2_rd_plan *p=&full.guard[head].ret;uint64_t r[16];
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234567800000000)+0x101*i;
    r[4]=0x60000100;memset(&directory,0,sizeof directory);directory.version=1;directory.serial=73;directory.count=4;
    for(unsigned i=0;i<4;i++)directory.row[i]=(struct li2_jd_domain_row){
        .pc=0x500200+0x1000*i,.generated=0x20000000+512*i,.generation=91,.slot=1,.head=i};
    struct li2_rd_window window={.version=1,.owner=0x72000000,.serial=73,.first=r[4]-256,.end=r[4]+256};
    if(mode==5)window.first=r[4]+1,window.end=window.first+512;
    if(mode==6)window.end=r[4]-1,window.first=window.end-512;
    uint64_t word=mode==0?directory.row[0].pc:mode==1?directory.row[3].pc:
        mode==3?UINT64_C(0x0100000000000000):directory.row[0].pc+1;
    current=&compact;current_head=head;struct rd_model_result out;
    assert(!rd_model_run(p,&directory,&window,r,flags_for(f,df),word,mode!=4,&out));current=0;
    assert(!out.stack_writes && out.original_rsp==r[4] && out.steps==out.recoveries && out.steps<=2048);
    if(mode<2)assert(out.hit==1 && !out.before_miss && !out.loaded_miss && !out.load_fault &&
        out.load_attempts==1 && out.guest_reads==1 && out.target_writes==1 && out.cell_writes==1 &&
        out.row_reads==(mode?4U:1U) && out.final_rsp==r[4]+8);
    if(mode==2 || mode==3)assert(out.loaded_miss==1 && !out.hit && !out.before_miss && !out.load_fault &&
        out.load_attempts==1 && out.guest_reads==1 && out.target_writes==1 && !out.cell_writes &&
        out.loaded_target==word && out.target==p->binding.loaded_miss && out.final_rsp==r[4]);
    if(mode==4)assert(out.load_fault==1 && !out.hit && !out.before_miss && !out.loaded_miss &&
        out.load_attempts==1 && !out.guest_reads && !out.target_writes && !out.cell_writes && !out.row_reads && out.final_rsp==r[4]);
    if(mode>=5)assert(out.before_miss==1 && !out.hit && !out.load_fault && !out.loaded_miss &&
        !out.load_attempts && !out.guest_reads && !out.target_writes && !out.cell_writes && !out.row_reads &&
        out.target==p->original.decoded.pc && out.final_rsp==r[4]);
    ++models;
}
static void canonical(void) {
    for(unsigned where=0;where<4;where++) {
        geometry_at(where>=2?UINT64_C(0x500000000000):0,where&1);
        unsigned offset=(where&1)?8191:0x200;source[offset/4096][offset%4096]=0xc3;
        prove(pages[0]+offset,1,1,0);
        assert(full.source_bytes==1 && full.head[0].kind==LI2_PG_RET &&
            full.original[0].decoded.available==((where&1)?1U:15U) && full.exit_pc[0]==pages[0]+offset);
        if(!where)for(unsigned df=0;df<2;df++)for(unsigned f=0;f<64;f++)for(unsigned m=0;m<7;m++)model(0,f,df,m);
        else for(unsigned m=0;m<7;m++)model(0,63,1,m);
    }
}
static void capacity(void) {
    for(unsigned count=64;count<=128;count+=64) {
        geometry_at(0,1);
        for(unsigned i=0;i<count;i++)memcpy(source[0]+0x200+4*i,"\x48\x83\xc0\x01",4);
        source[0][0x200+4*count]=0xc3;
        if(count==64) {prove(pages[0]+0x200,65,1,1);for(unsigned m=0;m<7;m++)model(64,63,1,m);}
        else {struct li2_pg_miss miss;int e=li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss);
            assert(e==LI2_PG_GRAPH && !full.ready && miss.reason==LI2_PGD_HEAD_LIMIT && miss.detail==128 &&
                li2_pg_miss_valid(&full,&miss,e));}
        ++capacities;
    }
    for(unsigned count=8;count<=9;count++) {
        geometry_at(0,0);
        for(unsigned i=0;i<count-1;i++) {unsigned at=0x200+6*i,to=0x400+i;
            source[0][at]=0x0f;source[0][at+1]=0x85;put32(source[0]+at+2,to-at-6);source[0][to]=0xc3;}
        source[0][0x200+6*(count-1)]=0xc3;
        if(count==8)prove(pages[0]+0x200,15,8,0);
        else {struct li2_pg_miss miss;int e=li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss);
            assert(e==LI2_PG_GRAPH && !full.ready && miss.reason==LI2_PGD_EXIT_LIMIT && miss.detail==8 &&
                li2_pg_miss_valid(&full,&miss,e));}
        ++capacities;
    }
}
static void invalid(void) {
    static const unsigned char forms[][4]={{0x66,0xc3},{0xf3,0xc3},{0xc2,0,0},{0xcb},{0xca,0,0},{0x48,0xc3}};
    for(unsigned i=0;i<6;i++) {geometry_at(0,0);memcpy(source[0]+0x200,forms[i],4);struct li2_pg_miss miss;
        int e=li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss);
        assert(e==LI2_PG_MISS && !full.ready && miss.reason==LI2_PGD_ROOT_UNSUPPORTED && li2_pg_miss_valid(&full,&miss,e));++refusals;}
    geometry_at(0,0);source[0][0x200]=0xc3;struct li2_pg_layout good=layout;
    uintptr_t bad_at[]={0,good.window,good.window+56,good.ret_miss+1,good.window+4096-1024+8,
        UINT64_MAX,good.directory,good.generated[0]};
    for(unsigned i=0;i<8;i++) {layout=good;layout.ret_miss=bad_at[i];struct li2_pg_miss miss;
        assert(li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss)==LI2_PG_ARGUMENT && !full.ready);++geometry;}
    layout=good;layout.ret_miss=layout.window+4096-1024;prove(pages[0]+0x200,1,1,0);
    struct li2_rd_binding binding;
    assert(!li2_pg_ret_binding(pages,&layout,table.address,128,127,&binding) && binding.loaded_miss==layout.window+4096-8);
    ++geometry;
    geometry_at(0,0);source[0][0x200]=0xc3;prove(pages[0]+0x200,1,1,0);
    for(unsigned i=0;i<20;i++) {
        bad_full=full;struct li2_rd_plan *p=&bad_full.guard[0].ret;
        if(i==0)p->record.version++;if(i==1)p->record.ready=0;if(i==2)p->record.result=1;if(i==3)p->record.reserved=1;
        if(i==4)p->record.load_offset++;if(i==5)p->record.save_offset++;if(i==6)p->record.commit_offset++;
        if(i==7)p->record.transfer_offset++;if(i==8)p->record.miss_offset++;if(i==9)p->record.loaded_miss_offset++;
        if(i==10)p->record.boundary[52].phase=LI2_RD_BEFORE;if(i==11)p->record.boundary[63].offset=1;
        if(i==12)p->record.scratch_regs[3]=4;if(i==13)p->binding.loaded_miss+=8;if(i==14)p->original.reserved[3]=1;
        if(i==15)p->image[285]=1;if(i==16)bad_full.guard[0].bytes[sizeof *p]=1;
        if(i==17)bad_full.head[0].successor_count=1;if(i==18)bad_full.stores=1;if(i==19)bad_full.image[0][511]=1;
        assert(li2_pg_compact_build(&bad_full,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
    for(unsigned i=0;i<16;i++) {
        bad=compact;struct li2_pg_ret_record *r=&bad.guard[0].ret;
        if(i==0)r->load_offset++;if(i==1)r->save_offset++;if(i==2)r->commit_offset++;if(i==3)r->transfer_offset++;
        if(i==4)r->miss_offset++;if(i==5)r->loaded_miss_offset++;if(i==6)r->boundary[52].phase=LI2_RD_BEFORE;
        if(i==7)r->boundary[63].offset=1;if(i==8)r->scratch_regs[3]=4;if(i==9)bad.layout.ret_miss+=8;
        if(i==10)bad.image[0][285]=1;if(i==11)bad.instruction[0].ret.reserved[3]=1;
        if(i==12)bad.original[0].decoded.bytes[15]=1;if(i==13)bad.frontier[0].decoded.pc++;
        if(i==14)bad.head[0].successor_count=1;if(i==15)bad.stores=1;
        assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++corruptions;
    }
    for(unsigned offset=0;offset<4096;offset++) {
        unsigned head;int e=li2_pg_compact_ret_loaded_miss(&compact,layout.window+offset,&head);
        assert(e==(offset==64?1:0) && head==(offset==64?0:UINT32_MAX));++landings;
    }
    unsigned head;bad=compact;bad.exits=2;bad.exit_pc[1]=bad.exit_pc[0];bad.frontier[1]=bad.frontier[0];
    assert(li2_pg_compact_ret_loaded_miss(&bad,layout.ret_miss,&head)==-2 && head==UINT32_MAX);++landings;
    bad=compact;bad.layout.ret_miss++;
    assert(li2_pg_compact_ret_loaded_miss(&bad,layout.ret_miss,&head)==-2 && head==UINT32_MAX);++landings;
    uint64_t raw[16]={0},spill[6]={0};raw[4]=0x60000100;spill[5]=0x500200;struct li2_rd_recovered out;
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned j=0;j<53;j++)found|=full.guard[0].ret.record.boundary[j].offset==offset;
        if(!found) {assert(li2_pg_compact_recover_ret(&compact,0,0,layout.generated[0]+offset,raw,0x202,spill,&out)==LI2_PG_MISS && !out.complete);++interiors;}
    }
    assert(li2_pg_compact_recover_ret(&compact,1,0,layout.generated[0],raw,0x202,spill,&out)==LI2_PG_CORRUPT && !out.complete);
    assert(li2_pg_compact_recover_ret(&compact,0,0,layout.ret_miss,raw,0x202,spill,&out)==LI2_PG_MISS && !out.complete);
}
static void invalid_arguments(void) {
    uint64_t raw[16]={0},spill[6]={0};struct li2_rd_recovered out;
    for(unsigned i=0;i<14;i++) {
        const struct li2_pg_compact *p=&compact;const uint64_t *r=raw,*s=spill;struct li2_rd_recovered *o=&out;
        if(i==0)p=0;if(i==1)r=0;if(i==2)s=0;if(i==3)o=0;
        if(i==4)p=(const void *)((const unsigned char *)&compact+1);
        if(i==5)r=(const void *)((const unsigned char *)raw+1);
        if(i==6)s=(const void *)((const unsigned char *)spill+1);
        if(i==7)o=(void *)((unsigned char *)&out+1);
        if(i==8)r=(const void *)&compact;if(i==9)s=(const void *)&compact;
        if(i==10)o=(void *)&compact;if(i==11)s=raw;if(i==12)o=(void *)raw;if(i==13)o=(void *)spill;
        assert(li2_pg_compact_recover_ret(p,0,0,layout.generated[0],r,0x202,s,o)==LI2_PG_ARGUMENT);++arguments;
    }
    for(unsigned i=0;i<5;i++) {
        const struct li2_pg_compact *p=&compact;unsigned head,*h=&head;
        if(i==0)p=0;if(i==1)h=0;
        if(i==2)p=(const void *)((const unsigned char *)&compact+1);
        if(i==3)h=(void *)((unsigned char *)&head+1);if(i==4)h=(void *)&compact;
        assert(li2_pg_compact_ret_loaded_miss(p,layout.ret_miss,h)==-2);++arguments;
    }
    for(unsigned i=0;i<5;i++) {
        const struct li2_pg_compact *p=&compact;struct li2_rd_plan actual,*a=&actual;
        if(i==0)p=0;if(i==1)a=0;
        if(i==2)p=(const void *)((const unsigned char *)&compact+1);
        if(i==3)a=(void *)((unsigned char *)&actual+1);if(i==4)a=(void *)&compact;
        assert(li2_pg_compact_ret(p,0,0,a)==LI2_PG_ARGUMENT);++arguments;
    }
}
static void far_geometry(void) {
    const uintptr_t shift=UINT64_C(0x500000000000);
    for(unsigned high=0;high<2;high++) {
        uintptr_t delta=high?shift:0;geometry_at(delta,high);
        layout.window=(high?0:shift)+0x70010000;layout.ret_miss=layout.window+64+high*1024;
        uintptr_t proof=delta+0x30000000;
        struct li2_mg_range ranges[]={{pages[0],pages[1]+4096},{layout.generated[0],layout.spill+4096},
            {proof,proof+0x100000},{layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES},
            {layout.window,layout.window+4096}};
        assert(!li2_mg_table_build(ranges,5,proof+offsetof(struct li2_pg_compact,table),&table));
        source[0][0x200]=0xc3;struct li2_pg_miss miss,empty={.version=LI2_PG_VERSION};
        assert(!li2_pg_plan_pages(pages,source,pages[0]+0x200,&layout,&table,&full,&miss) &&
            !memcmp(&miss,&empty,sizeof miss) && full.heads==1 && full.exits==1 && !full.links && !full.stores);
        assert(!li2_pg_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
        assert(!li2_pg_compact_build(&full,&scratch,&compact) &&
            !li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
        memset(&guard,0,sizeof guard);
        assert(!li2_pg_compact_ret(&compact,0,0,&guard.ret) && !memcmp(&guard,&full.guard[0],sizeof guard));
        const struct li2_rd_plan *p=&guard.ret;uint64_t literal=0;memcpy(&literal,p->image+504,8);
        uintptr_t next=p->generated+p->record.loaded_miss_offset+6;
        assert(!li2_rd_validate(p) && literal==layout.ret_miss && p->binding.loaded_miss==literal &&
            (next>literal?next-literal:literal-next)>UINT32_C(0x80000000) &&
            !memcmp(p->image,&compact.image[0][0],512));
        unsigned selected;assert(li2_pg_compact_ret_loaded_miss(&compact,literal,&selected)==1 && selected==0 &&
            li2_pg_compact_exit(&compact,literal,0x202)==-1);
        for(unsigned i=0;i<12;i++) {
            unsigned at=i<8?504+i:192+i-8;bad=compact;bad.image[0][at]^=1;
            assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++far_corruptions;
        }
        ++far_plans;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    canonical();capacity();invalid();invalid_arguments();
    far_geometry();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    for(unsigned i=0;i<53;i++)assert(seen[i]);
    assert(plans==8 && models==924 && refusals==6 && geometry==9 && capacities==4 && corruptions==36 &&
        interiors==459 && landings==4098 && loaded==528 && arguments==24);
    assert(far_plans==2 && far_corruptions==24);
    printf("ret-dispatch-plan plans=%u models=%u refusals=%u geometry=%u capacities=%u corruptions=%u interiors=%u landings=%u compact_recoveries=%u loaded_recoveries=%u rows=53 arguments=%u far_plans=%u far_corruptions=%u\n",
        plans,models,refusals,geometry,capacities,corruptions,interiors,landings,wrapped,loaded,arguments,far_plans,far_corruptions);
    return 0;
}
