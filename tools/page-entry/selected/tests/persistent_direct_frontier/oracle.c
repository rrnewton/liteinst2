/* Actual decoder/emitter/planner/compact code, independent byte interpretation.
   No emitted instructions, owner lifetime, physical mappings or guest run. */
#include "persistent_group_compact.h"
#include "model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full[2],scratch;
static struct li2_pg_compact compact[2],rebuilt,bad;
static union li2_pg_guard recovery_guard;
static struct li2_jd_domain_directory directory;
static unsigned char source[2][4096];
static struct li2_mg_table table;
static struct li2_dd_plan example;
static const struct li2_pg_layout layouts[2]={
    {{0x10000000,0x10008000},0x10010000,0x10011000,0x10012000,0x30000000},
    {{0x20000000,0x20008000},0x20010000,0x20011000,0x20012000,0x30000000}};
static unsigned descriptors,models,proofs,selectors,budgets,refusals,handoffs,typed;
static uint64_t steps,decoded_calls;
static const struct li2_pg_compact *current;
static unsigned current_head,nested;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *d) {
    ++decoded_calls;return __real_li2_decoder_decode(pc,b,n,d);
}
int __real_li2_dd_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_dd_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    uint64_t calls=decoded_calls;
    int e=__real_li2_dd_recover(p,pc,r,flags,spill,out);assert(decoded_calls==calls);
    if(current && !nested) {
        struct li2_pg_recovered logical;nested=1;
        assert(!e && !li2_pg_compact_recover(current,pc,r,flags,spill,&recovery_guard,&logical));nested=0;
        assert(decoded_calls==calls && logical.complete==1 && logical.kind==LI2_PG_DIRECT_MAP &&
            logical.phase==LI2_DD_BEFORE && logical.member==current_head/64 && logical.head==current_head%64 &&
            logical.original_pc==out->original_pc && logical.flags==out->flags &&
            !memcmp(logical.gpr,out->gpr,sizeof logical.gpr) &&
            !memcmp(&recovery_guard.direct,p,sizeof *p));++typed;
    }
    return e;
}
static uint64_t flags_for(unsigned n) {
    static const unsigned bit[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bit[i];return f;
}
static void frame(uint64_t r[16]) {
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234567800000000)+0x101*i;
}
static void put32(unsigned char *p,int64_t value) {
    assert(value>=INT32_MIN && value<=INT32_MAX);uint32_t x=(uint32_t)value;
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(x>>(8*i));
}
static void source_at(unsigned offset,const unsigned char *b,unsigned n) {
    assert(offset<8192 && n<=8192-offset);
    for(unsigned i=0;i<n;i++)source[(offset+i)/4096][(offset+i)%4096]=b[i];
}
static void table_for(unsigned slot,const uintptr_t pages[2]) {
    uintptr_t proof=0x40000000+slot*0x1000000;
    struct li2_mg_range ranges[5]={{pages[0],pages[1]+4096},
        {layouts[0].generated[0],layouts[0].spill+4096},
        {layouts[1].generated[0],layouts[1].spill+4096},
        {proof,proof+((sizeof compact[0]+4095)&~(size_t)4095)},
        {layouts[slot].directory,layouts[slot].directory+LI2_JD_DOMAIN_BYTES}};
    assert(!li2_mg_table_build(ranges,5,proof+offsetof(struct li2_pg_compact,table),&table));
}
static void accepted(unsigned slot,const uintptr_t pages[2],uintptr_t entry,unsigned heads,unsigned exits,unsigned links) {
    struct li2_pg_miss miss,zero={.version=LI2_PG_VERSION};table_for(slot,pages);
    assert(!li2_pg_plan_pages(pages,source,entry,&layouts[slot],&table,&full[slot],&miss));
    assert(!memcmp(&miss,&zero,sizeof miss) && full[slot].ready==1 && !full[slot].result &&
        full[slot].heads==heads && full[slot].exits==exits && full[slot].links==links && !full[slot].stores &&
        !memcmp(full[slot].source,source,sizeof source));
    assert(!li2_pg_plan_validate(&full[slot],&scratch) && !memcmp(&full[slot],&scratch,sizeof scratch));
    assert(!li2_pg_compact_build(&full[slot],&scratch,&compact[slot]));
    assert(!li2_pg_compact_validate(&compact[slot],&scratch,&rebuilt) && !memcmp(&compact[slot],&rebuilt,sizeof rebuilt));
    assert(!memcmp(compact[slot].source,source,sizeof source));++proofs;
}
static void directory_for(const struct li2_dd_plan *p,unsigned which) {
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=40;
    unsigned arms=p->original.flow==LI2_REGION_JCC?2:1;
    for(unsigned arm=0;arm<arms;arm++)if(p->original.external_mask&(1U<<arm)) {
        uint64_t target=p->original.target[arm];
        /* Mode2 asks for an interior (head+1), mode3 for an old head absent
           from the replacement directory. No stale row is claimed admissible. */
        uint64_t pc=which==0?target:which==1?target+0x10000:which==2?target-1:target+16;
        if(directory.count && directory.row[0].pc==pc)continue;
        unsigned i=(unsigned)directory.count++;
        directory.row[i]=(struct li2_jd_domain_row){pc,0x50000000+512*i,which==3?2:1,i,i};
    }
    assert(directory.count>=1 && directory.count<=2);
}
static struct dd_model_result run(const struct li2_dd_plan *p,uint64_t flags,unsigned which) {
    uint64_t r[16];frame(r);directory_for(p,which);
    unsigned arm=p->original.flow==LI2_REGION_JMP?0:(dd_model_taken(p->original.condition,flags)?0:1);
    assert(li2_dd_arm(&p->original,flags)==(int)arm &&
        li2_dd_arm(&p->original,flags|0x10100)==(int)arm);
    struct dd_model_result out;assert(!dd_model_run(p,&directory,r,flags,&out));
    assert(out.steps==out.recoveries && out.steps>0 && out.steps<=2048);
    if(!(p->original.external_mask&(1U<<arm))) {
        assert(out.internal==1 && !out.hit && !out.miss && out.target==p->internal[arm] &&
            out.steps==2 && !out.cell_writes && !out.row_reads);
    } else if(which==0) {
        unsigned i=0;while(i<directory.count && directory.row[i].pc!=p->original.target[arm])++i;
        assert(i<directory.count && out.hit==1 && !out.miss && !out.internal &&
            out.target==directory.row[i].generated && out.cell_writes==1 && out.row_reads==i+1);
    } else assert(out.miss==1 && !out.hit && !out.internal && !out.cell_writes &&
        out.target==p->original.decoded.pc && out.row_reads==directory.count);
    steps+=out.steps;++models;return out;
}
static void emitted_forms(void) {
    const struct li2_jd_binding binding={.rows=0x40010000,.image={0x10000000,0x10008000},.heads=1,.head=0,.directory=0x30000000};
    for(unsigned condition=0;condition<16;condition++)for(unsigned shape=0;shape<4;shape++) {
        uintptr_t pc=0x400200,internal[2]={0,0};unsigned external=shape==0?1:shape==1?2:3;
        unsigned char b[6]={0};unsigned n=shape==0||shape==3?2:6;
        if(n==2) {b[0]=(unsigned char)(0x70+condition);b[1]=shape==3?0:0x20;}
        else {b[0]=0x0f;b[1]=(unsigned char)(0x80+condition);put32(b+2,0x100);}
        if(external==1)internal[1]=0x10000200;
        if(external==2)internal[0]=0x10000400;
        struct li2_dd_plan p;assert(!li2_dd_emit(pc,b,n,external,0x10000000,0x10012000,&binding,internal,&p));
        assert(!li2_dd_validate(&p) && p.original.condition==condition && p.original.external_mask==external &&
            p.record.boundaries==(shape<2?39U:40U) && p.record.image_bytes==(shape<2?217U:227U));
        uint64_t visited=0;
        for(unsigned f=0;f<64;f++)for(unsigned which=0;which<4;which++)visited|=run(&p,flags_for(f),which).visited;
        assert(visited==((UINT64_C(1)<<p.record.boundaries)-1));++descriptors;
    }
    for(unsigned form=0;form<2;form++) {
        unsigned char b[5]={form?0xe9:0xeb,0,0,0,0};unsigned n=form?5:2;
        if(form)put32(b+1,0x100);else b[1]=0x20;
        const uintptr_t internal[2]={0,0};struct li2_dd_plan p;
        assert(!li2_dd_emit(0x400200,b,n,1,0x10000000,0x10012000,&binding,internal,&p) && !li2_dd_validate(&p) &&
            p.record.boundaries==37 && p.record.image_bytes==206);
        for(unsigned f=0;f<64;f++)for(unsigned which=0;which<4;which++)run(&p,flags_for(f),which);
        example=p;++descriptors;
    }
}
static void empty_or_excess_directory(void) {
    uint64_t raw[16];frame(raw);
    for(unsigned i=0;i<2;i++) {
        memset(&directory,0,sizeof directory);directory.version=1;directory.serial=40;directory.count=i?257:0;
        struct dd_model_result out;assert(!dd_model_run(&example,&directory,raw,flags_for(63),&out));
        assert(out.miss==1 && !out.hit && !out.internal && !out.row_reads && !out.cell_writes &&
            out.target==example.original.decoded.pc && out.steps==out.recoveries);
        ++models;steps+=out.steps;
    }
}
static void paired_arm_tokens(void) {
    for(unsigned condition=0;condition<16;condition++) {
        for(unsigned slot=0;slot<2;slot++) {
            uintptr_t pages[2]={0x400000+slot*0x200000,0x401000+slot*0x200000};
            memset(source,0xcc,sizeof source);unsigned char b[2]={(unsigned char)(0x70+condition),0};source_at(8190,b,2);
            accepted(slot,pages,pages[1]+4094,1,2,0);
            assert(full[slot].head[0].kind==LI2_PG_DIRECT && full[slot].head[0].successor_count==2 &&
                full[slot].head[0].successors[0]==128 && full[slot].head[0].successors[1]==129 &&
                full[slot].exit_pc[0]==full[slot].exit_pc[1] &&
                full[slot].instruction[0].direct.target[0]==full[slot].instruction[0].direct.target[1] &&
                !memcmp(&full[slot].frontier[0],&full[slot].frontier[1],sizeof full[slot].frontier[0]));
        }
        for(unsigned slot=0;slot<2;slot++) {
            current=&compact[slot];current_head=0;const struct li2_dd_plan *p=&full[slot].guard[0].direct;
            struct li2_dd_plan copy;assert(!li2_pg_compact_direct(current,0,0,&copy) && !memcmp(&copy,p,sizeof copy));
            for(unsigned f=0;f<64;f++) {
                uint64_t flags=flags_for(f);int arm=dd_model_taken(condition,flags)?0:1;
                const uint64_t added[3]={0,0x10000,0x10100};
                for(unsigned j=0;j<3;j++) {
                    assert(li2_pg_compact_exit(current,p->original.decoded.pc,flags|added[j])==arm &&
                        li2_pg_compact_exit(&compact[1-slot],p->original.decoded.pc,flags|added[j])==-1);++selectors;
                }
                run(p,flags,0);run(p,flags,1);
            }
        }
        current=0;
    }
}
static void asymmetric_plans(void) {
    const uintptr_t pages[2]={0x400000,0x401000};
    for(unsigned which=0;which<2;which++) {
        memset(source,0xcc,sizeof source);unsigned at=which?8186:0x200;
        uintptr_t target=which?0x400200:0x500200;
        unsigned char jcc[6]={0x0f,0x84,0,0,0,0};put32(jcc+2,(int64_t)target-(int64_t)(pages[0]+at+6));source_at(at,jcc,6);
        const unsigned char rest[]={0x48,0x83,0xc0,1,0xff,0x20};source_at(which?0x200:0x206,rest,sizeof rest);
        accepted(0,pages,pages[0]+at,2,2,0);
        const struct li2_dd_plan *p=&full[0].guard[0].direct;
        assert(p->original.external_mask==(which?2U:1U) && full[0].head[0].successors[which?0:1]==1 &&
            full[0].head[0].successors[which?1:0]==128 && full[0].head[1].kind==LI2_PE_NONE);
        current=&compact[0];current_head=0;
        for(unsigned f=0;f<64;f++) {
            int arm=dd_model_taken(4,flags_for(f))?0:1;
            assert(li2_pg_compact_exit(current,p->original.decoded.pc,flags_for(f))==(arm==(int)which?0:-1));++selectors;
            run(p,flags_for(f),0);run(p,flags_for(f),1);
        }
        current=0;
    }
}
static void boundary_budget(void) {
    const uintptr_t pages[2]={0x400000,0x401000};
    for(unsigned too_many=0;too_many<2;too_many++) {
        memset(source,0xcc,sizeof source);unsigned nodes=7+too_many,start=8190-2*(nodes-1);
        for(unsigned i=0;i<nodes;i++) {
            unsigned at=start+2*i;unsigned char b[2]={(unsigned char)(0x70+(i&15)),0};
            b[1]=i+1==nodes?0:(unsigned char)(0x402020-(pages[0]+at+2));source_at(at,b,2);
        }
        table_for(0,pages);
        if(!too_many) {
            accepted(0,pages,pages[0]+start,7,8,0);
            assert(full[0].head[6].successors[0]==134 && full[0].head[6].successors[1]==135 &&
                full[0].exit_pc[6]==full[0].exit_pc[7]);
        } else {
            struct li2_pg_miss miss;int e=li2_pg_plan_pages(pages,source,pages[0]+start,&layouts[0],&table,&full[0],&miss);
            assert(e==LI2_PG_GRAPH && li2_pg_miss_valid(&full[0],&miss,e) && miss.reason==LI2_PGD_EXIT_LIMIT &&
                miss.site==LI2_PGD_SOURCE && miss.pc==0x401ffe && miss.detail==8 && full[0].exits==8 &&
                full[0].heads==8 && !full[0].ready);++refusals;
        }
        ++budgets;
    }
    /* The same unchanged budget also counts capacity links, not just exits. */
    for(unsigned too_many=0;too_many<2;too_many++) {
        memset(source,0xcc,sizeof source);unsigned at=0x200;
        const unsigned char add[]={0x48,0x83,0xc0,1},frontier[]={0xff,0x20};
        for(unsigned i=0;i<63;i++,at+=4)source_at(at,add,4);
        for(unsigned i=0;i<6+too_many;i++,at+=6) {
            unsigned char b[6]={0x0f,(unsigned char)(0x80+i),0,0,0,0};
            put32(b+2,(int64_t)0x500000-(int64_t)(pages[0]+at+6));source_at(at,b,6);
        }
        source_at(at,frontier,2);table_for(0,pages);
        if(!too_many)accepted(0,pages,0x400200,69,7,1);
        else {
            struct li2_pg_miss miss;int e=li2_pg_plan_pages(pages,source,0x400200,&layouts[0],&table,&full[0],&miss);
            assert(e==LI2_PG_GRAPH && li2_pg_miss_valid(&full[0],&miss,e) && miss.reason==LI2_PGD_LINK_LIMIT &&
                miss.site==LI2_PGD_SOURCE && miss.detail==8 && full[0].exits==8 && !full[0].links &&
                full[0].heads==70 && !full[0].ready);++refusals;
        }
        ++budgets;
    }
}
static void stale_and_corrupt(void) {
    for(unsigned i=0;i<12;i++) {
        struct li2_dd_plan bad=example;
        if(i==0)bad.record.version++;
        if(i==1)bad.original.target[0]++;
        if(i==2)bad.original.external_mask=0;
        if(i==3)bad.original.decoded.pc++;
        if(i==4)bad.binding.directory++;
        if(i==5)bad.binding.rows++;
        if(i==6)bad.binding.heads=129;
        if(i==7)bad.internal[0]=0x10000200;
        if(i==8)bad.record.boundary[0].spill_valid=1;
        if(i==9)bad.record.boundary[0].dirty=1;
        if(i==10)bad.image[0]^=1;
        if(i==11)bad.record.boundary[0].phase=LI2_DD_CELL_READY;
        assert(li2_dd_validate(&bad)==LI2_DD_CORRUPT);++refusals;
    }
    uint64_t raw[16],poison[4]={UINT64_MAX,0xdeadbeef,0x12345678,0};frame(raw);
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned i=0;i<example.record.boundaries;i++)found|=example.record.boundary[i].offset==offset;
        if(!found) {
            struct li2_dd_recovered out;assert(li2_dd_recover(&example,example.generated+offset,raw,flags_for(63),poison,&out)==LI2_DD_CORRUPT);++refusals;
        }
    }
    /* Wrong or coalesced arm tokens must fail the actual compact selector. */
    const uintptr_t pages[2]={0x400000,0x401000};memset(source,0xcc,sizeof source);
    const unsigned char equal[]={0x74,0};source_at(8190,equal,2);accepted(0,pages,0x401ffe,1,2,0);
    bad=compact[0];bad.head[0].successors[1]=bad.head[0].successors[0];
    assert(li2_pg_compact_exit(&bad,0x401ffe,flags_for(0))==-2 && li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
    bad=compact[0];bad.frontier[1].decoded.pc++;
    assert(li2_pg_compact_exit(&bad,0x401ffe,flags_for(0))==-2 && li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
    bad=compact[0];unsigned token=bad.head[0].successors[0];bad.head[0].successors[0]=bad.head[0].successors[1];bad.head[0].successors[1]=token;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
}
static void target_first_boundary(void) {
    const uintptr_t pages[2]={0x600000,0x601000};memset(source,0xcc,sizeof source);
    const unsigned char bytes[]={0x48,0x83,0xc0,1,0x48,0x89,7,0xff,0xe2};source_at(0x200,bytes,sizeof bytes);
    table_for(1,pages);struct li2_pg_miss miss;
    assert(!li2_pg_plan_pages(pages,source,0x600200,&layouts[1],&table,&full[1],&miss) &&
        full[1].heads==3 && full[1].stores==1 && full[1].exits==1 && !full[1].links);
    assert(!li2_pg_compact_build(&full[1],&scratch,&compact[1]) && !li2_pg_compact_validate(&compact[1],&scratch,&rebuilt));++proofs;
    const uintptr_t pc[3]={0x600200,0x600204,0x600207};const unsigned kinds[3]={LI2_PG_COPIED,LI2_PG_GUARD,LI2_PG_DISPATCH_MAP};
    for(unsigned head=0;head<3;head++) {
        unsigned char branch[5]={0xe9,0,0,0,0};put32(branch+1,(int64_t)pc[head]-(int64_t)0x400205);
        const uintptr_t internal[2]={0,0};struct li2_dd_plan p;
        assert(!li2_dd_emit(0x400200,branch,5,1,example.generated,example.spill,&example.binding,internal,&p));
        for(unsigned f=0;f<64;f++) {
            memset(&directory,0,sizeof directory);directory.version=1;directory.count=1;directory.serial=40;
            directory.row[0]=(struct li2_jd_domain_row){pc[head],layouts[1].generated[0]+512*head,2,1,head};
            uint64_t raw[16],poison[4]={UINT64_MAX,0xdeadbeef,0x12345678,0};frame(raw);uint64_t flags=flags_for(f);
            struct dd_model_result out;assert(!dd_model_run(&p,&directory,raw,flags,&out) && out.hit==1 && out.target==directory.row[0].generated);
            struct li2_pg_recovered logical;assert(!li2_pg_compact_recover(&compact[1],out.target,raw,flags,poison,&recovery_guard,&logical));
            assert(logical.complete==1 && logical.original_pc==pc[head] && logical.kind==kinds[head] &&
                logical.phase==LI2_MG_BEFORE && logical.member==0 && logical.head==head && logical.flags==flags &&
                !memcmp(logical.gpr,raw,sizeof raw));++handoffs;++models;steps+=out.steps;
        }
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    emitted_forms();empty_or_excess_directory();paired_arm_tokens();asymmetric_plans();boundary_budget();stale_and_corrupt();target_first_boundary();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(descriptors==66 && models==21442 && proofs==38 && selectors==6272 && budgets==4 && refusals==492 && handoffs==192);
    assert(typed>0 && steps>models);
    printf("{\"version\":1,\"descriptors\":%u,\"models\":%u,\"proofs\":%u,\"selectors\":%u,\"budgets\":%u,\"refusals\":%u,\"handoffs\":%u,\"typed_recoveries\":%u,\"steps\":%llu,\"emitted_execution\":0,\"owner_credit\":0}\n",
        descriptors,models,proofs,selectors,budgets,refusals,handoffs,typed,(unsigned long long)steps);
    return 0;
}
