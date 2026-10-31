/* Actual decoder/planner/emitter plus independent byte interpretation. No
   emitted instruction runs. The old group/JD fixtures remain separate gates. */
#include "persistent_group_compact.h"
#include "tests/linked_jmp_dispatch/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int pda_model_run(const struct li2_jd_plan *,const struct li2_jd_domain_directory *,
    const uint64_t[16],uint64_t,struct jd_model_result *);
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full[2],scratch;
static struct li2_pg_compact compact[2],rebuilt;
static union li2_pg_guard recovered_guard;
static struct li2_jd_domain_directory directory;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static const uintptr_t roots[2]={0x400200,0x400400};
static const struct li2_pg_layout layouts[2]={
    {{0x10000000,0x10008000},0x10010000,0x10011000,0x10012000,UINT64_C(0x700000000000)},
    {{0x20000000,0x20008000},0x20010000,0x20011000,0x20012000,UINT64_C(0x700000000000)}};
static unsigned models,descriptors,refusals,proofs,handoffs,decoded,wrapped,nested;
static uint64_t steps;
static const struct li2_pg_compact *current;
static unsigned current_head;
int __real_li2_jd_recover(const struct li2_jd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_jd_recovered *);
int __wrap_li2_jd_recover(const struct li2_jd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_jd_recovered *out) {
    int e=__real_li2_jd_recover(p,pc,r,flags,spill,out);
    if(current && !nested) {
        struct li2_pg_recovered logical;nested=1;
        assert(!e && !li2_pg_compact_recover(current,pc,r,flags,spill,&recovered_guard,&logical));nested=0;
        assert(logical.complete==1 && logical.kind==LI2_PG_DISPATCH_MAP && logical.phase==LI2_JD_BEFORE &&
            logical.member==0 && logical.head==current_head && logical.original_pc==out->original_pc &&
            logical.flags==out->flags && !memcmp(logical.gpr,out->gpr,sizeof logical.gpr));
        assert(!memcmp(&recovered_guard.dispatch,p,sizeof *p));++wrapped;
    }
    return e;
}
static uint64_t flags_for(unsigned n) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned j=0;j<6;j++)f|=(uint64_t)((n>>j)&1)<<bits[j];return f;
}
static void frame(uint64_t r[16],unsigned seed) {
    for(unsigned j=0;j<16;j++)r[j]=UINT64_C(0x1234567800000000)+0x101*j+0x10000*seed;
}
static unsigned first(uint64_t target) {
    for(unsigned i=0;i<directory.count && i<LI2_JD_DOMAIN_HEADS;i++)if(directory.row[i].pc==target)return i;
    return LI2_JD_DOMAIN_HEADS;
}
static struct jd_model_result run(const struct li2_jd_plan *p,uint64_t target,uint64_t flags) {
    uint64_t r[16];frame(r,p->original.target);r[p->original.target]=target;
    struct jd_model_result out;assert(!pda_model_run(p,&directory,r,flags,&out));
    unsigned i=first(target),want;
    if(!directory.count || directory.count>LI2_JD_DOMAIN_HEADS) {
        want=directory.count?20:18;
        assert(out.miss==1 && !out.hit && !out.cell_writes && !out.row_reads && out.target==p->original.decoded.pc);
    } else if(i<directory.count) {
        want=27+5*i;
        assert(out.hit==1 && !out.miss && out.cell_writes==1 && out.row_reads==i+1 && out.target==directory.row[i].generated);
    } else {
        want=23+5*(unsigned)directory.count;
        assert(out.miss==1 && !out.hit && !out.cell_writes && out.row_reads==directory.count && out.target==p->original.decoded.pc);
    }
    assert(out.steps==want && out.recoveries==want);steps+=want;++models;return out;
}
static void directory_rows(void) {
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=40;
    for(unsigned i=0;i<2;i++)for(unsigned j=0;j<compact[i].heads;j++) {
        struct li2_jd_domain_row *r=&directory.row[directory.count++];
        *r=(struct li2_jd_domain_row){.pc=compact[i].original[j].decoded.pc,
            .generated=layouts[i].generated[j/64]+(j%64)*512U,.generation=i+1,.slot=i,.head=j};
    }
    assert(directory.count==7);
}
static void plans(void) {
    memset(source,0xcc,sizeof source);
    const unsigned char a[]={0x48,0x83,0xc0,1,0xff,0xe2};
    const unsigned char b[]={0x48,0x83,0xc0,2,0x48,0x83,0xe9,1,0x75,3,0x48,0x89,0xf3,0xff,0xe3};
    memcpy(source[0]+0x200,a,sizeof a);memcpy(source[0]+0x400,b,sizeof b);
    const uintptr_t expected[2][5]={{0x400200,0x400204},{0x400400,0x400404,0x400408,0x40040d,0x40040a}};
    for(unsigned i=0;i<2;i++) {
        uintptr_t proof=0x30000000+0x1000000*i;
        struct li2_mg_range ranges[7]={{pages[0],pages[1]+4096},
            {layouts[0].generated[0],layouts[0].spill+4096},{layouts[1].generated[0],layouts[1].spill+4096},
            {0x30000000,0x30100000},{0x31000000,0x31100000},
            {layouts[0].directory,layouts[0].directory+LI2_JD_DOMAIN_BYTES},{0x70000008,0x70000010}};
        assert(!li2_mg_table_build(ranges,7,proof+offsetof(struct li2_pg_compact,table),&table));
        struct li2_pg_miss miss,zero={.version=3};
        assert(!li2_pg_plan_pages(pages,source,roots[i],&layouts[i],&table,&full[i],&miss) && !memcmp(&miss,&zero,sizeof miss));
        assert(full[i].heads==(i?5U:2U) && full[i].exits==1 && !full[i].links && !full[i].stores);
        for(unsigned j=0;j<full[i].heads;j++)assert(full[i].original[j].decoded.pc==expected[i][j]);
        assert(!li2_pg_plan_validate(&full[i],&scratch) && !memcmp(&full[i],&scratch,sizeof scratch));
        assert(!li2_pg_compact_build(&full[i],&scratch,&compact[i]));
        assert(!li2_pg_compact_validate(&compact[i],&scratch,&rebuilt) && !memcmp(&compact[i],&rebuilt,sizeof rebuilt));++proofs;
        unsigned head=i?3:1;const struct li2_jd_plan *p=&full[i].guard[head].dispatch;
        assert(p->record.version==2 && p->record.boundaries==37 && p->record.image_bytes==199 &&
            p->record.miss_offset==146 && p->record.hit_offset==193 && p->binding.directory==layouts[i].directory);
        for(unsigned j=0;j<p->record.boundaries;j++) {
            const struct li2_mg_boundary *at=&p->record.boundary[j];struct li2_decoded d;
            assert(!li2_decoder_decode(p->generated+at->offset,p->image+at->offset,at->length,&d) &&
                d.decode_status==LI2_VALID && d.length==at->length && d.next_pc==p->generated+at->offset+at->length);++decoded;
        }
    }
    directory_rows();
}
static void all_registers(void) {
    struct li2_jd_binding binding=full[0].guard[1].dispatch.binding;
    for(unsigned reg=0;reg<16;reg++) {
        unsigned char b[3];unsigned n=0;if(reg>=8)b[n++]=0x41;b[n++]=0xff;b[n++]=(unsigned char)(0xe0+(reg&7));
        struct li2_jd_plan p;
        assert(!li2_jd_emit(0x400204,b,n,layouts[0].generated[0]+512,layouts[0].spill,&binding,&p));
        assert(!li2_jd_validate(&p) && p.record.boundaries==37 && p.original.target==reg);++descriptors;
        const uint64_t targets[]={directory.row[0].pc,directory.row[2].pc,directory.row[6].pc,UINT64_MAX};
        for(unsigned f=0;f<64;f++)for(unsigned j=0;j<4;j++)run(&p,targets[j],flags_for(f));
    }
    const struct li2_jd_plan *p=&full[0].guard[1].dispatch;
    directory.count=256;
    for(unsigned j=0;j<256;j++)directory.row[j]=(struct li2_jd_domain_row){.pc=0x600000+4*j,.generated=0x11000000+512*j,.slot=j/128,.generation=j/128+1,.head=j%128};
    const uint64_t target[]={0x600000,0x600200,0x6003fc,UINT64_MAX};
    for(unsigned f=0;f<64;f++)for(unsigned j=0;j<4;j++)run(p,target[j],flags_for(f));
    directory.count=0;run(p,0x600000,flags_for(63));directory.count=257;run(p,UINT64_MAX,flags_for(63));
    directory_rows();
}
static void integrated(void) {
    for(unsigned i=0;i<2;i++) {
        current=&compact[i];current_head=i?3:1;const struct li2_jd_plan *p=&full[i].guard[current_head].dispatch;
        for(unsigned f=0;f<64;f++) {
            run(p,roots[0],flags_for(f));run(p,roots[1],flags_for(f));run(p,roots[0]+1,flags_for(f));
        }
    }
    /* Each source uses its own spill. At the committed target's first head,
       deliberately unrelated stale target spill words must not affect state. */
    for(unsigned which=0;which<3;which++)for(unsigned f=0;f<64;f++) {
        unsigned source_slot=which?1:0,target_slot=1-source_slot,target_head=which==2?1:0;
        current=&compact[source_slot];current_head=source_slot?3:1;
        const struct li2_jd_plan *p=&full[source_slot].guard[current_head].dispatch;
        uint64_t target=compact[target_slot].original[target_head].decoded.pc;
        struct jd_model_result model=run(p,target,flags_for(f));
        uint64_t raw[16],poison[4]={UINT64_MAX,0xdeadbeef,0x12345678,0};frame(raw,p->original.target);raw[p->original.target]=target;
        struct li2_pg_recovered recovered;current=0;
        assert(!li2_pg_compact_recover(&compact[target_slot],model.target,raw,flags_for(f),poison,&recovered_guard,&recovered));
        assert(recovered.complete==1 && recovered.original_pc==target && recovered.phase==LI2_MG_BEFORE &&
            recovered.member==0 && recovered.head==target_head && recovered.flags==flags_for(f) &&
            !memcmp(recovered.gpr,raw,sizeof raw));++handoffs;
    }
    current=0;
}
static void corruptions(void) {
    const struct li2_jd_plan *good=&full[0].guard[1].dispatch;
    for(unsigned i=0;i<12;i++) {
        struct li2_jd_plan bad=*good;
        if(i==0)bad.record.version=1;
        if(i==1)bad.binding.directory+=4096;
        if(i==2)bad.binding.directory=bad.binding.image[0];
        if(i==3)bad.binding.directory++;
        if(i==4)bad.record.boundaries--;
        if(i==5)bad.record.boundary[16].dirty=0;
        if(i==6)bad.record.boundary[16].flags=0;
        if(i==7)bad.record.boundary[0].spill_valid=1;
        if(i==8)bad.record.boundary[36].phase=LI2_JD_BEFORE;
        if(i==9)bad.image[154]^=1;
        if(i==10)bad.original.target=0;
        if(i==11)bad.binding.heads=129;
        assert(li2_jd_validate(&bad)==LI2_JD_CORRUPT);++refusals;
    }
    uint64_t raw[16]={0},spill[4]={0};struct li2_jd_recovered out;
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned j=0;j<good->record.boundaries;j++)found|=good->record.boundary[j].offset==offset;
        if(!found){assert(li2_jd_recover(good,good->generated+offset,raw,0,spill,&out)==LI2_JD_CORRUPT);++refusals;}
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    plans();all_registers();integrated();corruptions();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(proofs==2 && descriptors==16 && decoded==74 && models==4930 && handoffs==192 && refusals==487);
    assert(steps==416230 && wrapped==43520);
    printf("active-domain-dispatch proofs=%u descriptors=%u decoded=%u models=%u handoffs=%u refusals=%u steps=%llu typed=%u\n",
        proofs,descriptors,decoded,models,handoffs,refusals,(unsigned long long)steps,wrapped);
    return 0;
}
