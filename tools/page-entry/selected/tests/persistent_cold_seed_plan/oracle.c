/* Actual sealed decoder, group planner and compact validators. The supplied
   whole8192 source is extracted from the inspected real fixture ELF. No emitted
   instruction, guest, source lease or mapping authority is exercised here. */
#include "persistent_group_compact.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static unsigned char source[2][4096],expected_source[2][4096];
static struct li2_pg_plan full,scratch;
static struct li2_pg_compact compact,rebuilt,bad;
static struct li2_mg_table table;
static const uintptr_t pages[2]={0x411000,0x412000};
static const struct li2_pg_layout layout={
    {0x10000000,0x10008000},0x10010000,0x10011000,0x10012000,0x30000000};
static unsigned cases,descriptors,validations,refusals;
static struct li2_span_decoded expected(unsigned offset,unsigned code,unsigned length,unsigned step,unsigned refusal) {
    struct li2_span_decoded d={0};d.decoded=(struct li2_decoded){
        .pc=pages[0]+offset,.next_pc=pages[0]+offset+length,.abi_version=1,
        .code=code,.destination=16,.step_disposition=step,.available=15,.length=length};
    memcpy(d.decoded.bytes,source[0]+offset,15);d.version=1;d.refusal=refusal;return d;
}
static void describe(unsigned offset,const struct li2_span_decoded *want) {
    struct li2_span_decoded actual;struct li2_decoded decoded;
    assert(!li2_decoder_decode(pages[0]+offset,source[0]+offset,15,&decoded));
    assert(!memcmp(&decoded,&want->decoded,sizeof decoded));
    assert(!li2_decoder_span_describe(pages[0]+offset,source[0]+offset,15,&actual));
    assert(!memcmp(&actual,want,sizeof actual));++descriptors;
}
static void ready(uintptr_t root,unsigned heads,unsigned exits,unsigned stores,unsigned bytes) {
    struct li2_pg_miss miss,zero={.version=LI2_PG_VERSION};
    assert(!li2_pg_plan_pages(pages,source,root,&layout,&table,&full,&miss));
    assert(!memcmp(&miss,&zero,sizeof miss) && full.ready==1 && !full.result &&
        full.heads==heads && full.exits==exits && full.stores==stores && full.source_bytes==bytes &&
        full.source_mask==1 && full.member_heads[0]==heads && !full.member_heads[1] && !full.links &&
        !memcmp(full.source,source,sizeof source));
    assert(!li2_pg_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));++validations;
    assert(!li2_pg_compact_build(&full,&scratch,&compact));++validations;
    assert(!li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));++validations;
    assert(!memcmp(compact.source,source,sizeof source));++cases;
}
static void original_nop(void) {
    source[0][0x100]=0x66;source[0][0x101]=0x90;
    struct li2_span_decoded d=expected(0x100,299,2,1,LI2_REGION_UNSUPPORTED);describe(0x100,&d);
    struct li2_pg_miss miss,want={LI2_PG_VERSION,LI2_PG_MISS,LI2_PGD_ROOT_UNSUPPORTED,
        LI2_PGD_SOURCE,0x411100,LI2_REGION_UNSUPPORTED};
    int result=li2_pg_plan_pages(pages,source,0x411100,&layout,&table,&full,&miss);
    assert(result==LI2_PG_MISS && !full.ready && full.result==LI2_PG_MISS &&
        !full.heads && !full.exits && !full.stores && !full.source_bytes &&
        !memcmp(&miss,&want,sizeof miss) && !memcmp(full.source,source,sizeof source));
    assert(li2_pg_miss_valid(&full,&miss,result));++cases;
    /* A coherent whole input differs only in S's actual two bytes. */
    source[0][0x100]=0x89;source[0][0x101]=0xc0;
    assert(!memcmp(source,expected_source,sizeof source));
}
static void mov_seed(void) {
    struct li2_span_decoded mov=expected(0x100,281,2,1,0);
    mov.ready=1;mov.condition=LI2_REGION_CONDITION_NONE;mov.operand_count=2;mov.register_count=2;
    mov.operands[0]=(struct li2_region_operand){0,LI2_REGION_REGISTER,0,32,LI2_REGION_WRITE,0,0};
    mov.operands[1]=(struct li2_region_operand){0,LI2_REGION_REGISTER,0,32,LI2_REGION_READ,0,0};
    /* The destination is the whole RAX, not a preserved upper32 half. The
       actual ordered factory rows retain its separate EAX source read. */
    mov.registers[0]=(struct li2_region_register){0,64,LI2_REGION_WRITE,0};
    mov.registers[1]=(struct li2_region_register){0,32,LI2_REGION_READ,0};
    mov.gpr_read=mov.gpr_write=1;describe(0x100,&mov);
    struct li2_span_decoded jump=expected(0x102,696,5,0,0);
    jump.ready=1;jump.target=0x411013;jump.flow=LI2_REGION_JMP;jump.condition=LI2_REGION_CONDITION_NONE;
    jump.operand_count=1;jump.operands[0]=(struct li2_region_operand){0x411013,LI2_REGION_BRANCH,0,64,LI2_REGION_READ,32,0};
    describe(0x102,&jump);
    struct li2_span_decoded frontier=expected(0x13,765,2,0,LI2_REGION_UNSUPPORTED);describe(0x13,&frontier);
    struct li2_span_decoded predecessor=expected(0xfe,299,2,1,LI2_REGION_UNSUPPORTED);describe(0xfe,&predecessor);
    ready(0x411100,2,1,0,7);
    const struct li2_pe_head heads[2]={{LI2_PE_NONE,0,0x100,2,1,{1,0},7},
        {LI2_PE_NONE,0,0x102,5,1,{128,0},5}};
    assert(!memcmp(full.head,heads,sizeof heads) && !memcmp(&full.original[0],&mov,sizeof mov) &&
        !memcmp(&full.original[1],&jump,sizeof jump) && !memcmp(&full.frontier[0],&frontier,sizeof frontier) &&
        full.exit_pc[0]==0x411013 && full.head[0].source_offset!=0 && full.head[1].source_offset!=0);
    assert(full.image[0][0]==0x89 && full.image[0][1]==0xc0 && full.image[0][2]==0xe9);
    /* Real reconstruction refuses losing zero-extension, the distinct source
       read, its ordered effect rows, or replacing the emitted MOV by NOP. */
    bad=compact;bad.original[0].registers[0].width_bits=32;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
    bad=compact;bad.original[0].gpr_read=0;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
    bad=compact;bad.original[0].registers[0]=mov.registers[1];bad.original[0].registers[1]=mov.registers[0];
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
    bad=compact;bad.image[0][0]=0x66;bad.image[0][1]=0x90;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++refusals;
}
int main(int argc,char **argv) {
    assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);
    assert(fread(source,1,sizeof source,f)==sizeof source && fgetc(f)==EOF && !ferror(f));assert(!fclose(f));
    memset(expected_source,0xcc,sizeof expected_source);
    const unsigned char target[]={0x48,0x89,7,0x48,0x83,0xc0,7,0x48,0x89,0x47,8,
        0x48,0x83,0xe9,1,0x75,2,0xff,0x23,0xff,0x26};
    const unsigned char seed[]={0x66,0x90,0x89,0xc0,0xe9,0x0c,0xff,0xff,0xff};
    memcpy(expected_source[0],target,sizeof target);memcpy(expected_source[0]+0xfe,seed,sizeof seed);
    assert(!memcmp(source,expected_source,sizeof source));
    uintptr_t proof=0x40000000;const struct li2_mg_range ranges[]={
        {pages[0],pages[1]+4096},{layout.generated[0],layout.spill+4096},
        {proof,proof+((sizeof compact+4095)&~(size_t)4095)},
        {layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES}};
    assert(!li2_mg_table_build(ranges,4,proof+offsetof(struct li2_pg_compact,table),&table));
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    original_nop();mov_seed();ready(0x411000,5,2,2,17);
    const unsigned offsets[5]={0,3,7,11,15};
    for(unsigned i=0;i<5;i++)assert(full.head[i].source_page==0 && full.head[i].source_offset==offsets[i]);
    assert(full.exit_pc[0]==0x411013 && full.exit_pc[1]==0x411011 &&
        full.head[0].kind==LI2_PE_MOV && full.head[2].kind==LI2_PE_MOV);
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(cases==3 && descriptors==5 && validations==6 && refusals==4);
    puts("{\"version\":1,\"cases\":3,\"descriptors\":5,\"validations\":6,\"refusals\":4,\"source_bytes\":8192,\"emitted_execution\":0,\"owner_credit\":0}");
    return 0;
}
