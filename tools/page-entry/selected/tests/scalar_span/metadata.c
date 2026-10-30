/* Metadata/planner component only. These supplied instruction bytes are never
   executed. Full336-byte expected effects are independently constructed from
   fixed encoding operands; only the old72-byte row comes from the old API. */
#include "region_plan.h"
#include "write_footprint.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
enum { Mov,Movzx,Lea,Add,Sub,And,Or,Xor,Cmp,Test,Shl,Shr,Sar };
enum { RmReg,RegRm,RegImm,AccImm,Group32,Group8,One,Count8,Cl };
enum { CF=1,PF=4,AF=16,ZF=64,SF=128,OF=2048 };
struct spec {unsigned code,family,encoding,width,opcode,group;};
static const struct spec specs[96]={
    {281,Mov,RmReg,32,0x89,0}, /* Mov_rm32_r32 */
    {285,Mov,RegRm,32,0x8b,0}, /* Mov_r32_rm32 */
    {2090,Movzx,RegRm,32,0xb6,0}, /* Movzx_r32_rm8 */
    {357,Mov,RegImm,32,0xb8,0}, /* Mov_r32_imm32 */
    {404,Mov,Group32,32,0xc7,0}, /* Mov_rm32_imm32 */
    {291,Lea,RegRm,32,0x8d,0}, /* Lea_r32_m */
    {282,Mov,RmReg,64,0x89,0}, /* Mov_rm64_r64 */
    {286,Mov,RegRm,64,0x8b,0}, /* Mov_r64_rm64 */
    {2091,Movzx,RegRm,64,0xb6,0}, /* Movzx_r64_rm8 */
    {358,Mov,RegImm,64,0xb8,0}, /* Mov_r64_imm64 */
    {405,Mov,Group32,64,0xc7,0}, /* Mov_rm64_imm32 */
    {292,Lea,RegRm,64,0x8d,0}, /* Lea_r64_m */
    {7,Add,RmReg,32,0x01,0}, /* Add_rm32_r32 */
    {11,Add,RegRm,32,0x03,0}, /* Add_r32_rm32 */
    {15,Add,AccImm,32,0x05,0}, /* Add_EAX_imm32 */
    {216,Add,Group32,32,0x81,0}, /* Add_rm32_imm32 */
    {248,Add,Group8,32,0x83,0}, /* Add_rm32_imm8 */
    {8,Add,RmReg,64,0x01,0}, /* Add_rm64_r64 */
    {12,Add,RegRm,64,0x03,0}, /* Add_r64_rm64 */
    {16,Add,AccImm,64,0x05,0}, /* Add_RAX_imm32 */
    {217,Add,Group32,64,0x81,0}, /* Add_rm64_imm32 */
    {249,Add,Group8,64,0x83,0}, /* Add_rm64_imm8 */
    {23,Or,RmReg,32,0x09,0}, /* Or_rm32_r32 */
    {27,Or,RegRm,32,0x0b,0}, /* Or_r32_rm32 */
    {31,Or,AccImm,32,0x0d,0}, /* Or_EAX_imm32 */
    {219,Or,Group32,32,0x81,1}, /* Or_rm32_imm32 */
    {251,Or,Group8,32,0x83,1}, /* Or_rm32_imm8 */
    {24,Or,RmReg,64,0x09,0}, /* Or_rm64_r64 */
    {28,Or,RegRm,64,0x0b,0}, /* Or_r64_rm64 */
    {32,Or,AccImm,64,0x0d,0}, /* Or_RAX_imm32 */
    {220,Or,Group32,64,0x81,1}, /* Or_rm64_imm32 */
    {252,Or,Group8,64,0x83,1}, /* Or_rm64_imm8 */
    {70,And,RmReg,32,0x21,0}, /* And_rm32_r32 */
    {74,And,RegRm,32,0x23,0}, /* And_r32_rm32 */
    {78,And,AccImm,32,0x25,0}, /* And_EAX_imm32 */
    {228,And,Group32,32,0x81,4}, /* And_rm32_imm32 */
    {260,And,Group8,32,0x83,4}, /* And_rm32_imm8 */
    {71,And,RmReg,64,0x21,0}, /* And_rm64_r64 */
    {75,And,RegRm,64,0x23,0}, /* And_r64_rm64 */
    {79,And,AccImm,64,0x25,0}, /* And_RAX_imm32 */
    {229,And,Group32,64,0x81,4}, /* And_rm64_imm32 */
    {261,And,Group8,64,0x83,4}, /* And_rm64_imm8 */
    {83,Sub,RmReg,32,0x29,0}, /* Sub_rm32_r32 */
    {87,Sub,RegRm,32,0x2b,0}, /* Sub_r32_rm32 */
    {91,Sub,AccImm,32,0x2d,0}, /* Sub_EAX_imm32 */
    {231,Sub,Group32,32,0x81,5}, /* Sub_rm32_imm32 */
    {263,Sub,Group8,32,0x83,5}, /* Sub_rm32_imm8 */
    {84,Sub,RmReg,64,0x29,0}, /* Sub_rm64_r64 */
    {88,Sub,RegRm,64,0x2b,0}, /* Sub_r64_rm64 */
    {92,Sub,AccImm,64,0x2d,0}, /* Sub_RAX_imm32 */
    {232,Sub,Group32,64,0x81,5}, /* Sub_rm64_imm32 */
    {264,Sub,Group8,64,0x83,5}, /* Sub_rm64_imm8 */
    {96,Xor,RmReg,32,0x31,0}, /* Xor_rm32_r32 */
    {100,Xor,RegRm,32,0x33,0}, /* Xor_r32_rm32 */
    {104,Xor,AccImm,32,0x35,0}, /* Xor_EAX_imm32 */
    {234,Xor,Group32,32,0x81,6}, /* Xor_rm32_imm32 */
    {266,Xor,Group8,32,0x83,6}, /* Xor_rm32_imm8 */
    {97,Xor,RmReg,64,0x31,0}, /* Xor_rm64_r64 */
    {101,Xor,RegRm,64,0x33,0}, /* Xor_r64_rm64 */
    {105,Xor,AccImm,64,0x35,0}, /* Xor_RAX_imm32 */
    {235,Xor,Group32,64,0x81,6}, /* Xor_rm64_imm32 */
    {267,Xor,Group8,64,0x83,6}, /* Xor_rm64_imm8 */
    {109,Cmp,RmReg,32,0x39,0}, /* Cmp_rm32_r32 */
    {113,Cmp,RegRm,32,0x3b,0}, /* Cmp_r32_rm32 */
    {117,Cmp,AccImm,32,0x3d,0}, /* Cmp_EAX_imm32 */
    {237,Cmp,Group32,32,0x81,7}, /* Cmp_rm32_imm32 */
    {269,Cmp,Group8,32,0x83,7}, /* Cmp_rm32_imm8 */
    {110,Cmp,RmReg,64,0x39,0}, /* Cmp_rm64_r64 */
    {114,Cmp,RegRm,64,0x3b,0}, /* Cmp_r64_rm64 */
    {118,Cmp,AccImm,64,0x3d,0}, /* Cmp_RAX_imm32 */
    {238,Cmp,Group32,64,0x81,7}, /* Cmp_rm64_imm32 */
    {270,Cmp,Group8,64,0x83,7}, /* Cmp_rm64_imm8 */
    {273,Test,RmReg,32,0x85,0}, /* Test_rm32_r32 */
    {341,Test,AccImm,32,0xa9,0}, /* Test_EAX_imm32 */
    {720,Test,Group32,32,0xf7,0}, /* Test_rm32_imm32 */
    {274,Test,RmReg,64,0x85,0}, /* Test_rm64_r64 */
    {342,Test,AccImm,64,0xa9,0}, /* Test_RAX_imm32 */
    {721,Test,Group32,64,0xf7,0}, /* Test_rm64_imm32 */
    {447,Shl,One,32,0xd1,4}, /* Shl_rm32_1 */
    {380,Shl,Count8,32,0xc1,4}, /* Shl_rm32_imm8 */
    {479,Shl,Cl,32,0xd3,4}, /* Shl_rm32_CL */
    {448,Shl,One,64,0xd1,4}, /* Shl_rm64_1 */
    {381,Shl,Count8,64,0xc1,4}, /* Shl_rm64_imm8 */
    {480,Shl,Cl,64,0xd3,4}, /* Shl_rm64_CL */
    {450,Shr,One,32,0xd1,5}, /* Shr_rm32_1 */
    {383,Shr,Count8,32,0xc1,5}, /* Shr_rm32_imm8 */
    {482,Shr,Cl,32,0xd3,5}, /* Shr_rm32_CL */
    {451,Shr,One,64,0xd1,5}, /* Shr_rm64_1 */
    {384,Shr,Count8,64,0xc1,5}, /* Shr_rm64_imm8 */
    {483,Shr,Cl,64,0xd3,5}, /* Shr_rm64_CL */
    {456,Sar,One,32,0xd1,7}, /* Sar_rm32_1 */
    {389,Sar,Count8,32,0xc1,7}, /* Sar_rm32_imm8 */
    {488,Sar,Cl,32,0xd3,7}, /* Sar_rm32_CL */
    {457,Sar,One,64,0xd1,7}, /* Sar_rm64_1 */
    {390,Sar,Count8,64,0xc1,7}, /* Sar_rm64_imm8 */
    {489,Sar,Cl,64,0xd3,7}, /* Sar_rm64_CL */
};
static _Alignas(64) unsigned char arena[2*1024*1024];
static struct li2_decoder_stats initial;
static unsigned calls,accepted,refusals,plan_controls,old_accepts,max_registers;
static struct li2_span_plan p,q;
static unsigned char page[4096];
static const uint64_t PC=UINT64_C(0x100000100);
static void stats(void){struct li2_decoder_stats a;assert(!li2_decoder_stats(&a)&&!memcmp(&a,&initial,sizeof(a)));}
static void put(unsigned char *b,unsigned *n,uint64_t value,unsigned count){assert(*n+count<=15);for(unsigned i=0;i<count;i++)b[(*n)++]=(unsigned char)(value>>(8*i));}
static struct li2_region_operand reg(unsigned r,unsigned w,unsigned a){return(struct li2_region_operand){.kind=1,.reg=r,.width_bits=w,.access=a};}
static void used(struct li2_span_decoded *d,unsigned r,unsigned w,unsigned a){assert(r<16&&d->register_count<4);d->registers[d->register_count++]=(struct li2_region_register){r,w,a,0};if(a&1)d->gpr_read|=1u<<r;if(a&2)d->gpr_write|=1u<<r;}
static void registers(struct li2_span_decoded *d,int lea){for(unsigned i=0;i<d->operand_count;i++){const struct li2_region_operand *o=d->operands+i;if(o->kind==1&&o->access){if(o->width_bits==32&&o->access==3){used(d,o->reg,32,1);used(d,o->reg,64,2);}else used(d,o->reg,o->width_bits==32&&o->access==2?64:o->width_bits,o->access);}else if(o->kind==2||o->kind==5){unsigned w=lea?d->operands[0].width_bits:64;if(d->address.base!=16)used(d,d->address.base,w,1);if(d->address.index!=16)used(d,d->address.index,w,1);}}}
static struct li2_span_decoded converted(const struct li2_region_decoded *a){struct li2_span_decoded d={0};d.decoded=a->decoded;d.target=a->target;memcpy(d.operands,a->operands,sizeof(a->operands));memcpy(d.registers,a->registers,sizeof(a->registers));d.address=a->memory;d.version=a->version;d.ready=a->ready;d.refusal=a->refusal;d.flow=a->flow;d.condition=a->condition;d.operand_count=a->operand_count;d.register_count=a->register_count;d.memory_count=d.address_count=a->memory_count;d.flags_read=a->flags_read;d.flags_written=a->flags_written;d.flags_set=a->flags_set;d.flags_cleared=a->flags_cleared;d.flags_undefined=a->flags_undefined;d.gpr_read=a->gpr_read;d.gpr_write=a->gpr_write;return d;}
static void compare(const unsigned char *b,unsigned n,unsigned code,struct li2_span_decoded *want){
    struct li2_decoded old;struct li2_region_decoded old47;struct li2_span_decoded a;
    assert(!li2_decoder_decode(PC,b,n,&old)&&old.code==code&&old.decode_status==LI2_VALID&&old.length==n);
    want->decoded=old;memset(&a,0xa5,sizeof(a));assert(!li2_decoder_span_describe(PC,b,n,&a));
    if(memcmp(&a,want,sizeof(a))){const unsigned char *x=(void *)&a,*y=(void *)want;unsigned i=0;while(i<sizeof(a)&&x[i]==y[i])i++;fprintf(stderr,"SPAN code=%u byte=%u actual=%u expected=%u\n",code,i,i<sizeof(a)?x[i]:0,i<sizeof(a)?y[i]:0);}
    assert(!memcmp(&a,want,sizeof(a)));assert(!li2_decoder_region_describe(PC,b,n,&old47));
    if(old47.ready){struct li2_span_decoded expected=converted(&old47);assert(!memcmp(&a,&expected,sizeof(a)));old_accepts++;}
    struct li2_write_registers state={0};struct li2_write_footprint fp,expected={.pc=PC,.next_pc=PC+n,.abi_version=1,.policy=LI2_WRITE_NONE,.code=code,.length=n};
    assert(!li2_decoder_write_footprint(PC,b,n,&state,&fp)&&!memcmp(&fp,&expected,sizeof(fp)));
    if(a.register_count>max_registers)max_registers=a.register_count;calls++;accepted++;stats();
}
static int readable_memory(struct spec s){return(s.encoding==RegRm)||((s.family==Cmp||s.family==Test)&&(s.encoding==RmReg||s.encoding==Group32||s.encoding==Group8));}
static void specimen(struct spec s,unsigned memory,int clear,unsigned count){
    unsigned char b[15]={0};unsigned n=0;struct li2_span_decoded d={.version=1,.ready=1,.condition=16,.operand_count=2};
    int lea=s.family==Lea,load8=s.family==Movzx;
    if(lea||load8){if(!memory)memory=1;clear=0;}
    assert(!memory||readable_memory(s));assert(!clear||(s.family==Sub||s.family==Xor));
    if(s.width==64)put(b,&n,0x48,1);
    if(load8)put(b,&n,0x0f,1);put(b,&n,s.opcode,1);
    int modrm=s.encoding!=RegImm&&s.encoding!=AccImm;
    unsigned rf=s.encoding==RmReg?3:s.encoding==RegRm?0:s.group;
    unsigned rm=s.encoding==RegRm?3:0;if(clear){rf=0;rm=0;}
    if(modrm){put(b,&n,(memory?(memory==1?0x44:5):0xc0|rm)|(rf<<3),1);if(memory==1){put(b,&n,0x8b,1);put(b,&n,0xef,1);}}
    unsigned displacement=n;if(memory>=2)put(b,&n,memory==2?0x12345:UINT32_C(0xfffedcbb),4);
    unsigned bits=s.encoding==RegImm?s.width:s.encoding==AccImm||s.encoding==Group32?32:s.encoding==Group8||s.encoding==Count8?8:0;
    uint64_t imm=s.encoding==Count8?count:s.encoding==RegImm?UINT64_C(0x8877665580000001):UINT64_MAX;
    if(bits)put(b,&n,imm,bits/8);
    unsigned a=(s.family==Mov||load8||lea)?2:(s.family==Cmp||s.family==Test)?1:clear?2:3;
    d.operands[0]=reg(0,s.width,a);
    int memfirst=memory&&s.encoding!=RegRm;
    if(s.encoding==RmReg)d.operands[1]=reg(clear?0:3,s.width,clear?0:1);
    else if(s.encoding==RegRm)d.operands[1]=reg(clear?0:3,s.width,clear?0:1);
    else if(s.encoding==Cl)d.operands[1]=reg(1,8,1);
    else {uint64_t value=s.encoding==One?1:s.encoding==Count8?count:s.width==32?(uint32_t)imm:imm;
        d.operands[1]=(struct li2_region_operand){.immediate=value,.kind=3,.width_bits=(s.encoding==One||s.encoding==Count8)?8:s.width,.access=1,.encoding_bits=bits};}
    if(memory){uint64_t disp=memory==1?UINT64_MAX-16:PC+n+(memory==2?INT64_C(0x12345):-INT64_C(0x12345));unsigned width=lea?0:load8?1:s.width/8;
        d.operands[memfirst?0:1]=(struct li2_region_operand){.kind=lea?5:2,.width_bits=lea?64:width*8,.access=lea?7:1};
        d.address=(struct li2_region_memory){.displacement=disp,.base=memory==1?3:16,.index=memory==1?1:16,.scale=memory==1?4:1,.width_bytes=width,.address_bits=64,.segment=lea?0:1,.access=lea?7:1};
        d.address_count=1;d.memory_count=!lea;if(memory>=2){d.rip_target=disp;d.relocation=1;d.displacement_offset=displacement;d.displacement_bytes=4;}}
    if(s.family==Add||s.family==Sub||s.family==Cmp)d.flags_written=CF|PF|AF|ZF|SF|OF;
    if(s.family==And||s.family==Or||s.family==Xor||s.family==Test){d.flags_written=PF|ZF|SF;d.flags_cleared=CF|OF;d.flags_undefined=AF;}
    if(clear){d.flags_written=0;d.flags_set=PF|ZF;d.flags_cleared=CF|SF|OF|(s.family==Sub?AF:0);d.flags_undefined=s.family==Xor?AF:0;}
    if(s.family>=Shl){unsigned c=s.encoding==One?1:s.encoding==Cl?2:count&(s.width-1);if(c){d.flags_written=CF|PF|ZF|SF|(c==1?OF:0);d.flags_undefined=AF|(c==1?0:OF);}}
    registers(&d,lea);compare(b,n,s.code,&d);
}
static void old_branches(void){for(unsigned near=0;near<2;near++)for(unsigned c=0;c<=16;c++){
    unsigned char b[15]={0};unsigned n=0;if(c==16)put(b,&n,near?0xe9:0xeb,1);else{if(near)put(b,&n,0x0f,1);put(b,&n,(near?0x80:0x70)+c,1);}put(b,&n,17,near?4:1);
    struct li2_region_decoded a;assert(!li2_decoder_region_describe(PC,b,n,&a)&&a.ready);struct li2_span_decoded d=converted(&a);compare(b,n,c==16?(near?696:701):(near?1856:161)+3*c,&d);}
    unsigned char b[2]={0x3c,0x7f};struct li2_region_decoded a;assert(!li2_decoder_region_describe(PC,b,2,&a)&&a.ready);struct li2_span_decoded d=converted(&a);compare(b,2,115,&d);
}
static void reject(const unsigned char *b,unsigned n,uint64_t pc,unsigned result){struct li2_span_decoded a,z={0};struct li2_decoded d;memset(&a,0xa5,sizeof(a));unsigned r=li2_decoder_span_describe(pc,b,n,&a);assert(r==result);if(!r){assert(!li2_decoder_decode(pc,b,n,&d));z.decoded=d;z.version=1;z.refusal=a.refusal;assert(z.refusal&&!a.ready);}assert(!memcmp(&a,&z,sizeof(a)));refusals++;stats();}
static void negatives(void){
    static const struct{unsigned n;unsigned char b[15];} cases[]={
        {3,{0x48,0x89,0x03}},{3,{0x48,0x01,0x03}},{3,{0x48,0x83,0x03}},
        {3,{0x48,0x8d,0xc3}},{3,{0x48,0x8b,0xe3}},{3,{0x48,0x01,0xdc}},
        {3,{0xc1,0xf0,1}},{3,{0xc1,0xe4,1}},
        {3,{0x66,0x01,0xd8}},{3,{0x67,0x8b,0x03}},{3,{0x64,0x8b,0x03}},
        {4,{0x40,0x40,0x01,0xd8}},{3,{0xf0,0x01,0xd8}},{3,{0xf3,0x01,0xd8}},
        {5,{0xe8,0,0,0,0}},{1,{0xc3}},{2,{0xff,0xe0}},{1,{0x50}},
        {4,{0x66,0x0f,0xef,0xc0}},{2,{0x0f,0xa2}},{1,{0x0f}}};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
        reject(cases[i].b,cases[i].n,PC,0);
    }
    unsigned char lea[7]={0x48,0x8d,0x05,0xff,0xff,0xff,0x7f};reject(lea,7,UINT64_C(0x7ffffffff000),0);
    unsigned char mov[2]={0x89,0xd8};reject(mov,0,PC,LI2_BAD_ARGUMENT);reject(mov,16,PC,LI2_BAD_ARGUMENT);reject(NULL,1,PC,LI2_BAD_ARGUMENT);reject(mov,2,UINT64_MAX-1,LI2_ADDRESS_OVERFLOW);
}
static void plans(void){
    memset(page,0xcc,sizeof(page));static const unsigned char code[]={0x48,0x8b,0x05,0,0,0,0,0x48,0x83,0xc0,1,0x48,0x85,0xc0,0x74,3,0x48,0x31,0xdb,0x90};memcpy(page+0x100,code,sizeof(code));
    uint32_t delta=0x800-0x107;memcpy(page+0x103,&delta,4);
    assert(!li2_span_plan_page(PC-0x100,page,PC,PC-0x100+4096,&p));
    assert(p.ready&&p.heads==5&&p.maps==6&&p.exits==1&&p.source_bytes==19&&p.original[0].rip_target==PC-0x100+0x800&&p.map[0].kind==4);
    assert(!li2_span_plan_validate(&p));stats();
    for(unsigned i=0;i<p.image_bytes;i++){struct li2_region_pc got,empty={0};unsigned j=0;while(j<p.maps&&p.map[j].generated_offset!=i)j++;int r=li2_span_map_pc(&p,p.generated+i,&got);if(j<p.maps)assert(!r&&!memcmp(&got,&p.map[j],sizeof(got)));else assert(r==LI2_REGION_PLAN_MISS&&!memcmp(&got,&empty,sizeof(got)));plan_controls++;}
    const size_t corrupt[]={offsetof(struct li2_span_plan,source)+0x100,offsetof(struct li2_span_plan,image),offsetof(struct li2_span_plan,original)+248,offsetof(struct li2_span_plan,original)+324,offsetof(struct li2_span_plan,emitted)+208,offsetof(struct li2_span_plan,head)+16,offsetof(struct li2_span_plan,exit_pc),offsetof(struct li2_span_plan,map)+32};
    for(unsigned i=0;i<sizeof(corrupt)/sizeof(corrupt[0]);i++){q=p;((unsigned char *)&q)[corrupt[i]]^=1;assert(li2_span_plan_validate(&q)==LI2_REGION_PLAN_CORRUPT);plan_controls++;}
    assert(li2_span_plan_page(PC-0x100,page,PC,PC-0x100+UINT64_C(0x100000000),&q)==LI2_REGION_PLAN_RELOCATION&&!q.ready);plan_controls++;
    for(unsigned sign=0;sign<2;sign++)for(unsigned outside=0;outside<2;outside++){
        uint64_t generated=sign?PC-0x100+4096:PC-0x100-4096;
        int64_t limit=sign?INT32_MIN:INT32_MAX,rel=limit+(sign?-(int64_t)outside:(int64_t)outside);
        uint64_t target=(uint64_t)((int64_t)(generated+7)+rel);
        int64_t original=(int64_t)target-(int64_t)(PC+7);assert(original>=INT32_MIN&&original<=INT32_MAX);
        uint32_t encoded=(uint32_t)original;memcpy(page+0x103,&encoded,4);
        int got=li2_span_plan_page(PC-0x100,page,PC,generated,&q);
        if(outside)assert(got==LI2_REGION_PLAN_RELOCATION&&!q.ready);
        else{int32_t actual;memcpy(&actual,q.image+3,4);assert(!got&&q.ready&&actual==limit&&q.original[0].rip_target==target&&q.emitted[0].rip_target==target);}
        plan_controls++;
    }
    memset(page,0xcc,sizeof(page));page[0x100]=0x89;page[0x101]=0xdb;page[0x102]=0x90;
    assert(li2_span_plan_page(PC-0xff,page,PC,PC-0x100+4096,&q)==LI2_REGION_PLAN_ARGUMENT&&!q.ready);plan_controls++;
    static const struct{unsigned n;unsigned char b[6];} bad_graphs[]={
        {3,{0xeb,0xfe,0x90}}, /* reachable cycle */
        {5,{0xeb,0x02,0x89,0xdb,0x90}}, /* selected unreachable MOV */
        {5,{0x75,0x01,0x89,0xdb,0x90}}, /* branch into a selected instruction */
        {6,{0xe9,0x00,0x10,0x00,0x00,0x90}} /* outside held source page */
    };
    for(unsigned i=0;i<4;i++){memset(page,0xcc,sizeof(page));memcpy(page+0x100,bad_graphs[i].b,bad_graphs[i].n);assert(li2_span_plan_page(PC-0x100,page,PC,PC-0x100+4096,&q)==LI2_REGION_PLAN_GRAPH&&!q.ready);plan_controls++;}
    memset(page,0xcc,sizeof(page));page[4094]=0x89;page[4095]=0xdb;
    assert(li2_span_plan_page(PC-0x100,page,PC-0x100+4094,PC-0x100+4096,&q)==LI2_REGION_PLAN_BOUNDARY&&!q.ready);plan_controls++;
    q=p;assert(li2_span_plan_page(p.page,p.source,p.entry,p.generated,&p)==LI2_REGION_PLAN_ARGUMENT&&!memcmp(&p,&q,sizeof(p)));plan_controls++;
    q=p;q.version=2;assert(li2_span_plan_validate(&q)==LI2_REGION_PLAN_CORRUPT);plan_controls++;
    stats();
}
int main(void){assert(!li2_decoder_initialize(arena,sizeof(arena),&initial));assert(initial.abi_version==1&&initial.phase==2&&!initial.first_fatal_reason&&!initial.reserved&&initial.arena_bytes==sizeof(arena)&&initial.retained_high_water&&initial.retained_high_water<=sizeof(arena));
    for(unsigned i=0;i<96;i++)specimen(specs[i],0,0,3);old_branches();assert(accepted==131);
    for(unsigned i=0;i<96;i++){struct spec s=specs[i];if(readable_memory(s)){for(unsigned m=1;m<=3;m++)specimen(s,m,0,3);}if((s.family==Sub||s.family==Xor)&&(s.encoding==RmReg||s.encoding==RegRm))specimen(s,0,1,0);if(s.encoding==Count8)for(unsigned j=0;j<6;j++){unsigned c[]={0,1,s.width-1,s.width,s.width+1,255};specimen(s,0,0,c[j]);}}
    unsigned before=calls;for(unsigned i=0;i<1024;i++)specimen(specs[13],1,0,0);assert(calls==before+1024&&max_registers==4);
    negatives();plans();stats();printf("{\"schema\":1,\"code_forms\":131,\"accepted\":%u,\"old_accepts\":%u,\"refusals\":%u,\"plan_controls\":%u,\"none_checks\":%u,\"max_register_rows\":4,\"postseal_equal\":1}\n",accepted,old_accepts,refusals,plan_controls,calls);return 0;}
