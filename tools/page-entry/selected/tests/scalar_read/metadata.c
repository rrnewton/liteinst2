/* Component source only: supplied instruction bytes are decoded, never run.
   Full336-byte expected rows come from literal encoding/semantic models; only
   the unchanged72-byte generic decode header is obtained from the old API. */
#include "scalar_read_decode.h"
#include "linked_rseq.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

enum { CF=1,PF=4,AF=16,ZF=64,SF=128,OF=2048, ALL=CF|PF|AF|ZF|SF|OF };
static _Alignas(64) unsigned char arena[2*1024*1024];
static struct li2_decoder_stats initial;
static unsigned accepted,refused,models,old_rows;
static const uint64_t PC=UINT64_C(0x100000100);

static void stable(void) {
    struct li2_decoder_stats s;
    assert(!li2_decoder_stats(&s) && !memcmp(&s,&initial,sizeof(s)));
}
static struct li2_region_operand reg(unsigned r,unsigned w,unsigned a) {
    return (struct li2_region_operand){.kind=1,.reg=r,.width_bits=w,.access=a};
}
static void used(struct li2_span_decoded *r,unsigned n,unsigned w,unsigned a) {
    assert(n<16 && r->register_count<4);
    r->registers[r->register_count++]=(struct li2_region_register){n,w,a,0};
    if(a&1) r->gpr_read|=1u<<n;
    if(a&2) r->gpr_write|=1u<<n;
}
static struct li2_span_decoded empty(void) {
    return (struct li2_span_decoded){.version=2,.ready=1,.condition=16};
}
static void compare(uint64_t pc,const unsigned char *b,unsigned n,unsigned code,
                    struct li2_span_decoded expected) {
    struct li2_decoded header;
    struct li2_span_decoded actual,old;
    assert(!li2_decoder_decode(pc,b,n,&header));
    assert(header.decode_status==LI2_VALID && header.code==code && header.length==n);
    expected.decoded=header;
    memset(&actual,0xa5,sizeof(actual));
    assert(!li2_decoder_scalar_read_describe(pc,b,n,&actual));
    assert(!memcmp(&actual,&expected,sizeof(actual)));
    assert(!li2_decoder_span_describe(pc,b,n,&old) && old.version==1 && !old.ready && old.refusal);
    struct li2_write_footprint got,want={.pc=pc,.next_pc=pc+n,.abi_version=1,
        .policy=LI2_WRITE_NONE,.code=code,.length=n};
    assert(!li2_decoder_scalar_read_none(pc,b,n,&got) && !memcmp(&got,&want,sizeof(got)));
    assert(!li2_decoder_link_none(pc,b,n,&got) && got.policy==LI2_WRITE_UNSUPPORTED
           && !got.first && !got.end);
    /* No data memory is ever dereferenced. Arbitrary/noncanonical address
       register values must not turn a no-write theorem into address authority. */
    struct li2_write_registers registers={0};
    for(unsigned i=0;i<16;i++) registers.gpr[i]=UINT64_C(0x800000000000)+17*i;
    registers.fs_base=UINT64_MAX; registers.gs_base=UINT64_MAX;
    assert(!li2_decoder_write_footprint(pc,b,n,&registers,&got));
    assert(!memcmp(&got,&want,sizeof(got)));
    accepted++; stable();
}
static void reject(uint64_t pc,const unsigned char *b,unsigned n,unsigned status) {
    struct li2_span_decoded got,expected={0}; struct li2_write_footprint fp;
    memset(&got,0xa5,sizeof(got)); memset(&fp,0xa5,sizeof(fp));
    assert(li2_decoder_scalar_read_describe(pc,b,n,&got)==status);
    assert(li2_decoder_scalar_read_none(pc,b,n,&fp)==status);
    if(!status) {
        assert(!li2_decoder_decode(pc,b,n,&expected.decoded));
        expected.version=2; expected.refusal=got.refusal;
        assert(expected.refusal && !got.ready);
        struct li2_write_footprint want={.pc=expected.decoded.pc,.next_pc=expected.decoded.next_pc,
            .abi_version=1,.code=expected.decoded.code,.length=expected.decoded.length};
        assert(!memcmp(&fp,&want,sizeof(fp)));
    } else { struct li2_write_footprint zero={0}; assert(!memcmp(&fp,&zero,sizeof(fp))); }
    assert(!memcmp(&got,&expected,sizeof(got))); refused++; stable();
}
static void register_forms(void) {
    for(unsigned dest=0;dest<16;dest++) for(unsigned src=0;src<16;src++) {
        unsigned char b[]={0x48|(dest>=8?4:0)|(src>=8?1:0),0x63,
            0xc0|((dest&7)<<3)|(src&7)};
        if(dest==4) { reject(PC,b,sizeof(b),0); continue; }
        struct li2_span_decoded want=empty(); want.operand_count=2;
        want.operands[0]=reg(dest,64,2); want.operands[1]=reg(src,32,1);
        used(&want,dest,64,2); used(&want,src,32,1);
        compare(PC,b,sizeof(b),140,want);
    }
    for(unsigned cmp=0;cmp<2;cmp++) for(unsigned left=0;left<16;left++)
        for(unsigned right=0;right<16;right++) {
            unsigned char b[3]; unsigned n=0;
            if(left>=4 || right>=4) b[n++]=0x40|(right>=8?4:0)|(left>=8?1:0);
            b[n++]=cmp?0x38:0x84; b[n++]=0xc0|((right&7)<<3)|(left&7);
            struct li2_span_decoded want=empty(); want.operand_count=2;
            want.operands[0]=reg(left,8,1); want.operands[1]=reg(right,8,1);
            used(&want,left,8,1); used(&want,right,8,1);
            want.flags_written=cmp?ALL:PF|ZF|SF;
            if(!cmp) { want.flags_cleared=CF|OF; want.flags_undefined=AF; }
            compare(PC,b,n,cmp?107:271,want);
        }
}
static void memory_forms(void) {
    static const struct item { unsigned n; unsigned char b[10]; unsigned base,index,scale,segment;
        int64_t disp; unsigned imm,rip_at; } items[]={
        {5,{0x41,0x80,0x78,0xf8,0},8,16,1,1,-8,0,0},
        {3,{0x80,0x38,0x3d},0,16,1,1,0,0x3d,0},
        {4,{0x80,0x7d,0xff,0x80},5,16,1,2,-1,0x80,0},
        {5,{0x80,0x7c,0x8c,0x7f,0xff},4,1,4,2,127,255,0},
        {4,{0x80,0x3c,0x00,1},0,0,1,1,0,1,0},
        {8,{0x80,0x3c,0x25,0,0x10,0,0,0},16,16,1,1,0x1000,0,0},
        {7,{0x80,0x3d,0x10,0,0,0,0x7f},16,16,1,1,16,127,2},
        {7,{0x80,0x3d,0xe0,0xff,0xff,0xff,0},16,16,1,1,-32,0,2},
        {6,{0x43,0x80,0x7c,0x88,0xf8,0x55},8,9,4,1,-8,0x55,0},
    };
    for(unsigned i=0;i<sizeof(items)/sizeof(items[0]);i++) {
        const struct item *t=items+i; struct li2_span_decoded want=empty();
        want.operand_count=2; want.memory_count=want.address_count=1; want.flags_written=ALL;
        want.operands[0]=(struct li2_region_operand){.kind=2,.width_bits=8,.access=1};
        want.operands[1]=(struct li2_region_operand){.immediate=t->imm,.kind=3,.width_bits=8,
            .access=1,.encoding_bits=8};
        uint64_t disp=t->rip_at?PC+t->n+(uint64_t)t->disp:(uint64_t)t->disp;
        want.address=(struct li2_region_memory){disp,t->base,t->index,t->scale,1,64,t->segment,1,0};
        if(t->rip_at) { want.rip_target=disp; want.relocation=1;
            want.displacement_offset=t->rip_at; want.displacement_bytes=4; }
        if(t->base!=16) used(&want,t->base,64,1);
        if(t->index!=16) used(&want,t->index,64,1);
        compare(PC,t->b,t->n,214,want);
    }
}
static void nops(void) {
    static const struct { unsigned n; unsigned char b[8]; } cases[]={
        {3,{0x0f,0x1f,0}}, {4,{0x0f,0x1f,0x40,0}}, {5,{0x0f,0x1f,0x44,0,0}},
        {7,{0x0f,0x1f,0x80,0,0,0,0}}, {8,{0x0f,0x1f,0x84,0,0,0,0,0}}
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)
        compare(PC,cases[i].b,cases[i].n,1057,empty());
}
static void negatives(void) {
    static const struct { unsigned n; unsigned char b[10]; } cases[]={
        {3,{0x48,0x63,0x00}}, /* memory MOVSXD stays unsupported */
        {2,{0x63,0xc0}}, {4,{0x66,0x48,0x63,0xc0}}, {3,{0x4a,0x63,0xc0}},
        {4,{0x48,0x48,0x63,0xc0}}, {2,{0x48,0x63}},
        {2,{0x84,0xe4}}, {2,{0x38,0xe4}}, /* AH aliases */
        {3,{0x40,0x84,0xc0}}, {3,{0x48,0x38,0xc0}}, {3,{0x42,0x84,0xc0}},
        {2,{0x84,0x00}}, {2,{0x38,0x00}}, /* byte reg/memory forms not added */
        {3,{0x80,0xf8,0}}, {3,{0x82,0x38,0}}, /* register/immediate and alias82 */
        {4,{0x64,0x80,0x38,0}}, {4,{0x67,0x80,0x38,0}},
        {4,{0xf0,0x80,0x38,0}}, {4,{0xf3,0x80,0x38,0}},
        {4,{0x48,0x80,0x38,0}}, {4,{0x44,0x80,0x38,0}}, {4,{0x40,0x80,0x38,0}},
        {4,{0x42,0x80,0x38,0}}, /* unused REX.X */
        {8,{0x41,0x80,0x3d,0,0,0,0,0}}, /* ignored REX.B on RIP */
        {2,{0x80,0x38}}, {3,{0x80,0x3c,0x25}},
        {4,{0x0f,0x1f,0x40,1}}, {4,{0x66,0x0f,0x1f,0}},
        {3,{0x0f,0x1f,0xc0}}, {1,{0x90}},
        {5,{0xe8,0,0,0,0}}, {1,{0xc3}}, {2,{0xff,0xe0}},
        {2,{0x88,0x07}}, {2,{0x00,0x07}}, {3,{0x0f,0xae,0x07}},
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) reject(PC,cases[i].b,cases[i].n,0);
    const unsigned char rip_plus[]={0x80,0x3d,0xff,0xff,0xff,0x7f,0};
    const unsigned char rip_minus[]={0x80,0x3d,0,0,0,0x80,0};
    reject(UINT64_C(0x7ffffffff000),rip_plus,sizeof(rip_plus),0);
    reject(16,rip_minus,sizeof(rip_minus),0);
    const unsigned char cmp[]={0x80,0x38,0};
    reject(UINT64_C(0x800000000000),cmp,sizeof(cmp),0);
    reject(UINT64_MAX-1,cmp,sizeof(cmp),LI2_ADDRESS_OVERFLOW);
    reject(PC,cmp,0,LI2_BAD_ARGUMENT); reject(PC,cmp,16,LI2_BAD_ARGUMENT);
    reject(PC,NULL,1,LI2_BAD_ARGUMENT);
    assert(li2_decoder_scalar_read_describe(PC,cmp,3,NULL)==LI2_BAD_ARGUMENT);
    assert(li2_decoder_scalar_read_none(PC,cmp,3,NULL)==LI2_BAD_ARGUMENT);
    stable();
}
/* Independent scalar value model: no instruction under test is executed. */
static uint64_t extend32(uint64_t source) {
    uint64_t low=source&UINT32_MAX;
    return low&UINT64_C(0x80000000)?low|UINT64_C(0xffffffff00000000):low;
}
static unsigned parity(unsigned value) {
    unsigned n=0; for(unsigned i=0;i<8;i++) n+=(value>>i)&1;
    return !(n&1);
}
static unsigned cmp8(unsigned a,unsigned b) {
    unsigned r=(a-b)&255;
    return (a<b?CF:0)|(parity(r)?PF:0)|((a^b^r)&16?AF:0)
        |(!r?ZF:0)|(r&128?SF:0)|((a^b)&(a^r)&128?OF:0);
}
static void scalar_models(void) {
    static const uint64_t input[]={0,UINT64_C(0x7fffffff),UINT64_C(0x80000000),
        UINT64_C(0xffffffff),UINT64_C(0xdeadbeef80000001),UINT64_C(0xffffffff00000001)};
    static const uint64_t output[]={0,UINT64_C(0x7fffffff),UINT64_C(0xffffffff80000000),
        UINT64_MAX,UINT64_C(0xffffffff80000001),1};
    for(unsigned i=0;i<6;i++) { assert(extend32(input[i])==output[i]); models++; }
    static const unsigned pairs[][3]={{0,0,PF|ZF},{0,1,CF|PF|AF|SF},{127,255,CF|SF|OF},
        {128,1,AF|OF},{255,1,SF},{1,255,CF|AF},{128,128,PF|ZF}};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(pairs[0]);i++) {
        assert(cmp8(pairs[i][0],pairs[i][1])==pairs[i][2]); models++;
    }
    /* High physical bits never feed an8-bit read; no GPR is modified. */
    uint64_t gpr[16],saved[16]; for(unsigned i=0;i<16;i++) gpr[i]=UINT64_C(0xff00ff0000000000)|i;
    memcpy(saved,gpr,sizeof(gpr));
    for(unsigned i=0;i<16;i++) for(unsigned j=0;j<16;j++) {
        unsigned a=(unsigned)gpr[i]&255,b=(unsigned)gpr[j]&255,r=a&b;
        /* This word models only defined flags; actual TEST AF is unspecified. */
        unsigned flags=(parity(r)?PF:0)|(!r?ZF:0)|(r&128?SF:0);
        assert(!(flags&(CF|OF|AF)) && !memcmp(gpr,saved,sizeof(gpr))); models++;
    }
}
static void legacy_and_boundary(void) {
    static const unsigned char cases[][5]={{0x48,0x89,0xd8},{0x48,0x83,0xc0,1},
        {0x48,0x8b,0x03},{0x75,0xfe},{0x3c,0x7f}};
    static const unsigned lengths[]={3,4,3,2,2};
    for(unsigned i=0;i<5;i++) {
        struct li2_span_decoded old,now; struct li2_write_footprint a,b;
        assert(!li2_decoder_span_describe(PC,cases[i],lengths[i],&old) && old.ready);
        assert(!li2_decoder_scalar_read_describe(PC,cases[i],lengths[i],&now));
        old.version=2; assert(!memcmp(&old,&now,sizeof(old)));
        assert(!li2_decoder_link_none(PC,cases[i],lengths[i],&a));
        assert(!li2_decoder_scalar_read_none(PC,cases[i],lengths[i],&b));
        assert(!memcmp(&a,&b,sizeof(a))); old_rows++;
    }
    unsigned char *pages=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(pages!=MAP_FAILED && !mprotect(pages+4096,4096,PROT_NONE));
    const unsigned char cmp[]={0x41,0x80,0x78,0xf8,0};
    for(unsigned n=1;n<sizeof(cmp);n++) {
        memcpy(pages+4096-n,cmp,n); reject(PC,pages+4096-n,n,0);
    }
    assert(!munmap(pages,8192)); stable();
}
int main(void) {
    assert(!li2_decoder_initialize(arena,sizeof(arena),&initial));
    assert(initial.abi_version==1 && initial.phase==2 && !initial.first_fatal_reason
        && !initial.reserved && initial.arena_bytes==sizeof(arena)
        && initial.retained_high_water && initial.retained_high_water<=sizeof(arena));
    register_forms(); memory_forms(); nops(); negatives(); scalar_models(); legacy_and_boundary();
    assert(accepted==766 && refused==63 && old_rows==5 && models==269); stable();
    printf("{\"schema\":1,\"descriptor_version\":2,\"new_codes\":5,\"accepted\":%u,"
        "\"refusals\":%u,\"model_cases\":%u,\"old_rows\":%u,\"postseal_equal\":true,"
        "\"instruction_execution\":false,\"owner_execution\":false}\n",
        accepted,refused,models,old_rows);
    return 0;
}
