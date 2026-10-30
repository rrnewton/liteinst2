#define _GNU_SOURCE
#include "../../region_decode.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* These are supplied bytes, never executed. The expected model is built from
 * the fixed encoding constructors/architectural operands, not decoder output.
 * Only the legacy 72-byte descriptive row comes from the unchanged old API. */
enum { MOV_TO=0,MOV_FROM=1,LOAD8=2,AND=3,XOR=4,TEST=5,CMP=6,
       ROWS=3898,BASES=47,GROUPS=9,TRUNCATIONS=124 };
enum { CF=1,PF=4,AF=16,ZF=64,SF=128,OF=2048 };
static _Alignas(4096) unsigned char arena[16*1024*1024];
struct specimen { unsigned char bytes[15]; unsigned n,code,group;
                  struct li2_region_decoded expected; };
static struct specimen specimens[ROWS];
static unsigned count,groups[GROUPS],checks,refusals,api_checks,guard_checks;
static struct li2_decoder_stats initial;
static void stats(void) {
    struct li2_decoder_stats value;
    assert(li2_decoder_stats(&value)==LI2_OK);
    assert(!memcmp(&value,&initial,sizeof value));
}
static void byte(struct specimen *s,unsigned value) {
    assert(s->n<sizeof s->bytes);s->bytes[s->n++]=(unsigned char)value;
}
static void disp32(struct specimen *s,int32_t value) {
    uint32_t v=(uint32_t)value;
    for(unsigned i=0;i<4;i++)byte(s,v>>(8*i));
}
static struct li2_region_operand reg(unsigned r,unsigned width,unsigned access) {
    return (struct li2_region_operand){.kind=LI2_REGION_REGISTER,.reg=r,
        .width_bits=width,.access=access};
}
static void used(struct li2_region_decoded *d,unsigned r,unsigned width,unsigned access) {
    assert(r<16&&d->register_count<3);
    d->registers[d->register_count++]=(struct li2_region_register){r,width,access,0};
    if(access&LI2_REGION_READ)d->gpr_read|=1u<<r;
    if(access&LI2_REGION_WRITE)d->gpr_write|=1u<<r;
}
static void registers(struct li2_region_decoded *d) {
    /* iced's published write-width rule is observable ABI: E32 writes are
       R64 writes, while ReadWrite E32 has a separate E32 read. Keep duplicates. */
    for(unsigned i=0;i<d->operand_count;i++) {
        const struct li2_region_operand *o=&d->operands[i];
        if(o->kind==LI2_REGION_REGISTER&&o->access) {
            if(o->width_bits==32&&o->access==LI2_REGION_READ_WRITE) {
                used(d,o->reg,32,LI2_REGION_READ);used(d,o->reg,64,LI2_REGION_WRITE);
            } else used(d,o->reg,o->width_bits==32&&(o->access&LI2_REGION_WRITE)?64:o->width_bits,o->access);
        } else if(o->kind==LI2_REGION_MEMORY) {
            if(d->memory.base!=16)used(d,d->memory.base,64,LI2_REGION_READ);
            if(d->memory.index!=16)used(d,d->memory.index,64,LI2_REGION_READ);
        }
    }
}
static struct specimen *begin(unsigned group,unsigned code) {
    assert(count<ROWS&&group<GROUPS);struct specimen *s=&specimens[count++];
    s->group=group;s->code=code;groups[group]++;
    s->expected.version=1;s->expected.ready=1;s->expected.condition=16;
    return s;
}
static void logic(struct li2_region_decoded *d,int zero) {
    d->flags_undefined=AF;d->flags_cleared=CF|OF;
    if(zero){d->flags_set=PF|ZF;d->flags_cleared|=SF;}
    else d->flags_written=PF|ZF|SF;
}
static unsigned scalar_code(unsigned kind,unsigned width) {
    /* Literal IDs from the locked iced-x86 1.21 Code enum, independently pinned. */
    static const unsigned codes[6][2]={{281,282},{285,286},{2090,2091},
                                     {260,261},{96,97},{273,274}};
    assert(kind<6&&(width==32||width==64));return codes[kind][width==64];
}
static void scalar(unsigned group,unsigned kind,unsigned width,unsigned dst,unsigned src,
                   int memory,unsigned base,unsigned index,unsigned scale,int32_t displacement,
                   int immediate,int forced_rex) {
    assert(kind<6&&dst<16&&src<16&&(!memory||kind==MOV_FROM||kind==LOAD8));
    assert(kind==TEST||dst!=4);assert(base<=16&&index<=16);
    struct specimen *s=begin(group,scalar_code(kind,width));
    struct li2_region_decoded *d=&s->expected;
    unsigned regfield=kind==AND?4:(kind==MOV_TO||kind==XOR||kind==TEST)?src:dst;
    unsigned rm=memory?(base==16?5:base&7):(kind==MOV_TO||kind==XOR||kind==TEST||kind==AND)?dst:src;
    int sib=memory&&(index!=16||base==16||(base&7)==4);
    unsigned rex=0x40|(width==64?8:0)|(kind!=AND&&regfield>=8?4:0)|
        (memory&&index!=16&&index>=8?2:0)|(memory?(base!=16&&base>=8):rm>=8);
    if(forced_rex>=0)rex=(unsigned)forced_rex;
    if(rex!=0x40||forced_rex>=0)byte(s,rex);
    static const unsigned op[]={0x89,0x8b,0,0x83,0x31,0x85};
    if(kind==LOAD8){byte(s,0x0f);byte(s,0xb6);}else byte(s,op[kind]);
    unsigned mod=memory?(base==16?0:displacement==0&&(base&7)!=5?0:
                        displacement>=-128&&displacement<=127?1:2):3;
    byte(s,(mod<<6)|((regfield&7)<<3)|(sib?4:rm&7));
    if(sib) {
        unsigned exponent=scale==1?0:scale==2?1:scale==4?2:3;
        assert(scale==1||scale==2||scale==4||scale==8);
        byte(s,(exponent<<6)|((index==16?4:index&7)<<3)|(base==16?5:base&7));
    }
    if(memory) {
        if(mod==1)byte(s,(unsigned)displacement);
        else if(mod==2||base==16)disp32(s,displacement);
    }
    if(kind==AND)byte(s,(unsigned)immediate);
    unsigned role=kind==TEST?LI2_REGION_READ:
        kind==AND||kind==XOR?LI2_REGION_READ_WRITE:LI2_REGION_WRITE;
    int zero=kind==XOR&&dst==src;if(zero)role=LI2_REGION_WRITE;
    d->operand_count=2;d->operands[0]=reg(dst,width,role);
    if(memory) {
        unsigned bytes=kind==LOAD8?1:width/8;
        d->operands[1]=(struct li2_region_operand){.kind=LI2_REGION_MEMORY,.width_bits=bytes*8,.access=LI2_REGION_READ};
        d->memory_count=1;
        d->memory=(struct li2_region_memory){.displacement=(uint64_t)(int64_t)displacement,
            .base=base,.index=index,.scale=scale,.width_bytes=bytes,.address_bits=64,
            .segment=base==4||base==5?LI2_REGION_SS:LI2_REGION_DS,.access=LI2_REGION_READ};
    } else if(kind==AND) {
        d->operands[1]=(struct li2_region_operand){.immediate=width==32?(uint32_t)(int32_t)(int8_t)immediate:(uint64_t)(int64_t)(int8_t)immediate,
            .kind=LI2_REGION_IMMEDIATE,.width_bits=width,.access=LI2_REGION_READ,.encoding_bits=8};
    } else d->operands[1]=reg(src,width,zero?0:LI2_REGION_READ);
    if(kind==AND||kind==XOR||kind==TEST)logic(d,zero);
    registers(d);
}
static void cmp(unsigned group,unsigned immediate) {
    struct specimen *s=begin(group,115);byte(s,0x3c);byte(s,immediate);
    s->expected.operand_count=2;s->expected.operands[0]=reg(0,8,LI2_REGION_READ);
    s->expected.operands[1]=(struct li2_region_operand){.immediate=immediate,.kind=LI2_REGION_IMMEDIATE,
        .width_bits=8,.access=LI2_REGION_READ,.encoding_bits=8};
    s->expected.flags_written=CF|PF|AF|ZF|SF|OF;registers(&s->expected);
}
static void branch(unsigned group,unsigned condition,int near,int32_t delta) {
    unsigned code=condition==16?(near?696:701):(near?1856:161)+3*condition;
    struct specimen *s=begin(group,code);
    if(condition==16)byte(s,near?0xe9:0xeb);
    else if(near){byte(s,0x0f);byte(s,0x80+condition);}else byte(s,0x70+condition);
    if(near)disp32(s,delta);else {assert(delta>=-128&&delta<=127);byte(s,(unsigned)delta);}
    struct li2_region_decoded *d=&s->expected;
    d->flow=condition==16?LI2_REGION_JMP:LI2_REGION_JCC;d->condition=condition;
    d->target=UINT64_C(0x100000000)+s->n+(int64_t)delta;d->operand_count=1;
    d->operands[0]=(struct li2_region_operand){.immediate=d->target,.kind=LI2_REGION_BRANCH,
        .width_bits=64,.access=LI2_REGION_READ,.encoding_bits=near?32:8};
    static const unsigned masks[8]={OF,CF,ZF,CF|ZF,SF,PF,SF|OF,ZF|SF|OF};
    if(condition<16)d->flags_read=masks[condition/2];
}
static void catalogue(void) {
    for(unsigned kind=0;kind<6;kind++)for(unsigned w=32;w<=64;w+=32)
        scalar(0,kind,w,3,1,kind==LOAD8,3,16,1,0,-1,-1);
    cmp(0,127);
    for(unsigned near=0;near<2;near++)for(unsigned c=0;c<16;c++)branch(0,c,near,17);
    branch(0,16,0,17);branch(0,16,1,17);assert(count==BASES);
    for(unsigned kind=0;kind<6;kind++)if(kind!=LOAD8&&kind!=AND)
        for(unsigned w=32;w<=64;w+=32)for(unsigned dst=0;dst<16;dst++)if(dst!=4||kind==TEST)
            for(unsigned src=0;src<16;src++)scalar(1,kind,w,dst,src,0,0,16,1,0,0,-1);
    const int immediates[]={-128,-1,0,1,127};
    for(unsigned w=32;w<=64;w+=32)for(unsigned d=0;d<16;d++)if(d!=4)
        for(unsigned i=0;i<5;i++)scalar(2,AND,w,d,0,0,0,16,1,0,immediates[i],-1);
    const unsigned imms[]={0,1,127,128,255};for(unsigned i=0;i<5;i++)cmp(3,imms[i]);
    for(unsigned kind=MOV_FROM;kind<=LOAD8;kind++)for(unsigned w=32;w<=64;w+=32)
        for(unsigned dst=0;dst<16;dst++)if(dst!=4)for(unsigned base=0;base<16;base++)
            scalar(4,kind,w,dst,0,1,base,16,1,0,0,-1);
    for(unsigned kind=MOV_FROM;kind<=LOAD8;kind++)for(unsigned w=32;w<=64;w+=32)
        for(unsigned index=0;index<16;index++)if(index!=4)for(unsigned scale=1;scale<=8;scale*=2)
            for(unsigned absent=0;absent<2;absent++)scalar(5,kind,w,0,0,1,absent?16:3,index,scale,0,0,-1);
    const int32_t displacements[]={0,-1,-128,127,INT32_MIN,INT32_MAX};
    for(unsigned kind=MOV_FROM;kind<=LOAD8;kind++)for(unsigned w=32;w<=64;w+=32)
        for(unsigned i=0;i<6;i++)for(unsigned shape=0;shape<3;shape++)
            scalar(6,kind,w,shape==1?3:shape==2?1:0,0,1,3,shape==2?1:16,1,displacements[i],0,-1);
    for(unsigned near=0;near<2;near++)for(unsigned c=0;c<=16;c++)for(unsigned i=0;i<4;i++) {
        const int32_t short_d[]={-128,-1,0,127},near_d[]={INT32_MIN,-1,0,INT32_MAX};
        branch(7,c,near,near?near_d[i]:short_d[i]);
    }
    /* All R/X/B bits, including ignored bits, at fixed W. Derive actual
       physical operands from the literal fields before invoking the decoder. */
    for(unsigned kind=0;kind<6;kind++)for(unsigned w=32;w<=64;w+=32)for(unsigned bits=0;bits<8;bits++) {
        unsigned r=(bits&4)?8:0,b=(bits&1)?8:0;
        unsigned dst=(kind==MOV_TO||kind==XOR||kind==TEST||kind==AND)?3+b:3+r;
        unsigned src=(kind==MOV_TO||kind==XOR||kind==TEST)?1+r:1+b;
        scalar(8,kind,w,dst,src,kind==LOAD8,3+b,16,1,0,-1,0x40|(w==64?8:0)|bits);
    }
    const unsigned expected[GROUPS]={47,1952,150,5,960,480,72,136,96};
    assert(count==ROWS&&!memcmp(groups,expected,sizeof expected));
}
static void compare(const struct specimen *s,const unsigned char *bytes,unsigned n,int truncated) {
    struct li2_region_decoded actual,expected;struct li2_decoded old;
    memset(&actual,0xa5,sizeof actual);memset(&expected,0,sizeof expected);
    assert(li2_decoder_decode(UINT64_C(0x100000000),bytes,n,&old)==LI2_OK);
    assert(li2_decoder_region_describe(UINT64_C(0x100000000),bytes,n,&actual)==LI2_OK);
    if(truncated) {assert(old.decode_status==LI2_TRUNCATED);expected.version=1;expected.refusal=LI2_REGION_TRUNCATED;}
    else {expected=s->expected;assert(old.decode_status==LI2_VALID&&old.code==s->code&&old.length==s->n);}
    expected.decoded=old;
    if(memcmp(&actual,&expected,sizeof actual)) {
        const unsigned char *a=(const unsigned char *)&actual,*e=(const unsigned char *)&expected;
        unsigned at=0;while(at<sizeof actual&&a[at]==e[at])at++;
        fprintf(stderr,"REGION_DESCRIPTOR group=%u code=%u available=%u byte=%u actual=%u expected=%u\n",
                s->group,s->code,n,at,at<sizeof actual?a[at]:0,at<sizeof actual?e[at]:0);
    }
    assert(!memcmp(&actual,&expected,sizeof actual));checks++;
}
struct negative {unsigned char bytes[15];unsigned n,refusal;uint64_t pc;};
static const struct negative negatives[]={
    {{0x90},1,LI2_REGION_UNSUPPORTED,0},{{0x01,0xc3},2,LI2_REGION_UNSUPPORTED,0},
    {{0x29,0xc3},2,LI2_REGION_UNSUPPORTED,0},{{0x8d,0x03},2,LI2_REGION_UNSUPPORTED,0},
    {{0x89,0x03},2,LI2_REGION_OPERANDS,0},{{0x48,0x89,0x03},3,LI2_REGION_OPERANDS,0},
    {{0x0f,0xb6,0xc0},3,LI2_REGION_OPERANDS,0},{{0x48,0x0f,0xb6,0xc0},4,LI2_REGION_OPERANDS,0},
    {{0x89,0xcc},2,LI2_REGION_OPERANDS,0},{{0x48,0x89,0xcc},3,LI2_REGION_OPERANDS,0},
    {{0x8b,0xe1},2,LI2_REGION_OPERANDS,0},{{0x48,0x8b,0xe1},3,LI2_REGION_OPERANDS,0},
    {{0x31,0xe4},2,LI2_REGION_OPERANDS,0},{{0x83,0xe4,0x7f},3,LI2_REGION_OPERANDS,0},
    {{0x66,0x89,0xcb},3,LI2_REGION_UNSUPPORTED,0},{{0x88,0xe0},2,LI2_REGION_UNSUPPORTED,0},
    {{0x8b,0x05,0,0,0,0},6,LI2_REGION_OPERANDS,0},
    {{0x67,0x8b,0x03},3,LI2_REGION_PREFIX,0},{{0x2e,0x89,0xcb},3,LI2_REGION_PREFIX,0},
    {{0x40,0x40,0x89,0xcb},4,LI2_REGION_PREFIX,0},{{0x2e,0x75,0},3,LI2_REGION_PREFIX,0},
    {{0x40,0x3c,1},3,LI2_REGION_PREFIX,0},{{0xf0,0x89,0xcb},3,LI2_REGION_INVALID,0},
    {{0xe8,0,0,0,0},5,LI2_REGION_UNSUPPORTED,0},{{0xc3},1,LI2_REGION_UNSUPPORTED,0},
    {{0xff,0xe0},2,LI2_REGION_UNSUPPORTED,0},{{0x06},1,LI2_REGION_INVALID,0},
    {{0x0f},1,LI2_REGION_TRUNCATED,0},{{0x0f,0xa2},2,LI2_REGION_EFFECTS,0},
    {{0x89,0xcb},2,LI2_REGION_ADDRESS,UINT64_C(0x800000000000)},
    {{0xeb,0x7f},2,LI2_REGION_ADDRESS,UINT64_C(0x7ffffffffff0)},
    {{0xeb,0x80},2,LI2_REGION_ADDRESS,1},
    {{0xeb,0x80},2,LI2_REGION_ADDRESS,UINT64_C(0xffff800000000000)}
};
enum { NEGATIVES=sizeof negatives/sizeof negatives[0] };
static void negative_tests(void) {
    for(unsigned i=0;i<NEGATIVES;i++) {
        const struct negative *n=&negatives[i];struct li2_decoded old;
        struct li2_region_decoded actual,expected={0};
        uint64_t pc=n->pc?n->pc:UINT64_C(0x100000000);
        assert(li2_decoder_decode(pc,n->bytes,n->n,&old)==LI2_OK);
        memset(&actual,0x5a,sizeof actual);
        assert(li2_decoder_region_describe(pc,n->bytes,n->n,&actual)==LI2_OK);
        expected.decoded=old;expected.version=1;expected.refusal=n->refusal;
        if(memcmp(&actual,&expected,sizeof actual))fprintf(stderr,"REGION_REFUSAL row=%u actual=%u expected=%u\n",i,actual.refusal,n->refusal);
        assert(!memcmp(&actual,&expected,sizeof actual));refusals++;
    }
    assert(refusals==33);stats();
}
static void api(void) {
    struct li2_region_decoded d,zero={0};const unsigned char b[]={0x89,0xcb};
#define REFUSE(call,status) do {memset(&d,0xa5,sizeof d);assert((call)==(status));assert(!memcmp(&d,&zero,sizeof d));api_checks++;}while(0)
    REFUSE(li2_decoder_region_describe(0,b,0,&d),LI2_BAD_ARGUMENT);
    REFUSE(li2_decoder_region_describe(0,b,16,&d),LI2_BAD_ARGUMENT);
    REFUSE(li2_decoder_region_describe(0,NULL,2,&d),LI2_BAD_ARGUMENT);
    REFUSE(li2_decoder_region_describe(0,(const unsigned char *)UINTPTR_MAX,2,&d),LI2_BAD_ARGUMENT);
    REFUSE(li2_decoder_region_describe(UINT64_MAX,b,2,&d),LI2_ADDRESS_OVERFLOW);
    assert(li2_decoder_region_describe(0,b,2,NULL)==LI2_BAD_ARGUMENT);api_checks++;
    assert(api_checks==6);stats();
#undef REFUSE
}
#ifdef LI2_REGION_TEST_EXPORTS
extern uint32_t li2_region_test_busy(uint64_t,const unsigned char *,size_t,struct li2_region_decoded *);
extern void li2_region_test_allocate(void);
#endif
int main(int argc,char **argv) {
    assert(argc==2&&strlen(argv[1])==1&&argv[1][0]>='0'&&argv[1][0]<='3');unsigned mode=(unsigned)(argv[1][0]-'0');
    struct li2_region_decoded d,zero={0};const unsigned char b[]={0x89,0xcb};
    memset(&d,0xa5,sizeof d);assert(li2_decoder_region_describe(0x1000,b,2,&d)==LI2_NOT_READY);
    assert(!memcmp(&d,&zero,sizeof d));
    assert(li2_decoder_initialize(arena,sizeof arena,&initial)==LI2_OK);
    assert(initial.abi_version==1&&initial.phase==2&&!initial.first_fatal_reason&&!initial.reserved);
    assert(initial.arena_bytes==sizeof arena&&initial.retained_high_water>0&&initial.retained_high_water<=sizeof arena);
    struct li2_decoder_stats again;
    assert(li2_decoder_initialize(arena,sizeof arena,&again)==LI2_ALREADY_INITIALIZED);stats();
    if(mode>=2) {
#ifdef LI2_REGION_TEST_EXPORTS
        if(mode==3){li2_region_test_allocate();return 3;}
        memset(&d,0xa5,sizeof d);assert(li2_region_test_busy(0x1000,b,2,&d)==LI2_BUSY);
        assert(!memcmp(&d,&zero,sizeof d));
        assert(li2_decoder_region_describe(0x1000,b,2,&d)==LI2_OK&&d.ready==1);stats();
#else
        assert(!"test artifact mode on production archive");
#endif
    } else {
        catalogue();
        if(mode==0) {
            for(unsigned pass=0;pass<2;pass++) {
                for(unsigned i=0;i<count;i++) {
                    unsigned at=pass?count-1-i:i;compare(&specimens[at],specimens[at].bytes,specimens[at].n,0);
                    if(i+1==count||specimens[at].group!=specimens[pass?at-1:at+1].group)stats();
                }
                stats();
            }
            assert(checks==2*ROWS);negative_tests();api();
            for(unsigned i=0;i<BASES;i++)for(unsigned n=1;n<specimens[i].n;n++)compare(&specimens[i],specimens[i].bytes,n,1);
            assert(checks==2*ROWS+TRUNCATIONS);
        } else {
            assert(sysconf(_SC_PAGESIZE)==4096);
            unsigned char *p=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            assert(p!=MAP_FAILED&&mprotect(p+4096,4096,PROT_NONE)==0);
            for(unsigned i=0;i<BASES;i++)for(unsigned n=1;n<=specimens[i].n;n++) {
                memcpy(p+4096-n,specimens[i].bytes,n);compare(&specimens[i],p+4096-n,n,n!=specimens[i].n);guard_checks++;
            }
            assert(guard_checks==BASES+TRUNCATIONS&&munmap(p,8192)==0);
        }
        stats();
    }
    printf("{\"version\":1,\"mode\":%u,\"forms\":%u,\"accepted_rows\":%u,\"accepted_calls\":%u,"
           "\"refusals\":%u,\"truncations\":%u,\"api_checks\":%u,\"guard_checks\":%u,\"busy\":%u,"
           "\"phase\":%u,\"first_fatal_reason\":%u,\"arena_bytes\":%llu,\"retained_high_water\":%llu,"
           "\"allocation_calls\":%llu,\"deallocation_calls\":%llu,\"stats_equal\":1}\n",
           mode,mode<2?BASES:0,mode==0?ROWS:0,mode==0?ROWS*2:mode==1?BASES:0,
           refusals,mode<2?TRUNCATIONS:0,api_checks,guard_checks,mode==2,
           initial.phase,initial.first_fatal_reason,(unsigned long long)initial.arena_bytes,
           (unsigned long long)initial.retained_high_water,(unsigned long long)initial.allocation_calls,
           (unsigned long long)initial.deallocation_calls);
    return 0;
}
