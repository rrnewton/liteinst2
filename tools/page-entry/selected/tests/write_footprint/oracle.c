/* Finite footprint-only native oracle. No rseq registration or RX owner claim. */
#include <stddef.h>
#include <stdint.h>
#include "decoder.h"
#include "write_footprint.h"
#define MEMORY_BYTES 16384U
#define CASES 38U
#define OLD_CASES 34U
#define DATA_VALUE UINT64_C(0x0123456789abcdef)
static unsigned char arena[2*1024*1024] __attribute__((aligned(64)));
unsigned char footprint_memory[MEMORY_BYTES] __attribute__((aligned(4096)));
unsigned char footprint_vector[16] __attribute__((aligned(16)));
uint64_t footprint_seed[16],footprint_before[16],footprint_after[16],footprint_caller[16];
uintptr_t footprint_target;
extern void footprint_enter(void),footprint_call_target(void);
#define LABEL(x) extern unsigned char x[],x##_end[]
LABEL(fp_mov8);LABEL(fp_mov16);LABEL(fp_mov32);LABEL(fp_mov64);LABEL(fp_mov128);
LABEL(fp_load64);LABEL(fp_reg);LABEL(fp_nop);LABEL(fp_endbr);LABEL(fp_add32);
LABEL(fp_xchg64);LABEL(fp_cmpxchg32);LABEL(fp_shift0);LABEL(fp_rip);LABEL(fp_sib);
LABEL(fp_addr32);LABEL(fp_wrap32);LABEL(fp_fs);LABEL(fp_gs);LABEL(fp_push);
LABEL(fp_pushmem);LABEL(fp_pushimm);LABEL(fp_call);LABEL(fp_callreg);LABEL(fp_pop);
LABEL(fp_popmem);LABEL(fp_btsmem);LABEL(fp_btrmem);LABEL(fp_btcimm);LABEL(fp_rep);LABEL(fp_unknown);
LABEL(fp_vpcmpeqb);LABEL(fp_blsmsk);
extern void footprint_palette_enter(void);
struct vector {const unsigned char *pc,*end;uint32_t policy,width;unsigned char bytes[15];};
#define V(x,p,w,...) {x,x##_end,p,w,{__VA_ARGS__}}
static const struct vector vectors[CASES]={
 V(fp_mov8,2,1,0x88,0x07), V(fp_mov16,2,2,0x66,0x89,0x07),
 V(fp_mov32,2,4,0x89,0x07), V(fp_mov64,2,8,0x48,0x89,0x07),
 V(fp_mov128,2,16,0x0f,0x11,0x07), V(fp_load64,1,0,0x48,0x8b,0x07),
 V(fp_reg,1,0,0x48,0x89,0xc3), V(fp_nop,1,0,0x90),
 V(fp_endbr,1,0,0xf3,0x0f,0x1e,0xfa), V(fp_add32,2,4,0x83,0x07,0x01),
 V(fp_xchg64,2,8,0x48,0x87,0x07), V(fp_cmpxchg32,2,4,0x0f,0xb1,0x0f),
 V(fp_cmpxchg32,2,4,0x0f,0xb1,0x0f), V(fp_shift0,2,4,0xc1,0x27,0x00),
 V(fp_rip,2,8,0x48,0x89,0x05,0,0,0,0), V(fp_sib,2,8,0x48,0x89,0x44,0x8d,0xf0),
 V(fp_addr32,2,8,0x67,0x48,0x89,0x07), V(fp_wrap32,2,4,0x67,0x89,0x44,0x8d,0x10),
 V(fp_fs,2,8,0x64,0x48,0x89,0x07), V(fp_gs,2,8,0x65,0x48,0x89,0x47,0xf8),
 V(fp_push,2,8,0x50), V(fp_pushmem,2,8,0xff,0x37), V(fp_pushimm,2,8,0x6a,0x7f),
 V(fp_call,2,8,0xe8,0,0,0,0), V(fp_callreg,2,8,0xff,0xd0), V(fp_pop,1,0,0x58),
 V(fp_popmem,0,0,0x8f,0x07), V(fp_btsmem,0,0,0x48,0x0f,0xab,0x07),
 V(fp_btrmem,0,0,0x48,0x0f,0xb3,0x07), V(fp_btcimm,0,0,0x48,0x0f,0xba,0x3f,0x01),
 V(fp_rep,0,0,0xf3,0x48,0xab), V(fp_unknown,0,0,0x0f,0x0b),
 V(fp_mov64,0,0,0x48,0x89,0x07), V(fp_push,0,0,0x50),
 /* All 34 historical rows above retain their original IDs and policies. */
 V(fp_vpcmpeqb,1,0,0x62,0xb1,0x75,0x40,0x74,0xc8),
 V(fp_vpcmpeqb,1,0,0x62,0xb1,0x75,0x40,0x74,0xc8),
 V(fp_blsmsk,1,0,0xc4,0xe2,0xc8,0xf3,0xd6),
 V(fp_blsmsk,1,0,0xc4,0xe2,0xc8,0xf3,0xd6)
};
struct observation {
 uint64_t id,attempted,queried,executed,passed,changed,expected_first,expected_end;
 struct li2_write_registers requested,actual;
 struct li2_write_footprint footprint;
 struct li2_decoded decoded;
 uint64_t post_gpr[16],fs_after,gs_after;
 unsigned char source[16],before[MEMORY_BYTES],after[MEMORY_BYTES];
};
static struct observation records[CASES];
/* Small additive evidence, leaving every original observation field intact. */
struct palette_vector {
 uint64_t id,expected_mask,mask_seed,before_mask,after_mask,checked,code,length;
 unsigned char seed[128],before[128],after[128];
};
static struct {
 uint64_t magic,version,bytes,cpuid_max,cpuid1_ecx,cpuid7_ebx,xcr0,checked;
 struct palette_vector vectors[2];
} palette;
unsigned char footprint_zmm_seed[128] __attribute__((aligned(64)));
unsigned char footprint_zmm_before[128] __attribute__((aligned(64)));
unsigned char footprint_zmm_after[128] __attribute__((aligned(64)));
uint64_t footprint_mask_seed,footprint_mask_before,footprint_mask_after;
static struct {
 uint64_t magic,version,header_bytes,record_bytes,cases,completed,executed,refused,api_controls,failure,decoder_abort;
 struct li2_decoder_stats initial,final;
} header;
static long raw(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
void *memcpy(void *out,const void *in,size_t n){unsigned char *d=out;const unsigned char *s=in;for(size_t i=0;i<n;i++)d[i]=s[i];return out;}
void *memset(void *out,int v,size_t n){unsigned char *d=out;for(size_t i=0;i<n;i++)d[i]=(unsigned char)v;return out;}
void *memmove(void *out,const void *in,size_t n){unsigned char *d=out;const unsigned char *s=in;if((uintptr_t)d<(uintptr_t)s){for(size_t i=0;i<n;i++)d[i]=s[i];}else{while(n){--n;d[n]=s[n];}}return out;}
int memcmp(const void *a,const void *b,size_t n){const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return x[i]<y[i]?-1:1;return 0;}
int bcmp(const void *a,const void *b,size_t n){return memcmp(a,b,n);}
static int write_all(long fd,const void *data,size_t bytes){const unsigned char *p=data;while(bytes){long n=raw(1,fd,(long)p,(long)bytes,0,0,0);if(n<=0||(size_t)n>bytes)return 0;p+=n;bytes-=(size_t)n;}return 1;}
static void dump(void){(void)li2_decoder_stats(&header.final);(void)write_all(3,&header,sizeof(header));(void)write_all(3,records,sizeof(records));(void)write_all(3,&palette,sizeof(palette));}
_Noreturn void li2_decoder_abort(uint32_t reason){header.decoder_abort=reason;dump();(void)write_all(1,"FOOTPRINT_DECODER_ABORT\n",24);(void)raw(231,125,0,0,0,0,0);__builtin_unreachable();}
static void need(int good,unsigned code){if(!good){header.failure=code;dump();(void)write_all(1,"FOOTPRINT_FAILURE\n",18);(void)raw(231,125,0,0,0,0,0);__builtin_unreachable();}}
static void put(unsigned char *p,uint64_t x,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(x>>(8*i));}
static int zero(const void *data,size_t n){const unsigned char *p=data;for(size_t i=0;i<n;i++)if(p[i])return 0;return 1;}
static void base_values(struct li2_write_registers *r) {
 for(unsigned i=0;i<16;i++)r->gpr[i]=UINT64_C(0x1234567812345678)+i;
 r->gpr[0]=DATA_VALUE;r->gpr[4]=(uintptr_t)footprint_memory+4096;
 r->gpr[7]=(uintptr_t)footprint_memory+128;
 need(!raw(158,0x1003,(long)&r->fs_base,0,0,0,0),10);
 need(!raw(158,0x1004,(long)&r->gs_base,0,0,0,0),11);
}
static void api_controls(void) {
 struct li2_write_registers state={0};struct li2_write_footprint f;
 memset(&f,0xa5,sizeof(f));need(li2_decoder_write_footprint((uintptr_t)fp_nop,fp_nop,1,&state,&f)==LI2_NOT_READY&&zero(&f,sizeof(f)),20);++header.api_controls;
 need(!li2_decoder_initialize(arena,sizeof(arena),&header.initial)&&header.initial.phase==2&&!header.initial.first_fatal_reason,21);
 memset(&f,0xa5,sizeof(f));need(li2_decoder_write_footprint((uintptr_t)fp_nop,fp_nop,0,&state,&f)==LI2_BAD_ARGUMENT&&zero(&f,sizeof(f)),22);++header.api_controls;
 memset(&f,0xa5,sizeof(f));need(li2_decoder_write_footprint((uintptr_t)fp_nop,fp_nop,1,0,&f)==LI2_BAD_ARGUMENT&&zero(&f,sizeof(f)),23);++header.api_controls;
 memset(&f,0xa5,sizeof(f));need(li2_decoder_write_footprint((uintptr_t)fp_nop,0,1,&state,&f)==LI2_BAD_ARGUMENT&&zero(&f,sizeof(f)),24);++header.api_controls;
 memset(&f,0xa5,sizeof(f));need(li2_decoder_write_footprint(UINT64_MAX,fp_nop,1,&state,&f)==LI2_ADDRESS_OVERFLOW&&zero(&f,sizeof(f)),25);++header.api_controls;
 need(li2_decoder_write_footprint((uintptr_t)fp_nop,fp_nop,1,&state,0)==LI2_BAD_ARGUMENT,26);++header.api_controls;
}
static void palette_preflight(void) {
 unsigned a=0,b,c=0,d;
 __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));palette.cpuid_max=a;
 need(a>=7,60);a=1;c=0;
 __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));palette.cpuid1_ecx=c;
 need((c&UINT32_C(0x1c000000))==UINT32_C(0x1c000000),61);a=7;c=0;
 __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));palette.cpuid7_ebx=b;
 need((b&UINT32_C(0x40010008))==UINT32_C(0x40010008),62);
 __asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0));palette.xcr0=(uint64_t)a|((uint64_t)d<<32);
 need((palette.xcr0&UINT64_C(0xe7))==UINT64_C(0xe7),63);palette.checked=1;
}
static void palette_seed(unsigned id) {
 need(id==34||id==35,64);struct palette_vector *v=&palette.vectors[id-34];
 v->id=id;v->expected_mask=id==34?UINT64_C(0x8000000180000081):UINT64_C(0x7ffffffe7fffff7e);
 v->mask_seed=UINT64_C(0x0123456789abcdef);v->code=1720;v->length=6;
 for(unsigned i=0;i<64;i++) {
  unsigned char a=(unsigned char)(i*13+3);
  v->seed[i]=a;v->seed[64+i]=(v->expected_mask&(UINT64_C(1)<<i))?a:(unsigned char)(a^0x5a);
 }
 memcpy(footprint_zmm_seed,v->seed,sizeof(v->seed));footprint_mask_seed=v->mask_seed;
 memset(footprint_zmm_before,0,sizeof(footprint_zmm_before));memset(footprint_zmm_after,0,sizeof(footprint_zmm_after));
 footprint_mask_before=footprint_mask_after=0;
}
static void palette_effects(unsigned id,const struct observation *o) {
 need(id>=34&&id<38&&palette.checked&&o->executed&&o->footprint.policy==LI2_WRITE_NONE&&
      !o->footprint.first&&!o->footprint.end&&!o->changed,65);
 if(id<36) {
  struct palette_vector *v=&palette.vectors[id-34];
  v->before_mask=footprint_mask_before;v->after_mask=footprint_mask_after;
  memcpy(v->before,footprint_zmm_before,sizeof(v->before));memcpy(v->after,footprint_zmm_after,sizeof(v->after));
  need(o->footprint.code==1720&&o->footprint.length==6&&v->before_mask==v->mask_seed&&
       v->after_mask==v->expected_mask&&!memcmp(v->before,v->seed,sizeof(v->seed))&&
       !memcmp(v->after,v->seed,sizeof(v->seed)),66);v->checked=1;
 } else need(o->footprint.code==3676&&o->footprint.length==5&&
             o->actual.gpr[6]==(id==36?0:UINT64_C(0x23456789abcde000))&&
             o->post_gpr[6]==(id==36?UINT64_MAX:UINT64_C(0x3fff)),67);
 for(unsigned i=0;i<16;i++)if(id<36||i!=6)need(o->post_gpr[i]==o->actual.gpr[i],68);
}
static void one(unsigned id) {
 const struct vector *v=&vectors[id];struct observation *o=&records[id];
 o->id=id;o->attempted=1;base_values(&o->requested);
 size_t n=(uintptr_t)v->end-(uintptr_t)v->pc;need(n&&n<=15,30);
 memcpy(o->source,v->bytes,n);uintptr_t first=(uintptr_t)footprint_memory+128;
 unsigned char expected[MEMORY_BYTES];memset(footprint_memory,0xa5,MEMORY_BYTES);
 for(unsigned j=0;j<16;j++)footprint_vector[j]=(unsigned char)(j*13+3);
 uint64_t value=DATA_VALUE;int unchanged=0;
 switch(id){
 case 9:value=UINT64_C(0xa5a5a5a6);break;
 case 11:o->requested.gpr[0]=UINT64_C(0xa5a5a5a5);o->requested.gpr[1]=UINT64_C(0x11223344);value=UINT64_C(0x11223344);break;
 case 12:o->requested.gpr[0]=0;o->requested.gpr[1]=UINT64_C(0x11223344);unchanged=1;break;
 case 13:unchanged=1;break;
 case 14:first=(uintptr_t)footprint_memory+1024;need(first>(uintptr_t)v->end&&first-(uintptr_t)v->end<=INT32_MAX,31);put(o->source+3,first-(uintptr_t)v->end,4);break;
 case 15:o->requested.gpr[5]=(uintptr_t)footprint_memory+768;o->requested.gpr[1]=3;first=(uintptr_t)footprint_memory+764;break;
 case 16:o->requested.gpr[7]=(UINT64_C(1)<<32)+first;break;
 case 17:first=(uintptr_t)footprint_memory+768;o->requested.gpr[5]=UINT64_C(0xfeed0000fffffff0);o->requested.gpr[1]=(UINT64_C(1)<<32)+first/4;break;
 case 18:o->requested.gpr[7]=64;first=(uintptr_t)footprint_memory+576;need(!raw(158,0x1002,(long)(footprint_memory+512),0,0,0,0),32);break;
 case 19:o->requested.gpr[7]=16;first=(uintptr_t)footprint_memory+648;need(!raw(158,0x1001,(long)(footprint_memory+640),0,0,0,0),33);break;
 case 20:case 21:case 22:case 23:case 24:first=(uintptr_t)footprint_memory+4088;
  if(id==21){o->requested.gpr[7]=(uintptr_t)footprint_memory+32;put(footprint_memory+32,DATA_VALUE,8);}
  if(id==22)value=127;
  if(id==23||id==24)value=(uintptr_t)v->end;
  if(id==23){int64_t d=(int64_t)(uintptr_t)footprint_call_target-(int64_t)(uintptr_t)v->end;need(d>=INT32_MIN&&d<=INT32_MAX,34);put(o->source+1,(uint64_t)d,4);}
  if(id==24)o->requested.gpr[0]=(uintptr_t)footprint_call_target;
  break;
 case 32:o->requested.gpr[7]=UINT64_MAX-3;break;
 case 33:o->requested.gpr[4]=4;break;
 case 34:palette_preflight();palette_seed(id);break;
 case 35:palette_seed(id);break;
 case 36:o->requested.gpr[6]=0;break;
 case 37:o->requested.gpr[6]=UINT64_C(0x23456789abcde000);break;
 default:break;
 }
 uint64_t oldfs=o->requested.fs_base,oldgs=o->requested.gs_base;
 need(!raw(158,0x1003,(long)&o->requested.fs_base,0,0,0,0)&&!raw(158,0x1004,(long)&o->requested.gs_base,0,0,0,0),35);
 need(!memcmp(o->source,v->pc,n),36);
 memcpy(o->before,footprint_memory,MEMORY_BYTES);memcpy(expected,o->before,MEMORY_BYTES);
 if(v->policy==LI2_WRITE_RANGE){o->expected_first=first;o->expected_end=first+v->width;
  need(first>=(uintptr_t)footprint_memory&&first+v->width<=(uintptr_t)footprint_memory+MEMORY_BYTES,37);
  if(!unchanged){if(id==4)memcpy(expected+(first-(uintptr_t)footprint_memory),footprint_vector,16);else put(expected+(first-(uintptr_t)footprint_memory),value,v->width);}}
 need(!li2_decoder_decode((uintptr_t)v->pc,v->pc,n,&o->decoded),38);
 need(!li2_decoder_write_footprint((uintptr_t)v->pc,v->pc,n,&o->requested,&o->footprint),39);o->queried=1;
 need(o->footprint.abi_version==1&&o->footprint.pc==(uintptr_t)v->pc&&o->footprint.next_pc==(uintptr_t)v->end&&
      o->footprint.code==o->decoded.code&&o->footprint.length==n&&o->footprint.policy==v->policy&&
      o->footprint.first==o->expected_first&&o->footprint.end==o->expected_end,40);
 if(v->policy!=LI2_WRITE_UNSUPPORTED){
  memcpy(footprint_seed,o->requested.gpr,sizeof(footprint_seed));footprint_target=(uintptr_t)v->pc;
  memset(footprint_before,0,sizeof(footprint_before));memset(footprint_after,0,sizeof(footprint_after));
  if(id==34||id==35)footprint_palette_enter();else footprint_enter();o->executed=1;++header.executed;
  memcpy(o->actual.gpr,footprint_before,sizeof(footprint_before));memcpy(o->post_gpr,footprint_after,sizeof(footprint_after));
  need(!raw(158,0x1003,(long)&o->actual.fs_base,0,0,0,0)&&!raw(158,0x1004,(long)&o->actual.gs_base,0,0,0,0),41);
  o->fs_after=o->actual.fs_base;o->gs_after=o->actual.gs_base;
  need(!memcmp(&o->actual,&o->requested,sizeof(o->actual)),42);
 }else ++header.refused;
 memcpy(o->after,footprint_memory,MEMORY_BYTES);
 need(!memcmp(o->after,expected,MEMORY_BYTES),43);
 for(size_t j=0;j<MEMORY_BYTES;j++)if(o->before[j]!=o->after[j]){
  uintptr_t address=(uintptr_t)footprint_memory+j;need(v->policy==LI2_WRITE_RANGE&&address>=o->footprint.first&&address<o->footprint.end,44);++o->changed;}
 if(v->policy!=LI2_WRITE_RANGE||unchanged)need(!o->changed,45);else need(o->changed,46);
 if(id>=OLD_CASES)palette_effects(id,o);
 need(!raw(158,0x1002,(long)oldfs,0,0,0,0)&&!raw(158,0x1001,(long)oldgs,0,0,0,0),47);
 need(!li2_decoder_stats(&header.final)&&!memcmp(&header.initial,&header.final,sizeof(header.initial)),48);
 o->passed=1;++header.completed;
}
int footprint_main(void){
 _Static_assert(sizeof(header)==184&&sizeof(records[0])==33400,"literal record ABI");
 _Static_assert(sizeof(palette)==960&&sizeof(struct palette_vector)==448,"additive palette ABI");
 _Static_assert(sizeof(header)+sizeof(records)+sizeof(palette)<16*1024*1024,"record cap");
 header.magic=UINT64_C(0x315057465032494c);header.version=1;header.header_bytes=sizeof(header);header.record_bytes=sizeof(records[0]);header.cases=CASES;
 palette.magic=UINT64_C(0x31544c504632494c);palette.version=1;palette.bytes=sizeof(palette);
 need((uintptr_t)footprint_memory+MEMORY_BYTES<UINT32_MAX,1);
 api_controls();for(unsigned i=0;i<CASES;i++)one(i);
 need(header.completed==38&&header.executed==30&&header.refused==8&&header.api_controls==6&&
      palette.checked&&palette.vectors[0].checked&&palette.vectors[1].checked,50);
 need(write_all(3,&header,sizeof(header))&&write_all(3,records,sizeof(records))&&write_all(3,&palette,sizeof(palette)),51);
 static const char ok[]="FOOTPRINT_PASS cases=38 actual=30 supplied_refusals=8 api_controls=6 sealed_stats=unchanged palette=4\n";
 need(write_all(1,ok,sizeof(ok)-1),52);return 0;
}
