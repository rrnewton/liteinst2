/* Distinct genuine-TRACE scalar-span application. Native-only TF and
   signal observations never execute in the gated path. Full owner state and
   failed-load bytes come from the protected capture channel, not stdout. */
#define _GNU_SOURCE
#include "app.h"
#include <asm/prctl.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>
#define RA_MAGIC UINT64_C(0x315050415453494c)
#define DATA_BASE UINT64_C(0x500000000000)
#define STACK_BASE UINT64_C(0x500000100000)
#define STACK_EXTENT (128U*1024U)
#define STACK_FAULT (STACK_BASE+8192)
#define ALT_BYTES (512U*1024U)
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define MASK UINT64_C(0xffffffffbffbfae7)
__attribute__((section(".li2_ua_state"))) struct ua_live ua_input,ua_before,ua_after;
__attribute__((section(".li2_ua_state"))) unsigned char ua_before_live[UA_LIVE],ua_after_live[UA_LIVE];
static struct ra_prefix prefix;
static struct ra_suffix suffix;
static struct ra_observation *observation;
static unsigned mode,native,handling,started,ended,frames,fault_seen;
static uintptr_t focal_head,predecessor,endpoint;
__attribute__((section(".li2_ua_state"))) uintptr_t ua_target;
static uint64_t steps,first_error;
static uintptr_t alt_area;
static struct sigaction old_actions[2];
static unsigned actions_installed;
static const uint64_t machine_zero[8]={0};
static const unsigned offsets[8]={0,5,10,13,16,23,27,29};
static const unsigned traces[4]={9,8,2,4};
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static const unsigned char graph[31]={0xb8,7,0,0,0,0x48,0x8d,0x54,0x48,3,0x48,0x01,0xd0,0x44,0x8b,7,0x44,0x8b,0x0d,0x69,0,0,0,0x48,0x83,0xf8,15,0x74,0x53,0xeb,0x31};
_Static_assert(sizeof(ucontext_t)==968 && offsetof(ucontext_t,uc_mcontext.gregs)==40 && offsetof(ucontext_t,uc_mcontext.fpregs)==224 && offsetof(ucontext_t,uc_sigmask)==296 && offsetof(ucontext_t,uc_stack)==16 && offsetof(siginfo_t,si_addr)==16,"actual Linux signal ABI");
_Static_assert(sizeof(struct ua_live)==152 && sizeof(struct ua_frame)==66784 && sizeof(struct ra_prefix)==14720 && sizeof(struct ra_observation)==217528 && sizeof(struct ra_suffix)==217656,"complete fixed application wire");
_Static_assert(sizeof(prefix)+sizeof(suffix)<512U*1024U,"complete app output below unchanged16MiB ceiling");
static long raw(long n,long a,long b,long c,long d,long e,long f){
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;long r;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
void copy(void *,const void *,size_t);int same(const void *,const void *,size_t);
void ua_data_pattern(unsigned char *,size_t);void ua_stack_pattern(unsigned char *,size_t);
static _Noreturn void die(unsigned n){if(!first_error)first_error=n;(void)RAW(SYS_exit_group,99,0,0,0,0,0);__builtin_trap();}
static void need(int yes,unsigned n){if(!yes)die(n);}
static int output(const void *p,size_t n){const unsigned char *b=p;while(n){long k=RAW(SYS_write,1,b,n,0,0,0);if(k<=0||(size_t)k>n)return 0;b+=k;n-=(size_t)k;}return 1;}
static uint32_t u32(const unsigned char *p){uint32_t x;copy(&x,p,4);return x;}
static uint64_t u64(const unsigned char *p){uint64_t x;copy(&x,p,8);return x;}
static int alt_range(const void *p,size_t n){uintptr_t a=(uintptr_t)p;return alt_area&&a>=alt_area+UA_PAGE&&a<=alt_area+UA_PAGE+ALT_BYTES&&n<=alt_area+UA_PAGE+ALT_BYTES-a;}
static uintptr_t fault_address(void){return DATA_BASE+UA_DATA;}
static void retain(int sig,const siginfo_t *si,const ucontext_t *uc,unsigned kind){
 need(frames<3&&alt_range(si,sizeof *si)&&alt_range(uc,sizeof *uc),20);struct ua_frame *f=&observation->frames[frames];
 const unsigned char *p=(const void *)uc->uc_mcontext.fpregs;
 need(!((uintptr_t)p&15)&&alt_range(p,512),21);size_t n=512;
 if(u32(p+464)==UINT32_C(0x46505853)){n=u32(p+468);size_t x=u32(p+480);need(n>=580&&n<=UA_FP&&x>=576&&x==n-4&&alt_range(p,n)&&u32(p+n-4)==UINT32_C(0x46505845)&&!u64(p+520),22);}
 need(n>=580,23);f->h[0]=1;f->h[1]=kind;f->h[2]=steps;f->h[3]=0;f->h[4]=(unsigned)sig;
 f->h[5]=(uintptr_t)si;f->h[6]=(uintptr_t)uc;f->h[7]=sizeof *uc;f->h[8]=(uintptr_t)p;f->h[9]=n;f->h[10]=alt_area+UA_PAGE;f->h[11]=ALT_BYTES;
 copy(f->si,si,sizeof *si);copy(f->uc,uc,sizeof *uc);copy(f->fp,p,n);++frames;
}
static void handler(int sig,siginfo_t *si,void *ptr){
 need(native&&!handling&&si&&ptr&&observation,30);handling=1;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;
 uintptr_t pc=(uintptr_t)g[REG_RIP],page=(uintptr_t)region_app_page;
 need(!ended&&!si->si_errno&&si->si_signo==sig,31);
 if(!started){
  need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&(uintptr_t)si->si_addr==predecessor&&pc==predecessor&&g[REG_ERR]==21&&g[REG_TRAPNO]==14&&(uintptr_t)g[REG_CR2]==predecessor,32);
  need((uint64_t)g[REG_EFL]==(ua_input.flags|RF),33);for(unsigned i=0;i<16;i++)need((uint64_t)g[regs[i]]==ua_input.g[i],34);
  retain(sig,si,uc,0);started=1;need(!RAW(SYS_mprotect,page,UA_PAGE,PROT_READ|PROT_EXEC,0,0,0),35);g[REG_EFL]|=(greg_t)TF;handling=0;return;
 }
 if(sig==SIGTRAP){
  need(si->si_code==TRAP_TRACE&&g[REG_ERR]==0&&g[REG_TRAPNO]==1&&(g[REG_EFL]&TF)&&steps<traces[mode],36);
  ++steps;uintptr_t want;
  if(steps==1)want=focal_head;
  else if(steps==traces[mode])want=endpoint;
  else {need(mode!=2&&steps<=8,37);want=focal_head+offsets[steps-1];}
  need(pc==want&&(uintptr_t)si->si_addr==want,38);
  if(steps==1){
   need((uint64_t)g[REG_EFL]==(ua_input.flags|TF),39);
   for(unsigned i=0;i<16;i++)need((uint64_t)g[regs[i]]==ua_input.g[i],40);
   retain(sig,si,uc,1);
  }else if(mode!=3&&steps==traces[mode]){retain(sig,si,uc,2);ended=1;g[REG_EFL]&=~(greg_t)TF;}
  handling=0;return;
 }
 need(mode==3&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&pc==endpoint&&(uintptr_t)si->si_addr==fault_address()&&g[REG_ERR]==4&&g[REG_TRAPNO]==14&&(uintptr_t)g[REG_CR2]==fault_address(),41);
 need(steps==traces[mode]&&(g[REG_EFL]&TF),42);retain(sig,si,uc,3);fault_seen=ended=1;
 /* Native-only terminal capture. The real failed load never resumes. */
 need(!RAW(SYS_mprotect,page,UA_PAGE,PROT_READ,0,0,0),43);
 g[REG_EFL]&=~(greg_t)TF;g[REG_RIP]=(greg_t)(uintptr_t)region_app_capture;handling=0;
}
static void hardware(void){
 unsigned leaves[3]={0,1,7};
 for(unsigned i=0;i<67;i++){
  unsigned leaf=i<3?leaves[i]:13,sub=i<3?0:i-3,a,b,c,d;
  __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
  uint32_t *r=prefix.hardware[i];r[0]=leaf;r[1]=sub;r[2]=a;r[3]=b;r[4]=c;r[5]=d;
 }
 need(prefix.hardware[0][2]>=13&&(prefix.hardware[1][4]&0x0c000000)==0x0c000000&&(prefix.hardware[2][3]&0x40010000)==0x40010000,50);
 unsigned a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
 prefix.h[14]=(uint64_t)a|((uint64_t)d<<32);prefix.h[15]=prefix.hardware[3][3];
 prefix.h[26]=(uint64_t)RAW(SYS_arch_prctl,0x1021,&prefix.h[27],0,0,0,0);
 prefix.h[28]=(uint64_t)RAW(SYS_arch_prctl,0x1022,&prefix.h[29],0,0,0,0);
 need(!prefix.h[26]&&!prefix.h[28],55);
 need((prefix.h[14]&0xe7)==0xe7&&prefix.h[15]>=576&&prefix.h[15]<=UA_FP,51);
 for(unsigned i=2;i<64;i++)if(prefix.h[14]&(UINT64_C(1)<<i)){
  const uint32_t *r=prefix.hardware[3+i];need(r[2]&&r[3]>=576&&(uint64_t)r[3]+r[2]<=prefix.h[15]&&!(r[4]&1),52);
 }
}
static void machine(uint64_t out[8]){
 need(!RAW(SYS_rt_sigprocmask,0,0,&out[0],8,0,0)&&out[0]==MASK,53);
 need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&out[1],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&out[2],0,0,0,0),54);
 uint16_t cs,ss,ds,es,fs,gs;__asm__ volatile("mov %%cs,%0;mov %%ss,%1;mov %%ds,%2;mov %%es,%3;mov %%fs,%4;mov %%gs,%5":"=r"(cs),"=r"(ss),"=r"(ds),"=r"(es),"=r"(fs),"=r"(gs));
 out[3]=cs;out[4]=ss;out[5]=(uint64_t)ds|((uint64_t)es<<16);out[6]=(uint64_t)fs|((uint64_t)gs<<16);out[7]=0;
}
static void native_setup(void){
 long a=RAW(SYS_mmap,0,ALT_BYTES+2*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(a>0,60);alt_area=(uintptr_t)a;
 need(!RAW(SYS_mprotect,alt_area+UA_PAGE,ALT_BYTES,PROT_READ|PROT_WRITE,0,0,0),61);
 stack_t st={.ss_sp=(void *)(alt_area+UA_PAGE),.ss_size=ALT_BYTES};need(!sigaltstack(&st,0),62);
 struct sigaction action={0};action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER;sigfillset(&action.sa_mask);
 const int unblocked[]={SIGILL,SIGTRAP,SIGSEGV,SIGSYS,SIGKILL,SIGSTOP};
 for(unsigned i=0;i<sizeof unblocked/sizeof unblocked[0];i++)sigdelset(&action.sa_mask,unblocked[i]);
 for(unsigned i=0;i<2;i++){
  int sig=i?SIGTRAP:SIGSEGV;need(!sigaction(sig,0,&old_actions[i])&&old_actions[i].sa_handler==SIG_DFL,63);
  need(!sigaction(sig,&action,0),64);++actions_installed;
 }
 need(!RAW(SYS_mprotect,region_app_page,UA_PAGE,PROT_READ,0,0,0),65);
}
static void cleanup(void){
 need(!RAW(SYS_munmap,DATA_BASE,UA_DATA+UA_PAGE,0,0,0,0),70);
 need(!RAW(SYS_munmap,STACK_BASE,STACK_EXTENT+2*UA_PAGE,0,0,0,0),71);
 if(native){
  for(unsigned i=0;i<actions_installed;i++)need(!sigaction(i?SIGTRAP:SIGSEGV,&old_actions[i],0),72);
  stack_t disabled={.ss_flags=SS_DISABLE};need(!sigaltstack(&disabled,0),73);
  need(!RAW(SYS_munmap,alt_area,ALT_BYTES+2*UA_PAGE,0,0,0,0),74);alt_area=0;
 }
 suffix.h[5]=1;
}
static void inputs(void){
 ua_data_pattern(prefix.data,UA_DATA);ua_stack_pattern(prefix.stack,UA_STACK);
 for(unsigned i=0;i<16;i++)ua_input.g[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
 ua_input.g[1]=mode==1?UINT64_MAX:3;ua_input.g[4]=STACK_BASE+UA_PAGE+STACK_EXTENT-504;
 ua_input.g[7]=mode==3?DATA_BASE+UA_DATA:DATA_BASE+128;
 ua_input.flags=mode%2?0x202:0xad7;need((ua_input.g[4]&15)==8,121);
 copy((void *)DATA_BASE,prefix.data,UA_DATA);copy((void *)(ua_input.g[4]-128),prefix.stack,UA_STACK);
 copy(&prefix.seed,&ua_input,sizeof prefix.seed);copy(prefix.source,region_app_page,UA_PAGE);
 ua_target=predecessor;
}
static void collect(void){
 need(!handling&&same(ua_before.g,ua_input.g,sizeof ua_input.g)&&ua_before.flags==ua_input.flags&&same(ua_before.selectors,ua_after.selectors,sizeof ua_before.selectors),90);
 if(native)need(started&&ended&&frames==3&&fault_seen==(mode==3)&&steps==traces[mode],91);
 else need(!started&&!ended&&!frames&&!fault_seen&&mode!=3,92);
 if(native&&mode!=3)need(!RAW(SYS_mprotect,region_app_page,UA_PAGE,PROT_READ,0,0,0),98);
 observation->h[0]=1;observation->h[1]=0;observation->h[2]=frames;observation->h[3]=steps;observation->h[4]=fault_seen;observation->h[5]=native;
 copy(&observation->before,&ua_before,sizeof observation->before);copy(&observation->after,&ua_after,sizeof observation->after);
 copy(observation->before_live,ua_before_live,UA_LIVE);copy(observation->after_live,ua_after_live,UA_LIVE);need(same(ua_before_live,ua_after_live,UA_LIVE),93);
 copy(observation->source,region_app_page,UA_PAGE);copy(observation->stack,(void *)(ua_input.g[4]-128),UA_STACK);copy(observation->data,(void *)DATA_BASE,UA_DATA);
 need(same(prefix.source,observation->source,UA_PAGE)&&same(prefix.stack,observation->stack,UA_STACK)&&same(prefix.data,observation->data,UA_DATA),94);
 uint64_t after_machine[8];copy(after_machine,machine_zero,sizeof after_machine);machine(after_machine);need(same(prefix.machine,after_machine,sizeof after_machine),95);
 unsigned cpu=0,node=0;need(!RAW(SYS_getcpu,&cpu,&node,0,0,0,0)&&cpu==prefix.h[8]&&node==prefix.h[9],96);
 observation->h[8]=endpoint;suffix.h[7]=frames;suffix.h[8]=steps;suffix.h[9]=fault_seen;
}
int main(int argc,char **argv){
 if(argc!=3||strlen(argv[1])!=1||argv[1][0]<'0'||argv[1][0]>'3'||(strcmp(argv[2],"native")&&strcmp(argv[2],"gated")))return 2;
 mode=(unsigned)(argv[1][0]-'0');native=!strcmp(argv[2],"native");
 focal_head=(uintptr_t)(mode==2?region_app_miss_head:region_app_head);
 predecessor=focal_head-2;endpoint=(uintptr_t)(mode==0?region_app_exit0:mode==1?region_app_exit1:mode==2?region_app_miss_exit:region_app_head+13);
 need(((uintptr_t)region_app_page&4095)==0&&region_app_head-region_app_page==0x200&&region_app_source_end-region_app_page==UA_PAGE&&same(region_app_head,graph,sizeof graph),80);
 need(region_app_predecessor-region_app_page==0x1fe&&region_app_miss_predecessor-region_app_page==0x2fe&&region_app_miss_head-region_app_page==0x300&&region_app_miss_exit-region_app_page==0x302,120);
 uint64_t *h=prefix.h;h[0]=RA_MAGIC;h[1]=1;h[2]=sizeof prefix;h[3]=sizeof suffix;h[4]=mode;h[5]=native;
 h[6]=(uint64_t)RAW(SYS_getpid,0,0,0,0,0,0);h[7]=(uint64_t)RAW(SYS_gettid,0,0,0,0,0,0);need(h[6]>0&&h[6]==h[7],81);
 unsigned cpu=0,node=0;need(!RAW(SYS_getcpu,&cpu,&node,0,0,0,0),82);h[8]=cpu;h[9]=node;
 h[10]=focal_head;h[11]=(uintptr_t)region_app_page;h[12]=DATA_BASE;h[13]=STACK_BASE;hardware();machine(prefix.machine);
 h[16]=mode;h[17]=mode==3;h[18]=(uintptr_t)region_app_seed_x87;h[19]=sizeof(ucontext_t);h[20]=sizeof(struct ua_frame);
 h[21]=offsetof(ucontext_t,uc_mcontext.gregs);h[22]=offsetof(ucontext_t,uc_mcontext.fpregs);h[23]=offsetof(ucontext_t,uc_sigmask);h[24]=offsetof(ucontext_t,uc_stack);h[25]=offsetof(siginfo_t,si_addr);
 need(RAW(SYS_mmap,DATA_BASE,UA_DATA+UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)DATA_BASE,83);
 need(!RAW(SYS_mprotect,DATA_BASE,UA_DATA,PROT_READ|PROT_WRITE,0,0,0),84);
 need(RAW(SYS_mmap,STACK_BASE,STACK_EXTENT+2*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)STACK_BASE,85);
 need(!RAW(SYS_mprotect,STACK_BASE+UA_PAGE,STACK_EXTENT,PROT_READ|PROT_WRITE,0,0,0),86);inputs();
 h[30]=1;h[31]=UA_STACK;h[32]=mode==3?fault_address():0;h[33]=mode==3?3:0;h[34]=endpoint;h[35]=predecessor;h[36]=traces[mode];h[37]=sizeof(struct ra_observation);h[38]=3;h[39]=31;
 h[40]=(uintptr_t)region_app_head;h[41]=(uintptr_t)region_app_miss_head;h[42]=(uintptr_t)region_app_constant;
 if(native)native_setup();
 need(output(&prefix,sizeof prefix),89);
 observation=&suffix.observations[0];region_app_enter();collect();
 suffix.h[0]=RA_MAGIC^1;suffix.h[1]=1;suffix.h[2]=mode;suffix.h[3]=native;suffix.h[4]=first_error;suffix.h[6]=1;
 cleanup();need(!first_error&&output(&suffix,sizeof suffix),97);return mode==3?125:0;
}
