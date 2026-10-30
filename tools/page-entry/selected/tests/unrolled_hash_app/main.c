/* Separate real system-loader application. Native-only signal observation;
   the gated path never installs handlers, sets TF or executes XSAVE/XRSTOR.
   Full gated kernel FP/UC and required-fault memory come from the independently
   protected owner adapter, not this application-writable stdout record. */
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
#include <sys/syscall.h>
#include <unistd.h>
#define UA_MAGIC UINT64_C(0x315050414855494c)
#define UA_DATA_BASE UINT64_C(0x500000000000)
#define UA_STACK_BASE UINT64_C(0x500000100000)
#define UA_STACK_BYTES (128U*1024U)
#define UA_ALT_BYTES (512U*1024U)
#define UA_TF UINT64_C(0x100)
#define UA_RF UINT64_C(0x10000)
#define UA_MASK UINT64_C(0xffffffffbffbfae7)
__attribute__((section(".li2_ua_state"))) struct ua_live ua_input,ua_before,ua_after;
__attribute__((section(".li2_ua_state"))) unsigned char ua_before_live[UA_LIVE],ua_after_live[UA_LIVE];
static struct ua_prefix prefix;
#ifdef LI2_CURRENT_TF_APP
#include "../current_custody_app/types.h"
static struct uct_output uct_output_record;
#define suffix uct_output_record.original
#define uct_record uct_output_record.current
#else
static struct ua_suffix suffix;
#endif
static unsigned mode,native,handling,started,ended,frame_count,fault_seen;
static uint64_t steps,copies,first_error;
static uintptr_t alt_area;
static struct sigaction old_actions[2];
static unsigned actions_installed;
static unsigned char source_bytes[UA_PAGE];
static const uint64_t machine_zero[8]={0};
static const unsigned nul_at[9]={1,2,63,64,65,2,64,0,0};
static const unsigned fault_copy[9]={0,0,0,0,0,0,0,0,63};
static const unsigned offsets[8]={0,3,7,11,14,17,20,22};
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static const unsigned char body[26]={0x48,0x89,0xd8,0x48,0x83,0xc1,0x01,0x48,0xc1,0xe0,0x05,0x48,0x01,0xc3,0x48,0x01,0xd3,0x0f,0xb6,0x11,0x84,0xd2,0x75,0xe8,0x89,0xdb};
_Static_assert(sizeof(ucontext_t)==968 && offsetof(ucontext_t,uc_mcontext.gregs)==40 && offsetof(ucontext_t,uc_mcontext.fpregs)==224 && offsetof(ucontext_t,uc_sigmask)==296 && offsetof(ucontext_t,uc_stack)==16 && offsetof(siginfo_t,si_addr)==16,"fixed actual compiled signal ABI");
_Static_assert(sizeof(struct ua_live)==152 && sizeof(siginfo_t)==128 && sizeof(ucontext_t)<=UA_UC,"actual Linux x86-64 capture bounds");
_Static_assert(sizeof(struct ua_prefix)==14528 && sizeof(struct ua_frame)==66784 && sizeof(struct ua_suffix)==217464,"fixed application wire");
_Static_assert(sizeof(prefix)+sizeof(suffix)<256U*1024U,"stdout within unchanged 16MiB application capture bound");
static long raw(long n,long a,long b,long c,long d,long e,long f){
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;long r;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
void copy(void *,const void *,size_t);
int same(const void *,const void *,size_t);
void ua_data_pattern(unsigned char *,size_t);
void ua_stack_pattern(unsigned char *,size_t);
static _Noreturn void die(unsigned n){if(!first_error)first_error=n;(void)RAW(SYS_exit_group,99,0,0,0,0,0);__builtin_trap();}
static void need(int yes,unsigned n){if(!yes)die(n);}
static int output(const void *p,size_t n){const unsigned char *b=p;while(n){long k=RAW(SYS_write,1,b,n,0,0,0);if(k<=0||(size_t)k>n)return 0;b+=k;n-=(size_t)k;}return 1;}
static uint32_t u32(const unsigned char *p){uint32_t x;copy(&x,p,4);return x;}
static uint64_t u64(const unsigned char *p){uint64_t x;copy(&x,p,8);return x;}
static int alt_range(const void *p,size_t n){uintptr_t a=(uintptr_t)p;return alt_area&&a>=alt_area+UA_PAGE&&a<=alt_area+UA_PAGE+UA_ALT_BYTES&&n<=alt_area+UA_PAGE+UA_ALT_BYTES-a;}
static void retain(int sig,const siginfo_t *si,const ucontext_t *uc,unsigned kind){
 need(frame_count<3&&alt_range(si,sizeof *si)&&alt_range(uc,sizeof *uc),20);
 struct ua_frame *f=&suffix.frames[frame_count];
 const unsigned char *p=(const void *)uc->uc_mcontext.fpregs;
 need(!((uintptr_t)p&15)&&alt_range(p,512),21);size_t n=512;
 if(u32(p+464)==UINT32_C(0x46505853)){
  n=u32(p+468);size_t x=u32(p+480);
  need(n>=580&&n<=UA_FP&&x>=576&&x==n-4&&alt_range(p,n)&&u32(p+n-4)==UINT32_C(0x46505845)&&!u64(p+520),22);
 }
 need(n>=580,23); /* This finite AVX-512 profile requires a genuine standard XSAVE signal frame. */
 f->h[0]=1;f->h[1]=kind;f->h[2]=steps;f->h[3]=copies;f->h[4]=(unsigned)sig;
 f->h[5]=(uintptr_t)si;f->h[6]=(uintptr_t)uc;f->h[7]=sizeof *uc;
 f->h[8]=(uintptr_t)p;f->h[9]=n;f->h[10]=alt_area+UA_PAGE;f->h[11]=UA_ALT_BYTES;
 copy(f->si,si,sizeof *si);copy(f->uc,uc,sizeof *uc);copy(f->fp,p,n);++frame_count;
}
#ifdef LI2_CURRENT_TF_APP
#include "../current_custody_app/native.inc"
#endif
static void handler(int sig,siginfo_t *si,void *ptr){
 need(native&&!handling&&si&&ptr,30);handling=1;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;
 uintptr_t pc=(uintptr_t)g[REG_RIP],head=(uintptr_t)unrolled_app_head,stop=(uintptr_t)unrolled_app_stop;
 need(!ended&&!si->si_errno&&si->si_signo==sig,31);
#ifdef LI2_CURRENT_TF_APP
 if(uct_native_handler(sig,si,uc)){handling=0;return;}
#endif
 if(!started){
  need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&(uintptr_t)si->si_addr==head&&pc==head&&g[REG_ERR]==21&&g[REG_TRAPNO]==14&&(uintptr_t)g[REG_CR2]==head,32);
  need((uint64_t)g[REG_EFL]==(ua_input.flags|UA_RF),33);
  for(unsigned i=0;i<16;i++)need((uint64_t)g[regs[i]]==ua_input.g[i],34);
  retain(sig,si,uc,0);started=1;
  need(!RAW(SYS_mprotect,unrolled_app_head,UA_PAGE,PROT_READ|PROT_EXEC,0,0,0),35);
  g[REG_EFL]|=(greg_t)UA_TF;handling=0;return;
 }
 if(sig==SIGTRAP){
  need(si->si_code==TRAP_TRACE&&g[REG_ERR]==0&&g[REG_TRAPNO]==1&&(g[REG_EFL]&UA_TF)&&steps<520,36);
  unsigned index=(unsigned)(steps%8);
  if(index==7)need(pc==head||pc==stop,37);else need(pc==head+offsets[index+1],38);
  ++steps;
  if(index==7){
   ++copies;
   if(pc==head&&copies==64){need(mode==4,39);retain(sig,si,uc,1);}
   if(pc==stop){need(mode<7&&copies==nul_at[mode],40);retain(sig,si,uc,2);ended=1;g[REG_EFL]&=~(greg_t)UA_TF;}
  }
  handling=0;return;
 }
 need(mode>=7&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&pc==head+17&&(uintptr_t)si->si_addr==UA_DATA_BASE+UA_DATA&&g[REG_ERR]==4&&g[REG_TRAPNO]==14&&(uintptr_t)g[REG_CR2]==UA_DATA_BASE+UA_DATA,41);
 need(copies==fault_copy[mode]&&steps==copies*8+5&&(g[REG_EFL]&UA_TF),42);
 retain(sig,si,uc,3);fault_seen=ended=1;
 /* Native-only observation continuation, not application fault-resumption
    qualification: retain the failed original frame first, then collect and exit125. */
 g[REG_EFL]&=~(greg_t)UA_TF;g[REG_RIP]=(greg_t)(uintptr_t)unrolled_app_capture;
 handling=0;
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
 need(!RAW(SYS_rt_sigprocmask,0,0,&out[0],8,0,0)&&out[0]==UA_MASK,53);
 need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&out[1],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&out[2],0,0,0,0),54);
 uint16_t cs,ss,ds,es,fs,gs;__asm__ volatile("mov %%cs,%0;mov %%ss,%1;mov %%ds,%2;mov %%es,%3;mov %%fs,%4;mov %%gs,%5":"=r"(cs),"=r"(ss),"=r"(ds),"=r"(es),"=r"(fs),"=r"(gs));
 out[3]=cs;out[4]=ss;out[5]=(uint64_t)ds|((uint64_t)es<<16);out[6]=(uint64_t)fs|((uint64_t)gs<<16);out[7]=0;
}
static void native_setup(void){
 long a=RAW(SYS_mmap,0,UA_ALT_BYTES+2*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(a>0,60);alt_area=(uintptr_t)a;
 need(!RAW(SYS_mprotect,alt_area+UA_PAGE,UA_ALT_BYTES,PROT_READ|PROT_WRITE,0,0,0),61);
 stack_t st={.ss_sp=(void *)(alt_area+UA_PAGE),.ss_size=UA_ALT_BYTES};need(!sigaltstack(&st,0),62);
 struct sigaction action={0};action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER;sigfillset(&action.sa_mask);
 const int unblocked[]={SIGILL,SIGTRAP,SIGSEGV,SIGSYS,SIGKILL,SIGSTOP};
 for(unsigned i=0;i<sizeof unblocked/sizeof unblocked[0];i++)sigdelset(&action.sa_mask,unblocked[i]);
 for(unsigned i=0;i<2;i++){
  int sig=i?SIGTRAP:SIGSEGV;need(!sigaction(sig,0,&old_actions[i])&&old_actions[i].sa_handler==SIG_DFL,63);
  need(!sigaction(sig,&action,0),64);++actions_installed;
 }
 need(!RAW(SYS_mprotect,unrolled_app_head,UA_PAGE,PROT_READ,0,0,0),65);
}
static void cleanup(void){
 need(!RAW(SYS_munmap,UA_DATA_BASE,UA_DATA+UA_PAGE,0,0,0,0),70);
 need(!RAW(SYS_munmap,UA_STACK_BASE,UA_STACK_BYTES+2*UA_PAGE,0,0,0,0),71);
 if(native){
  for(unsigned i=0;i<actions_installed;i++)need(!sigaction(i?SIGTRAP:SIGSEGV,&old_actions[i],0),72);
  stack_t disabled={.ss_flags=SS_DISABLE};need(!sigaltstack(&disabled,0),73);
  need(!RAW(SYS_munmap,alt_area,UA_ALT_BYTES+2*UA_PAGE,0,0,0,0),74);alt_area=0;
 }
 suffix.h[5]=1;
}
int main(int argc,char **argv){
#ifdef LI2_CURRENT_TF_APP
 if((argc!=3&&argc!=4)||strlen(argv[1])!=1||argv[1][0]<'0'||argv[1][0]>'8'||(strcmp(argv[2],"native")&&strcmp(argv[2],"gated")))return 2;
#else
 if(argc!=3||strlen(argv[1])!=1||argv[1][0]<'0'||argv[1][0]>'8'||(strcmp(argv[2],"native")&&strcmp(argv[2],"gated")))return 2;
#endif
 mode=(unsigned)(argv[1][0]-'0');native=!strcmp(argv[2],"native");
 need(((uintptr_t)unrolled_app_head&4095)==0&&unrolled_app_stop-unrolled_app_head==24&&unrolled_app_source_end-unrolled_app_head==UA_PAGE&&same(unrolled_app_head,body,sizeof body),80);
 copy(source_bytes,unrolled_app_head,UA_PAGE);
 uint64_t *h=prefix.h;h[0]=UA_MAGIC;h[1]=1;h[2]=sizeof prefix;h[3]=sizeof suffix;h[4]=mode;h[5]=native;
 h[6]=(uint64_t)RAW(SYS_getpid,0,0,0,0,0,0);h[7]=(uint64_t)RAW(SYS_gettid,0,0,0,0,0,0);need(h[6]>0&&h[6]==h[7],81);
 unsigned cpu=0,node=0;need(!RAW(SYS_getcpu,&cpu,&node,0,0,0,0),82);h[8]=cpu;h[9]=node;
 h[10]=(uintptr_t)unrolled_app_head;h[11]=(uintptr_t)unrolled_app_stop;h[12]=UA_DATA_BASE;h[13]=UA_STACK_BASE;hardware();machine(prefix.machine);
 h[16]=nul_at[mode];h[17]=mode>=7;h[18]=(uintptr_t)unrolled_app_seed_x87;h[19]=sizeof(ucontext_t);h[20]=sizeof(struct ua_frame);
 h[21]=offsetof(ucontext_t,uc_mcontext.gregs);h[22]=offsetof(ucontext_t,uc_mcontext.fpregs);h[23]=offsetof(ucontext_t,uc_sigmask);h[24]=offsetof(ucontext_t,uc_stack);h[25]=offsetof(siginfo_t,si_addr);
 need(RAW(SYS_mmap,UA_DATA_BASE,UA_DATA+UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)UA_DATA_BASE,83);
 need(!RAW(SYS_mprotect,UA_DATA_BASE,UA_DATA,PROT_READ|PROT_WRITE,0,0,0),84);
 need(RAW(SYS_mmap,UA_STACK_BASE,UA_STACK_BYTES+2*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)UA_STACK_BASE,85);
 need(!RAW(SYS_mprotect,UA_STACK_BASE+UA_PAGE,UA_STACK_BYTES,PROT_READ|PROT_WRITE,0,0,0),86);
 ua_data_pattern(prefix.data,UA_DATA);
 size_t first=mode==6?UA_DATA-64:mode==7?UA_DATA:mode==8?UA_DATA-63:128;
 if(nul_at[mode]){need(first+nul_at[mode]<=UA_DATA,87);prefix.data[first+nul_at[mode]-1]=0;}
 for(unsigned i=0;i<16;i++)ua_input.g[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
 ua_input.g[1]=UA_DATA_BASE+first-1;ua_input.g[2]=mode==5?UINT64_C(0xfedcba9876543280):0x41;
 ua_input.g[3]=mode==5?UINT64_MAX-3:UINT64_C(0x123456789abcdef0);ua_input.g[4]=UA_STACK_BASE+UA_PAGE+UA_STACK_BYTES-504;
 ua_input.flags=mode==5?0xad7:0x202;need((ua_input.g[4]&15)==8,88);
 ua_stack_pattern(prefix.stack,UA_STACK);
 copy((void *)UA_DATA_BASE,prefix.data,UA_DATA);copy((void *)(ua_input.g[4]-128),prefix.stack,UA_STACK);
 copy(&prefix.seed,&ua_input,sizeof prefix.seed);copy(prefix.source,source_bytes,UA_PAGE);

#ifdef LI2_CURRENT_TF_APP
 uct_initialize((uintptr_t)&argc,argc,argv);
#endif
 if(native)native_setup();
#ifdef LI2_CURRENT_TF_APP
 if(native)uct_native_setup();
#endif
 need(output(&prefix,sizeof prefix),89);unrolled_app_enter();
 need(!handling&&same(&ua_before.g,&ua_input.g,sizeof ua_input.g)&&ua_before.flags==ua_input.flags&&same(ua_before.selectors,ua_after.selectors,sizeof ua_before.selectors),90);
 if(native)need(started&&ended&&frame_count==(mode==4?3U:2U)&&fault_seen==(mode>=7)&&copies==(mode>=7?fault_copy[mode]:nul_at[mode])&&steps==copies*8+(mode>=7?5:0),91);
 else need(!started&&!ended&&!frame_count&&!fault_seen&&mode<7,92);
 suffix.h[0]=UA_MAGIC^1;suffix.h[1]=1;suffix.h[2]=mode;suffix.h[3]=native;suffix.h[4]=first_error;suffix.h[6]=frame_count;suffix.h[7]=steps;suffix.h[8]=copies;suffix.h[9]=fault_seen;
 copy(&suffix.before,&ua_before,sizeof suffix.before);copy(&suffix.after,&ua_after,sizeof suffix.after);copy(suffix.before_live,ua_before_live,UA_LIVE);copy(suffix.after_live,ua_after_live,UA_LIVE);
 need(same(ua_before_live,ua_after_live,UA_LIVE),93);
 copy(suffix.source,unrolled_app_head,UA_PAGE);copy(suffix.stack,(void *)(ua_input.g[4]-128),UA_STACK);copy(suffix.data,(void *)UA_DATA_BASE,UA_DATA);
 need(same(prefix.source,suffix.source,UA_PAGE)&&same(prefix.stack,suffix.stack,UA_STACK)&&same(prefix.data,suffix.data,UA_DATA),94);
 uint64_t after_machine[8];copy(after_machine,machine_zero,sizeof after_machine);machine(after_machine);need(same(prefix.machine,after_machine,sizeof after_machine),95);
 unsigned after_cpu=0,after_node=0;need(!RAW(SYS_getcpu,&after_cpu,&after_node,0,0,0,0)&&after_cpu==cpu&&after_node==node,96);
 cleanup();
#ifdef LI2_CURRENT_TF_APP
 uct_finish();need(!first_error&&output(&uct_output_record,sizeof uct_output_record),97);
#else
 need(!first_error&&output(&suffix,sizeof suffix),97);
#endif
 return mode>=7?125:0;
}
