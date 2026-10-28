/* Genuine native reference delivery, never a synthesized frame. This code is
   called only by the literal native argv lane, before registration/after work. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/ucontext.h>
#include "record.h"
#define RSEC __attribute__((section(".text.reference")))
static struct rn_native_record rn_native_record;
static unsigned char rn_altstack[131072] __attribute__((aligned(64)));
static unsigned rn_seen,rn_finished;
extern const uint64_t rn_case;
extern unsigned char rn_fault[],rn_tail[],rn_guard[];
static inline long call6(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static RSEC __attribute__((noreturn)) void die(long code) {
 call6(231,code,0,0,0,0,0);__builtin_unreachable();
}
static RSEC void copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static RSEC uint32_t u32(const unsigned char *b) {
 return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
static RSEC void capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)rn_altstack;
 if(sizeof *u>RN_UC || p<lo || p-lo>sizeof rn_altstack-512 || (p&15))die(98);
 const unsigned char *b=(const void *)p;size_t n=512;
 if(u32(b+464)==UINT32_C(0x46505853)) {
  n=u32(b+468);size_t x=u32(b+480);
  if(n<580 || n>RN_FP || n>sizeof rn_altstack-(p-lo) || x<576 || x>n-4 || u32(b+n-4)!=UINT32_C(0x46505845))die(98);
 }
 s->h[0]=1;s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 copy(s->uc,u,sizeof *u);copy(s->fp,b,n);
 copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);
}
RSEC void rn_native_finish(void) {
 if(rn_finished)die(98);
 rn_finished=1;rn_native_record.h[4]=rn_seen;rn_native_record.h[5]=1;
 size_t at=0;
 while(at<sizeof rn_native_record) {
  long n=call6(1,3,(long)((unsigned char *)&rn_native_record+at),sizeof rn_native_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof rn_native_record-at)die(98);
  at+=(size_t)n;
 }
}
static RSEC void handler(int sig,siginfo_t *si,void *ptr) {
 ucontext_t *u=ptr;uint64_t c=rn_case;
 if(rn_seen++ || sig!=11 || si->si_signo!=11 || si->si_errno || !u)die(98);
 capture(&rn_native_record.before,sig,si,u);
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP],address=(uintptr_t)si->si_addr;
 int prefix=c==12 || c==13 || c==15;
 int resume=c<=4 || c==6 || (c>=8 && c<=11) || prefix;
 if(resume) {
  uintptr_t target=prefix?RN_BODY:c==6?(uintptr_t)rn_tail:(uintptr_t)rn_guard;
  if(si->si_code!=SEGV_ACCERR || pc!=target || address!=target ||
     (uint64_t)u->uc_mcontext.gregs[REG_TRAPNO]!=14 ||
     (uint64_t)u->uc_mcontext.gregs[REG_ERR]!=21 ||
     (uintptr_t)u->uc_mcontext.gregs[REG_CR2]!=target ||
     *(const volatile uint64_t *)(uintptr_t)RN_WORD)die(98);
  if(call6(10,target,4096,5,0,0,0))die(98);
  capture(&rn_native_record.after,sig,si,u);rn_native_record.h[6]=1;
  if(prefix){rn_native_record.h[13]=1;rn_native_finish();}
  return;
 }
 if(c!=5 && c!=7 && c!=14)die(98);
 capture(&rn_native_record.after,sig,si,u);rn_native_record.h[7]=125;
 rn_native_finish();die(125);
}
__asm__(".section .text.reference,\"ax\",@progbits\n.global rn_restorer\nrn_restorer:\nmov $15,%eax\nsyscall\nud2\n.previous\n");
extern void rn_restorer(void);
RSEC long rn_native_setup(unsigned c) {
 if(c!=rn_case || c>15 || sizeof(ucontext_t)>RN_UC)return -1;
 volatile unsigned char *z=(void *)&rn_native_record;
 for(size_t i=0;i<sizeof rn_native_record;i++)z[i]=0;
 for(size_t i=0;i<sizeof rn_altstack;i++)rn_altstack[i]=0;
 rn_native_record.h[0]=RN_MAGIC;rn_native_record.h[1]=1;
 rn_native_record.h[2]=sizeof rn_native_record;rn_native_record.h[3]=c;
 rn_native_record.h[8]=call6(39,0,0,0,0,0,0);rn_native_record.h[9]=call6(186,0,0,0,0,0,0);
 uint32_t low,high;__asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
 rn_native_record.h[10]=(uint64_t)low|((uint64_t)high<<32);
 rn_native_record.h[11]=(uintptr_t)rn_altstack;rn_native_record.h[12]=sizeof rn_altstack;
 if((rn_native_record.h[10]&0xe7)!=0xe7)return -1;
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,d,ecx=bits[i];__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(ecx),"=d"(d)::"memory");
  rn_native_record.xstate[i][0]=bits[i];rn_native_record.xstate[i][1]=b;
  rn_native_record.xstate[i][2]=a;rn_native_record.xstate[i][3]=ecx;
 }
 stack_t stack={.ss_sp=rn_altstack,.ss_flags=0,.ss_size=sizeof rn_altstack};
 struct {void (*function)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action={handler,0x0c000004UL,rn_restorer,0};
 if(call6(131,(long)&stack,0,0,0,0,0) || call6(13,11,(long)&action,0,8,0,0))return -1;
 /* Same actual application signal-mask contract as the controlled profile;
    no cross-lane mask field is discarded by the comparator. */
 uint64_t mask=UINT64_MAX & ~(UINT64_C(1)<<10) & ~(UINT64_C(1)<<4) &
  ~(UINT64_C(1)<<30) & ~(UINT64_C(1)<<8) & ~(UINT64_C(1)<<18);
 if(call6(14,2,(long)&mask,0,8,0,0))return -1;
 uintptr_t page=0;
 if(c<=4 || (c>=8 && c<=11))page=RN_GUARD;
 if(c==5 || c==6 || c==7 || c==12 || c==13)page=RN_TAIL;
 if(page && call6(10,page,4096,1,0,0,0))return -1;
 if((c==12 || c==13 || c==15) && call6(10,RN_BODY,4096,1,0,0,0))return -1;
 return 0;
}
