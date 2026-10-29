/* Genuine native signal reference for one two-episode stack-growth program. No frame
   is manufactured or edited. All application pages are closed/opened through
   actual mprotect calls while the real registered word is observed zero. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/ucontext.h>
#include "record.h"
#define RSEC __attribute__((section(".text.reference")))
static struct pcs_native_record lso_native_record;
static unsigned char lso_altstack[131072] __attribute__((aligned(64)));
static unsigned lso_seen,lso_finished;
extern const uint64_t rn_case;
extern unsigned char rn_program[],pcs_again[],pcs_guard_again[];
static inline long call6(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static RSEC __attribute__((noreturn)) void die(void) {
 call6(231,98,0,0,0,0,0);__builtin_unreachable();
}
static RSEC void copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static RSEC uint32_t u32(const unsigned char *b) {
 return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
static RSEC unsigned expected(void) {return 4;}
static RSEC void capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)lso_altstack;
 if(sizeof *u>RN_UC || p<lo || p-lo>sizeof lso_altstack-512 || (p&15))die();
 const unsigned char *b=(const void *)p;size_t n=512;
 if(u32(b+464)==UINT32_C(0x46505853)) {
  n=u32(b+468);size_t x=u32(b+480);
  if(n<580 || n>RN_FP || n>sizeof lso_altstack-(p-lo) || x<576 || x>n-4 || u32(b+n-4)!=UINT32_C(0x46505845))die();
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
static RSEC void protect(struct pcs_native_row *r,unsigned slot,uintptr_t page,unsigned prot) {
 if(slot>2 || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die();
 uint64_t *h=r->h+8+slot*4;h[0]=page;h[1]=4096;h[2]=prot;
 h[3]=(uint64_t)call6(10,(long)page,4096,prot,0,0,0);
 if(h[3] || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die();
}
RSEC void lso_native_finish(void) {
 if(lso_finished || lso_seen!=expected())die();
 lso_finished=1;lso_native_record.h[4]=lso_seen;lso_native_record.h[5]=1;
 size_t at=0;
 while(at<sizeof lso_native_record) {
  long n=call6(1,3,(long)((unsigned char *)&lso_native_record+at),sizeof lso_native_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof lso_native_record-at)die();
  at+=(size_t)n;
 }
}
static RSEC void handler(int sig,siginfo_t *si,void *ptr) {
 ucontext_t *u=ptr;unsigned i=lso_seen;
 if(i>=expected() || i>=4 || sig!=11 || !si || !u || si->si_signo!=11 ||
    si->si_code!=SEGV_ACCERR || si->si_errno || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die();
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP],a=(uintptr_t)si->si_addr;
 const uintptr_t pcs[4]={(uintptr_t)rn_program,RN_GUARD,(uintptr_t)pcs_again,(uintptr_t)pcs_guard_again};
 uintptr_t want_pc=pcs[i],want_a=want_pc;
 if(pc!=want_pc || a!=want_a || u->uc_mcontext.gregs[REG_TRAPNO]!=14 ||
    u->uc_mcontext.gregs[REG_ERR]!=21 || (uintptr_t)u->uc_mcontext.gregs[REG_CR2]!=a ||
    ((uint64_t)u->uc_mcontext.gregs[REG_EFL]&0x10100)!=0x10000)die();
 struct pcs_native_row *r=&lso_native_record.rows[i];
 r->h[0]=1;r->h[1]=i;r->h[2]=pc;r->h[3]=a;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 capture(&r->before,sig,si,u);++lso_seen;
 if(!(i&1)) {protect(r,0,RN_GUARD,1);protect(r,1,RN_BODY,5);}
 else {protect(r,0,RN_BODY,1);protect(r,1,RN_GUARD,5);}
 capture(&r->after,sig,si,u);r->h[25]=(uintptr_t)si;r->h[4]=1;
}
__asm__(".section .text.reference,\"ax\",@progbits\n.global rn_restorer\nrn_restorer:\nmov $15,%eax\nsyscall\nud2\n.previous\n");
extern void rn_restorer(void);
RSEC long lso_native_setup(unsigned c) {
 if(c!=rn_case || c!=0 || sizeof(ucontext_t)>RN_UC)return -1;
 volatile unsigned char *z=(void *)&lso_native_record;
 for(size_t i=0;i<sizeof lso_native_record;i++)z[i]=0;
 for(size_t i=0;i<sizeof lso_altstack;i++)lso_altstack[i]=0;
 lso_native_record.h[0]=PCS_MAGIC;lso_native_record.h[1]=1;
 lso_native_record.h[2]=sizeof lso_native_record;lso_native_record.h[3]=c;
 lso_native_record.h[8]=call6(39,0,0,0,0,0,0);lso_native_record.h[9]=call6(186,0,0,0,0,0,0);
 uint32_t low,high;__asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
 lso_native_record.h[10]=(uint64_t)low|((uint64_t)high<<32);
 lso_native_record.h[11]=(uintptr_t)lso_altstack;lso_native_record.h[12]=sizeof lso_altstack;
 if((lso_native_record.h[10]&0xe7)!=0xe7)return -1;
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,d,ecx=bits[i];__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(ecx),"=d"(d)::"memory");
  lso_native_record.xstate[i][0]=bits[i];lso_native_record.xstate[i][1]=b;
  lso_native_record.xstate[i][2]=a;lso_native_record.xstate[i][3]=ecx;
 }
 stack_t stack={.ss_sp=lso_altstack,.ss_flags=0,.ss_size=sizeof lso_altstack};
 struct {void (*function)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action={handler,0x0c000004UL,rn_restorer,0};
 if(call6(131,(long)&stack,0,0,0,0,0) || call6(13,11,(long)&action,0,8,0,0))return -1;
 uint64_t mask=UINT64_MAX & ~(UINT64_C(1)<<10) & ~(UINT64_C(1)<<4) &
  ~(UINT64_C(1)<<30) & ~(UINT64_C(1)<<8) & ~(UINT64_C(1)<<18);
 if(call6(14,2,(long)&mask,0,8,0,0) || call6(10,RN_BODY,4096,1,0,0,0) ||
    call6(10,RN_GUARD,4096,1,0,0,0))return -1;
 return 0;
}
