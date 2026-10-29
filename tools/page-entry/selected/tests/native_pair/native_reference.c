/* Actual native signal reference. It mirrors the focal permission boundaries
   with real mprotect calls, never fabricates a signal or edits its frame. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/ucontext.h>
#include "record.h"
#define RSEC __attribute__((section(".text.reference")))
static struct npf_native_record npf_native_record;
static unsigned char npf_altstack[131072] __attribute__((aligned(64)));
static unsigned npf_seen,npf_finished,npf_live;
static uintptr_t npf_pages[2];
extern const uint64_t rn_case,npf_control;
extern unsigned char rn_body[],rn_b[],rn_tail[],rn_fault[],rn_abort[];
extern unsigned char rn_return[],rn_data_fault[],npf_close_gate[],rn_after_call[],npf_c[];
_Static_assert(sizeof(struct rn_frame)==117248 && sizeof(struct npf_native_row)==235136 &&
 sizeof(struct npf_native_record)==2822272 && sizeof(struct npf_native_record)<(16U<<20),
 "fixed complete native record extent");
static inline long call6(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static RSEC __attribute__((noreturn)) void die(unsigned status) {
 call6(231,status,0,0,0,0,0);__builtin_unreachable();
}
static RSEC void copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static RSEC int same(const void *a,const void *b,size_t n) {
 const volatile unsigned char *x=a,*y=b;
 for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
 return 1;
}
static RSEC uint32_t u32(const unsigned char *b) {
 return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
static RSEC unsigned expected(void) {
 unsigned c=(unsigned)rn_case;
 return c==0?2:c==4||c==5||c==6||c==19?4:c==7||c==8?5:c==9?7:3;
}
static RSEC void capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)npf_altstack;
 if(sizeof *u>RN_UC || p<lo || p-lo>sizeof npf_altstack-512 || (p&15))die(98);
 const unsigned char *b=(const void *)p;size_t n=512;
 if(u32(b+464)==UINT32_C(0x46505853)) {
  n=u32(b+468);size_t x=u32(b+480);
  if(n<580 || n>RN_FP || n>sizeof npf_altstack-(p-lo) || x<576 || x>n-4 || u32(b+n-4)!=UINT32_C(0x46505845))die(98);
 }
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 copy(s->uc,u,sizeof *u);copy(s->fp,b,n);
 copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);s->h[0]=1;
}
static RSEC void protect(struct npf_native_row *r,uintptr_t page,unsigned prot) {
 unsigned i=(unsigned)r->h[6];
 if(i>=4 || (page&4095) || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die(98);
 uint64_t *p=r->permissions[i];p[0]=page;p[1]=4096;p[2]=prot;
 p[3]=(uint64_t)call6(10,(long)page,4096,prot,0,0,0);++r->h[6];
 if(p[3] || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die(98);
}
static RSEC void close_pages(struct npf_native_row *r) {
 if(npf_live>2)die(98);
 for(unsigned i=0;i<npf_live;i++)protect(r,npf_pages[i],1);
 npf_live=0;npf_pages[0]=npf_pages[1]=0;
}
static RSEC void open_page(struct npf_native_row *r,uintptr_t pc) {
 uintptr_t page=pc&~UINT64_C(4095);
 if(npf_live==2 || (npf_live && npf_pages[0]==page))die(98);
 protect(r,page,5);npf_pages[npf_live++]=page;
}
RSEC void npf_native_finish(void) {
 if(npf_finished || npf_seen!=expected() || npf_live)die(98);
 npf_finished=1;npf_native_record.h[4]=npf_seen;npf_native_record.h[5]=1;
 size_t at=0;
 while(at<sizeof npf_native_record) {
  long n=call6(1,3,(long)((unsigned char *)&npf_native_record+at),sizeof npf_native_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof npf_native_record-at)die(98);
  at+=(size_t)n;
 }
}
static RSEC void handler(int sig,siginfo_t *si,void *ptr) {
 ucontext_t *u=ptr;unsigned c=(unsigned)rn_case,i=npf_seen;
 if(i>=expected() || i>=NPF_ROWS || sig!=11 || !si || !u || si->si_signo!=11 ||
    si->si_code!=SEGV_ACCERR || si->si_errno || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die(98);
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP],a=(uintptr_t)si->si_addr;
 uintptr_t want_pc,want_a;unsigned kind=0;
 if(i==0)want_pc=want_a=(uintptr_t)rn_body;
 else if(c==0)want_pc=want_a=(uintptr_t)npf_close_gate;
 else if(i==1)want_pc=want_a=(uintptr_t)rn_b;
 else if((c==7||c==8||c==9) && (i==2||i==3)) {
  want_pc=(uintptr_t)(c==7?rn_abort:rn_fault);want_a=i==2?RN_TAIL:want_pc;kind=i==2?1:2;
 } else if(c==9 && i==4)want_pc=want_a=(uintptr_t)rn_b;
 else if(c==9 && i==5)want_pc=want_a=(uintptr_t)rn_return;
 else if((c==4||c==5||c==6) && i==2)want_pc=want_a=(uintptr_t)npf_c;
 else if(c==10 && i==2){want_pc=(uintptr_t)rn_data_fault;want_a=RN_ARENA;kind=3;}
 else if(c==19 && i==2)want_pc=want_a=(uintptr_t)rn_after_call;
 else want_pc=want_a=(uintptr_t)npf_close_gate;
 if(pc!=want_pc || a!=want_a || u->uc_mcontext.gregs[REG_TRAPNO]!=14 ||
    u->uc_mcontext.gregs[REG_ERR]!=(kind==3?4:21) || (uintptr_t)u->uc_mcontext.gregs[REG_CR2]!=a ||
    ((uint64_t)u->uc_mcontext.gregs[REG_EFL]&0x10100)!=0x10000)die(98);
 struct npf_native_row *r=&npf_native_record.rows[i];
 r->h[0]=1;r->h[1]=i;r->h[2]=pc;r->h[3]=a;r->h[5]=kind;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 if(sizeof *si!=128)die(98);
 copy(r->signal_before,si,sizeof *si);capture(&r->before,sig,si,u);++npf_seen;
 if(i==0){protect(r,RN_MAIN,1);open_page(r,pc);}
 else if(kind==1)close_pages(r);
 else if(kind==2){open_page(r,RN_BODY);open_page(r,RN_TAIL);}
 else if(kind==3)close_pages(r);
 else if(pc==(uintptr_t)npf_close_gate){close_pages(r);protect(r,RN_MAIN,5);}
 else if((c==19 && i==1) || npf_live==2 || (c==19 && i==2) || (c==9 && i==5)) {
  close_pages(r);open_page(r,pc);
 } else open_page(r,pc);
 copy(r->signal_after,si,sizeof *si);capture(&r->after,sig,si,u);r->h[25]=(uintptr_t)si;
 if(!same(&r->before,&r->after,sizeof r->before) ||
    !same(r->signal_before,r->signal_after,sizeof r->signal_before))die(98);
 r->h[4]=1;
 if(kind==3){npf_native_record.h[7]=125;npf_native_finish();die(125);}
}
__asm__(".section .text.reference,\"ax\",@progbits\n.global rn_restorer\nrn_restorer:\nmov $15,%eax\nsyscall\nud2\n.previous\n");
extern void rn_restorer(void);
RSEC long npf_native_setup(unsigned c) {
 if(c!=rn_case || c>20 || npf_control>1 || (c!=16 && npf_control) || sizeof(ucontext_t)>RN_UC)return -1;
 volatile unsigned char *z=(void *)&npf_native_record;
 for(size_t i=0;i<sizeof npf_native_record;i++)z[i]=0;
 for(size_t i=0;i<sizeof npf_altstack;i++)npf_altstack[i]=0;
 npf_native_record.h[0]=RN_MAGIC;npf_native_record.h[1]=1;
 npf_native_record.h[2]=sizeof npf_native_record;npf_native_record.h[3]=c;
 npf_native_record.h[8]=call6(39,0,0,0,0,0,0);npf_native_record.h[9]=call6(186,0,0,0,0,0,0);
 uint32_t low,high;__asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
 npf_native_record.h[10]=(uint64_t)low|((uint64_t)high<<32);
 npf_native_record.h[11]=(uintptr_t)npf_altstack;npf_native_record.h[12]=sizeof npf_altstack;
 npf_native_record.h[21]=npf_control;
 { uint32_t a=0,b,cx=0,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
   npf_native_record.h[32]=a;npf_native_record.h[33]=b;
   npf_native_record.h[34]=cx;npf_native_record.h[35]=d; }
 if((npf_native_record.h[10]&0xe7)!=0xe7)return -1;
 /* Independent standard PKRU layout/value before seeding or admission. */
 { uint32_t a=7,b,cx=0,d;
   __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
   npf_native_record.h[43]=a;npf_native_record.h[44]=b;
   npf_native_record.h[45]=cx;npf_native_record.h[46]=d;
   if(npf_native_record.h[10]&(UINT64_C(1)<<9)) {
    if(npf_native_record.h[32]<13 || (cx&UINT32_C(0x18))!=UINT32_C(0x18))return -1;
    a=13;cx=9;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
    npf_native_record.h[36]=a;npf_native_record.h[37]=b;
    npf_native_record.h[38]=cx;npf_native_record.h[39]=d;
    if(a!=8 || b<576 || b>RN_FP-8 || (cx&1) || d)return -1;
    __asm__ volatile("rdpkru":"=a"(a),"=d"(d):"c"(0):"memory");
    npf_native_record.h[40]=a;npf_native_record.h[41]=d;npf_native_record.h[42]=1;
    if(d)return -1;
   }
 }
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,d,ecx=bits[i];__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(ecx),"=d"(d)::"memory");
  npf_native_record.xstate[i][0]=bits[i];npf_native_record.xstate[i][1]=b;
  npf_native_record.xstate[i][2]=a;npf_native_record.xstate[i][3]=ecx;
 }
 stack_t stack={.ss_sp=npf_altstack,.ss_flags=0,.ss_size=sizeof npf_altstack};
 struct {void (*function)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action={handler,0x0c000004UL,rn_restorer,0};
 if(call6(131,(long)&stack,0,0,0,0,0) || call6(13,11,(long)&action,0,8,0,0))return -1;
 uint64_t mask=UINT64_MAX & ~(UINT64_C(1)<<10) & ~(UINT64_C(1)<<4) &
  ~(UINT64_C(1)<<3) & ~(UINT64_C(1)<<30) & ~(UINT64_C(1)<<8) & ~(UINT64_C(1)<<18);
 if(call6(14,2,(long)&mask,0,8,0,0) || call6(10,RN_BODY,4096,1,0,0,0) ||
    call6(10,RN_TAIL,4096,1,0,0,0) || call6(10,RN_GUARD,4096,1,0,0,0))return -1;
 return 0;
}
