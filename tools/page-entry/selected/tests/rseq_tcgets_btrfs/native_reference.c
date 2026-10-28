/* Two genuine native NX deliveries around the one original syscall. */
#define _GNU_SOURCE
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/ucontext.h>
#include "record.h"
#define RSEC __attribute__((section(".text.reference")))
static struct rtc_native_record rtc_native_record;
static unsigned char rtc_altstack[131072] __attribute__((aligned(64)));
static unsigned rtc_seen,rtc_finished;
extern const uint64_t rn_case,rn_vdso,rn_startup;
extern unsigned char rn_fault[],rn_tail[];
static inline long call6(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static RSEC __attribute__((noreturn)) void die(long status) {
 call6(231,status,0,0,0,0,0);__builtin_unreachable();
}
static RSEC void copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static RSEC uint32_t u32(const unsigned char *b) {
 return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
static RSEC size_t private_size(void) {
 if(rn_case!=4)return 0;
 uintptr_t p=rn_vdso;
 if(!p || (p&4095))die(98);
 const Elf64_Ehdr *h=(const void *)p;
 if(u32(h->e_ident)!=UINT32_C(0x464c457f) || h->e_ident[4]!=2 || h->e_ident[5]!=1 ||
    h->e_type!=ET_DYN || h->e_machine!=EM_X86_64 || h->e_phentsize!=sizeof(Elf64_Phdr) ||
    !h->e_phnum || h->e_phnum>16 || h->e_phoff>4096 || h->e_phnum*sizeof(Elf64_Phdr)>4096-h->e_phoff)die(98);
 const Elf64_Phdr *ph=(const void *)(p+h->e_phoff);size_t n=0;
 for(unsigned i=0;i<h->e_phnum;i++)if(ph[i].p_type==PT_LOAD) {
  if(n || ph[i].p_vaddr || ph[i].p_offset || ph[i].p_flags!=(PF_R|PF_X) ||
     !ph[i].p_memsz || ph[i].p_memsz>RTC_PRIVATE_BYTES || ph[i].p_filesz!=ph[i].p_memsz)die(98);
  n=(ph[i].p_memsz+4095)&~(size_t)4095;
 }
 if(!n)die(98);
 return n;
}
static RSEC void capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)rtc_altstack;
 if(sizeof *u>RN_UC || p<lo || p-lo>sizeof rtc_altstack-512 || (p&15))die(98);
 const unsigned char *b=(const void *)p;size_t n=512;
 if(u32(b+464)==UINT32_C(0x46505853)) {
  n=u32(b+468);size_t x=u32(b+480);
  if(n<580 || n>RN_FP || n>sizeof rtc_altstack-(p-lo) || x<576 || x>n-4 || u32(b+n-4)!=UINT32_C(0x46505845))die(98);
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
RSEC void rtc_native_finish(void) {
 unsigned expected=rn_case==15?1:2;
 if(rtc_finished || rtc_seen!=expected)die(98);
 rtc_finished=1;rtc_native_record.h[4]=rtc_seen;rtc_native_record.h[5]=1;
 size_t at=0;
 while(at<sizeof rtc_native_record) {
  long n=call6(1,3,(long)((unsigned char *)&rtc_native_record+at),sizeof rtc_native_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof rtc_native_record-at)die(98);
  at+=(size_t)n;
 }
}
static RSEC void handler(int sig,siginfo_t *si,void *ptr) {
 ucontext_t *u=ptr;unsigned i=rtc_seen;
 if(i>=2 || sig!=11 || !si || !u || si->si_signo!=11 || si->si_code!=SEGV_ACCERR || si->si_errno ||
    *(const volatile uint64_t *)(uintptr_t)RN_WORD || sizeof *si!=128)die(98);
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP],a=(uintptr_t)si->si_addr;
 uintptr_t wanted=i?(uintptr_t)rn_tail:(uintptr_t)rn_fault;
 if(pc!=wanted || a!=wanted || u->uc_mcontext.gregs[REG_TRAPNO]!=14 || u->uc_mcontext.gregs[REG_ERR]!=21 ||
    (uintptr_t)u->uc_mcontext.gregs[REG_CR2]!=a || ((uint64_t)u->uc_mcontext.gregs[REG_EFL]&0x10100)!=0x10000)die(98);
 struct rtc_native_row *r=&rtc_native_record.rows[i];
 r->h[0]=1;r->h[1]=i;r->h[2]=pc;r->h[3]=a;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 capture(&r->before,sig,si,u);copy(r->siginfo_before,si,sizeof *si);
 size_t n=private_size();r->h[28]=rn_case==4?rn_vdso:0;r->h[29]=n;
 if(n)copy(r->private_before,(const void *)(uintptr_t)rn_vdso,n);
 ++rtc_seen;
 if(rn_case!=15) {
  r->h[8]=i?RN_TAIL:RN_BODY;r->h[9]=4096;r->h[10]=5;
  r->h[11]=(uint64_t)call6(10,r->h[8],4096,5,0,0,0);
  if(r->h[11] || *(const volatile uint64_t *)(uintptr_t)RN_WORD)die(98);
 }
 capture(&r->after,sig,si,u);copy(r->siginfo_after,si,sizeof *si);
 r->h[25]=(uintptr_t)si;r->h[4]=1;
 if(n)copy(r->private_after,(const void *)(uintptr_t)rn_vdso,n);
 if(rn_case==15) {
  rtc_native_record.h[13]=1;rtc_native_finish();die(0);
 }
}
__asm__(".section .text.reference,\"ax\",@progbits\n.global rn_restorer\nrn_restorer:\nmov $15,%eax\nsyscall\nud2\n.previous\n");
extern void rn_restorer(void);
RSEC long rtc_native_setup(unsigned c) {
 if(c!=rn_case || c>19 || sizeof(ucontext_t)>RN_UC || sizeof(siginfo_t)!=128)return -1;
 volatile unsigned char *z=(void *)&rtc_native_record;
 for(size_t i=0;i<sizeof rtc_native_record;i++)z[i]=0;
 for(size_t i=0;i<sizeof rtc_altstack;i++)rtc_altstack[i]=0;
 rtc_native_record.h[0]=RTC_MAGIC;rtc_native_record.h[1]=1;
 rtc_native_record.h[2]=sizeof rtc_native_record;rtc_native_record.h[3]=c;
 rtc_native_record.h[8]=call6(39,0,0,0,0,0,0);rtc_native_record.h[9]=call6(186,0,0,0,0,0);
 uint32_t low,high;__asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
 rtc_native_record.h[10]=(uint64_t)low|((uint64_t)high<<32);
 rtc_native_record.h[11]=(uintptr_t)rtc_altstack;rtc_native_record.h[12]=sizeof rtc_altstack;
 const volatile uint64_t *startup=(const void *)(uintptr_t)rn_startup;
 if(!startup || startup[0]!=2 || startup[3])return -1;
 size_t end=4;while(end<126 && startup[end])++end;
 if(end>=126)return -1;
 ++end;while(end+1<256 && startup[end])end+=2;
 if(end+1>=256 || startup[end] || startup[end+1])return -1;
 end+=2;rtc_native_record.h[22]=rn_startup;rtc_native_record.h[23]=end;
 for(size_t i=0;i<end;i++)rtc_native_record.startup[i]=startup[i];
 if((rtc_native_record.h[10]&0xe7)!=0xe7)return -1;
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,d,ecx=bits[i];__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(ecx),"=d"(d)::"memory");
  rtc_native_record.xstate[i][0]=bits[i];rtc_native_record.xstate[i][1]=b;
  rtc_native_record.xstate[i][2]=a;rtc_native_record.xstate[i][3]=ecx;
 }
 stack_t stack={.ss_sp=rtc_altstack,.ss_flags=0,.ss_size=sizeof rtc_altstack};
 struct {void (*function)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action={handler,0x0c000004UL,rn_restorer,0};
 if(call6(131,(long)&stack,0,0,0,0,0) || call6(13,11,(long)&action,0,8,0,0))return -1;
 uint64_t mask=UINT64_MAX & ~(UINT64_C(1)<<10) & ~(UINT64_C(1)<<4) &
  ~(UINT64_C(1)<<30) & ~(UINT64_C(1)<<8) & ~(UINT64_C(1)<<18);
 if(call6(14,2,(long)&mask,0,8,0,0) || call6(10,RN_BODY,4096,1,0,0,0) || call6(10,RN_TAIL,4096,1,0,0,0))return -1;
 return 0;
}
