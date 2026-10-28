/* Pure storage only after the real first-statement preentry proof. */
#include "rseq_boundary_record.h"
struct rnb_row {
 uint64_t h[32],permits[4][12];
 struct rn_frame before,after,guard_before,guard_after;
 struct li2_rseq_native_state native_before,native_after;
 struct li2_rseq_native_boundary_state boundary_before,boundary_after;
 struct li2_rseq_state guard_state;
 struct li2_native_close close;
};
struct rnb_record {
 uint64_t h[64],xstate[4][4];
 struct li2_selected_hardware hardware;
 struct rnb_row rows[RNB_ROWS];
 struct li2_rseq_native_state terminal_native;
 struct li2_rseq_native_boundary_state terminal_boundary;
 struct li2_rseq_state terminal_rseq;
 unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];
};
_Static_assert(sizeof(ucontext_t)<=RN_UC && sizeof(struct rnb_record)<(16U<<20),"bounded complete boundary record");
static struct rnb_record rnb_record;
static unsigned rnb_used,rnb_finished,rnb_current=RNB_ROWS;
static const ucontext_t *rnb_frame_pointer;
static siginfo_t rnb_signal;
static void rnb_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t rnb_u32(const unsigned char *s) {
 return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static int rnb_capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(!si || !u)return 0;
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
 size_t cap=fork_gate_stack.ss_size,n=512;
 if(p<lo || cap<512 || p-lo>cap-512 || (p&15))return 0;
 const unsigned char *b=(const void *)p;
 if(rnb_u32(b+464)==UINT32_C(0x46505853)) {
  n=rnb_u32(b+468);size_t x=rnb_u32(b+480);
  if(n<580 || n>RN_FP || n>cap-(p-lo) || x<576 || x>n-4 || rnb_u32(b+n-4)!=UINT32_C(0x46505845))return 0;
 }
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 rnb_copy(s->uc,u,sizeof *u);rnb_copy(s->fp,b,n);
 rnb_copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 rnb_copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 rnb_copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);
 s->h[0]=1;return 1;
}
static void rnb_initialize(void) {
 volatile unsigned char *z=(void *)&rnb_record;
 for(size_t i=0;i<sizeof rnb_record;i++)z[i]=0;
 checked(original_main.entry==RN_MAIN && !original_main.bias,1697,0);
 uint64_t c=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+8);
 checked(c<4 && *(const volatile uint64_t *)(uintptr_t)RN_DATA==RN_MAGIC,1697,1);
 rnb_record.h[0]=RNB_MAGIC;rnb_record.h[1]=1;rnb_record.h[2]=sizeof rnb_record;
 rnb_record.h[3]=c;rnb_record.h[4]=sizeof(ucontext_t);rnb_record.h[5]=sizeof(struct rnb_row);
 rnb_copy(&rnb_record.hardware,&selected_hardware,sizeof selected_hardware);
 checked(selected_hardware.leaf0[0]>=13 &&
  (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
  (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1697,2);
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");
 rnb_record.h[6]=(uint64_t)lo|((uint64_t)hi<<32);
 checked((rnb_record.h[6]&0xe7)==0xe7,1697,3);
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,cx=bits[i],d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
  rnb_record.xstate[i][0]=bits[i];rnb_record.xstate[i][1]=b;
  rnb_record.xstate[i][2]=a;rnb_record.xstate[i][3]=cx;
 }
 rnb_record.h[15]=(uintptr_t)fork_gate_stack.ss_sp;rnb_record.h[16]=fork_gate_stack.ss_size;
 rnb_record.h[7]=1;
}
static void rnb_permits(uint64_t p[12]) {
 p[0]=selected_step_pending;p[1]=selected_pending_route;
 p[2]=li2_lifecycle_fetch_interlock();p[3]=selected_tf_attempts;p[4]=selected_tf_steps;
 p[5]=selected_step.phase;p[6]=selected_step.open_started[0];p[7]=selected_step.open_started[1];
 p[8]=selected_step.opened[0];p[9]=selected_step.opened[1];
 p[10]=li2_lifecycle_native_counts()->admissions;p[11]=li2_lifecycle_native_counts()->closed;
}
static void rnb_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 rnb_current=RNB_ROWS;rnb_frame_pointer=0;
 if(!rnb_record.h[7] || rnb_finished || sig!=SIGSEGV || !si || !u ||
    *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1)return;
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP],a=(uintptr_t)si->si_addr;
 unsigned c=(unsigned)rnb_record.h[3];
 uintptr_t first=c==3?RN_TAIL-14:RN_TAIL-2,ret=RN_TAIL+(c==1?3:0);
 if(pc!=first && pc!=RN_GUARD && pc!=ret && a!=RN_TAIL)return;
 if(rnb_used==RNB_ROWS){rnb_record.h[8]=1;return;}
 rnb_current=rnb_used++;struct rnb_row *r=&rnb_record.rows[rnb_current];
 r->h[0]=1;r->h[1]=rnb_current;r->h[2]=pc;r->h[3]=a;
 rnb_frame_pointer=u;rnb_copy(&rnb_signal,si,sizeof rnb_signal);
 rnb_copy(&r->native_before,li2_rseq_native_snapshot(),sizeof r->native_before);
 rnb_copy(&r->boundary_before,li2_rseq_native_boundary_snapshot(),sizeof r->boundary_before);
 rnb_permits(r->permits[0]);
 if(!rnb_capture(&r->before,sig,si,u))rnb_record.h[8]=2;
}
static void rnb_epoch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 (void)sig;(void)si;
 if(rnb_current==RNB_ROWS || rnb_frame_pointer!=u)return;
 struct rnb_row *r=&rnb_record.rows[rnb_current];
 if(r->h[6]){rnb_record.h[8]=3;return;}
 r->h[6]=1;r->h[7]=(unsigned)result;
}
static void rnb_fetch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(rnb_current==RNB_ROWS || rnb_frame_pointer!=u)return;
 struct rnb_row *r=&rnb_record.rows[rnb_current];
 if(r->h[4]){rnb_record.h[8]=4;return;}
 r->h[4]=1;r->h[5]=(unsigned)result;
 rnb_copy(&r->native_after,li2_rseq_native_snapshot(),sizeof r->native_after);
 rnb_copy(&r->boundary_after,li2_rseq_native_boundary_snapshot(),sizeof r->boundary_after);
 rnb_copy(&r->close,li2_lifecycle_native_close_progress(),sizeof r->close);
 rnb_permits(r->permits[1]);
 if(!rnb_capture(&r->after,sig,si,u))rnb_record.h[8]=5;
}
int rnb_real_instruction(const struct li2_decoded *,const ucontext_t *);
int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *u) {
 unsigned c=(unsigned)rnb_record.h[3];
 uintptr_t pc=c==3?RN_TAIL-14:RN_TAIL-2;
 int observe=rnb_record.h[7] && c!=2 && d && d->pc==pc;
 struct rnb_row *r=rnb_current<RNB_ROWS?&rnb_record.rows[rnb_current]:0;
 if(observe) {
  checked(r && rnb_current==1 && rnb_frame_pointer==u && r->h[4] &&
          r->h[5]==0 && r->h[6]==1 && r->h[7]==LI2_NATIVE_READY && !r->h[8],1697,4);
  checked(rnb_capture(&r->guard_before,(int)r->before.h[4],&rnb_signal,u),1697,5);
  rnb_permits(r->permits[2]);r->h[8]=1;
 }
 int result=rnb_real_instruction(d,u);
 if(observe) {
  checked(rnb_capture(&r->guard_after,(int)r->before.h[4],&rnb_signal,u),1697,6);
  rnb_permits(r->permits[3]);rnb_copy(&r->guard_state,li2_rseq_snapshot(),sizeof r->guard_state);
  r->h[9]=1;r->h[10]=(unsigned)result;
 }
 return result;
}
static void rnb_terminal(unsigned status,unsigned code,long detail) {
 if(rnb_finished || !rnb_record.h[7])return;
 rnb_finished=1;rnb_record.h[9]=1;rnb_record.h[10]=status;rnb_record.h[11]=code;
 rnb_record.h[12]=(uint64_t)detail;rnb_record.h[13]=rnb_used;
 rnb_record.h[17]=li2_lifecycle_native_counts()->admissions;
 rnb_record.h[18]=li2_lifecycle_native_counts()->closed;
 rnb_copy(&rnb_record.terminal_native,li2_rseq_native_snapshot(),sizeof rnb_record.terminal_native);
 rnb_copy(&rnb_record.terminal_boundary,li2_rseq_native_boundary_snapshot(),sizeof rnb_record.terminal_boundary);
 rnb_copy(&rnb_record.terminal_rseq,li2_rseq_snapshot(),sizeof rnb_record.terminal_rseq);
 rnb_copy(rnb_record.terminal_source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 rnb_copy(rnb_record.terminal_data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 if(li2_rseq_snapshot()->registered) {
  rnb_copy(rnb_record.terminal_page,(const void *)(uintptr_t)RN_PAGE,4096);rnb_record.h[14]=1;
 }
 size_t at=0;
 while(at<sizeof rnb_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&rnb_record+at),sizeof rnb_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof rnb_record-at)return;
  at+=(size_t)n;
 }
}
