/* Read-only real-frame observation. First-entry storage runs only AFTER the
   product's first-statement pure preentry proof, before any old ingress gate. */
#include "rseq_native_record.h"
struct rn_row {
 uint64_t h[32],permits[2][12];
 struct rn_frame before,after,guard_before,guard_after;
 struct li2_rseq_native_state native_before,native_after;
 struct li2_rseq_state guard_state;
 struct li2_native_close close;
};
struct rn_record {
 uint64_t h[64],xstate[4][4];
 struct li2_selected_hardware hardware;
 struct rn_row rows[RN_MAX_ROWS];
 struct rn_frame publication_frame;
 struct li2_rseq_native_state terminal_native;
 struct li2_rseq_state terminal_rseq;
 unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];
};
_Static_assert(sizeof(ucontext_t)<=RN_UC && sizeof(struct rn_record)<(16U<<20),"bounded whole genuine-frame record");
static struct rn_record rn_record;
static unsigned rn_used,rn_finished,rn_current=RN_MAX_ROWS;
static const ucontext_t *rn_frame_pointer;
static siginfo_t rn_signal;
static void rn_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t rn_u32(const unsigned char *s) {
 return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static int rn_capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(!si || !u)return 0;
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
 size_t cap=fork_gate_stack.ss_size,n=512;
 if(p<lo || cap<512 || p-lo>cap-512 || (p&15))return 0;
 const unsigned char *b=(const void *)p;
 if(rn_u32(b+464)==UINT32_C(0x46505853)) {
  n=rn_u32(b+468);size_t x=rn_u32(b+480);
  if(n<580 || n>RN_FP || n>cap-(p-lo) || x<576 || x>n-4 || rn_u32(b+n-4)!=UINT32_C(0x46505845))return 0;
 }
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 rn_copy(s->uc,u,sizeof *u);rn_copy(s->fp,b,n);
 rn_copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 rn_copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 rn_copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);
 s->h[0]=1;return 1;
}
static void rn_initialize(void) {
 volatile unsigned char *z=(void *)&rn_record;
 for(size_t i=0;i<sizeof rn_record;i++)z[i]=0;
 checked(original_main.entry==RN_MAIN && !original_main.bias,1696,0);
 uint64_t c=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+8);
 checked(c<16 && *(const volatile uint64_t *)(uintptr_t)RN_DATA==RN_MAGIC,1696,1);
 rn_record.h[0]=RN_MAGIC;rn_record.h[1]=2;rn_record.h[2]=sizeof rn_record;
 rn_record.h[3]=c;rn_record.h[4]=sizeof(ucontext_t);rn_record.h[5]=sizeof(struct rn_row);
 rn_copy(&rn_record.hardware,&selected_hardware,sizeof selected_hardware);
 checked(selected_hardware.leaf0[0]>=13 &&
  (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
  (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1696,2);
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");
 rn_record.h[6]=(uint64_t)lo|((uint64_t)hi<<32);
 checked((rn_record.h[6]&0xe7)==0xe7,1696,3);
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,cx=bits[i],d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
  rn_record.xstate[i][0]=bits[i];rn_record.xstate[i][1]=b;
  rn_record.xstate[i][2]=a;rn_record.xstate[i][3]=cx;
 }
 rn_record.h[15]=(uintptr_t)fork_gate_stack.ss_sp;rn_record.h[16]=fork_gate_stack.ss_size;
 rn_record.h[7]=1;
}
static void rn_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 /* No raw calls, checked/fail, or manufactured event. An unsafe preentry
    cannot reach this function. An unexpected observation is retained failed. */
 rn_current=RN_MAX_ROWS;rn_frame_pointer=0;
 if(!rn_record.h[7] || rn_finished || sig!=SIGSEGV || !si || !u ||
    *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1 ||
    li2_rseq_native_snapshot()->phase!=LI2_RN_EXECUTING)return;
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP],a=(uintptr_t)si->si_addr;
 if(pc!=RN_BODY && pc!=RN_GUARD && a!=RN_TAIL && a!=RN_ARENA)return;
 if(rn_used==RN_MAX_ROWS){rn_record.h[8]=1;return;}
 rn_current=rn_used++;struct rn_row *r=&rn_record.rows[rn_current];
 r->h[0]=1;r->h[1]=rn_current;r->h[2]=pc;r->h[3]=a;
 rn_frame_pointer=u;
 rn_copy(&rn_signal,si,sizeof rn_signal);
 rn_copy(&r->native_before,li2_rseq_native_snapshot(),sizeof r->native_before);
 if(!rn_capture(&r->before,sig,si,u))rn_record.h[8]=2;
}
static void rn_epoch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(rn_current==RN_MAX_ROWS || rn_frame_pointer!=u)return;
 struct rn_row *r=&rn_record.rows[rn_current];
 if(r->h[4]){rn_record.h[8]=3;return;}
 r->h[4]=1;r->h[5]=(unsigned)result;
 rn_copy(&r->native_after,li2_rseq_native_snapshot(),sizeof r->native_after);
 rn_copy(&r->close,li2_lifecycle_native_close_progress(),sizeof r->close);
 if(!rn_capture(&r->after,sig,si,u))rn_record.h[8]=4;
}
static void rn_permits(uint64_t p[12]) {
 p[0]=selected_step_pending;p[1]=selected_pending_route;
 p[2]=li2_lifecycle_fetch_interlock();p[3]=selected_tf_attempts;p[4]=selected_tf_steps;
 p[5]=selected_step.phase;p[6]=selected_step.open_started[0];p[7]=selected_step.open_started[1];
 p[8]=selected_step.opened[0];p[9]=selected_step.opened[1];
 p[10]=li2_lifecycle_native_counts()->admissions;p[11]=li2_lifecycle_native_counts()->closed;
}
int rn_real_instruction(const struct li2_decoded *,const ucontext_t *);
int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *u) {
 int observe=rn_record.h[7] && rn_record.h[3]>=8 && rn_record.h[3]<=11 && d && d->pc==RN_GUARD;
 struct rn_row *r=rn_current<RN_MAX_ROWS?&rn_record.rows[rn_current]:0;
 if(observe) {
  checked(r && rn_frame_pointer==u && r->h[4] && !r->h[6],1696,4);
  checked(rn_capture(&r->guard_before,(int)r->before.h[4],&rn_signal,u),1696,5);
  rn_permits(r->permits[0]);r->h[6]=1;
 }
 int result=rn_real_instruction(d,u);
 if(observe) {
  checked(rn_capture(&r->guard_after,(int)r->before.h[4],&rn_signal,u),1696,6);
  rn_permits(r->permits[1]);rn_copy(&r->guard_state,li2_rseq_snapshot(),sizeof r->guard_state);
  r->h[7]=(unsigned)result;r->h[8]=1;
 }
 return result;
}
static void rn_store(unsigned terminal,unsigned status,unsigned code,long detail) {
 if(rn_finished || !rn_record.h[7])return;
 rn_finished=1;rn_record.h[9]=terminal;rn_record.h[10]=status;rn_record.h[11]=code;
 rn_record.h[12]=(uint64_t)detail;rn_record.h[13]=rn_used;
 rn_record.h[17]=li2_lifecycle_native_counts()->admissions;
 rn_record.h[18]=li2_lifecycle_native_counts()->closed;
 rn_copy(&rn_record.terminal_native,li2_rseq_native_snapshot(),sizeof rn_record.terminal_native);
 rn_copy(&rn_record.terminal_rseq,li2_rseq_snapshot(),sizeof rn_record.terminal_rseq);
 rn_copy(rn_record.terminal_source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 rn_copy(rn_record.terminal_data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 if(li2_rseq_snapshot()->registered) {
  rn_copy(rn_record.terminal_page,(const void *)(uintptr_t)RN_PAGE,4096);rn_record.h[14]=1;
 }
 size_t at=0;
 while(at<sizeof rn_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&rn_record+at),sizeof rn_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof rn_record-at)return;
  at+=(size_t)n;
 }
}
static void rn_terminal(unsigned status,unsigned code,long detail) {rn_store(1,status,code,detail);}
static void rn_admitted(uintptr_t pc,int sig,const siginfo_t *si,const ucontext_t *u) {
 unsigned c=(unsigned)rn_record.h[3];
 if(pc!=RN_BODY || (c!=12 && c!=13 && c!=15) || !rn_record.h[7])return;
 const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
 checked(rn_used==1 && rn_current==0 && rn_frame_pointer==u && !rn_record.h[19] &&
  n->phase==LI2_RN_EXECUTING && n->pc==RN_BODY && !n->first_error && !n->entry_checked &&
  n->admissions==n->closed+1 && !*(const volatile uint64_t *)(uintptr_t)RN_WORD,1696,7);
 checked(rn_capture(&rn_record.publication_frame,sig,si,u),1696,8);
 /* Safe, zero-word pre-effect evidence. No terminal syscall/report is added
    after publication of rseq_cs or after the intentionally fatal operation. */
 rn_record.h[19]=1;rn_store(0,0,0,0);
}
