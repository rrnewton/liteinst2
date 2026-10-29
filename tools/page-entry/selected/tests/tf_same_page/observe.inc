#include "tf_lease_record.h"
#include "tf_lease_types.h"
struct lso_event {
 uint64_t h[32],counts_before[16],counts_after[16];
 struct rn_frame before,after;
 struct li2_tf_owner owner_before,owner_after;
 struct li2_chain_fetch fetch_before,fetch_after,next_fetch;
 struct li2_chain_fetch next_first_fetch;
 struct li2_decoded next_first_decoded;
 struct li2_chain_release next_first_release;
 struct li2_chain_release release;
 struct li2_tf_continuation query;
 struct li2_step_frame next_before;
 struct li2_tf_same_page lease;
 struct li2_rseq_state rseq_before,rseq;
};
struct lso_record {
 uint64_t h[64],xstate[4][4];struct li2_selected_hardware hardware;
 struct lso_native_row endpoints[2];struct lso_event events[LSO_ROWS];
 uint64_t cpuid_h[20];struct rn_frame cpuid_before,cpuid_after;
 struct li2_tf_chain terminal_chain;struct li2_rseq_state terminal_rseq;
 struct li2_fetch_rx_view fault_view;
 struct li2_fetch_map_progress terminal_maps;
 struct rn_frame nested;
 unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];
};
_Static_assert(sizeof(ucontext_t)<=RN_UC && sizeof(struct lso_record)<(16U<<20),"bounded complete lease record");
static struct lso_record lso_record;
static unsigned lso_finished,lso_count,lso_endpoint=2,lso_event_current=LSO_ROWS,lso_injected;
static const ucontext_t *lso_endpoint_context,*lso_cpuid_context;
static const siginfo_t *lso_cpuid_signal;
static void lso_terminal(unsigned,unsigned,long);
int lso_page_protection(uintptr_t,struct li2_fetch_map_progress *,unsigned *);
static void lso_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t lso_u32(const unsigned char *s) {
 return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static int lso_capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(!si || !u)return 0;
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
 size_t cap=fork_gate_stack.ss_size,n=512;
 if(p<lo || cap<512 || p-lo>cap-512 || (p&15))return 0;
 const unsigned char *b=(const void *)p;
 if(lso_u32(b+464)==UINT32_C(0x46505853)) {
  n=lso_u32(b+468);size_t x=lso_u32(b+480);
  if(n<580 || n>RN_FP || n>cap-(p-lo) || x<576 || x>n-4 || lso_u32(b+n-4)!=UINT32_C(0x46505845))return 0;
 }
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 lso_copy(s->uc,u,sizeof *u);lso_copy(s->fp,b,n);
 lso_copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 lso_copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 lso_copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);
 s->h[0]=1;return 1;
}
static void lso_initialize(void) {
 volatile unsigned char *z=(void *)&lso_record;
 for(size_t i=0;i<sizeof lso_record;i++)z[i]=0;
 checked(original_main.entry==RN_MAIN && !original_main.bias,1697,0);
 uint64_t c=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+8);
 checked(c<10 && *(const volatile uint64_t *)(uintptr_t)RN_DATA==RN_MAGIC,1697,1);
 lso_record.h[0]=LSO_MAGIC;lso_record.h[1]=2;lso_record.h[2]=sizeof lso_record;
 lso_record.h[3]=c;lso_record.h[4]=sizeof(ucontext_t);lso_record.h[5]=sizeof(struct lso_event);
 lso_copy(&lso_record.hardware,&selected_hardware,sizeof selected_hardware);
 checked(selected_hardware.leaf0[0]>=13 &&
  (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
  (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1697,2);
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");
 lso_record.h[6]=(uint64_t)lo|((uint64_t)hi<<32);
 checked((lso_record.h[6]&0xe7)==0xe7,1697,3);
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,cx=bits[i],d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
  lso_record.xstate[i][0]=bits[i];lso_record.xstate[i][1]=b;
  lso_record.xstate[i][2]=a;lso_record.xstate[i][3]=cx;
 }
 lso_record.h[15]=(uintptr_t)fork_gate_stack.ss_sp;lso_record.h[16]=fork_gate_stack.ss_size;
 lso_record.h[7]=1;
}

static uintptr_t lso_first(unsigned c) {return c==3?RN_TAIL-7:c==4?RN_TAIL-5:RN_BODY+32;}
static int lso_program(uintptr_t pc) {
 unsigned c=(unsigned)lso_record.h[3];
 return c==3||c==4 ? pc>=lso_first(c) && pc<RN_TAIL+16 : pc>=RN_BODY+32 && pc<RN_BODY+128;
}
static void lso_counts(uint64_t v[16]) {
 const struct li2_tf_chain *c=&selected_chain;
 v[0]=c->event_id;v[1]=c->sequence;v[2]=c->attempts;v[3]=c->steps;
 v[4]=c->nx_entries;v[5]=c->trace_entries;v[6]=c->fallbacks;
 v[7]=c->prepare_attempts;v[8]=c->releases;v[9]=c->unexpected_events;
 v[10]=(unsigned)c->active;v[11]=(unsigned)c->pending;v[12]=c->first_error;
 v[13]=selected_step_pending;v[14]=selected_pending_route;v[15]=li2_lifecycle_fetch_interlock();
}
static void lso_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 lso_endpoint=2;lso_endpoint_context=0;
 if(!lso_record.h[7] || lso_finished || !si || !u ||
    *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1)return;
 if(lso_event_current<LSO_ROWS && lso_injected>=3) {
  if(lso_record.h[41]) {lso_record.h[8]=10;return;}
  lso_record.h[41]=1;lso_record.h[42]=(unsigned)sig;
  lso_record.h[47]=(uintptr_t)si;lso_record.h[48]=sizeof *si;lso_record.h[49]=offsetof(siginfo_t,si_pid);
  if(!lso_capture(&lso_record.nested,sig,si,u))lso_record.h[8]=11;
 }
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP];
 if(sig==SIGSEGV && lso_record.h[3]==2 && pc==RN_BODY+36) {
  checked(!lso_record.cpuid_h[0] && lso_capture(&lso_record.cpuid_before,sig,si,u),1698,8);
  lso_record.cpuid_h[0]=1;lso_cpuid_context=u;lso_cpuid_signal=si;
 }
 if(sig!=SIGSEGV || (pc!=lso_first((unsigned)lso_record.h[3]) && pc!=RN_GUARD))return;
 unsigned i=pc==RN_GUARD;struct lso_native_row *r=&lso_record.endpoints[i];
 if(r->h[0]) {lso_record.h[8]=12;return;}
 r->h[0]=1;r->h[1]=i;r->h[2]=pc;r->h[3]=(uintptr_t)si->si_addr;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 if(!lso_capture(&r->before,sig,si,u))lso_record.h[8]=13;
 lso_endpoint=i;lso_endpoint_context=u;
}
static void lso_fetch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(lso_endpoint==2 || lso_endpoint_context!=u)return;
 struct lso_native_row *r=&lso_record.endpoints[lso_endpoint];
 if(r->h[4]) {lso_record.h[8]=14;return;}
 r->h[4]=1;r->h[5]=(unsigned)result;r->h[25]=(uintptr_t)si;
 if(!lso_capture(&r->after,sig,si,u))lso_record.h[8]=15;
}
static void lso_cpuid_after(const ucontext_t *u,unsigned phase,uint64_t attempts,uint64_t samples,uint64_t commits,
                           uintptr_t pc,uintptr_t next,unsigned leaf,unsigned sub,const uint32_t a[4],const uint32_t b[4]) {
 if(!lso_record.h[7] || lso_record.h[3]!=2 || pc!=RN_BODY+36)return;
 checked(lso_record.cpuid_h[0]==1 && !lso_record.cpuid_h[1] && u==lso_cpuid_context && lso_cpuid_signal,1698,9);
 uint64_t *h=lso_record.cpuid_h;h[1]=1;h[2]=phase;h[3]=attempts;h[4]=samples;h[5]=commits;
 h[6]=pc;h[7]=next;h[8]=leaf;h[9]=sub;
 for(unsigned i=0;i<4;i++){h[10+i]=a[i];h[14+i]=b[i];}
 checked(lso_capture(&lso_record.cpuid_after,SIGSEGV,lso_cpuid_signal,u),1698,10);
}
static void lso_after(struct lso_event *r,unsigned slot) {
 const struct li2_tf_chain_slot *s=&selected_chain.slots[slot];
 const struct li2_tf_chain_slot *next=&selected_chain.slots[selected_chain.active];
 lso_copy(&r->owner_after,&s->owner,sizeof r->owner_after);
 lso_copy(&r->fetch_after,&s->fetch,sizeof r->fetch_after);
 lso_copy(&r->release,&s->release,sizeof r->release);
 lso_copy(&r->query,&s->query,sizeof r->query);
 lso_copy(&r->next_fetch,&next->fetch,sizeof r->next_fetch);
 lso_copy(&r->next_first_fetch,&next->first_fetch,sizeof r->next_first_fetch);
 lso_copy(&r->next_first_decoded,&next->first_decoded,sizeof r->next_first_decoded);
 lso_copy(&r->next_first_release,&next->first_release,sizeof r->next_first_release);
 lso_copy(&r->next_before,&next->owner.step.before,sizeof r->next_before);
 r->h[6]=next->index;r->h[7]=next->generation;r->h[8]=(unsigned)next->phase;
 r->h[9]=next->origin;r->h[10]=next->retry;r->h[11]=next->fallback;
 r->h[12]=next->prepare_attempted;r->h[13]=next->prepare_complete;
 r->h[14]=next->decoded.decode_status;r->h[15]=next->decoded.length;r->h[16]=next->decoded.pc;
 lso_copy(&r->rseq,li2_rseq_snapshot(),sizeof r->rseq);lso_counts(r->counts_after);
#ifdef LI2_TF_SAME_PAGE_LEASE
 lso_copy(&r->lease,&selected_chain.lease,sizeof r->lease);
#endif
}
static enum li2_chain_result lso_trace(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *u) {
 if(!lso_record.h[7] || !lso_program(c->slots[c->active].owner.step.request.decoded.pc))
  return li2_tf_chain_trace(c,sig,si,u);
 checked(c==&selected_chain && lso_count<LSO_ROWS && lso_event_current==LSO_ROWS,1698,0);
 unsigned slot=(unsigned)c->active;struct lso_event *r=&lso_record.events[lso_count];
 r->h[0]=1;r->h[1]=lso_count;r->h[2]=slot;r->h[3]=c->slots[slot].generation;
 r->h[17]=c->slots[slot].event_id;
 r->h[18]=c->slots[slot].origin;r->h[19]=(unsigned)c->slots[slot].phase;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 lso_event_current=lso_count++;lso_counts(r->counts_before);
 lso_copy(&r->owner_before,&c->slots[slot].owner,sizeof r->owner_before);
 lso_copy(&r->fetch_before,&c->slots[slot].fetch,sizeof r->fetch_before);
 lso_copy(&r->rseq_before,li2_rseq_snapshot(),sizeof r->rseq_before);
 checked(lso_capture(&r->before,sig,si,u),1698,1);
 enum li2_chain_result result=li2_tf_chain_trace(c,sig,si,u);
 r->h[4]=1;r->h[5]=(unsigned)result;r->h[25]=(uintptr_t)si;
 lso_after(r,slot);checked(lso_capture(&r->after,sig,si,u),1698,2);
 lso_event_current=LSO_ROWS;return result;
}
/* Test-only exported seam: actual staged/fetch-committed state is retained
   before any supplied mutation or real failing operation. */
void lso_fetch_phase(unsigned phase,const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *v) {
 unsigned c=(unsigned)lso_record.h[3],control=c>=6?c-5:0;
 if(!control || lso_injected || lso_event_current==LSO_ROWS ||
    (control==4?phase!=2:phase!=1))return;
 checked(ref && v && lso_event_current==0 && selected_chain.active>=0,1698,3);
 lso_copy(&lso_record.fault_view,v,sizeof *v);
 lso_record.h[32]=control;lso_record.h[33]=phase;lso_record.h[34]=ref->sequence;
 lso_record.h[35]=li2_lifecycle_fetch_interlock();lso_injected=control;
 if(control==1) {
  checked(ref==&selected_chain.slots[selected_chain.active].fetch.ref && ref->sequence<UINT64_MAX,1698,4);
  ++selected_chain.slots[selected_chain.active].fetch.ref.sequence;
  lso_record.h[36]=selected_chain.slots[selected_chain.active].fetch.ref.sequence;
 } else if(control==2) {
  checked(v->backing.retained_fd>3,1698,5);lso_record.h[36]=v->backing.retained_fd;
  lso_record.h[37]=1;lso_record.h[38]=(uint64_t)raw(SYS_close,v->backing.retained_fd,0,0,0,0,0);lso_record.h[39]=1;
  checked(!lso_record.h[38],1698,6);
 } else {
  lso_record.h[37]=1;
  lso_record.h[38]=(uint64_t)raw(SYS_tgkill,selected_chain.session->pid,selected_chain.session->tid,SIGTRAP,0,0,0);
  lso_record.h[39]=1;fail(1698,7); /* a returned nested control is never success */
 }
}
static void lso_terminal(unsigned status,unsigned code,long detail) {
 if(lso_finished || !lso_record.h[7])return;
 lso_finished=1;lso_record.h[9]=1;lso_record.h[10]=status;lso_record.h[11]=code;
 lso_record.h[12]=(uint64_t)detail;lso_record.h[13]=lso_count;
 lso_record.h[17]=li2_lifecycle_native_counts()->admissions;lso_record.h[18]=li2_lifecycle_native_counts()->closed;
 lso_record.h[19]=selected_chain.session->pid;lso_record.h[20]=selected_chain.session->tid;
 lso_record.h[21]=li2_lifecycle_fetch_interlock();
 if(lso_event_current<LSO_ROWS)lso_after(&lso_record.events[lso_event_current],(unsigned)lso_record.events[lso_event_current].h[2]);
 lso_copy(&lso_record.terminal_chain,&selected_chain,sizeof selected_chain);
 lso_copy(&lso_record.terminal_rseq,li2_rseq_snapshot(),sizeof lso_record.terminal_rseq);
 lso_copy(lso_record.terminal_source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 lso_copy(lso_record.terminal_data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 if(li2_rseq_snapshot()->registered) {lso_copy(lso_record.terminal_page,(const void *)(uintptr_t)RN_PAGE,4096);lso_record.h[14]=1;}
 if(status && lso_count) {
  unsigned prot=0;lso_record.h[43]=1;
  lso_record.h[44]=(unsigned)lso_page_protection(RN_BODY,&lso_record.terminal_maps,&prot);
  lso_record.h[45]=prot;lso_record.h[46]=1;
 }
 size_t at=0;
 while(at<sizeof lso_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&lso_record+at),sizeof lso_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof lso_record-at)return;
  at+=(size_t)n;
 }
}
