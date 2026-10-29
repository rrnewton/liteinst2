#include "tf_interval_record.h"
/* Exact owner identity/progress; no per-event FP payload or synthesized close. */
struct tfi_owner {
 uint64_t h[32];struct li2_step_request request;
 struct li2_fetch_ref ref;struct li2_fetch_progress progress;
 struct li2_chain_release release;
};
struct tfi_event {
 uint64_t h[16],counts_before[16],counts_after[16];
 struct tfi_trace_frame before,after;
 struct tfi_owner owner_before,owner_after;
 struct li2_fetch_rx_view transfer;
 struct li2_rseq_state rseq_before,rseq_after;
};
struct tfi_record {
 uint64_t h[64],xstate[4][4];struct li2_selected_hardware hardware;
 struct tfi_endpoint endpoints[2],read;
 struct li2_decoded read_decoded;struct li2_chain_fetch read_fetch;
 struct li2_fetch_progress read_released;
 struct li2_fetch_map_progress read_maps;struct li2_lifecycle_page_view read_page;
 struct li2_rseq_state read_rseq;
 struct li2_tf_chain_slot opening,closing;struct li2_tf_same_page body_lease_before,closed_lease;
 struct rn_frame opened,last_before,last_after;
 struct tfi_event events[TFI_MAX_EVENTS];
 struct li2_tf_chain terminal_chain;struct li2_rseq_state terminal_rseq;
 unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];
};
_Static_assert(sizeof(ucontext_t)<=RN_UC && sizeof(siginfo_t)==128 &&
 sizeof(((ucontext_t *)0)->uc_mcontext.gregs)==23*8 && sizeof(struct tfi_record)<(16U<<20),
 "fixed complete endpoints and bounded compact trace record");
static struct tfi_record tfi_record;
static unsigned tfi_finished,tfi_count,tfi_endpoint=2,tfi_trace_active;
static const ucontext_t *tfi_endpoint_context,*tfi_read_context;
static const siginfo_t *tfi_read_signal;
int tfi_page_protection(uintptr_t,struct li2_fetch_map_progress *,unsigned *);
static void tfi_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t tfi_u32(const unsigned char *s) {
 return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static size_t tfi_extent(const ucontext_t *u) {
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
 size_t cap=fork_gate_stack.ss_size,n=512;
 if(p<lo || cap<512 || p-lo>cap-512 || (p&15))return 0;
 const unsigned char *b=(const void *)p;
 if(tfi_u32(b+464)==UINT32_C(0x46505853)) {
  n=tfi_u32(b+468);size_t x=tfi_u32(b+480);
  if(n<580 || n>RN_FP || n>cap-(p-lo) || x<576 || x>n-4 || tfi_u32(b+n-4)!=UINT32_C(0x46505845))return 0;
 }
 return n;
}
static int tfi_capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(!si || !u)return 0;
 size_t n=tfi_extent(u);if(!n)return 0;
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 tfi_copy(s->uc,u,sizeof *u);tfi_copy(s->fp,u->uc_mcontext.fpregs,n);
 tfi_copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 tfi_copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 tfi_copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);s->h[0]=1;return 1;
}
static void tfi_compact(struct tfi_trace_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 checked(si && u && tfi_extent(u),1760,0);
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[0]=1;s->h[1]=(unsigned)sig;s->h[2]=(unsigned)si->si_signo;
 s->h[3]=(unsigned)si->si_code;s->h[4]=(unsigned)si->si_errno;s->h[5]=(uintptr_t)si->si_addr;
 s->h[6]=(uintptr_t)si;s->h[7]=(uintptr_t)u;s->h[8]=(uintptr_t)u->uc_mcontext.fpregs;
 s->h[9]=tfi_extent(u);s->h[10]=sizeof *si;s->h[11]=offsetof(siginfo_t,si_addr);
 s->h[12]=fs;s->h[13]=gs;s->h[14]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 tfi_copy(s->greg,u->uc_mcontext.gregs,sizeof s->greg);
 tfi_copy(&s->mask,&u->uc_sigmask,8);tfi_copy(s->siginfo,si,sizeof *si);
}
static void tfi_counts(uint64_t h[16]) {
 const struct li2_tf_chain *c=&selected_chain;const struct li2_tf_same_page *l=&c->lease;
 h[0]=c->event_id;h[1]=c->sequence;h[2]=c->attempts;h[3]=c->steps;
 h[4]=c->nx_entries;h[5]=c->trace_entries;h[6]=c->fallbacks;h[7]=c->releases;
 h[8]=l->candidates;h[9]=l->misses;h[10]=l->transfers;h[11]=l->closed_leases;
 h[12]=l->phase;h[13]=l->origin_active;h[14]=selected_pending_route;h[15]=li2_lifecycle_fetch_interlock();
}
static void tfi_owner(struct tfi_owner *r,const struct li2_tf_chain_slot *s) {
 const struct li2_step_owner *p=&s->owner.step;uint64_t *h=r->h;
 h[0]=s->index;h[1]=s->generation;h[2]=s->event_id;h[3]=(unsigned)s->phase;
 h[4]=(unsigned)p->phase;h[5]=p->first_error;h[6]=p->trace_seen;
 for(unsigned i=0;i<2;i++) {
  h[7+i]=p->open_started[i];h[9+i]=p->opened[i];h[11+i]=(uint64_t)p->open_result[i];
  h[13+i]=p->revoke_started[i];h[15+i]=p->revoked[i];h[17+i]=(uint64_t)p->revoke_result[i];
 }
 h[19]=p->open_sync;h[20]=p->revoke_sync_started;h[21]=(uint64_t)p->revoke_sync;
 h[22]=s->origin;h[23]=s->fallback;h[24]=s->fetch.pc;h[25]=s->fetch.length;
 h[26]=s->fetch.page_count;h[27]=(uint64_t)s->fetch.pid;h[28]=(uint64_t)s->fetch.tid;
 h[29]=s->fetch.identity_observed;h[30]=s->owner.actual_post_pc;h[31]=s->owner.actual_post_flags;
 tfi_copy(&r->request,&p->request,sizeof r->request);tfi_copy(&r->ref,&s->fetch.ref,sizeof r->ref);
 tfi_copy(&r->progress,&s->fetch.progress,sizeof r->progress);tfi_copy(&r->release,&s->release,sizeof r->release);
}
static void tfi_initialize(void) {
 checked(original_main.entry==RN_MAIN && !original_main.bias &&
  *(const volatile uint64_t *)(uintptr_t)RN_DATA==RN_MAGIC,1760,1);
 uint64_t n=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+8);
 checked(n==1 || n==256,1760,2);
 tfi_record.h[0]=TFI_MAGIC;tfi_record.h[1]=2;tfi_record.h[2]=sizeof tfi_record;tfi_record.h[3]=n;
 tfi_record.h[4]=sizeof(ucontext_t);tfi_record.h[5]=sizeof(struct tfi_event);
 tfi_copy(&tfi_record.hardware,&selected_hardware,sizeof selected_hardware);
 checked(selected_hardware.leaf0[0]>=13 &&
  (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
  (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1760,3);
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");
 tfi_record.h[6]=(uint64_t)lo|((uint64_t)hi<<32);checked((tfi_record.h[6]&0xe7)==0xe7,1760,4);
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,cx=bits[i],d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
  tfi_record.xstate[i][0]=bits[i];tfi_record.xstate[i][1]=b;tfi_record.xstate[i][2]=a;tfi_record.xstate[i][3]=cx;
 }
 tfi_record.h[15]=(uintptr_t)fork_gate_stack.ss_sp;tfi_record.h[16]=fork_gate_stack.ss_size;tfi_record.h[7]=1;
}
static void tfi_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 tfi_endpoint=2;tfi_endpoint_context=0;tfi_read_context=0;tfi_read_signal=0;
 if(!tfi_record.h[7] || tfi_finished || !si || !u ||
  *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1)return;
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP];
 if(sig!=SIGSEGV)return;
 if(pc==TFI_READ) {
  checked(!tfi_record.read.h[0] && tfi_capture(&tfi_record.read.before,sig,si,u),1760,5);
  tfi_record.read.h[0]=1;tfi_record.read.h[2]=pc;tfi_record.read.h[3]=(uintptr_t)si->si_addr;
  tfi_record.read.h[24]=(uintptr_t)si;
  tfi_record.read.h[26]=sizeof *si;tfi_record.read.h[27]=offsetof(siginfo_t,si_addr);
  tfi_read_context=u;tfi_read_signal=si;
 }
 if(pc!=TFI_BODY && pc!=RN_GUARD)return;
 unsigned i=pc==RN_GUARD;struct tfi_endpoint *r=&tfi_record.endpoints[i];
 checked(!r->h[0] && tfi_capture(&r->before,sig,si,u),1760,6);
 r->h[0]=1;r->h[1]=i;r->h[2]=pc;r->h[3]=(uintptr_t)si->si_addr;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 tfi_endpoint=i;tfi_endpoint_context=u;
}
static void tfi_fetch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(tfi_endpoint==2 || tfi_endpoint_context!=u)return;
 struct tfi_endpoint *r=&tfi_record.endpoints[tfi_endpoint];
 checked(!r->h[4] && tfi_capture(&r->after,sig,si,u),1760,7);
 r->h[4]=1;r->h[5]=(unsigned)result;r->h[25]=(uintptr_t)si;
}
static void tfi_syscall_before(const ucontext_t *u) {
 if(u!=tfi_read_context)return;
 checked(tfi_read_signal && tfi_record.read.h[0] && !tfi_record.read.h[6],1760,8);
 tfi_record.read.h[6]=1;tfi_copy(&tfi_record.read_decoded,&selected_decoded,sizeof selected_decoded);
 struct li2_chain_fetch *f=&tfi_record.read_fetch;
 checked(selected_view.length<=15 && selected_view.page_count<=2,1760,17);
 tfi_copy(&f->ref,&selected_borrow,sizeof selected_borrow);
 tfi_copy(&f->progress,li2_lifecycle_fetch_progress(),sizeof f->progress);
 f->pc=selected_view.pc;f->length=selected_view.length;f->page_count=selected_view.page_count;
 f->pid=selected_view.pid;f->tid=selected_view.tid;f->identity_observed=selected_view.identity_observed;
 tfi_copy(f->bytes,selected_view.bytes,selected_view.length);
 tfi_copy(f->pages,selected_view.pages,selected_view.page_count*sizeof f->pages[0]);
 tfi_copy(f->backing,selected_view.backing,selected_view.page_count*sizeof f->backing[0]);
 if(selected_view.last_backing)tfi_copy(&f->last_backing,selected_view.last_backing,sizeof f->last_backing);
}
static void tfi_syscall_after(const ucontext_t *u) {
 if(u!=tfi_read_context)return;
 checked(tfi_read_signal && tfi_record.read.h[6] && !tfi_record.read.h[4],1760,9);
 unsigned prot=0;tfi_record.read.h[8]=1;
 tfi_record.read.h[9]=(unsigned)tfi_page_protection(TFI_BODY,&tfi_record.read_maps,&prot);
 tfi_record.read.h[10]=prot;tfi_record.read.h[11]=(unsigned)li2_lifecycle_query(TFI_BODY,&tfi_record.read_page);
 tfi_record.read.h[12]=selected_step_pending;tfi_record.read.h[13]=selected_pending_route;
 tfi_record.read.h[14]=li2_lifecycle_fetch_interlock();
 tfi_copy(&tfi_record.read_released,li2_lifecycle_fetch_progress(),sizeof tfi_record.read_released);
 tfi_copy(&tfi_record.read_rseq,li2_rseq_snapshot(),sizeof tfi_record.read_rseq);
 checked(tfi_capture(&tfi_record.read.after,SIGSEGV,tfi_read_signal,u),1760,10);
 tfi_record.read.h[25]=(uintptr_t)tfi_read_signal;
 tfi_record.read.h[5]=(uint64_t)u->uc_mcontext.gregs[REG_RAX];tfi_record.read.h[4]=1;
}
static void tfi_begin(struct li2_tf_chain *c,const struct li2_fetch_ref *ref,const struct li2_decoded *d,
 uint64_t flags,int sig,siginfo_t *si,ucontext_t *u) {
 if(d->pc==TFI_BODY) {
  checked(c==&selected_chain && !tfi_record.h[17],1760,18);
  tfi_copy(&tfi_record.body_lease_before,&c->lease,sizeof c->lease);
 }
 li2_tf_chain_begin_nx(c,ref,d,flags,sig,si,u);
 if(d->pc!=TFI_BODY)return;
 checked(c==&selected_chain && !tfi_record.h[17] && c->active>=0 && c->active<2,1760,11);
 tfi_copy(&tfi_record.opening,&c->slots[c->active],sizeof tfi_record.opening);
 checked(tfi_capture(&tfi_record.opened,sig,si,u),1760,12);tfi_record.h[17]=1;
}
static enum li2_chain_result tfi_trace(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *u) {
 checked(c==&selected_chain && c->active>=0 && c->active<2,1760,13);
 const struct li2_tf_chain_slot *s=&c->slots[c->active];uintptr_t pc=s->owner.step.request.decoded.pc;
 if(pc<TFI_BODY || pc>=TFI_BODY+4*tfi_record.h[3])return li2_tf_chain_trace(c,sig,si,u);
 checked(tfi_record.h[17] && !tfi_trace_active && tfi_count<tfi_record.h[3] && tfi_count<TFI_MAX_EVENTS,1760,14);
 struct tfi_event *r=&tfi_record.events[tfi_count];unsigned slot=(unsigned)c->active;
 r->h[0]=1;r->h[1]=tfi_count;r->h[2]=slot;r->h[3]=s->generation;tfi_trace_active=1;
 tfi_counts(r->counts_before);tfi_compact(&r->before,sig,si,u);tfi_owner(&r->owner_before,s);
 tfi_copy(&r->rseq_before,li2_rseq_snapshot(),sizeof r->rseq_before);
 if(tfi_count+1==tfi_record.h[3])checked(tfi_capture(&tfi_record.last_before,sig,si,u),1760,15);
 enum li2_chain_result result=li2_tf_chain_trace(c,sig,si,u);
 r->h[4]=1;r->h[5]=(unsigned)result;r->h[6]=(unsigned)c->active;
 tfi_counts(r->counts_after);tfi_compact(&r->after,sig,si,u);tfi_owner(&r->owner_after,&c->slots[slot]);
 tfi_copy(&r->transfer,&c->lease.transfer,sizeof r->transfer);
 tfi_copy(&r->rseq_after,li2_rseq_snapshot(),sizeof r->rseq_after);
 if(tfi_count+1==tfi_record.h[3]) {
  tfi_copy(&tfi_record.closing,&c->slots[slot],sizeof tfi_record.closing);
  tfi_copy(&tfi_record.closed_lease,&c->lease,sizeof c->lease);
  checked(tfi_capture(&tfi_record.last_after,sig,si,u),1760,16);tfi_record.h[18]=1;
 }
 ++tfi_count;tfi_trace_active=0;return result;
}
static void tfi_terminal(unsigned status,unsigned code,long detail) {
 if(tfi_finished || !tfi_record.h[7])return;
 tfi_finished=1;tfi_record.h[9]=1;tfi_record.h[10]=status;tfi_record.h[11]=code;
 tfi_record.h[12]=(uint64_t)detail;tfi_record.h[13]=tfi_count;tfi_record.h[14]=tfi_trace_active;
 tfi_record.h[19]=selected_chain.session->pid;tfi_record.h[20]=selected_chain.session->tid;
 tfi_record.h[21]=li2_lifecycle_fetch_interlock();
 tfi_copy(&tfi_record.terminal_chain,&selected_chain,sizeof selected_chain);
 tfi_copy(&tfi_record.terminal_rseq,li2_rseq_snapshot(),sizeof tfi_record.terminal_rseq);
 tfi_copy(tfi_record.terminal_source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 tfi_copy(tfi_record.terminal_data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 if(li2_rseq_snapshot()->registered)tfi_copy(tfi_record.terminal_page,(const void *)(uintptr_t)RN_PAGE,4096);
 size_t at=0;
 while(at<sizeof tfi_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&tfi_record+at),sizeof tfi_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof tfi_record-at)return;
  at+=(size_t)n;
 }
}
