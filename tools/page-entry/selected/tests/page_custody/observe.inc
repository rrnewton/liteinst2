/* Pure observation around the outer custody APIs and the real handler end.
   The generated old observer differs only in storage placement; its existing
   functions and first write sequence are retained verbatim. */
#include "page_custody_config.h"
#if LI2_TF_SEALED_CUSTODY != 1 || CSO_STACK < 0 || CSO_STACK > 1 || \
    CSO_FAULT_EVENT < 0 || CSO_FAULT_EVENT > 1 || CSO_OVERLAP < 0 || CSO_OVERLAP > 1
#error fixed custody observation profile required
#endif
#define lso_initialize cso_old_initialize
#define lso_entry cso_old_entry
#define lso_fetch_return cso_old_fetch_return
#define lso_trace cso_old_trace
#define lso_terminal cso_old_terminal
#include "tf_lease_observe.inc"
#undef lso_initialize
#undef lso_entry
#undef lso_fetch_return
#undef lso_trace
#undef lso_terminal
#define cso_record cso_stream.custody
static unsigned cso_current=LSO_ROWS,cso_stack_endpoint=2,cso_finished;
static const ucontext_t *cso_stack_context;

static void cso_meta_copy(struct cso_meta *o,unsigned point,int result,
                          const struct li2_fetch_ref *ref,const struct li2_fetch_ref *published) {
 checked(!o->present && selected_chain.active>=0 && selected_chain.active<2 &&
         selected_chain.session,1798,1);
 const struct li2_tf_chain_slot *s=&selected_chain.slots[selected_chain.active];
 o->point=point;o->index=cso_current;o->result=result;o->slot=(unsigned)selected_chain.active;
 o->chain=(uintptr_t)&selected_chain;o->slot_address=(uintptr_t)s;
 o->owner_address=(uintptr_t)&s->owner;o->step_address=(uintptr_t)&s->owner.step;
 o->ref_address=(uintptr_t)ref;o->session_address=(uintptr_t)s->owner.step.session;
 o->chain_session_address=(uintptr_t)selected_chain.session;
 o->event=selected_chain.event_id;o->generation=s->generation;
 if(ref)lso_copy(&o->argument_ref,ref,sizeof *ref);
 if(published)lso_copy(&o->published_ref,published,sizeof *published);
 lso_copy(&o->custody,li2_page_custody_snapshot(),sizeof o->custody);
 li2_maps_stats_read(&o->maps);
 lso_copy(&o->rx,li2_lifecycle_fetch_rx_progress(),sizeof o->rx);
 if(s->owner.step.session)lso_copy(&o->session,s->owner.step.session,sizeof o->session);
 o->present=1;
}
/* Deliberately the copy-only partial-view API. No validator, query, ref
   authentication or current-map observation is called by this snapshot. */
static void cso_fetch_copy(struct li2_chain_fetch *o,const struct li2_fetch_ref *ref) {
 struct li2_fetch_view v={0};
 li2_lifecycle_fetch_partial_view(&v);
 if(ref)lso_copy(&o->ref,ref,sizeof *ref);
 lso_copy(&o->progress,li2_lifecycle_fetch_progress(),sizeof o->progress);
 o->pc=v.pc;o->length=v.length;o->page_count=v.page_count;
 o->pid=v.pid;o->tid=v.tid;o->identity_observed=v.identity_observed;
 checked(v.length<=sizeof o->bytes && v.page_count<=2 &&
         (!v.length || v.bytes) && (!v.page_count || (v.pages && v.backing)),1798,2);
 if(v.length)lso_copy(o->bytes,v.bytes,v.length);
 for(size_t i=0;i<v.page_count;i++) {
  lso_copy(&o->pages[i],&v.pages[i],sizeof o->pages[i]);
  lso_copy(&o->backing[i],&v.backing[i],sizeof o->backing[i]);
 }
 if(v.last_backing)lso_copy(&o->last_backing,v.last_backing,sizeof o->last_backing);
}
static void cso_snapshot_copy(struct cso_snapshot *o,unsigned point,int result,
                             const struct li2_fetch_ref *ref,const struct li2_fetch_ref *published) {
 cso_meta_copy(&o->meta,point,result,ref,published);
 const struct li2_tf_chain_slot *s=&selected_chain.slots[selected_chain.active];
 lso_copy(&o->owner,&s->owner,sizeof o->owner);
 cso_fetch_copy(&o->fetch,ref);
 lso_copy(&o->rseq,li2_rseq_snapshot(),sizeof o->rseq);
}
static void lso_initialize(void) {
 volatile unsigned char *z=(void *)&cso_record;
 for(size_t i=0;i<sizeof cso_record;i++)z[i]=0;
 cso_old_initialize();
 cso_record.h[0]=CSO_MAGIC;cso_record.h[1]=1;cso_record.h[2]=sizeof cso_record;
 cso_record.h[3]=LSO_ROWS;cso_record.h[4]=CSO_STACK;
 cso_record.h[5]=CSO_FAULT_EVENT;cso_record.h[6]=CSO_OVERLAP;
 checked(!(CSO_STACK && CSO_OVERLAP) &&
         (!CSO_STACK || !lso_record.h[3]) &&
         (!CSO_OVERLAP || lso_record.h[3]==5),1798,3);
 cso_record.h[7]=1;
}
static void lso_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 cso_old_entry(sig,si,u);cso_stack_endpoint=2;cso_stack_context=0;
 if(!CSO_STACK || !cso_record.h[7] || lso_finished || !si || !u ||
    *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1 || sig!=SIGSEGV)return;
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP];
 if(pc!=RN_BODY+96 && pc!=RN_GUARD+128)return;
 unsigned i=pc==RN_GUARD+128;struct lso_native_row *r=&cso_record.stack_endpoints[i];
 checked(!r->h[0],1798,4);
 r->h[0]=1;r->h[1]=i+2;r->h[2]=pc;r->h[3]=(uintptr_t)si->si_addr;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 checked(lso_capture(&r->before,sig,si,u),1798,5);
 cso_stack_endpoint=i;cso_stack_context=u;
}
static void lso_fetch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 cso_old_fetch_return(result,sig,si,u);
 if(cso_stack_endpoint==2 || cso_stack_context!=u)return;
 struct lso_native_row *r=&cso_record.stack_endpoints[cso_stack_endpoint];
 checked(!r->h[4],1798,6);r->h[4]=1;r->h[5]=(unsigned)result;r->h[25]=(uintptr_t)si;
 checked(lso_capture(&r->after,sig,si,u),1798,7);
}
static enum li2_chain_result lso_trace(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *u) {
 if(!lso_record.h[7] || !lso_program(c->slots[c->active].owner.step.request.decoded.pc))
  return cso_old_trace(c,sig,si,u);
 checked(cso_current==LSO_ROWS && lso_count<LSO_ROWS,1798,8);
 cso_current=lso_count;struct cso_row *r=&cso_record.rows[cso_current];
 cso_meta_copy(&r->entry,CSO_ENTRY,0,&c->slots[c->active].fetch.ref,0);
 enum li2_chain_result result=cso_old_trace(c,sig,si,u);
 cso_meta_copy(&r->returned,CSO_RETURN,(int)result,&c->slots[c->active].fetch.ref,0);
 return result;
}
/* Called after the real outer function returns. Cold seeding is now complete,
   and retained execution is observed even though it skips the old inner API. */
void cso_fetch_returned(unsigned phase,int result,const struct li2_fetch_ref *ref,
                        const struct li2_fetch_ref *before,
                        const struct li2_custody_owner *key,
                        const struct li2_fetch_rx_view *view,const struct li2_fetch_ref *published) {
 if(!cso_record.h[7] || cso_current==LSO_ROWS)return;
 checked(key && key->chain==&selected_chain && selected_chain.active>=0 &&
         key->owner==&selected_chain.slots[selected_chain.active].owner.step &&
         key->slot==(unsigned)selected_chain.active,1798,9);
 struct cso_row *r=&cso_record.rows[cso_current];
 checked(phase==1 || phase==2,1798,10);
 cso_snapshot_copy(phase==1?&r->stage:&r->commit,phase==1?CSO_STAGE:CSO_COMMIT,result,ref,published);
 checked(before != 0,1798,18);
 lso_copy(phase==1?&r->stage.meta.argument_ref:&r->commit.meta.argument_ref,before,sizeof *before);
 if(!result)checked(view==li2_lifecycle_fetch_rx_progress(),1798,11);
}
/* The two injection positions are explicit test-only seams. STAGE is after
   the outer return/seed snapshot; COMMIT is after the actual singleton copy
   but before publication of its new ref. Evidence is copied before mutation. */
void cso_fetch_phase(unsigned phase,const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *view) {
 unsigned c=(unsigned)lso_record.h[3],control=c>=6?c-5:0;
 if(!control || lso_injected || cso_current!=CSO_FAULT_EVENT ||
    (control==4?phase!=2:phase!=1))return;
 checked(cso_current<LSO_ROWS && lso_event_current==cso_current && ref && view,1798,12);
 cso_snapshot_copy(&cso_record.fault,CSO_FAULT,(int)phase,ref,0);
 lso_copy(&lso_record.fault_view,view,sizeof *view);
 lso_record.h[32]=control;lso_record.h[33]=phase;lso_record.h[34]=ref->sequence;
 lso_record.h[35]=li2_lifecycle_fetch_interlock();lso_injected=control;
 if(control==1) {
  checked(ref==&selected_chain.slots[selected_chain.active].fetch.ref && ref->sequence<UINT64_MAX,1798,13);
  ++selected_chain.slots[selected_chain.active].fetch.ref.sequence;
  lso_record.h[36]=selected_chain.slots[selected_chain.active].fetch.ref.sequence;
 } else if(control==2) {
  checked(view->backing.retained_fd>3,1798,14);lso_record.h[36]=view->backing.retained_fd;
  lso_record.h[37]=1;lso_record.h[38]=(uint64_t)raw(SYS_close,view->backing.retained_fd,0,0,0,0,0);lso_record.h[39]=1;
  checked(!lso_record.h[38],1798,15);
 } else {
  lso_record.h[37]=1;
  lso_record.h[38]=(uint64_t)raw(SYS_tgkill,selected_chain.session->pid,selected_chain.session->tid,SIGTRAP,0,0,0);
  lso_record.h[39]=1;fail(1798,16);
 }
}
static void cso_handler_end(struct li2_tf_chain *c,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(cso_current==LSO_ROWS) {li2_tf_chain_handler_end(c);return;}
 struct cso_row *r=&cso_record.rows[cso_current];
 cso_meta_copy(&r->handler_before,CSO_HANDLER_BEFORE,0,&c->slots[c->active].fetch.ref,0);
 li2_tf_chain_handler_end(c);
 cso_snapshot_copy(&r->ready,CSO_HANDLER_AFTER,0,&c->slots[c->active].fetch.ref,0);
 checked(lso_capture(&r->ready_frame,sig,si,u),1798,17);
 cso_current=LSO_ROWS;
}
static void lso_terminal(unsigned status,unsigned code,long detail) {
 if(cso_finished || !cso_record.h[7])return;
 cso_finished=1;cso_record.h[8]=1;cso_record.h[10]=status;
 cso_record.h[11]=code;cso_record.h[12]=(uint64_t)detail;cso_record.h[13]=lso_count;
 cso_meta_copy(&cso_record.terminal,CSO_TERMINAL,(int)status,
               &selected_chain.slots[selected_chain.active].fetch.ref,0);
 cso_old_terminal(status,code,detail);
 size_t at=0;
 while(at<sizeof cso_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&cso_record+at),sizeof cso_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof cso_record-at)return;
  at+=(size_t)n;
 }
}
