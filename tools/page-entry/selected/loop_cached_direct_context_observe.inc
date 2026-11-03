/* Test-only observation. No copied field can authorize production execution.
   Preserve the actual shared frame, completion and LCX values by value. A
   no-auxiliary activation has genuinely absent LCX proof, recorded as such. */
#include "loop_cached_direct_context_observe.h"
#define LCXO_MAGIC UINT64_C(0x314f58434132494c)
#define LCXO_FOOTER UINT64_C(0x314658434132494c)
enum { LCXO_VERSION=1,LCXO_EPOCHS=4,LCXO_COUNTS=64 };
struct lcxo_member {
    struct li2_pgd_ref identity;
    struct li2_pg_source_key key;
    uint64_t h[8],head[LI2_PG_HEADS];
};
struct lcxo_phase {
    uint64_t h[16],counts[LCXO_COUNTS];
    struct le_permission code_write,code_seal,code_open,code_close,proof_write,proof_seal;
    struct li2_private_code_query spill_before,spill_closed;
};
struct lcxo_epoch {
    uint64_t h[32];
    struct lcxo_member member[LI2_PGD_MEMBERS];
    struct lcxo_phase phase[4];
    struct le_frame entry,event;
    struct lcx_bundle bundle;
    struct pda_completion completion;
    struct lcx_side_value side;
};
struct lcxo_wire {
    uint64_t h[32];
    struct stat initial,terminal;
    struct lcxo_epoch epoch[LCXO_EPOCHS];
};
static struct {
    struct lcxo_wire wire;
    unsigned initialized,active,epochs,failure,reported;
} lcxo;
_Static_assert(LI2_PTR_SLOTS==8 && LI2_PGD_MEMBERS==8 && LI2_PGD_RECEIPTS==9 &&
    LI2_LTA_NODES==12 && LI2_DD_AUX_SLOTS==8 && LI2_PG_HEADS==128,
    "unchanged original arena and active union bounds");
_Static_assert(sizeof(struct lcxo_wire)+64<4U*1024U*1024U,
    "bounded complete observation, including all native frame bytes");
/* Compiler layout is read from the actual readonly ELF. The independent
   reader binds each size/offset; these values never enter runtime policy. */
const uint64_t li2_lcxo_layout[] __attribute__((used,visibility("hidden")))={
    LCXO_VERSION,sizeof(struct lcxo_wire),sizeof(struct lcxo_epoch),LCXO_EPOCHS,
    offsetof(struct lcxo_wire,epoch),sizeof(struct lcxo_member),sizeof(struct lcxo_phase),
    offsetof(struct lcxo_epoch,member),offsetof(struct lcxo_epoch,phase),
    offsetof(struct lcxo_epoch,entry),offsetof(struct lcxo_epoch,event),
    offsetof(struct lcxo_epoch,bundle),offsetof(struct lcxo_epoch,completion),
    offsetof(struct lcxo_epoch,side),sizeof(struct lcx_bundle),sizeof(struct lcx_side_value),
    sizeof(struct pda_completion),sizeof(struct li2_pgd_ref),sizeof(struct li2_pg_source_key),
    sizeof(struct le_frame),offsetof(struct le_frame,si),offsetof(struct le_frame,uc),
    offsetof(struct le_frame,frame),offsetof(struct le_frame,fs),offsetof(struct le_frame,tls_complete),
    sizeof(struct li2_step_frame),offsetof(struct li2_step_frame,fp),
    sizeof(struct le_permission),sizeof(struct li2_private_code_query),sizeof(struct stat),
    sizeof(struct li2_lcx_image),sizeof(struct li2_lcx_lease),sizeof(struct li2_lcx_directory),
    sizeof(struct li2_lcx_capability),sizeof(struct li2_lcx_tail),sizeof(struct li2_dd_aux_plan),
    offsetof(struct lcx_bundle,ref),offsetof(struct lcx_bundle,key),
    offsetof(struct lcx_bundle,route),offsetof(struct lcx_bundle,image),
    offsetof(struct lcx_bundle,lease),offsetof(struct lcx_bundle,directory),
    offsetof(struct lcx_side_value,bundle),offsetof(struct lcx_side_value,code_closed),
    offsetof(struct lcx_side_value,spill_closed),sizeof(struct pda_member_completion),
    offsetof(struct pda_completion,member),offsetof(struct pda_completion,source),
    offsetof(struct pda_completion,domain_source),offsetof(struct pda_completion,rseq),
    offsetof(struct pda_completion,fetch),offsetof(struct pda_completion,directory_closed),
    offsetof(struct pda_completion,rx),offsetof(struct pda_completion,direct_exit),
    sizeof pe,sizeof(struct pe_payload),PE_PROOF_BYTES,
    offsetof(struct pe_payload,source),offsetof(struct pe_payload,plan),
    sizeof lcx_live,sizeof lcx_cells[0],sizeof lcx_runtime
};
static _Noreturn void lcxo_fail(unsigned code) {
    if(!lcxo.failure)lcxo.failure=code;
    selected_persistent_abort(PE_PUBLICATION,9500+(long)code);
}
static void lcxo_need(int value,unsigned code) {if(!value)lcxo_fail(code);}
static void lcxo_counts(uint64_t out[LCXO_COUNTS]) {
    out[0]=*PGC_EVENT_REF;for(unsigned i=0;i<5;i++)out[1+i]=*PGC_SIGNAL_REF(i);
    const uint64_t owner[]={PGC_VALUE(publications),PGC_VALUE(cold_attempts),PGC_VALUE(hits),
        PGC_VALUE(offers),PGC_VALUE(entries),PGC_VALUE(completed)};
    copy(out+6,owner,sizeof owner);
    const uint64_t rx[]={pe.rx.code_opens,pe.rx.code_revokes,pe.rx.code_writes,pe.rx.code_syncs,
        pe.rx.metadata_permissions,pe.rx.metadata_syncs,pe.rx.retained_entries};
    copy(out+12,rx,sizeof rx);
    const struct li2_loop_cache8_progress *p=li2_loop_cache8_progress();
    const uint64_t cache[]={p->cold_calls,p->compact_build_calls,p->compact_validate_calls,
        p->attach_attempts,p->accepted,p->source_declines};copy(out+19,cache,sizeof cache);
    const uint64_t direct[]={pe.rx.direct_offers,pe.rx.direct_steps,pe.rx.transit_offers,
        pe.rx.transit_steps,pe.rx.transit_declined,pe.rx.transit_limit,
        pe.loop.counts.historical_reconstructions};copy(out+25,direct,sizeof direct);
    const uint64_t arena[]={lta_writer.value.detached,lta_writer.value.rebound,
        lta_writer.value.rebound_peers,lta_writer.value.cold_nodes,lta_writer.value.evicted,
        lta_writer.value.epoch_invalidations,lta_writer.value.stale_refusals,
        lta_writer.value.physical_checks,pe.arena.next_binding,lta_writer.value.poisoned};
    copy(out+32,arena,sizeof arena);
    const struct lcx_owner *x=&lcx_runtime.value;
    const uint64_t auxiliary[]={x->builds,x->opens,x->closes,x->entries,x->recoveries,
        x->retirements,x->invalidations};copy(out+42,auxiliary,sizeof auxiliary);
}
static void lcxo_phase(struct lcxo_epoch *e,unsigned stage) {
    lcxo_need(stage<4 && !e->phase[stage].h[0],1);
    struct lcxo_phase *out=&e->phase[stage];const struct lcx_owner *x=&lcx_runtime.value;
    const struct lcx_work *w=&x->work;uint64_t *h=out->h;
    h[0]=1;h[1]=pe.p.serial;h[2]=pe.p.phase;h[3]=pe_busy;h[4]=pe_active;
    h[5]=w->serial;h[6]=w->built;h[7]=w->published;h[8]=w->opened;h[9]=w->closed;
    h[10]=x->code_epoch;h[11]=x->proof_epoch;h[12]=x->directory_epoch;
    h[13]=x->poisoned;h[14]=w->recovery_owned;h[15]=w->recovery_result;
    lcxo_counts(out->counts);
    out->code_write=w->code_write;out->code_seal=w->code_seal;
    out->code_open=w->code_open;out->code_close=w->code_close;
    out->proof_write=w->proof_write;out->proof_seal=w->proof_seal;
    out->spill_before=w->spill_before;out->spill_closed=w->spill_closed;
}
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT_ABA
#include "loop_cached_direct_context_aba.inc"
#endif
static int lcxo_initialize(void) {
    if(lcxo.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&lcxo,sizeof lcxo))return PE_STATE;
    uint64_t *h=lcxo.wire.h;
    long fd=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),fl=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long st=raw(SYS_fstat,3,(long)&lcxo.wire.initial,0,0,0,0);
    if(fd || fl<0 || (fl&(O_ACCMODE|O_APPEND|O_NONBLOCK))!=O_WRONLY || st ||
       !S_ISREG(lcxo.wire.initial.st_mode) || (lcxo.wire.initial.st_mode&07777)!=0600 ||
       lcxo.wire.initial.st_nlink!=1 || lcxo.wire.initial.st_size)return PE_STATE;
    h[0]=LCXO_MAGIC;h[1]=LCXO_VERSION;h[2]=sizeof lcxo.wire;h[3]=sizeof(struct lcxo_epoch);
    h[4]=LCXO_EPOCHS;h[5]=LI2_PTR_SLOTS;h[6]=LI2_PGD_MEMBERS;h[7]=LI2_PGD_RECEIPTS;
    h[8]=LI2_LTA_NODES;h[9]=(uintptr_t)&pe;h[10]=(uintptr_t)&lcxo;
    h[11]=(uint64_t)fd;h[12]=(uint64_t)fl;h[13]=(uint64_t)st;
    h[14]=(uintptr_t)fork_gate_stack.ss_sp;h[15]=fork_gate_stack.ss_size;
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT_ABA
    if(selected_run_protect_add(0,(uintptr_t)&lcxa,sizeof lcxa))return PE_STATE;
#endif
    lcxo.initialized=1;return 0;
}
static void lcxo_bound(void) {
    const struct li2_pgd_view *v=&pe.domain.work.view;uintptr_t entry=v->entry.target.pc;
    if(entry!=UINT64_C(0x410200) && entry!=UINT64_C(0x412200))return;
    lcxo_need(lcxo.initialized && !lcxo.active && lcxo.epochs<LCXO_EPOCHS &&
        pda_ready(0) && v->count && v->count<=LI2_PGD_MEMBERS,2);
    struct lcxo_epoch *e=&lcxo.wire.epoch[lcxo.epochs];uint64_t *h=e->h;
    h[0]=1;h[4]=entry;h[5]=pe.p.serial;h[6]=v->count;h[7]=pe.warm;
    h[8]=pe.selected_slot;h[9]=pe.selected_bank;h[10]=pe.domain.work.receipt;
    h[11]=v->directory;h[12]=pe.entry.generation;h[13]=pe.entry.build_serial;
    h[14]=pe.entry.target.root;h[15]=pe.entry.target.generated;h[16]=pe.entry.target.head;
    const struct lcx_bundle *b=lcx_current_bundle();
    h[17]=b!=0;if(b) {lcxo_need(b->count && b->serial==pe.p.serial,3);e->bundle=*b;}
    for(unsigned i=0;i<v->count;i++) {
        const struct li2_pgd_member *m=&v->member[i];struct lcxo_member *out=&e->member[i];
        lcxo_need(m->plan && m->key && m->plan->heads && m->plan->heads<=LI2_PG_HEADS,4);
        out->identity=m->identity;out->key=*m->key;
        out->h[0]=1;out->h[1]=m->plan->version;out->h[2]=m->plan->heads;
        out->h[3]=m->plan->exits;out->h[4]=m->plan->links;
        out->h[5]=(uintptr_t)m->key;out->h[6]=(uintptr_t)m->plan;
        for(unsigned j=0;j<m->plan->heads;j++)out->head[j]=m->plan->original[j].decoded.pc;
        if(b)lcxo_need(equal(&out->identity,&b->ref[i],sizeof out->identity) &&
            equal(&out->key,&b->key[i],sizeof out->key),5);
    }
    lcxo_phase(e,0);lcxo.active=lcxo.epochs+1;
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT_ABA
    lcxa_bound(e);
#endif
}
static void lcxo_same_bundle(const struct lcxo_epoch *e) {
    const struct lcx_bundle *b=lcx_current_bundle();
    lcxo_need((b!=0)==e->h[17] && (!b || equal(b,&e->bundle,sizeof *b)),6);
}
static void lcxo_enter(void) {
    if(!lcxo.active)return;
    struct lcxo_epoch *e=&lcxo.wire.epoch[lcxo.active-1];
    lcxo_need(e->h[0]==1 && !e->h[1] && e->h[5]==pe.p.serial && pda_ready(1),7);
    lcxo_same_bundle(e);e->entry=pe.before;e->h[1]=1;lcxo_phase(e,1);
}
static void lcxo_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!lcxo.active)return;
    struct lcxo_epoch *e=&lcxo.wire.epoch[lcxo.active-1];
    lcxo_need(e->h[1]==1 && !e->h[2],8);
    lcxo_phase(e,2);lcxo_same_bundle(e);
    lcxo_need(!le_capture(&e->event,sig,si,uc),9);
    e->h[2]=1;e->h[20]=(uintptr_t)si;e->h[21]=(uintptr_t)uc;
}
static void lcxo_complete(const struct pda_completion *c) {
    if(!lcxo.active)return;
    struct lcxo_epoch *e=&lcxo.wire.epoch[lcxo.active-1];
    lcxo_need(e->h[2]==1 && !e->h[3] && c->serial==e->h[5] && c->count==e->h[6] &&
        c->complete==1 && pda_receipt(c),10);
    e->completion=*c;
    const struct lcx_side_value *side=lcx_completion_bundle(pe.domain.work.receipt);
    e->h[18]=side!=0;
    lcxo_need(e->h[18]==e->h[17] && (!side ||
        (side->completion==c && side->id==c->id && side->serial==c->serial &&
         equal(&side->bundle,&e->bundle,sizeof e->bundle))),11);
    if(side)e->side=*side;
    e->h[3]=1;e->h[19]=c->id;e->h[22]=pe.domain.work.exit_member;
    e->h[23]=pe.exit_index;e->h[24]=pe.exit_seen;e->h[25]=pe.recovery_complete;
    e->h[26]=pe.guest_data_fault;e->h[27]=pe.p.phase;
    lcxo_phase(e,3);++lcxo.epochs;lcxo.active=0;
}
static void lcxo_report(unsigned status,unsigned code) {
    if(!lcxo.initialized || lcxo.reported)return;
    lcxo.reported=1;uint64_t *h=lcxo.wire.h;
    h[16]=lcxo.epochs;h[17]=lcxo.active;h[18]=lcxo.failure;
    h[22]=status;h[23]=code;h[24]=pe.p.first_error;h[25]=(uint64_t)pe.p.first_detail;
    h[26]=pe_active;h[27]=pe_busy;
    long fl=raw(SYS_fcntl,3,F_GETFL,0,0,0,0),st=raw(SYS_fstat,3,(long)&lcxo.wire.terminal,0,0,0,0);
    h[28]=(uint64_t)fl;h[29]=(uint64_t)st;h[30]=(uint64_t)pe.session.pid;h[31]=(uint64_t)pe.session.tid;
    const struct stat *a=&lcxo.wire.initial,*b=&lcxo.wire.terminal;
    if(st || fl!=(long)h[12] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;long result=0;
    while(at<sizeof lcxo.wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lcxo.wire+at),sizeof lcxo.wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lcxo.wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lcxo.wire)return;
    const uint64_t footer[]={LCXO_FOOTER,LCXO_VERSION,sizeof lcxo.wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT_ABA
    lcxa_report(status,code);
#endif
}
