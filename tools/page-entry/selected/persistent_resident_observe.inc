/* Capture-only evidence for the actual resident271 epoch. Selectors restrict copies
   after ordinary eligibility; they never select or bypass runtime admission. */
#include "persistent_resident_observe_memory.h"
#include "persistent_resident_capture_config.h"
#if LI2_PERSISTENT_RESIDENT_CAPTURE != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PR_CAPTURE_VERSION != 2 || LI2_PERSISTENT_DISPATCH != 1 || defined(LI2_PERSISTENT_GROUP_CAPTURE)
#error "actual resident capture profile"
#endif
#define PRO_MAGIC UINT64_C(0x324f525049324c)
#define PRO_FOOTER UINT64_C(0x3246525049324c)
struct pro_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct pro_counts {
    uint64_t next_serial,next_generation,offers,publications,hits,cold_attempts;
    uint64_t cancelled,retirements,permit_claims,entries,completed,unexpected;
    uint64_t misses[LI2_PGD_REASON_COUNT];
};
struct pro_stage {
    struct li2_pg_progress progress;
    struct pro_counts counts;
    struct li2_pg_generation generation;
    struct li2_span_transfer_progress transfer;
    struct li2_pg_source_progress source;
    struct li2_pg_rseq_progress rseq;
    struct li2_rseq_state state;
    struct li2_fetch_progress fetch;
    struct ped_permit permit;
    unsigned busy,active,failing,resuming,route,pending;
};
/* Actual small controller fields. Cold/rebuild copies are deliberately absent:
   the complete actual immutable primary and every recovery input are retained. */
struct pro_epoch_info {
    unsigned selected_bank,warm,initialized,registered,code_allocated,proof_allocated,code_registered,proof_registered;
    unsigned close_started,close_complete,prepare_started,prepare_complete,build_started,build_returned;
    unsigned redirected,exit_seen,exit_index,recovery_started,recovery_complete,guest_data_fault;
    unsigned cleanup_started,cleanup_complete,consumed,plan_proofs,none_proofs;
    long code_allocation,proof_allocation;
    int build_result,recovery_result,release_result;
    uint64_t flags,gpr_written,flags_written;
    struct li2_pg_token token;
    struct li2_step_session session;
    uintptr_t ticket;
    struct li2_fetch_ref ref;
    struct li2_link_rseq_live live[3];
    struct li2_pg_recovered recovered;
    union li2_pg_guard recovery_scratch;
    struct li2_fetch_progress final_fetch;
    struct pg_proof_query proof_exit,claim_proof;
    struct li2_private_code_query claim_spill,claim_slots;
    struct pg_proof_query proof_before;
    struct li2_private_code_query code_exit[3],claim_code[3],bank_before[3];
    struct le_permission reopen_code[3];
    struct pg_proof_permission reopen_proof;
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    struct ped_bank banks[2];
};
/* Literal complete predecessor prefix, including both full actual frames,
   all permissions, continuation, fetch and release fields. Only the unused
   unexpected frame is encoded as zero after a complete actual byte scan. */
#define PRO_SLOT_PREFIX offsetof(struct li2_tf_chain_slot,owner.step.before)
#define PRO_SLOT_UNEXPECTED offsetof(struct li2_tf_chain_slot,unexpected)
struct pro_predecessor {
    uint64_t complete,unexpected_compared,unexpected_nonzero;
    unsigned char before_prefix[PRO_SLOT_PREFIX];
    unsigned char closed[PRO_SLOT_UNEXPECTED];
};
struct pro_epoch {
    uint64_t h[24];
    struct pro_counts prior_counts;
    struct ped_permit prior_permit;
    struct li2_pg_generation prior_generation;
    struct pro_registry initial_registry,terminal_registry;
    struct pro_predecessor predecessor;
    struct le_frame ingress,before,returned,after;
    struct pro_stage entered,terminal;
    struct pro_epoch_info info;
    struct li2_pro_memory before_memory,after_memory;
    struct pe_payload initial_payload,terminal_payload;
    unsigned char initial_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char terminal_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char initial_code[PE_CODE_BYTES],terminal_code[PE_CODE_BYTES];
    unsigned char initial_slots[PAGE],terminal_slots[PAGE];
};
/* The next raw TRACE is retained before any owner edits. Its complete closed
   ordinary slot and actual TLS observations follow in that same handler, after
   genuine revoke/release and before successor preparation. */
struct pro_next {
    uint64_t expected_ordinal,raw_ordinal,capture_result,ingress_complete;
    uint64_t slot_index,closed_complete,tls_complete,event_id;
    struct le_frame frame;
    struct li2_tf_chain_slot closed;
};
struct pro_wire {
    uint64_t h[64],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct pro_registry startup_registry;
    struct pro_epoch epochs[1];
    struct pro_next next;
    struct pro_counts final_counts;
    struct li2_pg_progress final_progress;
    uint64_t final_row[29];
};
static struct pro_wire pro_wire;
static unsigned pro_ready,pro_finished,pro_capturing,pro_kind,pro_index,pro_epochs;
static const uint64_t pro_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct pro_wire)+64<4U*1024U*1024U,"complete resident evidence within original4MiB record bound");
_Static_assert(sizeof(struct pro_wire)==1719936 && sizeof(struct pro_epoch)==1446080 &&
    sizeof(struct pro_next)==267968 && sizeof(struct pro_stage)==46896 &&
    sizeof(struct pro_epoch_info)==15160,"exact source-model resident extents; actual DWARF mandatory");
static void pro_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void pro_counts(struct pro_counts *o) {
#define C(n) o->n=pe.n
    C(next_serial);C(next_generation);C(offers);C(publications);C(hits);C(cold_attempts);
    C(cancelled);C(retirements);C(permit_claims);C(entries);C(completed);C(unexpected);
#undef C
    pro_copy(o->misses,pe.misses,sizeof o->misses);
}
static void pro_stage(struct pro_stage *o) {
    pro_copy(&o->progress,&pe.p,sizeof o->progress);pro_counts(&o->counts);
    pro_copy(&o->generation,&pe.generation,sizeof o->generation);
    pro_copy(&o->transfer,&pe.transfer,sizeof o->transfer);
    pro_copy(&o->source,li2_pg_source_progress(),sizeof o->source);
    pro_copy(&o->rseq,li2_pg_rseq_progress(),sizeof o->rseq);
    pro_copy(&o->state,li2_rseq_snapshot(),sizeof o->state);
    pro_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    pro_copy(&o->permit,&pe.permit,sizeof o->permit);
    o->busy=pe_busy;o->active=pe_active;o->failing=pe_failing;o->resuming=pe.resuming;
    o->route=selected_pending_route;o->pending=selected_step_pending;
}
static void pro_info(struct pro_epoch_info *o) {
#define C(n) o->n=pe.n
    C(selected_bank);C(warm);C(initialized);C(registered);C(code_allocated);C(proof_allocated);C(code_registered);C(proof_registered);
    C(close_started);C(close_complete);C(prepare_started);C(prepare_complete);C(build_started);C(build_returned);
    C(redirected);C(exit_seen);C(exit_index);C(recovery_started);C(recovery_complete);C(guest_data_fault);
    C(cleanup_started);C(cleanup_complete);C(consumed);C(plan_proofs);C(none_proofs);
    C(code_allocation);C(proof_allocation);C(build_result);C(recovery_result);C(release_result);
    C(flags);C(gpr_written);C(flags_written);C(token);C(session);C(ref);C(recovered);C(final_fetch);
    C(proof_exit);C(claim_proof);C(claim_spill);C(claim_slots);C(proof_before);
    C(reopen_proof);C(registry_count);
#undef C
    pro_copy(o->code_exit,pe.code_exit,sizeof o->code_exit);
    pro_copy(o->claim_code,pe.claim_code,sizeof o->claim_code);
    pro_copy(o->bank_before,pe.bank_before,sizeof o->bank_before);
    pro_copy(o->reopen_code,pe.reopen_code,sizeof o->reopen_code);
    o->ticket=(uintptr_t)pe.ticket;
    pro_copy(o->live,pe.live,sizeof o->live);pro_copy(&o->recovery_scratch,&pe.recovery_scratch,sizeof o->recovery_scratch);
    pro_copy(o->registry,pe.registry,sizeof o->registry);pro_copy(o->banks,pe.banks,sizeof o->banks);
}
static void pro_registry(struct pro_registry *out) {
    pe_need(!out->complete && protected_count && protected_count<=RANGES,PE_STATE,100);
    const struct image *b=bridge_runtime_image();
    pe_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,PE_STATE,101);
    pro_copy(&out->bridge,b,sizeof *b);pro_copy(out->ph,b->ph,b->n*sizeof *b->ph);
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    pro_copy(out->ranges,protected,protected_count*sizeof *protected);
    pro_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void pro_initialize(void) {
    __asm__ volatile(""::"r"(&pro_step_frame_fp_alignment):"memory");
    pe_need(!pro_ready && !pro_finished && !pe.p.serial,PE_STATE,102);
    uint64_t *h=pro_wire.h;
    h[0]=PRO_MAGIC;h[1]=2;h[2]=sizeof pro_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&pro_wire,sizeof pro_wire),PE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pro_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(pro_wire.sink_initial.st_mode) && (pro_wire.sink_initial.st_mode&07777)==0600 &&
        pro_wire.sink_initial.st_nlink==1 && !pro_wire.sink_initial.st_size,PE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_RESIDENT_APP_MODE");
    pe_need(mode && mode[0]=='0' && !mode[1],PE_STATE,105);h[19]=(unsigned)(mode[0]-'0');
    pro_copy(&pro_wire.main,&original_main,sizeof original_main);
    pro_copy(&pro_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    pro_copy(&pro_wire.hardware,&selected_hardware,sizeof selected_hardware);
    pro_copy(&pro_wire.session,&selected_session,sizeof selected_session);
    h[20]=(uintptr_t)&pe;h[21]=(uintptr_t)&pro_wire;h[22]=(uintptr_t)li2_pg_source_progress();
    h[23]=(uintptr_t)li2_pg_rseq_progress();h[24]=(uintptr_t)&selected_chain;
    h[25]=(uintptr_t)li2_tf_chain_span_progress();h[26]=pe.banks[0].generated;
    h[27]=pe.generation.proof;h[28]=pe.banks[0].spill;
    h[29]=pe.banks[1].generated;h[30]=pe.banks[1].spill;
    h[31]=original_main.bias+LI2_PR_HEAD_RVA;h[32]=original_main.bias+LI2_PR_DISPATCH_RVA;
    h[33]=original_main.bias+LI2_PR_NEXT_RVA;
    pro_registry(&pro_wire.startup_registry);pro_ready=1;
}
static void pro_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pro_ready)return;
    if(pro_wire.raw_ingress[0]==UINT64_MAX || pro_capturing) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pro_wire.raw_ingress[0];
    unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    if(pro_wire.raw_ingress[i]==UINT64_MAX) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pro_wire.raw_ingress[i];
    struct pro_next *n=&pro_wire.next;
    if(n->expected_ordinal && !n->ingress_complete) {
        n->raw_ordinal=pro_wire.raw_ingress[0];n->slot_index=(uint64_t)selected_chain.active;
        n->capture_result=(uint64_t)le_capture(&n->frame,sig,si,uc);n->ingress_complete=1;
    }
}
/* This symbol is called only by the capture-only hook after chain_closed and
   whole after-frame equality, before any successor preparation or effects. */
void li2_pro_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    struct pro_next *n=&pro_wire.next;
    if(!pro_ready || !n->expected_ordinal || n->closed_complete)return;
    pe_need(!pro_capturing && n->ingress_complete && !n->capture_result &&
        n->expected_ordinal==n->raw_ordinal && n->raw_ordinal==pro_wire.raw_ingress[0] &&
        chain==&selected_chain && n->slot_index<2 && slot==&chain->slots[n->slot_index] &&
        chain->active==(int)n->slot_index && chain->in_handler==1 && chain->pending==1 &&
        handling==1 && chain->event_id>slot->event_id && !chain->first_error && !chain->unexpected_events &&
        slot->phase==LI2_CHAIN_CLOSED && !slot->unexpected_frame_observed &&
        slot->decoded.pc==pro_wire.h[32] && slot->owner.actual_post_pc==pro_wire.h[33] &&
        n->frame.complete && (uintptr_t)n->frame.frame.greg[REG_RIP]==pro_wire.h[33],PE_STATE,122);
    pro_capturing=1;n->event_id=chain->event_id;
    pro_copy(&n->closed,slot,sizeof n->closed);
    pe_tls(&n->frame);n->tls_complete=1;n->closed_complete=1;pro_capturing=0;
}
static void pro_begin(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pro_ready || (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=pro_wire.h[31])return;
    /* This selector copies evidence only after the ordinary real eligibility. */
    pe_need(!pro_kind && !pro_capturing && !pro_epochs &&
        selected_chain.active>=0 && selected_chain.active<2,PE_STATE,106);
    pro_capturing=1;pro_index=pro_epochs++;
    struct pro_epoch *o=&pro_wire.epochs[pro_index];uint64_t *h=o->h;
    h[0]=1;h[1]=pro_index;h[2]=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];h[3]=pro_wire.raw_ingress[0];
    pro_counts(&o->prior_counts);pro_copy(&o->prior_permit,&pe.permit,sizeof o->prior_permit);
    pro_copy(&o->prior_generation,&pe.generation,sizeof o->prior_generation);pro_registry(&o->initial_registry);
    pro_copy(o->predecessor.before_prefix,&selected_chain.slots[selected_chain.active],PRO_SLOT_PREFIX);
    pe_need(!le_capture(&o->ingress,sig,si,uc),PE_FRAME,101);
    h[15]=(unsigned)selected_chain.active;h[16]=(uintptr_t)selected_chain.session;
    h[17]=selected_chain.event_id;h[18]=selected_chain.sequence;h[19]=(unsigned)selected_chain.active;
    h[20]=(unsigned)selected_chain.pending;h[21]=(unsigned)selected_chain.in_handler;
    h[22]=selected_chain.first_error;h[23]=selected_chain.initialized;
    pro_kind=2;pro_capturing=0;
}
static void pro_closed(void) {
    if(!pro_kind)return;
    pe_need(pe.transfer.previous<2,PE_STATE,120);
    struct pro_epoch *o=&pro_wire.epochs[pro_index];struct pro_predecessor *x=&o->predecessor;
    pe_need(pe.transfer.previous==o->h[15] && !x->complete,PE_STATE,117);
    const struct li2_tf_chain_slot *slot=&selected_chain.slots[pe.transfer.previous];
    pro_copy(x->closed,slot,sizeof x->closed);
    const volatile unsigned char *actual=(const void *)&slot->unexpected;
    for(size_t i=0;i<sizeof slot->unexpected;i++){++x->unexpected_compared;if(actual[i])++x->unexpected_nonzero;}
    x->complete=1;pro_copy(&o->before,&pe.before,sizeof pe.before);o->h[4]=1;
}
static void pro_miss_held(void) {
    /* A focal classified miss is recorded as a failed observation, never
       synthesized into the one required accepted epoch. */
    if(pro_kind){pro_wire.h[45]=1;pro_kind=0;}
}
static void pro_publication(struct pro_epoch *o,unsigned terminal) {
    const struct pe_payload *p=pe_payload();
    pro_copy(terminal?&o->terminal_payload:&o->initial_payload,p,sizeof *p);
    pro_copy(terminal?o->terminal_tail:o->initial_tail,
        (const unsigned char *)p+sizeof *p,PE_PROOF_BYTES-sizeof *p);
    unsigned char *code=terminal?o->terminal_code:o->initial_code;
    for(unsigned i=0;i<3;i++)pro_copy(code+(i<2?i*LI2_PE_IMAGE_BYTES:2*LI2_PE_IMAGE_BYTES),
        (const void *)pg_extent(&pe.generation.layout,i),pg_extent_bytes(i));
    pro_copy(terminal?o->terminal_slots:o->initial_slots,(const void *)pe.generation.layout.slots,PAGE);
}
static void pro_entered(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pro_kind)return;
    pe_need(pro_kind==2 && !pro_capturing && pe_ready() && pe.p.phase==LI2_PG_EXECUTING && pe_active && pe_busy,PE_STATE,111);
    pro_capturing=1;struct pro_epoch *o=&pro_wire.epochs[pro_index];
    pe_need(o->h[4] && !o->h[5],PE_STATE,112);o->h[5]=1;o->h[6]=pro_wire.raw_ingress[0];
    /* pe.before now includes the actual pre-entry TLS observation. */
    pro_copy(&o->before,&pe.before,sizeof pe.before);
    pe_need(!li2_lifecycle_pr_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,&o->before_memory),PE_STATE,113);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,103);pe_tls(&o->returned);
    pro_stage(&o->entered);pro_publication(o,0);
    o->h[7]=*(const volatile uint64_t *)(li2_pg_rseq_progress()->address+8);o->h[8]=1;pro_capturing=0;
}
static void pro_terminal(unsigned failed) {
    if(!pro_ready || !pro_kind)return;
    if(failed){pro_wire.h[46]=1;pro_kind=0;return;}
    if(pro_capturing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_need(pro_kind==2,PE_STATE,114);pro_capturing=1;
    struct pro_epoch *o=&pro_wire.epochs[pro_index];pe_need(o->h[5] && !o->h[9],PE_STATE,115);
    o->h[9]=1;o->h[10]=failed;o->h[11]=pro_wire.raw_ingress[0];
    o->h[12]=(uint64_t)li2_lifecycle_pr_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],failed,&o->after_memory);
    pro_copy(&o->after,&pe.after,sizeof pe.after);if(o->after.complete)pe_tls(&o->after);
    pro_stage(&o->terminal);pro_info(&o->info);pro_publication(o,1);
    o->h[13]=*(const volatile uint64_t *)(li2_pg_rseq_progress()->address+8);pro_registry(&o->terminal_registry);
    o->h[14]=1;
    pe_need(pro_wire.raw_ingress[0]!=UINT64_MAX && !pro_wire.next.expected_ordinal,PE_STATE,123);
    pro_wire.next.expected_ordinal=pro_wire.raw_ingress[0]+1;
    pro_kind=0;pro_capturing=0;
}
static void pro_finish(unsigned status,unsigned code,long detail) {
    if(!pro_ready || pro_finished)return;
    pro_finished=1;pro_wire.h[47]=1;pro_wire.h[48]=status;pro_wire.h[49]=code;pro_wire.h[50]=(uint64_t)detail;
    pro_counts(&pro_wire.final_counts);pro_copy(&pro_wire.final_progress,&pe.p,sizeof pe.p);
    uint64_t row[]={2,status,code,detail<0?0ULL-(uint64_t)detail:(uint64_t)detail,detail<0,
        pe.p.phase,pe.p.serial,pe.generation.generation,pe.generation.build_serial,
        pe.offers,pe.cold_attempts,pe.publications,pe.hits,pe.cancelled,pe.retirements,pe.permit_claims,
        pe.entries,pe.completed,pe.unexpected,pe.permit.valid,pe.p.opened_pages,pe.p.closed_pages,
        pe.p.anchor_released,pe.p.registration_rechecked,pe.guest_data_fault,pe.recovery_complete,
        pe.p.first_error,pe_active,pe_busy};
    _Static_assert(sizeof row==29*8,"exact resident terminal scalar row");
    pro_copy(pro_wire.final_row,row,sizeof row);pro_wire.h[35]=pro_epochs;pro_wire.h[38]=pro_kind;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pro_wire.sink_terminal,0,0,0,0);
    pro_wire.h[51]=(uint64_t)flags;pro_wire.h[52]=(uint64_t)result;
    const struct stat *a=&pro_wire.sink_initial,*b=&pro_wire.sink_terminal;
    if(result || flags!=(long)pro_wire.h[16] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof pro_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&pro_wire+at),sizeof pro_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof pro_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof pro_wire)return;
    const uint64_t footer[]={PRO_FOOTER,2,sizeof pro_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
