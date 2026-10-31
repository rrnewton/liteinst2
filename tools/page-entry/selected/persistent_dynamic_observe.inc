/* Capture-only evidence for actual dynamic attempts. Selectors restrict copies
   after ordinary eligibility; they never select or bypass runtime admission. */
#include "persistent_dynamic_observe_memory.h"
#include "persistent_dynamic_capture_config.h"
#if LI2_PERSISTENT_DYNAMIC_CAPTURE != 1 || LI2_PERSISTENT_DYNAMIC != 1 || LI2_PD_CAPTURE_VERSION != 1
#error "actual dynamic finite capture profile"
#endif
#define PDO_MAGIC UINT64_C(0x314f445049324c)
#define PDO_FOOTER UINT64_C(0x3146445049324c)
struct pdo_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct pdo_counts {
    uint64_t next_serial,next_generation,offers,publications,hits,cold_attempts;
    uint64_t cancelled,retirements,permit_claims,entries,completed,unexpected;
    uint64_t misses[LI2_PED_REASON_COUNT];
};
struct pdo_stage {
    struct li2_pe_progress progress;
    struct pdo_counts counts;
    struct li2_pe_generation generation;
    struct li2_span_transfer_progress transfer;
    struct li2_pe_source_progress source;
    struct li2_pe_rseq_progress rseq;
    struct li2_rseq_state state;
    struct li2_fetch_progress fetch;
    struct ped_permit permit;
    unsigned busy,active,failing,resuming,route,pending;
};
/* Actual small controller fields. Cold/rebuild copies are deliberately absent:
   the complete actual immutable primary and every recovery input are retained. */
struct pdo_epoch_info {
    unsigned selected_bank,warm,initialized,registered,code_allocated,proof_allocated,code_registered,proof_registered;
    unsigned close_started,close_complete,prepare_started,prepare_complete,build_started,build_returned;
    unsigned redirected,exit_seen,exit_index,recovery_started,recovery_complete,guest_data_fault;
    unsigned cleanup_started,cleanup_complete,consumed,plan_proofs,none_proofs;
    long code_allocation,proof_allocation;
    int build_result,recovery_result,release_result;
    uint64_t flags,gpr_written,flags_written;
    struct li2_pe_token token;
    struct li2_step_session session;
    uintptr_t ticket;
    struct li2_fetch_ref ref;
    struct li2_link_rseq_live live[3];
    struct li2_pe_recovered recovered;
    struct li2_mg_plan recovery_scratch;
    struct li2_fetch_progress final_fetch;
    struct li2_private_code_query proof_exit,code_exit,claim_code,claim_proof,claim_spill,bank_before,proof_before;
    struct le_permission reopen_code,reopen_proof;
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    struct ped_bank banks[2];
};
/* Literal complete predecessor prefix, including both full actual frames,
   all permissions, continuation, fetch and release fields. Only the unused
   unexpected frame is encoded as zero after a complete actual byte scan. */
#define PDO_SLOT_PREFIX offsetof(struct li2_tf_chain_slot,owner.step.before)
#define PDO_SLOT_UNEXPECTED offsetof(struct li2_tf_chain_slot,unexpected)
struct pdo_predecessor {
    uint64_t complete,unexpected_compared,unexpected_nonzero;
    unsigned char before_prefix[PDO_SLOT_PREFIX];
    unsigned char closed[PDO_SLOT_UNEXPECTED];
};
struct pdo_epoch {
    uint64_t h[24];
    struct pdo_counts prior_counts;
    struct ped_permit prior_permit;
    struct li2_pe_generation prior_generation;
    struct pdo_registry initial_registry,terminal_registry;
    struct pdo_predecessor predecessor;
    struct le_frame ingress,before,returned,after;
    struct pdo_stage entered,terminal;
    struct pdo_epoch_info info;
    struct li2_pdo_memory before_memory,after_memory;
    struct pe_payload initial_payload,terminal_payload;
    unsigned char initial_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char terminal_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char initial_code[PE_CODE_BYTES],terminal_code[PE_CODE_BYTES];
};
/* The deliberately unready M plan has no emitted/head/guard storage. Retain
   its exact nonzero-capable prefix/table and scan every omitted actual byte.
   A nonzero omitted byte is a captured refusal, never reconstructed as zero. */
struct pdo_miss_plan {
    uint32_t version,bytes,ready,result,heads,exits,stores,source_bytes;
    uint32_t source_mask,decoder_result,guard_result,reserved;
    uintptr_t page[LI2_PE_SOURCES],entry,generated,spill;
    unsigned char source[LI2_PE_SOURCES][LI2_REGION_PAGE];
    struct li2_mg_table table;
    uint64_t scan_started,scan_complete,scanned,nonzero,first_nonzero,first_value;
};
struct pdo_miss {
    uint64_t h[24];
    struct pdo_counts prior_counts;
    struct ped_permit prior_permit;
    struct li2_pe_generation prior_generation;
    struct pdo_registry initial_registry,terminal_registry;
    struct li2_tf_chain_slot predecessor;
    struct li2_tf_chain resumed_chain;
    struct le_frame ingress,before,returned,next_trace;
    struct pdo_stage held,resumed;
    struct li2_pdo_memory before_memory;
    struct li2_pe_dynamic_miss miss;
    struct pdo_miss_plan plan;
};
struct pdo_wire {
    uint64_t h[64],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct pdo_registry startup_registry;
    struct pdo_miss miss;
    struct pdo_epoch epochs[3];
    struct le_frame unexpected_frame;
    struct pdo_counts final_counts;
    struct li2_pe_progress final_progress;
    uint64_t final_row[29];
};
static struct pdo_wire pdo_wire;
static unsigned pdo_ready,pdo_finished,pdo_capturing,pdo_kind,pdo_index,pdo_epochs,pdo_miss_next;
static const uint64_t pdo_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct pdo_wire)+64<4U*1024U*1024U,"complete dynamic evidence within original4MiB record bound");
static void pdo_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void pdo_counts(struct pdo_counts *o) {
#define C(n) o->n=pe.n
    C(next_serial);C(next_generation);C(offers);C(publications);C(hits);C(cold_attempts);
    C(cancelled);C(retirements);C(permit_claims);C(entries);C(completed);C(unexpected);
#undef C
    pdo_copy(o->misses,pe.misses,sizeof o->misses);
}
static void pdo_stage(struct pdo_stage *o) {
    pdo_copy(&o->progress,&pe.p,sizeof o->progress);pdo_counts(&o->counts);
    pdo_copy(&o->generation,&pe.generation,sizeof o->generation);
    pdo_copy(&o->transfer,&pe.transfer,sizeof o->transfer);
    pdo_copy(&o->source,li2_pe_source_progress(),sizeof o->source);
    pdo_copy(&o->rseq,li2_pe_rseq_progress(),sizeof o->rseq);
    pdo_copy(&o->state,li2_rseq_snapshot(),sizeof o->state);
    pdo_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    pdo_copy(&o->permit,&pe.permit,sizeof o->permit);
    o->busy=pe_busy;o->active=pe_active;o->failing=pe_failing;o->resuming=pe.resuming;
    o->route=selected_pending_route;o->pending=selected_step_pending;
}
static void pdo_info(struct pdo_epoch_info *o) {
#define C(n) o->n=pe.n
    C(selected_bank);C(warm);C(initialized);C(registered);C(code_allocated);C(proof_allocated);C(code_registered);C(proof_registered);
    C(close_started);C(close_complete);C(prepare_started);C(prepare_complete);C(build_started);C(build_returned);
    C(redirected);C(exit_seen);C(exit_index);C(recovery_started);C(recovery_complete);C(guest_data_fault);
    C(cleanup_started);C(cleanup_complete);C(consumed);C(plan_proofs);C(none_proofs);
    C(code_allocation);C(proof_allocation);C(build_result);C(recovery_result);C(release_result);
    C(flags);C(gpr_written);C(flags_written);C(token);C(session);C(ref);C(recovered);C(final_fetch);
    C(proof_exit);C(code_exit);C(claim_code);C(claim_proof);C(claim_spill);C(bank_before);C(proof_before);
    C(reopen_code);C(reopen_proof);C(registry_count);
#undef C
    o->ticket=(uintptr_t)pe.ticket;
    pdo_copy(o->live,pe.live,sizeof o->live);pdo_copy(&o->recovery_scratch,&pe.recovery_scratch,sizeof o->recovery_scratch);
    pdo_copy(o->registry,pe.registry,sizeof o->registry);pdo_copy(o->banks,pe.banks,sizeof o->banks);
}
static void pdo_registry(struct pdo_registry *out) {
    pe_need(!out->complete && protected_count && protected_count<=RANGES,PE_STATE,100);
    const struct image *b=bridge_runtime_image();
    pe_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,PE_STATE,101);
    pdo_copy(&out->bridge,b,sizeof *b);pdo_copy(out->ph,b->ph,b->n*sizeof *b->ph);
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    pdo_copy(out->ranges,protected,protected_count*sizeof *protected);
    pdo_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void pdo_initialize(void) {
    __asm__ volatile(""::"r"(&pdo_step_frame_fp_alignment):"memory");
    pe_need(!pdo_ready && !pdo_finished && !pe.p.serial,PE_STATE,102);
    uint64_t *h=pdo_wire.h;
    h[0]=PDO_MAGIC;h[1]=1;h[2]=sizeof pdo_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&pdo_wire,sizeof pdo_wire),PE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pdo_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(pdo_wire.sink_initial.st_mode) && (pdo_wire.sink_initial.st_mode&07777)==0600 &&
        pdo_wire.sink_initial.st_nlink==1 && !pdo_wire.sink_initial.st_size,PE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_DYNAMIC_APP_MODE");
    pe_need(mode && mode[0]>='0' && mode[0]<='2' && !mode[1],PE_STATE,105);h[19]=(unsigned)(mode[0]-'0');
    pdo_copy(&pdo_wire.main,&original_main,sizeof original_main);
    pdo_copy(&pdo_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    pdo_copy(&pdo_wire.hardware,&selected_hardware,sizeof selected_hardware);
    pdo_copy(&pdo_wire.session,&selected_session,sizeof selected_session);
    h[20]=(uintptr_t)&pe;h[21]=(uintptr_t)&pdo_wire;h[22]=(uintptr_t)li2_pe_source_progress();
    h[23]=(uintptr_t)li2_pe_rseq_progress();h[24]=(uintptr_t)&selected_chain;
    h[25]=(uintptr_t)li2_tf_chain_span_progress();h[26]=pe.banks[0].generated;
    h[27]=pe.generation.proof;h[28]=pe.banks[0].spill;
    h[29]=pe.banks[1].generated;h[30]=pe.banks[1].spill;
    h[31]=original_main.bias+LI2_PD_MISS_RVA;h[32]=original_main.bias+LI2_PD_A_RVA;
    h[33]=original_main.bias+LI2_PD_B_RVA;
    pdo_registry(&pdo_wire.startup_registry);pdo_ready=1;
}
static void pdo_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pdo_ready)return;
    if(pdo_wire.raw_ingress[0]==UINT64_MAX || pdo_capturing) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pdo_wire.raw_ingress[0];
    unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    if(pdo_wire.raw_ingress[i]==UINT64_MAX) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pdo_wire.raw_ingress[i];
    if(pdo_miss_next) {
        /* First real next event, before controller/rseq/ordinary dispatch. */
        pdo_miss_next=0;pdo_wire.miss.h[10]=pdo_wire.raw_ingress[0];
        pdo_wire.miss.h[11]=(uint64_t)le_capture(&pdo_wire.miss.next_trace,sig,si,uc);
        pdo_wire.miss.h[12]=1;
    }
}
static void pdo_begin(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pdo_ready)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    unsigned kind=pc==pdo_wire.h[31]?1U:(pc==pdo_wire.h[32] || pc==pdo_wire.h[33])?2U:0U;
    if(!kind)return;
    pe_need(!pdo_kind && !pdo_capturing,PE_STATE,106);pdo_capturing=1;
    if(kind==1) {
        struct pdo_miss *o=&pdo_wire.miss;
        pe_need(!o->h[0] && !pdo_wire.h[19] && selected_chain.active>=0 && selected_chain.active<2,PE_STATE,107);
        o->h[0]=1;o->h[1]=pdo_wire.raw_ingress[0];o->h[2]=(uintptr_t)pc;o->h[3]=(unsigned)selected_chain.active;
        o->h[13]=(uintptr_t)selected_chain.session;o->h[14]=selected_chain.event_id;o->h[15]=selected_chain.sequence;
        o->h[16]=(unsigned)selected_chain.active;o->h[17]=(unsigned)selected_chain.pending;
        o->h[18]=(unsigned)selected_chain.in_handler;o->h[19]=selected_chain.first_error;o->h[20]=selected_chain.initialized;
        pdo_counts(&o->prior_counts);pdo_copy(&o->prior_permit,&pe.permit,sizeof o->prior_permit);
        pdo_copy(&o->prior_generation,&pe.generation,sizeof o->prior_generation);pdo_registry(&o->initial_registry);
        pdo_copy(&o->predecessor,&selected_chain.slots[selected_chain.active],sizeof o->predecessor);
        pe_need(!le_capture(&o->ingress,sig,si,uc),PE_FRAME,100);
    } else {
        pe_need(pdo_epochs<3 && (!pdo_wire.h[19] || !pdo_epochs),PE_STATE,108);
        pdo_index=pdo_epochs++;struct pdo_epoch *o=&pdo_wire.epochs[pdo_index];
        o->h[0]=1;o->h[1]=pdo_index;o->h[2]=pc;o->h[3]=pdo_wire.raw_ingress[0];
        pdo_counts(&o->prior_counts);pdo_copy(&o->prior_permit,&pe.permit,sizeof o->prior_permit);
        pdo_copy(&o->prior_generation,&pe.generation,sizeof o->prior_generation);pdo_registry(&o->initial_registry);
        pe_need(selected_chain.active>=0 && selected_chain.active<2,PE_STATE,116);
        o->h[15]=(unsigned)selected_chain.active;
        o->h[16]=(uintptr_t)selected_chain.session;o->h[17]=selected_chain.event_id;o->h[18]=selected_chain.sequence;
        o->h[19]=(unsigned)selected_chain.active;o->h[20]=(unsigned)selected_chain.pending;
        o->h[21]=(unsigned)selected_chain.in_handler;o->h[22]=selected_chain.first_error;o->h[23]=selected_chain.initialized;
        pdo_copy(o->predecessor.before_prefix,&selected_chain.slots[selected_chain.active],PDO_SLOT_PREFIX);
        pe_need(!le_capture(&o->ingress,sig,si,uc),PE_FRAME,101);
    }
    pdo_kind=kind;pdo_capturing=0;
}
static void pdo_closed(void) {
    if(!pdo_kind)return;
    if(pdo_kind==1) {pdo_copy(&pdo_wire.miss.before,&pe.before,sizeof pe.before);pdo_wire.miss.h[4]=1;}
    else {
        struct pdo_epoch *o=&pdo_wire.epochs[pdo_index];struct pdo_predecessor *x=&o->predecessor;
        pe_need(pe.transfer.previous<2 && pe.transfer.previous==o->h[15] && !x->complete,PE_STATE,117);
        const struct li2_tf_chain_slot *s=&selected_chain.slots[pe.transfer.previous];
        pdo_copy(x->closed,s,sizeof x->closed);
        const volatile unsigned char *actual=(const void *)&s->unexpected;
        for(size_t i=0;i<sizeof s->unexpected;i++){++x->unexpected_compared;if(actual[i])++x->unexpected_nonzero;}
        x->complete=1;pdo_copy(&o->before,&pe.before,sizeof pe.before);o->h[4]=1;
    }
}
static void pdo_miss_plan(struct pdo_miss_plan *out,const struct li2_pe_plan *p) {
#define C(n) out->n=p->n
    C(version);C(bytes);C(ready);C(result);C(heads);C(exits);C(stores);C(source_bytes);
    C(source_mask);C(decoder_result);C(guard_result);C(reserved);C(entry);C(generated);C(spill);
#undef C
    pdo_copy(out->page,p->page,sizeof out->page);pdo_copy(out->source,p->source,sizeof out->source);
    pdo_copy(&out->table,&p->table,sizeof out->table);out->scan_started=1;
    const volatile unsigned char *b=(const void *)p;
    const size_t begin=offsetof(struct li2_pe_plan,image),table=offsetof(struct li2_pe_plan,table);
    const size_t tail=table+sizeof p->table;
    for(size_t i=begin;i<sizeof *p;i++) {
        if(i>=table && i<tail)continue;
        unsigned char v=b[i];++out->scanned;
        if(v) {if(!out->nonzero){out->first_nonzero=i;out->first_value=v;}++out->nonzero;}
    }
    out->scan_complete=1;
}
static void pdo_miss_held(void) {
    if(!pdo_kind)return;
    pe_need(pdo_kind==1 && !pdo_wire.miss.h[5],PE_STATE,109);
    struct pdo_miss *o=&pdo_wire.miss;pdo_stage(&o->held);
    pdo_miss_plan(&o->plan,&pe.cold);pdo_copy(&o->miss,&pe.miss,sizeof o->miss);
    pe_tls(&o->before);
    pe_need(!li2_lifecycle_pd_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,&o->before_memory),PE_STATE,118);
    o->h[5]=1;
}
static void pdo_cancelled(int sig,siginfo_t *si,ucontext_t *uc,enum li2_chain_result result) {
    if(!pdo_kind)return;
    pe_need(pdo_kind==1 && pdo_wire.miss.h[5] && !pdo_wire.miss.h[6] && !pdo_capturing,PE_STATE,110);
    pdo_capturing=1;struct pdo_miss *o=&pdo_wire.miss;
    o->h[6]=1;o->h[7]=pdo_wire.raw_ingress[0];o->h[8]=(unsigned)result;
    pdo_stage(&o->resumed);pdo_copy(&o->resumed_chain,&selected_chain,sizeof selected_chain);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,102);pe_tls(&o->returned);
    pdo_registry(&o->terminal_registry);o->h[9]=1;pdo_miss_next=1;pdo_kind=0;pdo_capturing=0;
}
static void pdo_publication(struct pdo_epoch *o,unsigned terminal) {
    const struct pe_payload *p=pe_payload();
    pdo_copy(terminal?&o->terminal_payload:&o->initial_payload,p,sizeof *p);
    pdo_copy(terminal?o->terminal_tail:o->initial_tail,
        (const unsigned char *)p+sizeof *p,PE_PROOF_BYTES-sizeof *p);
    pdo_copy(terminal?o->terminal_code:o->initial_code,(const void *)pe.generation.generated,PE_CODE_BYTES);
}
static void pdo_entered(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pdo_kind)return;
    pe_need(pdo_kind==2 && !pdo_capturing && pe_ready() && pe.p.phase==LI2_PE_EXECUTING && pe_active && pe_busy,PE_STATE,111);
    pdo_capturing=1;struct pdo_epoch *o=&pdo_wire.epochs[pdo_index];
    pe_need(o->h[4] && !o->h[5],PE_STATE,112);o->h[5]=1;o->h[6]=pdo_wire.raw_ingress[0];
    /* pe.before now includes the actual pre-entry TLS observation. */
    pdo_copy(&o->before,&pe.before,sizeof pe.before);
    pe_need(!li2_lifecycle_pd_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,&o->before_memory),PE_STATE,113);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,103);pe_tls(&o->returned);
    pdo_stage(&o->entered);pdo_publication(o,0);
    o->h[7]=*(const volatile uint64_t *)(li2_pe_rseq_progress()->address+8);o->h[8]=1;pdo_capturing=0;
}
static void pdo_terminal(unsigned failed) {
    if(!pdo_ready || !pdo_kind)return;
    if(pdo_capturing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_need(pdo_kind==2,PE_STATE,114);pdo_capturing=1;
    struct pdo_epoch *o=&pdo_wire.epochs[pdo_index];pe_need(o->h[5] && !o->h[9],PE_STATE,115);
    o->h[9]=1;o->h[10]=failed;o->h[11]=pdo_wire.raw_ingress[0];
    o->h[12]=(uint64_t)li2_lifecycle_pd_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],failed,&o->after_memory);
    pdo_copy(&o->after,&pe.after,sizeof pe.after);if(o->after.complete)pe_tls(&o->after);
    pdo_stage(&o->terminal);pdo_info(&o->info);pdo_publication(o,1);
    if(failed)pdo_copy(&pdo_wire.unexpected_frame,&pe.unexpected_frame,sizeof pe.unexpected_frame);
    o->h[13]=*(const volatile uint64_t *)(li2_pe_rseq_progress()->address+8);pdo_registry(&o->terminal_registry);
    o->h[14]=1;pdo_kind=0;pdo_capturing=0;
}
static void pdo_finish(unsigned status,unsigned code,long detail) {
    if(!pdo_ready || pdo_finished)return;
    pdo_finished=1;pdo_wire.h[47]=1;pdo_wire.h[48]=status;pdo_wire.h[49]=code;pdo_wire.h[50]=(uint64_t)detail;
    pdo_counts(&pdo_wire.final_counts);pdo_copy(&pdo_wire.final_progress,&pe.p,sizeof pe.p);
    uint64_t row[]={1,status,code,detail<0?0ULL-(uint64_t)detail:(uint64_t)detail,detail<0,
        pe.p.phase,pe.p.serial,pe.generation.generation,pe.generation.build_serial,
        pe.offers,pe.cold_attempts,pe.publications,pe.hits,pe.cancelled,pe.retirements,pe.permit_claims,
        pe.entries,pe.completed,pe.unexpected,pe.permit.valid,pe.p.opened_pages,pe.p.closed_pages,
        pe.p.anchor_released,pe.p.registration_rechecked,pe.guest_data_fault,pe.recovery_complete,
        pe.p.first_error,pe_active,pe_busy};
    _Static_assert(sizeof row==29*8,"exact dynamic terminal scalar row");
    pdo_copy(pdo_wire.final_row,row,sizeof row);pdo_wire.h[34]=pdo_epochs;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pdo_wire.sink_terminal,0,0,0,0);
    pdo_wire.h[51]=(uint64_t)flags;pdo_wire.h[52]=(uint64_t)result;
    const struct stat *a=&pdo_wire.sink_initial,*b=&pdo_wire.sink_terminal;
    if(result || flags!=(long)pdo_wire.h[16] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof pdo_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&pdo_wire+at),sizeof pdo_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof pdo_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof pdo_wire)return;
    const uint64_t footer[]={PDO_FOOTER,1,sizeof pdo_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
