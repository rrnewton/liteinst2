/* Capture-only evidence for actual loop-only group attempts. Selectors restrict copies
   after ordinary eligibility; they never select or bypass runtime admission. */
#include "persistent_group_observe_memory.h"
#include "persistent_group_capture_config.h"
#if LI2_PERSISTENT_GROUP_CAPTURE != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PG_CAPTURE_VERSION != 1
#error "actual loop-only group capture profile"
#endif
#define PGO_MAGIC UINT64_C(0x314f475049324c)
#define PGO_FOOTER UINT64_C(0x3146475049324c)
struct pgo_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct pgo_counts {
    uint64_t next_serial,next_generation,offers,publications,hits,cold_attempts;
    uint64_t cancelled,retirements,permit_claims,entries,completed,unexpected;
    uint64_t misses[LI2_PGD_REASON_COUNT];
};
struct pgo_stage {
    struct li2_pg_progress progress;
    struct pgo_counts counts;
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
struct pgo_epoch_info {
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
    struct li2_mg_plan recovery_scratch;
    struct li2_fetch_progress final_fetch;
    struct li2_private_code_query proof_exit,claim_proof,claim_spill,claim_slots,proof_before;
    struct li2_private_code_query code_exit[3],claim_code[3],bank_before[3];
    struct le_permission reopen_code[3],reopen_proof;
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    struct ped_bank banks[2];
};
/* Literal complete predecessor prefix, including both full actual frames,
   all permissions, continuation, fetch and release fields. Only the unused
   unexpected frame is encoded as zero after a complete actual byte scan. */
#define PGO_SLOT_PREFIX offsetof(struct li2_tf_chain_slot,owner.step.before)
#define PGO_SLOT_UNEXPECTED offsetof(struct li2_tf_chain_slot,unexpected)
struct pgo_predecessor {
    uint64_t complete,unexpected_compared,unexpected_nonzero;
    unsigned char before_prefix[PGO_SLOT_PREFIX];
    unsigned char closed[PGO_SLOT_UNEXPECTED];
};
struct pgo_epoch {
    uint64_t h[24];
    struct pgo_counts prior_counts;
    struct ped_permit prior_permit;
    struct li2_pg_generation prior_generation;
    struct pgo_registry initial_registry,terminal_registry;
    struct pgo_predecessor predecessor;
    struct le_frame ingress,before,returned,after;
    struct pgo_stage entered,terminal;
    struct pgo_epoch_info info;
    struct li2_pgo_memory before_memory,after_memory;
    struct pe_payload initial_payload,terminal_payload;
    unsigned char initial_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char terminal_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char initial_code[PE_CODE_BYTES],terminal_code[PE_CODE_BYTES];
    unsigned char initial_slots[PAGE],terminal_slots[PAGE];
};
/* Each deliberately unready trampoline-root plan has no emitted/head/guard storage. Retain
   its exact nonzero-capable prefix/table and scan every omitted actual byte.
   A nonzero omitted byte is a captured refusal, never reconstructed as zero. */
struct pgo_miss_plan {
    uint32_t version,bytes,ready,result,heads,exits,stores,source_bytes;
    uint32_t source_mask,decoder_result,guard_result,reserved;
    uint32_t member_heads[2],links,reserved2;
    uintptr_t page[LI2_PE_SOURCES],entry;
    struct li2_pg_layout layout;
    unsigned char source[LI2_PE_SOURCES][LI2_REGION_PAGE];
    struct li2_mg_table table;
    uint64_t scan_started,scan_complete,scanned,nonzero,first_nonzero,first_value;
};
/* Deliberately typed ordinary-owner progress projection. The two large
   step frames and unused unexpected frame are not represented or fabricated.
   Full actual logical before/returned/next-event frames are retained below. */
#define PGO_SLOT_AFTER (offsetof(struct li2_tf_chain_slot,owner.step.after)+sizeof(struct li2_step_frame))
#define PGO_CHAIN_PREFIX offsetof(struct li2_tf_chain,slots)
struct pgo_slot_progress {
    uint64_t complete,index;
    unsigned char chain[PGO_CHAIN_PREFIX];
    unsigned char prefix[PGO_SLOT_PREFIX];
    unsigned char suffix[PGO_SLOT_UNEXPECTED-PGO_SLOT_AFTER];
};
struct pgo_miss {
    uint64_t h[32];
    struct le_frame before,returned,next_trace;
    struct pgo_stage held,resumed;
    struct pgo_registry initial_registry,terminal_registry;
    struct pgo_slot_progress closed_slot,resumed_slot;
    struct li2_pg_miss miss;
    struct pgo_miss_plan plan;
};
struct pgo_wire {
    uint64_t h[64],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct pgo_registry startup_registry;
    struct pgo_miss misses[4];
    struct pgo_epoch epochs[2];
    struct pgo_counts final_counts;
    struct li2_pg_progress final_progress;
    uint64_t final_row[29];
};
static struct pgo_wire pgo_wire;
static unsigned pgo_ready,pgo_finished,pgo_capturing,pgo_kind,pgo_index,pgo_epochs,pgo_misses,pgo_miss_index,pgo_miss_next;
static const uint64_t pgo_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct pgo_wire)+64<4U*1024U*1024U,"complete loop-only group evidence within original4MiB record bound");
_Static_assert(sizeof(struct pgo_wire)==4175360 && sizeof(struct pgo_epoch)==1442176 &&
    sizeof(struct pgo_miss)==321280 && sizeof(struct pgo_slot_progress)==3792,
    "exact source-model group capture extents; actual DWARF still mandatory");
static void pgo_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void pgo_counts(struct pgo_counts *o) {
#define C(n) o->n=pe.n
    C(next_serial);C(next_generation);C(offers);C(publications);C(hits);C(cold_attempts);
    C(cancelled);C(retirements);C(permit_claims);C(entries);C(completed);C(unexpected);
#undef C
    pgo_copy(o->misses,pe.misses,sizeof o->misses);
}
static void pgo_stage(struct pgo_stage *o) {
    pgo_copy(&o->progress,&pe.p,sizeof o->progress);pgo_counts(&o->counts);
    pgo_copy(&o->generation,&pe.generation,sizeof o->generation);
    pgo_copy(&o->transfer,&pe.transfer,sizeof o->transfer);
    pgo_copy(&o->source,li2_pg_source_progress(),sizeof o->source);
    pgo_copy(&o->rseq,li2_pg_rseq_progress(),sizeof o->rseq);
    pgo_copy(&o->state,li2_rseq_snapshot(),sizeof o->state);
    pgo_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    pgo_copy(&o->permit,&pe.permit,sizeof o->permit);
    o->busy=pe_busy;o->active=pe_active;o->failing=pe_failing;o->resuming=pe.resuming;
    o->route=selected_pending_route;o->pending=selected_step_pending;
}
static void pgo_info(struct pgo_epoch_info *o) {
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
    pgo_copy(o->code_exit,pe.code_exit,sizeof o->code_exit);
    pgo_copy(o->claim_code,pe.claim_code,sizeof o->claim_code);
    pgo_copy(o->bank_before,pe.bank_before,sizeof o->bank_before);
    pgo_copy(o->reopen_code,pe.reopen_code,sizeof o->reopen_code);
    o->ticket=(uintptr_t)pe.ticket;
    pgo_copy(o->live,pe.live,sizeof o->live);pgo_copy(&o->recovery_scratch,&pe.recovery_scratch,sizeof o->recovery_scratch);
    pgo_copy(o->registry,pe.registry,sizeof o->registry);pgo_copy(o->banks,pe.banks,sizeof o->banks);
}
static void pgo_registry(struct pgo_registry *out) {
    pe_need(!out->complete && protected_count && protected_count<=RANGES,PE_STATE,100);
    const struct image *b=bridge_runtime_image();
    pe_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,PE_STATE,101);
    pgo_copy(&out->bridge,b,sizeof *b);pgo_copy(out->ph,b->ph,b->n*sizeof *b->ph);
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    pgo_copy(out->ranges,protected,protected_count*sizeof *protected);
    pgo_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void pgo_initialize(void) {
    __asm__ volatile(""::"r"(&pgo_step_frame_fp_alignment):"memory");
    pe_need(!pgo_ready && !pgo_finished && !pe.p.serial,PE_STATE,102);
    uint64_t *h=pgo_wire.h;
    h[0]=PGO_MAGIC;h[1]=1;h[2]=sizeof pgo_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&pgo_wire,sizeof pgo_wire),PE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pgo_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(pgo_wire.sink_initial.st_mode) && (pgo_wire.sink_initial.st_mode&07777)==0600 &&
        pgo_wire.sink_initial.st_nlink==1 && !pgo_wire.sink_initial.st_size,PE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_GROUP_APP_MODE");
    pe_need(mode && mode[0]=='0' && !mode[1],PE_STATE,105);h[19]=(unsigned)(mode[0]-'0');
    pgo_copy(&pgo_wire.main,&original_main,sizeof original_main);
    pgo_copy(&pgo_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    pgo_copy(&pgo_wire.hardware,&selected_hardware,sizeof selected_hardware);
    pgo_copy(&pgo_wire.session,&selected_session,sizeof selected_session);
    h[20]=(uintptr_t)&pe;h[21]=(uintptr_t)&pgo_wire;h[22]=(uintptr_t)li2_pg_source_progress();
    h[23]=(uintptr_t)li2_pg_rseq_progress();h[24]=(uintptr_t)&selected_chain;
    h[25]=(uintptr_t)li2_tf_chain_span_progress();h[26]=pe.banks[0].generated;
    h[27]=pe.generation.proof;h[28]=pe.banks[0].spill;
    h[29]=pe.banks[1].generated;h[30]=pe.banks[1].spill;
    h[31]=original_main.bias+LI2_PG_HEAD_RVA;h[32]=original_main.bias+LI2_PG_EXIT_RVA;
    h[33]=h[32]+3;h[34]=h[32]+6;
    pgo_registry(&pgo_wire.startup_registry);pgo_ready=1;
}
static void pgo_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pgo_ready)return;
    if(pgo_wire.raw_ingress[0]==UINT64_MAX || pgo_capturing) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pgo_wire.raw_ingress[0];
    unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    if(pgo_wire.raw_ingress[i]==UINT64_MAX) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pgo_wire.raw_ingress[i];
    if(pgo_miss_next) {
        unsigned index=pgo_miss_next-1;pgo_miss_next=0;
        struct pgo_miss *o=&pgo_wire.misses[index];
        o->h[10]=pgo_wire.raw_ingress[0];
        o->h[11]=(uint64_t)le_capture(&o->next_trace,sig,si,uc);o->h[12]=1;
    }
}
static void pgo_begin(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pgo_ready)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    unsigned kind=pc==pgo_wire.h[31]?2U:(pc==pgo_wire.h[33] || pc==pgo_wire.h[34])?1U:0U;
    if(!kind)return; /* Observation selector occurs only after real eligibility. */
    pe_need(!pgo_kind && !pgo_capturing && selected_chain.active>=0 && selected_chain.active<2,
        PE_STATE,106);pgo_capturing=1;
    uint64_t *h;
    if(kind==1) {
        pe_need(pgo_misses<4 && pc==pgo_wire.h[33+pgo_misses%2],PE_STATE,107);
        pgo_miss_index=pgo_misses++;struct pgo_miss *o=&pgo_wire.misses[pgo_miss_index];h=o->h;
        h[0]=1;h[1]=pgo_miss_index;h[2]=pc;h[3]=pgo_wire.raw_ingress[0];
        pgo_registry(&o->initial_registry);
    } else {
        pe_need(pgo_epochs<2,PE_STATE,108);pgo_index=pgo_epochs++;
        struct pgo_epoch *o=&pgo_wire.epochs[pgo_index];h=o->h;
        h[0]=1;h[1]=pgo_index;h[2]=pc;h[3]=pgo_wire.raw_ingress[0];
        pgo_counts(&o->prior_counts);pgo_copy(&o->prior_permit,&pe.permit,sizeof o->prior_permit);
        pgo_copy(&o->prior_generation,&pe.generation,sizeof o->prior_generation);pgo_registry(&o->initial_registry);
        pgo_copy(o->predecessor.before_prefix,&selected_chain.slots[selected_chain.active],PGO_SLOT_PREFIX);
        pe_need(!le_capture(&o->ingress,sig,si,uc),PE_FRAME,101);
    }
    h[15]=(unsigned)selected_chain.active;h[16]=(uintptr_t)selected_chain.session;
    h[17]=selected_chain.event_id;h[18]=selected_chain.sequence;h[19]=(unsigned)selected_chain.active;
    h[20]=(unsigned)selected_chain.pending;h[21]=(unsigned)selected_chain.in_handler;
    h[22]=selected_chain.first_error;h[23]=selected_chain.initialized;
    pgo_kind=kind;pgo_capturing=0;
}

static void pgo_slot_progress(struct pgo_slot_progress *out,unsigned index) {
    pe_need(!out->complete && index<2,PE_STATE,119);out->index=index;
    const struct li2_tf_chain_slot *slot=&selected_chain.slots[index];
    pgo_copy(out->chain,&selected_chain,sizeof out->chain);
    pgo_copy(out->prefix,slot,sizeof out->prefix);
    pgo_copy(out->suffix,(const unsigned char *)slot+PGO_SLOT_AFTER,sizeof out->suffix);
    out->complete=1;
}
static void pgo_closed(void) {
    if(!pgo_kind)return;
    pe_need(pe.transfer.previous<2,PE_STATE,120);
    if(pgo_kind==1) {
        struct pgo_miss *o=&pgo_wire.misses[pgo_miss_index];
        pe_need(pe.transfer.previous==o->h[15] && !o->h[4],PE_STATE,121);
        pgo_copy(&o->before,&pe.before,sizeof pe.before);
        pgo_slot_progress(&o->closed_slot,pe.transfer.previous);o->h[4]=1;
    } else {
        struct pgo_epoch *o=&pgo_wire.epochs[pgo_index];struct pgo_predecessor *x=&o->predecessor;
        pe_need(pe.transfer.previous==o->h[15] && !x->complete,PE_STATE,117);
        const struct li2_tf_chain_slot *slot=&selected_chain.slots[pe.transfer.previous];
        pgo_copy(x->closed,slot,sizeof x->closed);
        const volatile unsigned char *actual=(const void *)&slot->unexpected;
        for(size_t i=0;i<sizeof slot->unexpected;i++){++x->unexpected_compared;if(actual[i])++x->unexpected_nonzero;}
        x->complete=1;pgo_copy(&o->before,&pe.before,sizeof pe.before);o->h[4]=1;
    }
}
static void pgo_miss_plan(struct pgo_miss_plan *out,const struct li2_pg_plan *p) {
#define C(n) out->n=p->n
    C(version);C(bytes);C(ready);C(result);C(heads);C(exits);C(stores);C(source_bytes);
    C(source_mask);C(decoder_result);C(guard_result);C(reserved);C(links);C(reserved2);C(entry);C(layout);
#undef C
    pgo_copy(out->member_heads,p->member_heads,sizeof out->member_heads);
    pgo_copy(out->page,p->page,sizeof out->page);pgo_copy(out->source,p->source,sizeof out->source);
    pgo_copy(&out->table,&p->table,sizeof out->table);out->scan_started=1;
    const volatile unsigned char *b=(const void *)p;
    const size_t begin=offsetof(struct li2_pg_plan,image),table=offsetof(struct li2_pg_plan,table);
    const size_t tail=table+sizeof p->table;
    for(size_t i=begin;i<sizeof *p;i++) {
        if(i>=table && i<tail)continue;
        unsigned char v=b[i];++out->scanned;
        if(v) {if(!out->nonzero){out->first_nonzero=i;out->first_value=v;}++out->nonzero;}
    }
    out->scan_complete=1;
}
static void pgo_miss_held(void) {
    if(!pgo_kind)return;
    pe_need(pgo_kind==1 && !pgo_wire.misses[pgo_miss_index].h[5],PE_STATE,109);
    struct pgo_miss *o=&pgo_wire.misses[pgo_miss_index];pgo_stage(&o->held);
    pgo_miss_plan(&o->plan,&pe.cold);pgo_copy(&o->miss,&pe.miss,sizeof o->miss);pe_tls(&o->before);
    pe_need(o->plan.scan_started==1 && o->plan.scan_complete==1 && !o->plan.nonzero &&
        o->plan.scanned==sizeof pe.cold - offsetof(struct li2_pg_plan,image) - sizeof pe.cold.table,PE_PLAN,100);
    o->h[5]=1;
}
static void pgo_cancelled(int sig,siginfo_t *si,ucontext_t *uc,enum li2_chain_result result) {
    if(!pgo_kind)return;
    struct pgo_miss *o=&pgo_wire.misses[pgo_miss_index];
    pe_need(pgo_kind==1 && o->h[5] && !o->h[6] && !pgo_capturing && !pgo_miss_next &&
        selected_chain.active>=0 && selected_chain.active<2,PE_STATE,110);
    pgo_capturing=1;o->h[6]=1;o->h[7]=pgo_wire.raw_ingress[0];o->h[8]=(unsigned)result;
    pgo_stage(&o->resumed);pgo_slot_progress(&o->resumed_slot,(unsigned)selected_chain.active);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,102);pe_tls(&o->returned);
    pgo_registry(&o->terminal_registry);o->h[9]=1;pgo_miss_next=pgo_miss_index+1;
    pgo_kind=0;pgo_capturing=0;
}
static void pgo_publication(struct pgo_epoch *o,unsigned terminal) {
    const struct pe_payload *p=pe_payload();
    pgo_copy(terminal?&o->terminal_payload:&o->initial_payload,p,sizeof *p);
    pgo_copy(terminal?o->terminal_tail:o->initial_tail,
        (const unsigned char *)p+sizeof *p,PE_PROOF_BYTES-sizeof *p);
    unsigned char *code=terminal?o->terminal_code:o->initial_code;
    for(unsigned i=0;i<3;i++)pgo_copy(code+(i<2?i*LI2_PE_IMAGE_BYTES:2*LI2_PE_IMAGE_BYTES),
        (const void *)pg_extent(&pe.generation.layout,i),pg_extent_bytes(i));
    pgo_copy(terminal?o->terminal_slots:o->initial_slots,(const void *)pe.generation.layout.slots,PAGE);
}
static void pgo_entered(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pgo_kind)return;
    pe_need(pgo_kind==2 && !pgo_capturing && pe_ready() && pe.p.phase==LI2_PG_EXECUTING && pe_active && pe_busy,PE_STATE,111);
    pgo_capturing=1;struct pgo_epoch *o=&pgo_wire.epochs[pgo_index];
    pe_need(o->h[4] && !o->h[5],PE_STATE,112);o->h[5]=1;o->h[6]=pgo_wire.raw_ingress[0];
    /* pe.before now includes the actual pre-entry TLS observation. */
    pgo_copy(&o->before,&pe.before,sizeof pe.before);
    pe_need(!li2_lifecycle_pg_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,&o->before_memory),PE_STATE,113);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,103);pe_tls(&o->returned);
    pgo_stage(&o->entered);pgo_publication(o,0);
    o->h[7]=*(const volatile uint64_t *)(li2_pg_rseq_progress()->address+8);o->h[8]=1;pgo_capturing=0;
}
static void pgo_terminal(unsigned failed) {
    if(!pgo_ready || !pgo_kind)return;
    if(failed){pgo_wire.h[46]=1;pgo_kind=0;return;}
    if(pgo_capturing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_need(pgo_kind==2,PE_STATE,114);pgo_capturing=1;
    struct pgo_epoch *o=&pgo_wire.epochs[pgo_index];pe_need(o->h[5] && !o->h[9],PE_STATE,115);
    o->h[9]=1;o->h[10]=failed;o->h[11]=pgo_wire.raw_ingress[0];
    o->h[12]=(uint64_t)li2_lifecycle_pg_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],failed,&o->after_memory);
    pgo_copy(&o->after,&pe.after,sizeof pe.after);if(o->after.complete)pe_tls(&o->after);
    pgo_stage(&o->terminal);pgo_info(&o->info);pgo_publication(o,1);
    o->h[13]=*(const volatile uint64_t *)(li2_pg_rseq_progress()->address+8);pgo_registry(&o->terminal_registry);
    o->h[14]=1;pgo_kind=0;pgo_capturing=0;
}
static void pgo_finish(unsigned status,unsigned code,long detail) {
    if(!pgo_ready || pgo_finished)return;
    pgo_finished=1;pgo_wire.h[47]=1;pgo_wire.h[48]=status;pgo_wire.h[49]=code;pgo_wire.h[50]=(uint64_t)detail;
    pgo_counts(&pgo_wire.final_counts);pgo_copy(&pgo_wire.final_progress,&pe.p,sizeof pe.p);
    uint64_t row[]={1,status,code,detail<0?0ULL-(uint64_t)detail:(uint64_t)detail,detail<0,
        pe.p.phase,pe.p.serial,pe.generation.generation,pe.generation.build_serial,
        pe.offers,pe.cold_attempts,pe.publications,pe.hits,pe.cancelled,pe.retirements,pe.permit_claims,
        pe.entries,pe.completed,pe.unexpected,pe.permit.valid,pe.p.opened_pages,pe.p.closed_pages,
        pe.p.anchor_released,pe.p.registration_rechecked,pe.guest_data_fault,pe.recovery_complete,
        pe.p.first_error,pe_active,pe_busy};
    _Static_assert(sizeof row==29*8,"exact group terminal scalar row");
    pgo_copy(pgo_wire.final_row,row,sizeof row);pgo_wire.h[35]=pgo_epochs;pgo_wire.h[36]=pgo_misses;
    pgo_wire.h[37]=pgo_miss_next;pgo_wire.h[38]=pgo_kind;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pgo_wire.sink_terminal,0,0,0,0);
    pgo_wire.h[51]=(uint64_t)flags;pgo_wire.h[52]=(uint64_t)result;
    const struct stat *a=&pgo_wire.sink_initial,*b=&pgo_wire.sink_terminal;
    if(result || flags!=(long)pgo_wire.h[16] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof pgo_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&pgo_wire+at),sizeof pgo_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof pgo_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof pgo_wire)return;
    const uint64_t footer[]={PGO_FOOTER,1,sizeof pgo_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
