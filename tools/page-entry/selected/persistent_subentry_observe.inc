/* Distinct two-activation exact-root/subentry capture. One whole immutable
   certificate is scanned at every focal checkpoint; all entry receipts,
   frames, mutable cells and each full17-page lifetime remain literal. */
#include "persistent_subentry_observe_memory.h"
#include "persistent_subentry_capture_config.h"
#if LI2_PERSISTENT_SUBENTRY_CAPTURE != 1 || LI2_PERSISTENT_SUBENTRY != 1 || LI2_PERSISTENT_UNREGISTERED != 1 || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || LI2_PSO_CAPTURE_VERSION != 7 || LI2_PERSISTENT_DISPATCH != 1 || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || defined(LI2_PERSISTENT_GROUP_CAPTURE)
#error "actual active-domain capture profile"
#endif
#define PSO_MAGIC UINT64_C(0x374f53555049324c)
#define PSO_FOOTER UINT64_C(0x374653555049324c)
struct pso_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct pso_counts {
    uint64_t next_serial,next_generation,offers,publications,hits,cold_attempts;
    uint64_t cancelled,retirements,permit_claims,entries,completed,unexpected;
    uint64_t misses[LI2_PGD_REASON_COUNT];
    uint64_t subentry_selections,subentry_hits,subentry_entries,subentry_completed;
};
/* Complete bounded comparison evidence against one literal certificate. */
struct pso_scan {
    uint64_t started,complete,expected,compared,differences,first_offset,expected_value,actual_value;
};
struct pso_check {
    uint64_t certificate,slot,generation;
    struct pso_scan proof,code,publication;
};
/* Every retained slot field except the shared immutable publication mirror.
   Its complete bytes are checked against the same certificate payload below. */
struct pso_slot {
    struct li2_ptr_slot_ref identity;
    uintptr_t proof;
    struct ped_bank banks[2];
    struct li2_pg_generation generation;
    struct ped_permit permit;
    struct li2_pgd_claim claim;
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    uint64_t last_completed;
    unsigned code_allocated,code_registered,proof_allocated,proof_registered;
    struct pso_check check;
};
struct pso_slots {
    unsigned selected_slot,reserved;
    struct li2_ptr_slot_ref selection,previous_selection;
    struct pso_slot slots[LI2_PTR_SLOTS];
};
/* Completion cells are literal in initial_domain and each terminal_domain.
   Between completions every byte is compared with the preceding literal;
   only the separately retained claim masks/work may change. */
struct pso_domain_checkpoint {
    uintptr_t directory;
    unsigned allocated,registered;
    uint64_t next_id,dual_entries,dual_completed;
    struct le_permission initial_seal;
    struct li2_private_code_query initial;
    struct pda_work work;
    unsigned claimed[LI2_PGD_RECEIPTS];
    struct pso_scan cells;
};
struct pso_stage {
    struct li2_pg_progress progress;
    struct li2_pgs_entry entry;
    struct pso_counts counts;
    struct pso_slots slots;
    struct li2_span_transfer_progress transfer;
    struct li2_pg_source_progress source;
    struct li2_pgd_source_progress domain_source;
    struct li2_pg_rseq_progress rseq;
    struct li2_rseq_state state;
    struct li2_fetch_progress fetch;
    unsigned busy,active,failing,resuming,route,pending;
    struct pso_domain_checkpoint domain;
};
struct pso_epoch_info {
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
#define PSO_SLOT_PREFIX offsetof(struct li2_tf_chain_slot,owner.step.before)
#define PSO_SLOT_UNEXPECTED offsetof(struct li2_tf_chain_slot,unexpected)
struct pso_predecessor {
    uint64_t complete,unexpected_compared,unexpected_nonzero;
    unsigned char before_prefix[PSO_SLOT_PREFIX];
    unsigned char closed[PSO_SLOT_UNEXPECTED];
};
struct pso_certificate {
    uint64_t complete,index,slot,generation,entry,proof_bytes,code_bytes,publication_bytes;
    struct pe_payload payload;
    unsigned char tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char code[PE_CODE_BYTES];
};
struct pso_epoch {
    uint64_t h[32];
    struct pso_counts prior_counts;
    struct pso_slots prior;
    struct pso_domain_checkpoint prior_domain;
    struct pso_registry initial_registry,terminal_registry;
    struct pso_predecessor predecessor;
    struct le_frame ingress,before,returned,after;
    struct pso_stage entered,terminal;
    struct pso_epoch_info info;
    struct li2_pso_memory before_memory,after_memory;
    unsigned char initial_slots[LI2_PGD_MEMBERS][PAGE],terminal_slots[LI2_PGD_MEMBERS][PAGE];
    unsigned char initial_spill[LI2_PGD_MEMBERS][PAGE],terminal_spill[LI2_PGD_MEMBERS][PAGE];
    unsigned char initial_directory[LI2_JD_DOMAIN_BYTES],terminal_directory[LI2_JD_DOMAIN_BYTES];
    struct pda_state terminal_domain;
};
struct pso_next {
    uint64_t expected_ordinal,raw_ordinal,capture_result,ingress_complete;
    uint64_t slot_index,closed_complete,tls_complete,event_id;
    struct le_frame frame;
    struct li2_tf_chain_slot closed;
};
struct pso_wire {
    uint64_t h[64],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct pso_registry startup_registry;
    struct pda_state initial_domain;
    struct pso_certificate certificates[1];
    struct pso_epoch epochs[2];
    struct pso_next next[2];
    struct pso_counts final_counts;
    struct li2_pg_progress final_progress;
    uint64_t final_row[39],final_subentry[15];
};
static struct pso_wire pso_wire;
static unsigned pso_ready,pso_finished,pso_capturing,pso_kind,pso_index,pso_epochs;
static const uint64_t pso_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct pso_wire)+64<4U*1024U*1024U,"shared immutable active-domain evidence within original4MiB record bound");
_Static_assert(sizeof(struct pso_wire)==3057152 &&
    sizeof(struct pso_epoch)==958400 &&
    sizeof(struct pso_certificate)==434240 &&
    sizeof(struct pso_stage)==104120 &&
    sizeof(struct pso_domain_checkpoint)==11792 &&
    sizeof(struct pda_state)==164080 &&
    sizeof(struct pda_completion)==50784 &&
    sizeof(struct pda_work)==11312 &&
    sizeof(struct pso_next)==267968 &&
    sizeof(struct pso_epoch_info)==15176,
    "exact subentry source arithmetic; actual compiler/DWARF mandatory");
static void pso_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void pso_counts(struct pso_counts *o) {
#define C(n) o->n=pe.n
    C(next_serial);C(next_generation);C(offers);C(publications);C(hits);C(cold_attempts);
    C(cancelled);C(retirements);C(permit_claims);C(entries);C(completed);C(unexpected);
    C(subentry_selections);C(subentry_hits);C(subentry_entries);C(subentry_completed);
#undef C
    pso_copy(o->misses,pe.misses,sizeof o->misses);
}
static void pso_scan_part(struct pso_scan *o,const void *expected,const void *actual,size_t n) {
    pe_need(o->started==1 && !o->complete && o->compared<=o->expected &&
        n<=o->expected-o->compared,PE_STATE,130);
    const unsigned char *a=expected;const volatile unsigned char *b=actual;
    for(size_t i=0;i<n;i++) {
        unsigned char value=b[i];
        if(a[i]!=value) {
            if(!o->differences){o->first_offset=o->compared;o->expected_value=a[i];o->actual_value=value;}
            ++o->differences;
        }
        ++o->compared;
    }
}
static void pso_scan_begin(struct pso_scan *o,size_t n) {
    pe_need(!o->started && !o->complete && !o->expected && !o->compared &&
        !o->differences && !o->first_offset && !o->expected_value && !o->actual_value && n,
        PE_STATE,131);o->expected=n;o->started=1;
}
static void pso_scan_end(struct pso_scan *o) {
    pe_need(o->started==1 && !o->complete && o->compared==o->expected,PE_STATE,132);
    o->complete=1;pe_need(!o->differences,PE_STATE,133);
}
static void pso_check(struct pso_check *out,unsigned index) {
    pe_need(index<LI2_PTR_SLOTS,PE_STATE,134);
    const struct li2_ptr_slot *slot=&pe.retained[index];
    const struct li2_pg_generation *g=&slot->generation;
    unsigned found=1;
    for(unsigned i=0;i<1;i++) {
        const struct pso_certificate *c=&pso_wire.certificates[i];
        if(c->complete && c->slot==index && c->generation==slot->identity.generation) {
            pe_need(found==1,PE_STATE,135);found=i;
        }
    }
    out->slot=index;out->generation=slot->identity.generation;
    if(found==1) {
        /* Explicit unavailable comparison for empty/unrelated startup material.
           The focal source may never use this representation. */
        pe_need(!g->installed || slot->publication.source.entry!=pso_wire.h[31],PE_STATE,141);
        return;
    }
    const struct pso_certificate *c=&pso_wire.certificates[found];
    pe_need(c->complete==1 && slot->identity.owner==&pe && slot->identity.index==index &&
        !slot->identity.reserved && g->installed==1 && g->generation==c->generation &&
        g->proof==slot->proof && g->proof==c->payload.header.table-
            offsetof(struct pe_payload,plan.table) &&
        equal(&g->layout,&c->payload.header.layout,sizeof g->layout),PE_STATE,136);
    out->certificate=found+1;out->slot=index;out->generation=g->generation;
    pso_scan_begin(&out->proof,PE_PROOF_BYTES);
    pso_scan_part(&out->proof,&c->payload,(const void *)g->proof,sizeof c->payload);
    pso_scan_part(&out->proof,c->tail,(const void *)(g->proof+sizeof c->payload),sizeof c->tail);
    pso_scan_end(&out->proof);
    pso_scan_begin(&out->code,PE_CODE_BYTES);
    for(unsigned i=0;i<3;i++)pso_scan_part(&out->code,
        c->code+(i<2?i*LI2_PE_IMAGE_BYTES:2*LI2_PE_IMAGE_BYTES),
        (const void *)pg_extent(&g->layout,i),pg_extent_bytes(i));
    pso_scan_end(&out->code);
    pso_scan_begin(&out->publication,sizeof slot->publication);
    pso_scan_part(&out->publication,&c->payload,&slot->publication,sizeof slot->publication);
    pso_scan_end(&out->publication);
}
static void pso_slots(struct pso_slots *out) {
    out->selected_slot=pe.selected_slot;out->selection=pe.selection;out->previous_selection=pe.previous_selection;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        struct pso_slot *o=&out->slots[i];const struct li2_ptr_slot *s=&pe.retained[i];
#define C(n) pso_copy(&o->n,&s->n,sizeof o->n)
        C(identity);C(proof);C(banks);C(generation);C(permit);C(claim);C(registry_count);C(registry);C(last_completed);
        C(code_allocated);C(code_registered);C(proof_allocated);C(proof_registered);
#undef C
        pso_check(&o->check,i);
    }
}
static const struct pda_state *pso_previous_domain(void) {
    return pso_index?&pso_wire.epochs[pso_index-1].terminal_domain:&pso_wire.initial_domain;
}
static void pso_domain_checkpoint(struct pso_domain_checkpoint *o,const struct pda_state *previous) {
#define C(n) pso_copy(&o->n,&pe.domain.n,sizeof o->n)
    C(directory);C(allocated);C(registered);C(next_id);C(dual_entries);
    C(dual_completed);C(initial_seal);C(initial);C(work);C(claimed);
#undef C
    pso_scan_begin(&o->cells,sizeof pe.domain.completion);
    pso_scan_part(&o->cells,previous->completion,pe.domain.completion,sizeof pe.domain.completion);
    pso_scan_end(&o->cells);
}
static void pso_mutable(unsigned char slots[LI2_PGD_MEMBERS][PAGE],
    unsigned char spill[LI2_PGD_MEMBERS][PAGE],unsigned char directory[LI2_JD_DOMAIN_BYTES]) {
    const struct li2_pgd_view *v=&pe.domain.work.view;
    pe_need(pe.domain.work.bound==1 && v->count && v->count<=LI2_PGD_MEMBERS &&
        v->directory==pe.domain.directory &&
        ((pe.p.phase==LI2_PG_EXECUTING && li2_pgd_owner_view(&pe.token)==v) ||
         (pe.p.phase==LI2_PG_CLOSED && pe.domain.work.completion==1 &&
          pe.domain.work.receipt<LI2_PGD_RECEIPTS &&
          pda_receipt(&pe.domain.completion[pe.domain.work.receipt]))),PE_STATE,145);
    for(unsigned i=0;i<v->count;i++) {
        const struct li2_pgd_ref *r=&v->member[i].identity;
        pe_need(r->slot<LI2_PTR_SLOTS && r->bank<2 &&
            equal(&r->layout,&pe.retained[r->slot].generation.layout,sizeof r->layout) &&
            r->generation==pe.retained[r->slot].generation.generation,PE_STATE,146);
        pso_copy(slots[i],(const void *)r->layout.slots,PAGE);
        pso_copy(spill[i],(const void *)r->layout.spill,PAGE);
    }
    pso_copy(directory,(const void *)v->directory,LI2_JD_DOMAIN_BYTES);
}
static void pso_stage(struct pso_stage *o,const struct pda_state *previous) {
    pso_copy(&o->entry,&pe.entry,sizeof o->entry);
    pso_copy(&o->progress,&pe.p,sizeof o->progress);pso_counts(&o->counts);pso_slots(&o->slots);
    pso_copy(&o->transfer,&pe.transfer,sizeof o->transfer);
    pso_copy(&o->source,li2_pg_source_progress(),sizeof o->source);
    pso_copy(&o->domain_source,li2_pgd_source_progress(),sizeof o->domain_source);
    pso_copy(&o->rseq,li2_pg_rseq_progress(),sizeof o->rseq);
    pso_copy(&o->state,li2_rseq_snapshot(),sizeof o->state);
    pso_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    o->busy=pe_busy;o->active=pe_active;o->failing=pe_failing;o->resuming=pe.resuming;
    o->route=selected_pending_route;o->pending=selected_step_pending;
    pso_domain_checkpoint(&o->domain,previous);
}
static void pso_info(struct pso_epoch_info *o) {
#define C(n) o->n=pe.n
    C(selected_bank);C(warm);C(initialized);C(registered);
    C(close_started);C(close_complete);C(prepare_started);C(prepare_complete);C(build_started);C(build_returned);
    C(redirected);C(exit_seen);C(exit_index);C(recovery_started);C(recovery_complete);C(guest_data_fault);
    C(cleanup_started);C(cleanup_complete);C(consumed);C(plan_proofs);C(none_proofs);
    C(code_allocation);C(proof_allocation);C(build_result);C(recovery_result);C(release_result);
    C(flags);C(gpr_written);C(flags_written);C(token);C(session);C(ref);C(recovered);C(final_fetch);
    C(proof_exit);C(claim_proof);C(claim_spill);C(claim_slots);C(proof_before);
    C(reopen_proof);
#undef C
    pso_copy(o->code_exit,pe.code_exit,sizeof o->code_exit);
    pso_copy(o->claim_code,pe.claim_code,sizeof o->claim_code);
    pso_copy(o->bank_before,pe.bank_before,sizeof o->bank_before);
    pso_copy(o->reopen_code,pe.reopen_code,sizeof o->reopen_code);
    o->ticket=(uintptr_t)pe.ticket;
    pso_copy(o->live,pe.live,sizeof o->live);pso_copy(&o->recovery_scratch,&pe.recovery_scratch,sizeof o->recovery_scratch);
    o->code_allocated=PE_SLOT(code_allocated);o->proof_allocated=PE_SLOT(proof_allocated);
    o->code_registered=PE_SLOT(code_registered);o->proof_registered=PE_SLOT(proof_registered);
    o->registry_count=PE_SLOT(registry_count);
    pso_copy(o->registry,PE_SLOT(registry),sizeof o->registry);pso_copy(o->banks,PE_SLOT(banks),sizeof o->banks);
}
static void pso_registry(struct pso_registry *out) {
    pe_need(!out->complete && protected_count && protected_count<=RANGES,PE_STATE,100);
    const struct image *b=bridge_runtime_image();
    pe_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,PE_STATE,101);
    pso_copy(&out->bridge,b,sizeof *b);pso_copy(out->ph,b->ph,b->n*sizeof *b->ph);
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    pso_copy(out->ranges,protected,protected_count*sizeof *protected);
    pso_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void pso_initialize(void) {
    __asm__ volatile(""::"r"(&pso_step_frame_fp_alignment):"memory");
    pe_need(!pso_ready && !pso_finished && !pe.p.serial,PE_STATE,102);
    uint64_t *h=pso_wire.h;
    h[0]=PSO_MAGIC;h[1]=7;h[2]=sizeof pso_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&pso_wire,sizeof pso_wire),PE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pso_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(pso_wire.sink_initial.st_mode) && (pso_wire.sink_initial.st_mode&07777)==0600 &&
        pso_wire.sink_initial.st_nlink==1 && !pso_wire.sink_initial.st_size,PE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_SUBENTRY_APP_MODE");
    pe_need(mode && mode[0]=='0' && !mode[1],PE_STATE,105);h[19]=(unsigned)(mode[0]-'0');
    pso_copy(&pso_wire.main,&original_main,sizeof original_main);
    pso_copy(&pso_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    pso_copy(&pso_wire.hardware,&selected_hardware,sizeof selected_hardware);
    pso_copy(&pso_wire.session,&selected_session,sizeof selected_session);
    h[20]=(uintptr_t)&pe;h[21]=(uintptr_t)&pso_wire;h[22]=(uintptr_t)li2_pg_source_progress();
    h[23]=(uintptr_t)li2_pg_rseq_progress();h[24]=(uintptr_t)&selected_chain;
    h[25]=(uintptr_t)li2_tf_chain_span_progress();
    h[26]=(uintptr_t)&pe.retained[0];h[27]=(uintptr_t)&pe.retained[1];h[28]=LI2_PTR_SLOTS;
    h[29]=sizeof(struct li2_ptr_slot);h[30]=sizeof(struct li2_ptr_slot_ref);
    h[31]=original_main.bias+LI2_PSO_ROOT_RVA;h[32]=original_main.bias+LI2_PSO_HEAD_RVA;
    h[33]=(uintptr_t)&pe.domain;h[34]=(uintptr_t)li2_pgd_source_progress();
    h[39]=original_main.bias+LI2_PSO_NEXT_RVA;
    h[53]=original_main.bias+LI2_PSO_EXIT_RVA;h[54]=original_main.bias+LI2_PSO_TRAMPOLINE_RVA;
    h[41]=sizeof(struct pda_state);h[42]=sizeof(struct pda_completion);
    h[43]=sizeof(struct pda_work);h[44]=LI2_JD_DOMAIN_BYTES;h[45]=LI2_PGD_RECEIPTS;
    pso_registry(&pso_wire.startup_registry);pso_ready=1;
}
static void pso_closed(void) {
    if(!pso_kind)return;
    pe_need(pe.transfer.previous<2,PE_STATE,120);
    struct pso_epoch *o=&pso_wire.epochs[pso_index];struct pso_predecessor *x=&o->predecessor;
    pe_need(pe.transfer.previous==o->h[15] && !x->complete,PE_STATE,117);
    const struct li2_tf_chain_slot *slot=&selected_chain.slots[pe.transfer.previous];
    pso_copy(x->closed,slot,sizeof x->closed);
    const volatile unsigned char *actual=(const void *)&slot->unexpected;
    for(size_t i=0;i<sizeof slot->unexpected;i++){++x->unexpected_compared;if(actual[i])++x->unexpected_nonzero;}
    x->complete=1;pso_copy(&o->before,&pe.before,sizeof pe.before);o->h[4]=1;
}
static void pso_certificate(void) {
    const unsigned ci=0;struct pso_certificate *c=&pso_wire.certificates[ci];
    if(c->complete) {
        pe_need(pso_index==1 && c->slot==pe.selected_slot &&
            c->generation==PE_SLOT(generation).generation && c->entry==pe_payload()->source.entry &&
            c->entry==pso_wire.h[31] && pe.entry.target.pc==pso_wire.h[32] &&
            pe.entry.target.head==64 && pe.entry.target.member==1 && pe.entry.target.local==0,
            PE_STATE,137);return;
    }
    pe_need(pso_index==0 && pe.selected_slot<LI2_PTR_SLOTS &&
        pe.selection.index==pe.selected_slot && pe.selection.generation==PE_SLOT(generation).generation &&
        pe_payload()->source.entry==pso_wire.h[31] && pe.entry.target.pc==pso_wire.h[31] &&
        pe.entry.target.head==0,PE_STATE,138);
    c->index=ci;c->slot=pe.selected_slot;c->generation=PE_SLOT(generation).generation;
    c->entry=pe_payload()->source.entry;c->proof_bytes=PE_PROOF_BYTES;c->code_bytes=PE_CODE_BYTES;
    c->publication_bytes=sizeof(struct pe_payload);
    pso_copy(&c->payload,pe_payload(),sizeof c->payload);
    pso_copy(c->tail,(const unsigned char *)pe_payload()+sizeof c->payload,sizeof c->tail);
    for(unsigned i=0;i<3;i++)pso_copy(c->code+(i<2?i*LI2_PE_IMAGE_BYTES:2*LI2_PE_IMAGE_BYTES),
        (const void *)pg_extent(&PE_SLOT(generation).layout,i),pg_extent_bytes(i));
    c->complete=1;
}
static void pso_entered(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pso_kind)return;
    pe_need(pso_kind==2 && !pso_capturing && pe_ready() && pe.p.phase==LI2_PG_EXECUTING && pe_active && pe_busy,PE_STATE,111);
    pso_capturing=1;struct pso_epoch *o=&pso_wire.epochs[pso_index];
    pe_need(o->h[4] && !o->h[5],PE_STATE,112);o->h[5]=1;o->h[6]=pso_wire.raw_ingress[0];
    /* pe.before now includes the actual pre-entry TLS observation. */
    pso_copy(&o->before,&pe.before,sizeof pe.before);
    pe_need(!li2_lifecycle_pso_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,&o->before_memory),PE_STATE,113);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,103);pe_tls(&o->returned);
    pso_certificate();pso_stage(&o->entered,pso_previous_domain());
    pso_mutable(o->initial_slots,o->initial_spill,o->initial_directory);
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    pe_need(r->lifetime_mode==LI2_PGU_UNREGISTERED && !r->word_observed &&
        !r->address && li2_pgu_progress_valid(r),PE_STATE,147);
    /* h7/h8: unavailable value and attempted=0, not an observed zero word. */
    o->h[25]=LI2_PGU_UNREGISTERED;o->h[26]=1;pso_capturing=0;
}
static void pso_terminal(unsigned failed) {
    if(!pso_ready || !pso_kind)return;
    if(failed){pso_wire.h[46]=1;pso_kind=0;return;}
    if(pso_capturing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_need(pso_kind==2,PE_STATE,114);pso_capturing=1;
    struct pso_epoch *o=&pso_wire.epochs[pso_index];pe_need(o->h[5] && !o->h[9],PE_STATE,115);
    o->h[9]=1;o->h[10]=failed;o->h[11]=pso_wire.raw_ingress[0];
    o->h[12]=(uint64_t)li2_lifecycle_pso_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],failed,&o->after_memory);
    pso_copy(&o->after,&pe.after,sizeof pe.after);if(o->after.complete)pe_tls(&o->after);
    pso_copy(&o->terminal_domain,&pe.domain,sizeof o->terminal_domain);
    pso_stage(&o->terminal,&o->terminal_domain);pso_info(&o->info);
    pso_mutable(o->terminal_slots,o->terminal_spill,o->terminal_directory);
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    pe_need(r->lifetime_mode==LI2_PGU_UNREGISTERED && !r->word_observed &&
        !r->address && li2_pgu_progress_valid(r),PE_STATE,148);
    /* h13 remains unavailable; h27 separately records attempted=0. */
    o->h[28]=LI2_PGU_UNREGISTERED;o->h[29]=1;pso_registry(&o->terminal_registry);
    o->h[14]=1;
    struct pso_next *n=&pso_wire.next[pso_index];
    pe_need(pso_wire.raw_ingress[0]!=UINT64_MAX && !n->expected_ordinal,PE_STATE,123);
    n->expected_ordinal=pso_wire.raw_ingress[0]+1;
    pso_kind=0;pso_capturing=0;
}
static void pso_finish(unsigned status,unsigned code,long detail) {
    if(!pso_ready || pso_finished)return;
    pso_finished=1;pso_wire.h[47]=1;pso_wire.h[48]=status;pso_wire.h[49]=code;pso_wire.h[50]=(uint64_t)detail;
    pso_counts(&pso_wire.final_counts);pso_copy(&pso_wire.final_progress,&pe.p,sizeof pe.p);
    uint64_t row[]={1,status,code,detail<0?0ULL-(uint64_t)detail:(uint64_t)detail,detail<0,
        pe.p.phase,pe.p.serial,pe.selected_slot<2?PE_SLOT(generation).generation:0,pe.selected_slot<2?PE_SLOT(generation).build_serial:0,
        pe.offers,pe.cold_attempts,pe.publications,pe.hits,pe.cancelled,pe.retirements,pe.permit_claims,
        pe.entries,pe.completed,pe.unexpected,pe.selected_slot<2?PE_SLOT(claim).valid:0,pe.p.opened_pages,pe.p.closed_pages,
        pe.p.anchor_released,pe.p.registration_rechecked,pe.guest_data_fault,pe.recovery_complete,
        pe.p.first_error,pe_active,pe_busy,pe.selected_slot,
        pe.retained[0].identity.generation,pe.retained[1].identity.generation,
        pe.retained[0].claim.valid,pe.retained[1].claim.valid,
        pe.retained[0].last_completed,pe.retained[1].last_completed,
        pe.domain.work.view.count,pe.domain.dual_entries,pe.domain.dual_completed};
    _Static_assert(sizeof row==39*8,"exact active-domain terminal scalar row");
    const uint64_t sub[]={1,status,code,pe.subentry_selections,pe.subentry_hits,
        pe.subentry_entries,pe.subentry_completed,pe.entry.token.serial,pe.entry.generation,
        pe.entry.target.root,pe.entry.target.pc,pe.entry.target.head,pe.entry.slot,pe.entry.bank,pe.entry.complete};
    _Static_assert(sizeof sub==15*8,"exact separate subentry terminal row");
    pso_copy(pso_wire.final_subentry,sub,sizeof sub);
    pso_copy(pso_wire.final_row,row,sizeof row);pso_wire.h[35]=pso_epochs;pso_wire.h[36]=pe.domain.dual_entries;pso_wire.h[37]=pe.domain.next_id;
    pso_wire.h[38]=pso_kind;pso_wire.h[40]=pe.domain.directory;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pso_wire.sink_terminal,0,0,0,0);
    pso_wire.h[51]=(uint64_t)flags;pso_wire.h[52]=(uint64_t)result;
    const struct stat *a=&pso_wire.sink_initial,*b=&pso_wire.sink_terminal;
    if(result || flags!=(long)pso_wire.h[16] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof pso_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&pso_wire+at),sizeof pso_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof pso_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof pso_wire)return;
    const uint64_t footer[]={PSO_FOOTER,7,sizeof pso_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
static void pso_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pso_ready)return;
    if(pso_wire.raw_ingress[0]==UINT64_MAX || pso_capturing) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pso_wire.raw_ingress[0];
    unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    if(pso_wire.raw_ingress[i]==UINT64_MAX) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++pso_wire.raw_ingress[i];
    for(unsigned j=0;j<2;j++) {
        struct pso_next *n=&pso_wire.next[j];
        if(n->expected_ordinal && !n->ingress_complete) {
            n->raw_ordinal=pso_wire.raw_ingress[0];n->slot_index=(uint64_t)selected_chain.active;
            n->capture_result=(uint64_t)le_capture(&n->frame,sig,si,uc);n->ingress_complete=1;
        }
    }
}
/* Actual same-handler ordinary close, before successor preparation. Neither
   raw frame is edited; only actual TLS results are appended after close. */
void li2_pso_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    if(!pso_ready)return;
    for(unsigned j=0;j<2;j++) {
        struct pso_next *n=&pso_wire.next[j];
        if(!n->expected_ordinal || n->closed_complete)continue;
        uintptr_t next=pso_wire.h[j?39:54];
        pe_need(!pso_capturing && n->ingress_complete && !n->capture_result &&
            n->expected_ordinal==n->raw_ordinal && n->raw_ordinal==pso_wire.raw_ingress[0] &&
            chain==&selected_chain && n->slot_index<2 && slot==&chain->slots[n->slot_index] &&
            chain->active==(int)n->slot_index && chain->in_handler==1 && chain->pending==1 &&
            handling==1 && chain->event_id>slot->event_id && !chain->first_error && !chain->unexpected_events &&
            slot->phase==LI2_CHAIN_CLOSED && !slot->unexpected_frame_observed &&
            slot->decoded.pc==pso_wire.h[53] && slot->owner.actual_post_pc==next &&
            n->frame.complete && (uintptr_t)n->frame.frame.greg[REG_RIP]==next,PE_STATE,122);
        pso_capturing=1;n->event_id=chain->event_id;pso_copy(&n->closed,slot,sizeof n->closed);
        pe_tls(&n->frame);n->tls_complete=1;n->closed_complete=1;pso_capturing=0;
    }
}
static void pso_begin(int sig,siginfo_t *si,ucontext_t *uc,unsigned proposed_slot) {
    if(!pso_ready)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(pc!=pso_wire.h[31] && pc!=pso_wire.h[32])return;
    /* The selector observes only after actual profile eligibility succeeded. */
    pe_need(!pso_kind && !pso_capturing && proposed_slot<LI2_PTR_SLOTS &&
        selected_chain.active>=0 && selected_chain.active<2 && pso_epochs<2 &&
        pc==pso_wire.h[pso_epochs?32:31],PE_STATE,108);
    pso_capturing=1;pso_index=pso_epochs++;
    if(!pso_index)pso_copy(&pso_wire.initial_domain,&pe.domain,sizeof pe.domain);
    struct pso_epoch *o=&pso_wire.epochs[pso_index];uint64_t *h=o->h;
    h[0]=1;h[1]=pso_index;h[2]=pc;h[3]=pso_wire.raw_ingress[0];
    pso_counts(&o->prior_counts);pso_slots(&o->prior);pso_registry(&o->initial_registry);
    pso_domain_checkpoint(&o->prior_domain,pso_previous_domain());
    pso_copy(o->predecessor.before_prefix,&selected_chain.slots[selected_chain.active],PSO_SLOT_PREFIX);
    pe_need(!le_capture(&o->ingress,sig,si,uc),PE_FRAME,101);
    h[15]=(unsigned)selected_chain.active;h[16]=(uintptr_t)selected_chain.session;
    h[17]=selected_chain.event_id;h[18]=selected_chain.sequence;h[19]=(unsigned)selected_chain.active;
    h[20]=(unsigned)selected_chain.pending;h[21]=(unsigned)selected_chain.in_handler;
    h[22]=selected_chain.first_error;h[23]=selected_chain.initialized;h[24]=proposed_slot;
    pso_kind=2;pso_capturing=0;
}
