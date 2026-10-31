/* Distinct retained-two observer. Every mutable epoch/frame is literal.
   Two shared immutable certificate literals are checked by complete byte scans
   at each captured activation/checkpoint; no digest replaces those bytes. */
#include "persistent_retained_two_observe_memory.h"
#include "persistent_retained_two_capture_config.h"
#if LI2_PERSISTENT_RETAINED_TWO_CAPTURE != 1 || LI2_PERSISTENT_RETAINED_TWO != 1 || LI2_PTR_CAPTURE_VERSION != 3 || LI2_PERSISTENT_DISPATCH != 1 || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || defined(LI2_PERSISTENT_GROUP_CAPTURE)
#error "actual retained-two capture profile"
#endif
#define PTR2O_MAGIC UINT64_C(0x334f32525449324c)
#define PTR2O_FOOTER UINT64_C(0x334632525449324c)
struct ptr2o_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct ptr2o_counts {
    uint64_t next_serial,next_generation,offers,publications,hits,cold_attempts;
    uint64_t cancelled,retirements,permit_claims,entries,completed,unexpected;
    uint64_t misses[LI2_PGD_REASON_COUNT];
};
/* Complete bounded comparison evidence against one literal certificate. */
struct ptr2o_scan {
    uint64_t started,complete,expected,compared,differences,first_offset,expected_value,actual_value;
};
struct ptr2o_check {
    uint64_t certificate,slot,generation;
    struct ptr2o_scan proof,code,publication;
};
/* Every retained slot field except the shared immutable publication mirror.
   Its complete bytes are checked against the same certificate payload below. */
struct ptr2o_slot {
    struct li2_ptr_slot_ref identity;
    uintptr_t proof;
    struct ped_bank banks[2];
    struct li2_pg_generation generation;
    struct ped_permit permit;
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    uint64_t last_completed;
    unsigned code_allocated,code_registered,proof_allocated,proof_registered;
    struct ptr2o_check check;
};
struct ptr2o_slots {
    unsigned selected_slot,reserved;
    struct li2_ptr_slot_ref selection,previous_selection;
    struct ptr2o_slot slots[LI2_PTR_SLOTS];
};
struct ptr2o_stage {
    struct li2_pg_progress progress;
    struct ptr2o_counts counts;
    struct ptr2o_slots slots;
    struct li2_span_transfer_progress transfer;
    struct li2_pg_source_progress source;
    struct li2_pg_rseq_progress rseq;
    struct li2_rseq_state state;
    struct li2_fetch_progress fetch;
    unsigned busy,active,failing,resuming,route,pending;
};
struct ptr2o_epoch_info {
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
#define PTR2O_SLOT_PREFIX offsetof(struct li2_tf_chain_slot,owner.step.before)
#define PTR2O_SLOT_UNEXPECTED offsetof(struct li2_tf_chain_slot,unexpected)
struct ptr2o_predecessor {
    uint64_t complete,unexpected_compared,unexpected_nonzero;
    unsigned char before_prefix[PTR2O_SLOT_PREFIX];
    unsigned char closed[PTR2O_SLOT_UNEXPECTED];
};
struct ptr2o_certificate {
    uint64_t complete,index,slot,generation,entry,proof_bytes,code_bytes,publication_bytes;
    struct pe_payload payload;
    unsigned char tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char code[PE_CODE_BYTES];
};
struct ptr2o_epoch {
    uint64_t h[32];
    struct ptr2o_counts prior_counts;
    struct ptr2o_slots prior;
    struct ptr2o_registry initial_registry,terminal_registry;
    struct ptr2o_predecessor predecessor;
    struct le_frame ingress,before,returned,after;
    struct ptr2o_stage entered,terminal;
    struct ptr2o_epoch_info info;
    struct li2_ptr2o_memory before_memory,after_memory;
    unsigned char initial_slots[PAGE],terminal_slots[PAGE];
};
struct ptr2o_miss_plan {
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
#define PTR2O_SLOT_AFTER (offsetof(struct li2_tf_chain_slot,owner.step.after)+sizeof(struct li2_step_frame))
#define PTR2O_CHAIN_PREFIX offsetof(struct li2_tf_chain,slots)
struct ptr2o_slot_progress {
    uint64_t complete,index;
    unsigned char chain[PTR2O_CHAIN_PREFIX];
    unsigned char prefix[PTR2O_SLOT_PREFIX];
    unsigned char suffix[PTR2O_SLOT_UNEXPECTED-PTR2O_SLOT_AFTER];
};
struct ptr2o_miss {
    uint64_t h[32];
    struct ptr2o_slots prior;
    struct le_frame before,returned,next_trace;
    struct ptr2o_stage held,resumed;
    struct ptr2o_registry initial_registry,terminal_registry;
    struct ptr2o_slot_progress closed_slot,resumed_slot,next_slot;
    struct li2_pg_miss miss;
    struct ptr2o_miss_plan plan;
};
struct ptr2o_next {
    uint64_t expected_ordinal,raw_ordinal,capture_result,ingress_complete;
    uint64_t slot_index,closed_complete,tls_complete,event_id;
    struct le_frame frame;
    struct li2_tf_chain_slot closed;
};
struct ptr2o_wire {
    uint64_t h[64],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct ptr2o_registry startup_registry;
    struct ptr2o_certificate certificates[2];
    struct ptr2o_epoch epochs[3];
    struct ptr2o_miss misses[2];
    struct ptr2o_next next;
    struct ptr2o_counts final_counts;
    struct li2_pg_progress final_progress;
    uint64_t final_row[36];
};
static struct ptr2o_wire ptr2o_wire;
static unsigned ptr2o_ready,ptr2o_finished,ptr2o_capturing,ptr2o_kind,ptr2o_index,ptr2o_epochs;
static unsigned ptr2o_misses,ptr2o_miss_index,ptr2o_miss_next,ptr2o_miss_closing;
static const uint64_t ptr2o_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct ptr2o_wire)+64<4U*1024U*1024U,"shared immutable retained-two evidence within original4MiB record bound");
_Static_assert(sizeof(struct ptr2o_wire)==4169600 && sizeof(struct ptr2o_certificate)==434240 &&
    sizeof(struct ptr2o_epoch)==693504 && sizeof(struct ptr2o_miss)==473344 &&
    sizeof(struct ptr2o_stage)==85464 && sizeof(struct ptr2o_slots)==68936,
    "exact retained-two source extent; independent actual DWARF required");
static void ptr2o_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void ptr2o_counts(struct ptr2o_counts *o) {
#define C(n) o->n=pe.n
    C(next_serial);C(next_generation);C(offers);C(publications);C(hits);C(cold_attempts);
    C(cancelled);C(retirements);C(permit_claims);C(entries);C(completed);C(unexpected);
#undef C
    ptr2o_copy(o->misses,pe.misses,sizeof o->misses);
}
static void ptr2o_scan_part(struct ptr2o_scan *o,const void *expected,const void *actual,size_t n) {
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
static void ptr2o_scan_begin(struct ptr2o_scan *o,size_t n) {
    pe_need(!o->started && !o->complete && !o->expected && !o->compared &&
        !o->differences && !o->first_offset && !o->expected_value && !o->actual_value && n,
        PE_STATE,131);o->expected=n;o->started=1;
}
static void ptr2o_scan_end(struct ptr2o_scan *o) {
    pe_need(o->started==1 && !o->complete && o->compared==o->expected,PE_STATE,132);
    o->complete=1;pe_need(!o->differences,PE_STATE,133);
}
static void ptr2o_check(struct ptr2o_check *out,unsigned index) {
    pe_need(index<LI2_PTR_SLOTS,PE_STATE,134);
    const struct li2_ptr_slot *slot=&pe.retained[index];
    const struct li2_pg_generation *g=&slot->generation;
    unsigned found=2;
    for(unsigned i=0;i<2;i++) {
        const struct ptr2o_certificate *c=&ptr2o_wire.certificates[i];
        if(c->complete && c->slot==index && c->generation==slot->identity.generation) {
            pe_need(found==2,PE_STATE,135);found=i;
        }
    }
    out->slot=index;out->generation=slot->identity.generation;
    if(found==2) {
        /* Explicit unavailable comparison for empty/unrelated startup material.
           Focal A/B may never silently use this representation. */
        pe_need(!g->installed || (slot->publication.source.entry!=ptr2o_wire.h[31] &&
            slot->publication.source.entry!=ptr2o_wire.h[32]),PE_STATE,141);
        return;
    }
    const struct ptr2o_certificate *c=&ptr2o_wire.certificates[found];
    pe_need(c->complete==1 && slot->identity.owner==&pe && slot->identity.index==index &&
        !slot->identity.reserved && g->installed==1 && g->generation==c->generation &&
        g->proof==slot->proof && g->proof==c->payload.header.table-
            offsetof(struct pe_payload,plan.table) &&
        equal(&g->layout,&c->payload.header.layout,sizeof g->layout),PE_STATE,136);
    out->certificate=found+1;out->slot=index;out->generation=g->generation;
    ptr2o_scan_begin(&out->proof,PE_PROOF_BYTES);
    ptr2o_scan_part(&out->proof,&c->payload,(const void *)g->proof,sizeof c->payload);
    ptr2o_scan_part(&out->proof,c->tail,(const void *)(g->proof+sizeof c->payload),sizeof c->tail);
    ptr2o_scan_end(&out->proof);
    ptr2o_scan_begin(&out->code,PE_CODE_BYTES);
    for(unsigned i=0;i<3;i++)ptr2o_scan_part(&out->code,
        c->code+(i<2?i*LI2_PE_IMAGE_BYTES:2*LI2_PE_IMAGE_BYTES),
        (const void *)pg_extent(&g->layout,i),pg_extent_bytes(i));
    ptr2o_scan_end(&out->code);
    ptr2o_scan_begin(&out->publication,sizeof slot->publication);
    ptr2o_scan_part(&out->publication,&c->payload,&slot->publication,sizeof slot->publication);
    ptr2o_scan_end(&out->publication);
}
static void ptr2o_slots(struct ptr2o_slots *out) {
    out->selected_slot=pe.selected_slot;out->selection=pe.selection;out->previous_selection=pe.previous_selection;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        struct ptr2o_slot *o=&out->slots[i];const struct li2_ptr_slot *s=&pe.retained[i];
#define C(n) ptr2o_copy(&o->n,&s->n,sizeof o->n)
        C(identity);C(proof);C(banks);C(generation);C(permit);C(registry_count);C(registry);C(last_completed);
        C(code_allocated);C(code_registered);C(proof_allocated);C(proof_registered);
#undef C
        ptr2o_check(&o->check,i);
    }
}
static void ptr2o_stage(struct ptr2o_stage *o) {
    ptr2o_copy(&o->progress,&pe.p,sizeof o->progress);ptr2o_counts(&o->counts);ptr2o_slots(&o->slots);
    ptr2o_copy(&o->transfer,&pe.transfer,sizeof o->transfer);
    ptr2o_copy(&o->source,li2_pg_source_progress(),sizeof o->source);
    ptr2o_copy(&o->rseq,li2_pg_rseq_progress(),sizeof o->rseq);
    ptr2o_copy(&o->state,li2_rseq_snapshot(),sizeof o->state);
    ptr2o_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    o->busy=pe_busy;o->active=pe_active;o->failing=pe_failing;o->resuming=pe.resuming;
    o->route=selected_pending_route;o->pending=selected_step_pending;
}
static void ptr2o_info(struct ptr2o_epoch_info *o) {
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
    ptr2o_copy(o->code_exit,pe.code_exit,sizeof o->code_exit);
    ptr2o_copy(o->claim_code,pe.claim_code,sizeof o->claim_code);
    ptr2o_copy(o->bank_before,pe.bank_before,sizeof o->bank_before);
    ptr2o_copy(o->reopen_code,pe.reopen_code,sizeof o->reopen_code);
    o->ticket=(uintptr_t)pe.ticket;
    ptr2o_copy(o->live,pe.live,sizeof o->live);ptr2o_copy(&o->recovery_scratch,&pe.recovery_scratch,sizeof o->recovery_scratch);
    o->code_allocated=PE_SLOT(code_allocated);o->proof_allocated=PE_SLOT(proof_allocated);
    o->code_registered=PE_SLOT(code_registered);o->proof_registered=PE_SLOT(proof_registered);
    o->registry_count=PE_SLOT(registry_count);
    ptr2o_copy(o->registry,PE_SLOT(registry),sizeof o->registry);ptr2o_copy(o->banks,PE_SLOT(banks),sizeof o->banks);
}
static void ptr2o_registry(struct ptr2o_registry *out) {
    pe_need(!out->complete && protected_count && protected_count<=RANGES,PE_STATE,100);
    const struct image *b=bridge_runtime_image();
    pe_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,PE_STATE,101);
    ptr2o_copy(&out->bridge,b,sizeof *b);ptr2o_copy(out->ph,b->ph,b->n*sizeof *b->ph);
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    ptr2o_copy(out->ranges,protected,protected_count*sizeof *protected);
    ptr2o_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void ptr2o_initialize(void) {
    __asm__ volatile(""::"r"(&ptr2o_step_frame_fp_alignment):"memory");
    pe_need(!ptr2o_ready && !ptr2o_finished && !pe.p.serial,PE_STATE,102);
    uint64_t *h=ptr2o_wire.h;
    h[0]=PTR2O_MAGIC;h[1]=3;h[2]=sizeof ptr2o_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&ptr2o_wire,sizeof ptr2o_wire),PE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&ptr2o_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(ptr2o_wire.sink_initial.st_mode) && (ptr2o_wire.sink_initial.st_mode&07777)==0600 &&
        ptr2o_wire.sink_initial.st_nlink==1 && !ptr2o_wire.sink_initial.st_size,PE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_RETAINED_TWO_APP_MODE");
    pe_need(mode && mode[0]=='0' && !mode[1],PE_STATE,105);h[19]=(unsigned)(mode[0]-'0');
    ptr2o_copy(&ptr2o_wire.main,&original_main,sizeof original_main);
    ptr2o_copy(&ptr2o_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    ptr2o_copy(&ptr2o_wire.hardware,&selected_hardware,sizeof selected_hardware);
    ptr2o_copy(&ptr2o_wire.session,&selected_session,sizeof selected_session);
    h[20]=(uintptr_t)&pe;h[21]=(uintptr_t)&ptr2o_wire;h[22]=(uintptr_t)li2_pg_source_progress();
    h[23]=(uintptr_t)li2_pg_rseq_progress();h[24]=(uintptr_t)&selected_chain;
    h[25]=(uintptr_t)li2_tf_chain_span_progress();
    h[26]=(uintptr_t)&pe.retained[0];h[27]=(uintptr_t)&pe.retained[1];h[28]=LI2_PTR_SLOTS;
    h[29]=sizeof(struct li2_ptr_slot);h[30]=sizeof(struct li2_ptr_slot_ref);
    h[31]=original_main.bias+LI2_PTR_A_RVA;h[32]=original_main.bias+LI2_PTR_B_RVA;
    h[33]=original_main.bias+LI2_PTR_M_RVA;h[34]=original_main.bias+LI2_PTR_MJUMP_RVA;
    h[39]=original_main.bias+LI2_PTR_NEXT_RVA;
    ptr2o_registry(&ptr2o_wire.startup_registry);ptr2o_ready=1;
}
static void ptr2o_slot_progress(struct ptr2o_slot_progress *out,unsigned index) {
    pe_need(!out->complete && index<2,PE_STATE,119);out->index=index;
    const struct li2_tf_chain_slot *slot=&selected_chain.slots[index];
    ptr2o_copy(out->chain,&selected_chain,sizeof out->chain);
    ptr2o_copy(out->prefix,slot,sizeof out->prefix);
    ptr2o_copy(out->suffix,(const unsigned char *)slot+PTR2O_SLOT_AFTER,sizeof out->suffix);
    out->complete=1;
}
static void ptr2o_closed(void) {
    if(!ptr2o_kind)return;
    pe_need(pe.transfer.previous<2,PE_STATE,120);
    if(ptr2o_kind==1) {
        struct ptr2o_miss *o=&ptr2o_wire.misses[ptr2o_miss_index];
        pe_need(pe.transfer.previous==o->h[15] && !o->h[4],PE_STATE,121);
        ptr2o_copy(&o->before,&pe.before,sizeof pe.before);
        ptr2o_slot_progress(&o->closed_slot,pe.transfer.previous);o->h[4]=1;
    } else {
        struct ptr2o_epoch *o=&ptr2o_wire.epochs[ptr2o_index];struct ptr2o_predecessor *x=&o->predecessor;
        pe_need(pe.transfer.previous==o->h[15] && !x->complete,PE_STATE,117);
        const struct li2_tf_chain_slot *slot=&selected_chain.slots[pe.transfer.previous];
        ptr2o_copy(x->closed,slot,sizeof x->closed);
        const volatile unsigned char *actual=(const void *)&slot->unexpected;
        for(size_t i=0;i<sizeof slot->unexpected;i++){++x->unexpected_compared;if(actual[i])++x->unexpected_nonzero;}
        x->complete=1;ptr2o_copy(&o->before,&pe.before,sizeof pe.before);o->h[4]=1;
    }
}
static void ptr2o_miss_plan(struct ptr2o_miss_plan *out,const struct li2_pg_plan *p) {
#define C(n) out->n=p->n
    C(version);C(bytes);C(ready);C(result);C(heads);C(exits);C(stores);C(source_bytes);
    C(source_mask);C(decoder_result);C(guard_result);C(reserved);C(links);C(reserved2);C(entry);C(layout);
#undef C
    ptr2o_copy(out->member_heads,p->member_heads,sizeof out->member_heads);
    ptr2o_copy(out->page,p->page,sizeof out->page);ptr2o_copy(out->source,p->source,sizeof out->source);
    ptr2o_copy(&out->table,&p->table,sizeof out->table);out->scan_started=1;
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
static void ptr2o_miss_held(void) {
    if(!ptr2o_kind)return;
    pe_need(ptr2o_kind==1 && !ptr2o_wire.misses[ptr2o_miss_index].h[5],PE_STATE,109);
    struct ptr2o_miss *o=&ptr2o_wire.misses[ptr2o_miss_index];ptr2o_stage(&o->held);
    ptr2o_miss_plan(&o->plan,&pe.cold);ptr2o_copy(&o->miss,&pe.miss,sizeof o->miss);pe_tls(&o->before);
    pe_need(o->plan.scan_started==1 && o->plan.scan_complete==1 && !o->plan.nonzero &&
        o->plan.scanned==sizeof pe.cold - offsetof(struct li2_pg_plan,image) - sizeof pe.cold.table,PE_PLAN,100);
    o->h[5]=1;
}
static void ptr2o_cancelled(int sig,siginfo_t *si,ucontext_t *uc,enum li2_chain_result result) {
    if(!ptr2o_kind)return;
    struct ptr2o_miss *o=&ptr2o_wire.misses[ptr2o_miss_index];
    pe_need(ptr2o_kind==1 && o->h[5] && !o->h[6] && !ptr2o_capturing && !ptr2o_miss_next && !ptr2o_miss_closing &&
        selected_chain.active>=0 && selected_chain.active<2,PE_STATE,110);
    ptr2o_capturing=1;o->h[6]=1;o->h[7]=ptr2o_wire.raw_ingress[0];o->h[8]=(unsigned)result;
    ptr2o_stage(&o->resumed);ptr2o_slot_progress(&o->resumed_slot,(unsigned)selected_chain.active);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,102);pe_tls(&o->returned);
    ptr2o_registry(&o->terminal_registry);o->h[9]=1;ptr2o_miss_next=ptr2o_miss_index+1;
    ptr2o_kind=0;ptr2o_capturing=0;
}
static void ptr2o_certificate(void) {
    unsigned ci=ptr2o_index==1?1U:0U;struct ptr2o_certificate *c=&ptr2o_wire.certificates[ci];
    if(c->complete) {
        pe_need(ptr2o_index==2 && c->slot==pe.selected_slot &&
            c->generation==PE_SLOT(generation).generation,PE_STATE,137);return;
    }
    pe_need(ptr2o_index<2 && pe.selected_slot<LI2_PTR_SLOTS &&
        pe.selection.index==pe.selected_slot && pe.selection.generation==PE_SLOT(generation).generation,
        PE_STATE,138);
    c->index=ci;c->slot=pe.selected_slot;c->generation=PE_SLOT(generation).generation;
    c->entry=pe_payload()->source.entry;c->proof_bytes=PE_PROOF_BYTES;c->code_bytes=PE_CODE_BYTES;
    c->publication_bytes=sizeof(struct pe_payload);
    ptr2o_copy(&c->payload,pe_payload(),sizeof c->payload);
    ptr2o_copy(c->tail,(const unsigned char *)pe_payload()+sizeof c->payload,sizeof c->tail);
    for(unsigned i=0;i<3;i++)ptr2o_copy(c->code+(i<2?i*LI2_PE_IMAGE_BYTES:2*LI2_PE_IMAGE_BYTES),
        (const void *)pg_extent(&PE_SLOT(generation).layout,i),pg_extent_bytes(i));
    c->complete=1;
}
static void ptr2o_entered(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!ptr2o_kind)return;
    pe_need(ptr2o_kind==2 && !ptr2o_capturing && pe_ready() && pe.p.phase==LI2_PG_EXECUTING && pe_active && pe_busy,PE_STATE,111);
    ptr2o_capturing=1;struct ptr2o_epoch *o=&ptr2o_wire.epochs[ptr2o_index];
    pe_need(o->h[4] && !o->h[5],PE_STATE,112);o->h[5]=1;o->h[6]=ptr2o_wire.raw_ingress[0];
    /* pe.before now includes the actual pre-entry TLS observation. */
    ptr2o_copy(&o->before,&pe.before,sizeof pe.before);
    pe_need(!li2_lifecycle_ptr2_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,&o->before_memory),PE_STATE,113);
    pe_need(!le_capture(&o->returned,sig,si,uc),PE_FRAME,103);pe_tls(&o->returned);
    ptr2o_certificate();ptr2o_stage(&o->entered);
    ptr2o_copy(o->initial_slots,(const void *)PE_SLOT(generation).layout.slots,PAGE);
    o->h[7]=*(const volatile uint64_t *)(li2_pg_rseq_progress()->address+8);o->h[8]=1;ptr2o_capturing=0;
}
static void ptr2o_terminal(unsigned failed) {
    if(!ptr2o_ready || !ptr2o_kind)return;
    if(failed){ptr2o_wire.h[46]=1;ptr2o_kind=0;return;}
    if(ptr2o_capturing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_need(ptr2o_kind==2,PE_STATE,114);ptr2o_capturing=1;
    struct ptr2o_epoch *o=&ptr2o_wire.epochs[ptr2o_index];pe_need(o->h[5] && !o->h[9],PE_STATE,115);
    o->h[9]=1;o->h[10]=failed;o->h[11]=ptr2o_wire.raw_ingress[0];
    o->h[12]=(uint64_t)li2_lifecycle_ptr2_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],failed,&o->after_memory);
    ptr2o_copy(&o->after,&pe.after,sizeof pe.after);if(o->after.complete)pe_tls(&o->after);
    ptr2o_stage(&o->terminal);ptr2o_info(&o->info);
    ptr2o_copy(o->terminal_slots,(const void *)PE_SLOT(generation).layout.slots,PAGE);
    o->h[13]=*(const volatile uint64_t *)(li2_pg_rseq_progress()->address+8);ptr2o_registry(&o->terminal_registry);
    o->h[14]=1;
    if(ptr2o_index==2) {
        pe_need(ptr2o_wire.raw_ingress[0]!=UINT64_MAX && !ptr2o_wire.next.expected_ordinal,PE_STATE,123);
        ptr2o_wire.next.expected_ordinal=ptr2o_wire.raw_ingress[0]+1;
    }
    ptr2o_kind=0;ptr2o_capturing=0;
}
static void ptr2o_finish(unsigned status,unsigned code,long detail) {
    if(!ptr2o_ready || ptr2o_finished)return;
    ptr2o_finished=1;ptr2o_wire.h[47]=1;ptr2o_wire.h[48]=status;ptr2o_wire.h[49]=code;ptr2o_wire.h[50]=(uint64_t)detail;
    ptr2o_counts(&ptr2o_wire.final_counts);ptr2o_copy(&ptr2o_wire.final_progress,&pe.p,sizeof pe.p);
    uint64_t row[]={3,status,code,detail<0?0ULL-(uint64_t)detail:(uint64_t)detail,detail<0,
        pe.p.phase,pe.p.serial,pe.selected_slot<2?PE_SLOT(generation).generation:0,pe.selected_slot<2?PE_SLOT(generation).build_serial:0,
        pe.offers,pe.cold_attempts,pe.publications,pe.hits,pe.cancelled,pe.retirements,pe.permit_claims,
        pe.entries,pe.completed,pe.unexpected,pe.selected_slot<2?PE_SLOT(permit).valid:0,pe.p.opened_pages,pe.p.closed_pages,
        pe.p.anchor_released,pe.p.registration_rechecked,pe.guest_data_fault,pe.recovery_complete,
        pe.p.first_error,pe_active,pe_busy,pe.selected_slot,
        pe.retained[0].identity.generation,pe.retained[1].identity.generation,
        pe.retained[0].permit.valid,pe.retained[1].permit.valid,
        pe.retained[0].last_completed,pe.retained[1].last_completed};
    _Static_assert(sizeof row==36*8,"exact retained-two terminal scalar row");
    ptr2o_copy(ptr2o_wire.final_row,row,sizeof row);ptr2o_wire.h[35]=ptr2o_epochs;ptr2o_wire.h[36]=ptr2o_misses;ptr2o_wire.h[37]=ptr2o_miss_next;
    ptr2o_wire.h[38]=ptr2o_kind;ptr2o_wire.h[40]=ptr2o_miss_closing;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&ptr2o_wire.sink_terminal,0,0,0,0);
    ptr2o_wire.h[51]=(uint64_t)flags;ptr2o_wire.h[52]=(uint64_t)result;
    const struct stat *a=&ptr2o_wire.sink_initial,*b=&ptr2o_wire.sink_terminal;
    if(result || flags!=(long)ptr2o_wire.h[16] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof ptr2o_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&ptr2o_wire+at),sizeof ptr2o_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof ptr2o_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof ptr2o_wire)return;
    const uint64_t footer[]={PTR2O_FOOTER,3,sizeof ptr2o_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
static void ptr2o_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!ptr2o_ready)return;
    if(ptr2o_wire.raw_ingress[0]==UINT64_MAX || ptr2o_capturing) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++ptr2o_wire.raw_ingress[0];
    unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    if(ptr2o_wire.raw_ingress[i]==UINT64_MAX) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++ptr2o_wire.raw_ingress[i];
    if(ptr2o_miss_next) {
        unsigned index=ptr2o_miss_next-1;
        if(index>=2 || ptr2o_miss_closing) {
            (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
        }
        ptr2o_miss_next=0;ptr2o_miss_closing=index+1;
        struct ptr2o_miss *o=&ptr2o_wire.misses[index];
        o->h[10]=ptr2o_wire.raw_ingress[0];o->h[13]=(uint64_t)selected_chain.active;
        o->h[11]=(uint64_t)le_capture(&o->next_trace,sig,si,uc);o->h[12]=1;
    }
    struct ptr2o_next *n=&ptr2o_wire.next;
    if(n->expected_ordinal && !n->ingress_complete) {
        n->raw_ordinal=ptr2o_wire.raw_ingress[0];n->slot_index=(uint64_t)selected_chain.active;
        n->capture_result=(uint64_t)le_capture(&n->frame,sig,si,uc);n->ingress_complete=1;
    }
}
/* Actual same-handler ordinary close, before successor preparation. Neither
   raw frame is edited; only actual TLS results are appended after close. */
void li2_ptr2o_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    if(!ptr2o_ready)return;
    if(ptr2o_miss_closing) {
        unsigned index=ptr2o_miss_closing-1;pe_need(index<2,PE_STATE,139);
        struct ptr2o_miss *o=&ptr2o_wire.misses[index];
        uintptr_t expected=index?ptr2o_wire.h[31]:ptr2o_wire.h[34];
        pe_need(!ptr2o_capturing && o->h[12]==1 && !o->h[11] && !o->h[14] &&
            o->h[10]==o->h[7]+1 && o->h[10]==ptr2o_wire.raw_ingress[0] &&
            o->h[13]<2 && chain==&selected_chain && slot==&chain->slots[o->h[13]] &&
            chain->active==(int)o->h[13] && chain->in_handler==1 && chain->pending==1 &&
            handling==1 && chain->event_id>slot->event_id && !chain->first_error &&
            !chain->unexpected_events && slot->phase==LI2_CHAIN_CLOSED &&
            !slot->unexpected_frame_observed && slot->decoded.pc==o->h[2] &&
            slot->owner.actual_post_pc==expected && o->next_trace.complete &&
            (uintptr_t)o->next_trace.frame.greg[REG_RIP]==expected,PE_STATE,140);
        ptr2o_capturing=1;ptr2o_slot_progress(&o->next_slot,(unsigned)o->h[13]);
        pe_tls(&o->next_trace);o->h[14]=1;o->h[25]=chain->event_id;o->h[26]=1;
        ptr2o_miss_closing=0;ptr2o_capturing=0;
    }
    struct ptr2o_next *n=&ptr2o_wire.next;
    if(!n->expected_ordinal || n->closed_complete)return;
    pe_need(!ptr2o_capturing && n->ingress_complete && !n->capture_result &&
        n->expected_ordinal==n->raw_ordinal && n->raw_ordinal==ptr2o_wire.raw_ingress[0] &&
        chain==&selected_chain && n->slot_index<2 && slot==&chain->slots[n->slot_index] &&
        chain->active==(int)n->slot_index && chain->in_handler==1 && chain->pending==1 &&
        handling==1 && chain->event_id>slot->event_id && !chain->first_error && !chain->unexpected_events &&
        slot->phase==LI2_CHAIN_CLOSED && !slot->unexpected_frame_observed &&
        slot->decoded.pc==ptr2o_wire.h[31]+8 && slot->owner.actual_post_pc==ptr2o_wire.h[39] &&
        n->frame.complete && (uintptr_t)n->frame.frame.greg[REG_RIP]==ptr2o_wire.h[39],PE_STATE,122);
    ptr2o_capturing=1;n->event_id=chain->event_id;ptr2o_copy(&n->closed,slot,sizeof n->closed);
    pe_tls(&n->frame);n->tls_complete=1;n->closed_complete=1;ptr2o_capturing=0;
}
static void ptr2o_begin(int sig,siginfo_t *si,ucontext_t *uc,unsigned proposed_slot) {
    if(!ptr2o_ready)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    unsigned kind=(pc==ptr2o_wire.h[31] || pc==ptr2o_wire.h[32])?2U:
        (pc==ptr2o_wire.h[33] || pc==ptr2o_wire.h[34])?1U:0U;
    if(!kind)return; /* Copies only; actual eligibility has already succeeded. */
    pe_need(!ptr2o_kind && !ptr2o_capturing &&
        proposed_slot<LI2_PTR_SLOTS && selected_chain.active>=0 && selected_chain.active<2,
        PE_STATE,106);ptr2o_capturing=1;
    uint64_t *h;
    if(kind==1) {
        pe_need(ptr2o_epochs==2 && ptr2o_misses<2 && pc==ptr2o_wire.h[33+ptr2o_misses],PE_STATE,107);
        ptr2o_miss_index=ptr2o_misses++;struct ptr2o_miss *o=&ptr2o_wire.misses[ptr2o_miss_index];h=o->h;
        h[0]=1;h[1]=ptr2o_miss_index;h[2]=pc;h[3]=ptr2o_wire.raw_ingress[0];
        ptr2o_slots(&o->prior);ptr2o_registry(&o->initial_registry);
    } else {
        pe_need(ptr2o_epochs<3 && pc==ptr2o_wire.h[ptr2o_epochs==1?32:31] &&
            (ptr2o_epochs<2 || ptr2o_misses==2),PE_STATE,108);ptr2o_index=ptr2o_epochs++;
        struct ptr2o_epoch *o=&ptr2o_wire.epochs[ptr2o_index];h=o->h;
        h[0]=1;h[1]=ptr2o_index;h[2]=pc;h[3]=ptr2o_wire.raw_ingress[0];
        ptr2o_counts(&o->prior_counts);ptr2o_slots(&o->prior);ptr2o_registry(&o->initial_registry);
        ptr2o_copy(o->predecessor.before_prefix,&selected_chain.slots[selected_chain.active],PTR2O_SLOT_PREFIX);
        pe_need(!le_capture(&o->ingress,sig,si,uc),PE_FRAME,101);
    }
    h[15]=(unsigned)selected_chain.active;h[16]=(uintptr_t)selected_chain.session;
    h[17]=selected_chain.event_id;h[18]=selected_chain.sequence;h[19]=(unsigned)selected_chain.active;
    h[20]=(unsigned)selected_chain.pending;h[21]=(unsigned)selected_chain.in_handler;
    h[22]=selected_chain.first_error;h[23]=selected_chain.initialized;h[24]=proposed_slot;
    ptr2o_kind=kind;ptr2o_capturing=0;
}
