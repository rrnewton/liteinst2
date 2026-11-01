/* Three finite RET cases: cached hit, clean loaded miss and poisoned consumed
   word. Every frame is actual; the separately named committed ucontext is the
   explicit owner transformation. No alternate authority or whole-pool wire. */
#include "persistent_ret_owner_memory.h"
#include "persistent_ret_owner_config.h"
#if LI2_PRTO_VERSION != 1 || LI2_PRTO_PAGE_RVA != 0x410000 || LI2_PRTO_U_PAGE_RVA != 0x412000
#error "exact independent RET fixture binding required"
#endif
#define PRTO_MAGIC UINT64_C(0x314f54525049324c)
#define PRTO_FOOTER UINT64_C(0x314654525049324c)
#define PRTO_CLOSED_BYTES offsetof(struct li2_tf_chain_slot,unexpected)
struct prto_counts {
    uint64_t offers,publications,hits,cold_attempts,cancelled,retirements,permit_claims,entries,completed,unexpected;
};
struct prto_scan { uint64_t compared,differences,first_offset,expected,actual; };
struct prto_phase {
    uint64_t complete,ordinal,phase,pending,busy,pe_active,pe_busy,resuming,handling;
    uint64_t route,step_pending,serial,completion_id,last_consumed,cell_value,cell_serial;
};
struct prto_private {
    uintptr_t owner,allocation,code,cell;
    unsigned initialized,registered;
    uint64_t prior_consumed,prior_cell_value,prior_cell_serial;
    struct le_permission initial_code,initial_cell;
    struct li2_private_code_query initial;
    unsigned char code_page[PAGE],initial_operand_page[PAGE],operand_page[PAGE];
};
struct prto_poison {
    uint64_t complete,applied,original_rsp,word_address,target,before,after,changed_bytes;
};
struct prto_wire {
    uint64_t h[96],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct prto_counts prior_counts,entered_counts,terminal_counts,final_counts;
    struct li2_span_transfer_progress predecessor;
    struct le_frame before,terminal,next,following,loaded_ingress;
    struct li2_prto_memory memory[5];
    struct prto_phase phase[5];
    struct pda_ret_exit loaded;
    struct prr_attempt resume;
    struct prto_private private_state;
    struct prto_poison poison;
    ucontext_t committed;
    struct pe_payload payload;
    unsigned char proof_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char code[PE_CODE_BYTES];
    struct li2_pg_generation entered_generation;
    struct li2_pg_progress entered_progress,terminal_progress;
    struct li2_pg_source_progress entered_source;
    struct li2_pg_rseq_progress entered_rseq;
    struct pda_work entered_work,terminal_work;
    struct pda_completion completion;
    struct li2_pgd_claim claim;
    struct pcw_seed window_seed;
    struct li2_maps_call_stack prepared_stack,bound_stack;
    struct li2_cd_window expected_window;
    struct le_permission window_write,window_seal;
    unsigned char window[PAGE],initial_directory[LI2_JD_DOMAIN_BYTES],terminal_directory[LI2_JD_DOMAIN_BYTES];
    struct prto_scan proof_scan,code_scan,window_scan,unexpected_scan,private_scan;
    unsigned char next_closed[PRTO_CLOSED_BYTES];
    struct li2_pg_recovered recovered;
    uint64_t final_row[39],final_subentry[15],final_misses[18];
};
static struct prto_wire prto_wire;
static unsigned prto_ready,prto_frozen,prto_busy,prto_finished,prto_active;
static const uint64_t prto_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct prto_wire)+64<4U*1024U*1024U,"strict original record bound");
static void prto_callback(void) {
    if(prto_frozen){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
static void prto_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void prto_counts(struct prto_counts *o) {
#define C(n) o->n=pe.n
    C(offers);C(publications);C(hits);C(cold_attempts);C(cancelled);C(retirements);
    C(permit_claims);C(entries);C(completed);C(unexpected);
#undef C
}
static void prto_compare(struct prto_scan *o,const void *expected,const void *actual,size_t bytes) {
    const unsigned char *a=expected;const volatile unsigned char *b=actual;
    for(size_t i=0;i<bytes;i++) {
        unsigned char x=b[i],y=a?a[i]:0;
        if(x!=y){if(!o->differences){o->first_offset=o->compared;o->expected=y;o->actual=x;}++o->differences;}
        ++o->compared;
    }
    pe_need(!o->differences,PE_STATE,180);
}
static void prto_lifetime(const struct li2_pg_rseq_progress *r) {
    pe_need(r && li2_pgu_progress_valid(r) && r->lifetime_mode==LI2_PGU_UNREGISTERED &&
        !r->registration_epoch && !r->registration_calls && !r->word_observed && r->tls_complete==1,PE_STATE,181);
}
static void prto_memory(unsigned site) {
    struct li2_prto_memory *m=&prto_wire.memory[site];
    pe_need(!li2_lifecycle_prto_memory(prto_wire.h[30],site,m),PE_STATE,182);
    const struct li2_maps_call_stack *a=&prto_wire.bound_stack,*b=&m->stack_origin;
    pe_need(a->anchor==b->anchor && a->origin_first==b->origin_first && a->origin_end==b->origin_end &&
        a->origin_acquisition==b->origin_acquisition && a->first==b->first && a->end==b->end,PE_STATE,183);
}
static void prto_initialize(void) {
    prto_callback();__asm__ volatile(""::"r"(&prto_step_frame_fp_alignment):"memory");
    pe_need(!prto_ready && !prto_finished && !pe.p.serial && !original_main.bias,PE_STATE,150);
    uint64_t *h=prto_wire.h;
    h[0]=PRTO_MAGIC;h[1]=1;h[2]=sizeof prto_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)&pe;
    h[10]=(uintptr_t)&prto_wire;h[11]=(uintptr_t)&selected_chain;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&prto_wire,sizeof prto_wire),PE_STATE,151);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&prto_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(prto_wire.sink_initial.st_mode) && (prto_wire.sink_initial.st_mode&07777)==0600 &&
        prto_wire.sink_initial.st_nlink==1 && !prto_wire.sink_initial.st_size,PE_STATE,152);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_RET_OWNER_APP_MODE");
    pe_need(mode && mode[0]>='0' && mode[0]<='2' && !mode[1],PE_STATE,153);h[19]=(unsigned)(mode[0]-'0');
    h[20]=LI2_PRTO_PAGE_RVA;h[21]=h[19]?LI2_PRTO_A_MISS_RVA:LI2_PRTO_A_RVA;
    h[22]=h[21]+10;h[23]=h[21]+13;h[24]=LI2_PRTO_B_RVA;h[25]=LI2_PRTO_RET_RVA;
    h[26]=LI2_PRTO_U_RVA;h[27]=LI2_PRTO_CAPTURE_RVA;h[28]=h[24];
    h[29]=h[19]?0:h[21]+17;h[31]=h[19]?h[23]:h[27];
    h[78]=LI2_PRTO_A_RVA;h[79]=LI2_PRTO_A_MISS_RVA;h[80]=h[21]+17;
    h[54]=LI2_PTR_SLOTS;h[55]=LI2_PGD_MEMBERS;h[56]=LI2_PGD_RECEIPTS;h[57]=PRTO_CLOSED_BYTES;
    prto_copy(&prto_wire.main,&original_main,sizeof original_main);
    prto_copy(&prto_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    prto_copy(&prto_wire.hardware,&selected_hardware,sizeof selected_hardware);
    prto_copy(&prto_wire.session,&selected_session,sizeof selected_session);prto_ready=1;
}
static void prto_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    prto_callback();if(!prto_ready)return;
    pe_need(!prto_busy && prto_wire.raw_ingress[0]!=UINT64_MAX,PE_STATE,154);
    ++prto_wire.raw_ingress[0];unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    pe_need(prto_wire.raw_ingress[i]!=UINT64_MAX,PE_STATE,155);++prto_wire.raw_ingress[i];
    uint64_t *h=prto_wire.h;
    if(h[38] && !h[39]) {
        pe_need(h[38]==prto_wire.raw_ingress[0] && !h[40],PE_STATE,156);
        h[39]=prto_wire.raw_ingress[0];h[40]=(uint64_t)selected_chain.active;
        pe_need(!le_capture(&prto_wire.next,sig,si,uc),PE_FRAME,150);
        if(h[19]) {
            pe_need(prto_wire.phase[4].complete==1 && h[39]==h[82]+1 &&
                sig==SIGSEGV && si && si->si_code==SEGV_ACCERR &&
                (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h[23] &&
                (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==h[30],PE_FRAME,181);
            pe_tls(&prto_wire.next);h[83]=h[39]+1;
        }
    }
    if(h[83] && !h[84] && prto_wire.raw_ingress[0]>h[39]) {
        pe_need(prto_wire.raw_ingress[0]==h[83] && h[19] && h[39] &&
            selected_chain.active>=0 && selected_chain.active<2,PE_STATE,184);
        h[84]=prto_wire.raw_ingress[0];h[85]=(unsigned)selected_chain.active;
        pe_need(!le_capture(&prto_wire.following,sig,si,uc),PE_FRAME,182);
    }
}
static void prto_declined(const ucontext_t *uc) {
    prto_callback();if(!prto_ready || !uc)return;
    if((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==prto_wire.h[21]) {
        prto_wire.h[45]=1;pe_need(0,PE_STATE,157);
    }
}
static void prto_begin(int sig,siginfo_t *si,ucontext_t *uc,unsigned proposed_slot) {
    prto_callback();if(!prto_ready || (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=prto_wire.h[21])return;
    uint64_t *h=prto_wire.h;
    pe_need(!prto_busy && !prto_active && !h[32] && !h[34] && proposed_slot<LI2_PTR_SLOTS &&
        sig==SIGTRAP && si && si->si_code==TRAP_TRACE && selected_chain.active>=0 && selected_chain.active<2,
        PE_STATE,158);
    prto_busy=1;h[32]=1;h[33]=prto_wire.raw_ingress[0];h[30]=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    h[58]=proposed_slot;h[59]=(unsigned)selected_chain.active;h[60]=selected_chain.event_id;
    pe_need((uintptr_t)uc->uc_mcontext.gregs[REG_R12]==h[28],PE_STATE,159);
    prto_counts(&prto_wire.prior_counts);prto_active=1;prto_busy=0;
}
static void prto_miss(void) {
    prto_callback();if(prto_active){prto_wire.h[46]=1;pe_need(0,PE_PLAN,150);}
}
static void prto_entered(void) {
    prto_callback();if(!prto_active)return;
    uint64_t *h=prto_wire.h;const struct pda_work *w=&pe.domain.work;
    pe_need(!prto_busy && h[32]==1 && !h[34] && pe_ready() && pe.p.phase==LI2_PG_EXECUTING &&
        pe_active && pe_busy && pe.warm==0 && !pe.subentry_selected && pe.close_complete &&
        w->bound==1 && w->view.count==1 && w->peer==LI2_PTR_SLOTS && !w->completion &&
        w->view.member[0].identity.slot==pe.selected_slot && pe.selected_slot==h[58] &&
        pe_payload()->source.entry==h[21] && pcw.prepared==1 && pcw.bound==1 && pcw_equal(),PE_STATE,160);
    prto_busy=1;h[34]=1;h[35]=prto_wire.raw_ingress[0];h[61]=pe.selected_slot;h[62]=pe.selected_bank;
    h[63]=pe.p.serial;h[64]=PE_SLOT(generation).generation;h[65]=pcw.address;h[66]=pe.domain.directory;
    h[67]=(uintptr_t)pe_payload();h[68]=pe_payload()->header.table;h[69]=w->receipt;
    pe_need(h[35]==h[33] && h[35]<UINT64_MAX-1 && pe.before.complete && pe.before.tls_complete &&
        (uintptr_t)pe.before.frame.greg[REG_RIP]==h[21] && (uintptr_t)pe.before.frame.greg[REG_RSP]==h[30] &&
        pe.transfer.previous==h[59] && pe.transfer.phase==LI2_ST_CONSUMED,PE_STATE,161);
    prto_copy(&prto_wire.before,&pe.before,sizeof pe.before);
    prto_copy(&prto_wire.predecessor,&pe.transfer,sizeof pe.transfer);
    prto_copy(&prto_wire.payload,pe_payload(),sizeof prto_wire.payload);
    prto_copy(prto_wire.proof_tail,(const unsigned char *)pe_payload()+sizeof(struct pe_payload),sizeof prto_wire.proof_tail);
    for(unsigned i=0;i<3;i++)prto_copy(prto_wire.code+i*LI2_PE_IMAGE_BYTES,
        (const void *)pg_extent(&PE_SLOT(generation).layout,i),pg_extent_bytes(i));
    prto_copy(&prto_wire.entered_generation,&PE_SLOT(generation),sizeof prto_wire.entered_generation);
    prto_copy(&prto_wire.entered_progress,&pe.p,sizeof pe.p);
    prto_copy(&prto_wire.entered_source,li2_pg_source_progress(),sizeof prto_wire.entered_source);
    prto_copy(&prto_wire.entered_rseq,li2_pg_rseq_progress(),sizeof prto_wire.entered_rseq);
    prto_copy(&prto_wire.entered_work,w,sizeof *w);prto_counts(&prto_wire.entered_counts);
    prto_copy(&prto_wire.window_seed,&pcw.seed,sizeof pcw.seed);
    prto_copy(&prto_wire.prepared_stack,&pcw.prepared_stack,sizeof pcw.prepared_stack);
    prto_copy(&prto_wire.bound_stack,&pcw.bound_stack,sizeof pcw.bound_stack);
    prto_copy(&prto_wire.expected_window,&pcw.expected,sizeof pcw.expected);
    prto_copy(&prto_wire.window_write,&pcw.write,sizeof pcw.write);
    prto_copy(&prto_wire.window_seal,&pcw.seal,sizeof pcw.seal);
    prto_copy(prto_wire.window,(const void *)pcw.address,PAGE);
    prto_copy(prto_wire.initial_directory,(const void *)pe.domain.directory,LI2_JD_DOMAIN_BYTES);
    pe_need(prr.run.phase==PRR_IDLE && !prr_pending && !prr_busy && prr_storage() &&
        pe_payload()->plan.heads==7 && pe_payload()->plan.exits==3,PE_STATE,185);
    h[81]=PE_SLOT(generation).layout.ret_miss+6U*8U;
    if(h[19])h[29]=h[81];
    struct prto_private *v=&prto_wire.private_state;
    v->owner=(uintptr_t)&prr;v->allocation=prr.allocation;v->code=prr.code;v->cell=prr.cell;
    v->initialized=prr.initialized;v->registered=prr.registered;
    v->prior_consumed=prr.last_consumed;v->prior_cell_value=prr.cell_value;v->prior_cell_serial=prr.cell_serial;
    prto_copy(&v->initial_code,&prr.initial_code,sizeof v->initial_code);
    prto_copy(&v->initial_cell,&prr.initial_cell,sizeof v->initial_cell);
    prto_copy(&v->initial,&prr.initial,sizeof v->initial);
    pe_need(prr_bytes(prr.cell_value),PE_PUBLICATION,180);
    prto_copy(v->code_page,(const void *)prr.allocation,PAGE);
    prto_copy(v->initial_operand_page,(const void *)(prr.allocation+PAGE),PAGE);
    prto_copy(v->operand_page,v->initial_operand_page,PAGE);
    prto_lifetime(&prto_wire.entered_rseq);prto_memory(0);prto_busy=0;
}
static void prto_terminal(void) {
    prto_callback();if(!prto_active)return;
    uint64_t *h=prto_wire.h;const struct pda_work *w=&pe.domain.work;
    pe_need(!prto_busy && h[34]==1 && !h[36] && pe.p.phase==LI2_PG_CLOSED && pe_active && pe_busy &&
        w->bound==1 && w->completion==1 && w->view.count==1 && w->receipt<LI2_PGD_RECEIPTS &&
        w->receipt==h[69] && w->exit_member==(h[19]?LI2_PGD_MEMBERS:0) &&
        pe.selected_slot==h[61] && pe.p.serial==h[63] &&
        pe.after.complete && pe.after.tls_complete && (uintptr_t)pe.after.frame.greg[REG_RIP]==h[29] &&
        prto_wire.raw_ingress[0]==h[35]+1 && !pe.guest_data_fault,PE_STATE,162);
    pe_need(h[19]?(prr.run.phase==PRR_DRAINED && prto_wire.phase[0].complete==1):
        (prr.run.phase==PRR_IDLE && !prr.run.loaded.complete),PE_STATE,186);
    prto_busy=1;h[36]=1;h[37]=prto_wire.raw_ingress[0];
    if(!h[19])h[38]=h[37]+1;
    h[70]=pe.exit_index;h[71]=pe.recovery_complete;h[72]=pe.p.opened_pages;h[73]=pe.p.closed_pages;
    h[74]=pe.p.anchor_released;h[75]=pe.p.completion_permit;h[76]=pe.gpr_written;h[77]=pe.flags_written;
    prto_copy(&prto_wire.terminal,&pe.after,sizeof pe.after);
    prto_copy(&prto_wire.terminal_progress,&pe.p,sizeof pe.p);
    prto_copy(&prto_wire.terminal_work,w,sizeof *w);
    prto_copy(&prto_wire.completion,&pe.domain.completion[w->receipt],sizeof prto_wire.completion);
    prto_copy(&prto_wire.claim,&PE_SLOT(claim),sizeof prto_wire.claim);
    prto_copy(&prto_wire.recovered,&pe.recovered,sizeof pe.recovered);
    prto_counts(&prto_wire.terminal_counts);
    prto_compare(&prto_wire.proof_scan,&prto_wire.payload,pe_payload(),sizeof prto_wire.payload);
    prto_compare(&prto_wire.proof_scan,prto_wire.proof_tail,(const unsigned char *)pe_payload()+sizeof(struct pe_payload),sizeof prto_wire.proof_tail);
    for(unsigned i=0;i<3;i++)prto_compare(&prto_wire.code_scan,prto_wire.code+i*LI2_PE_IMAGE_BYTES,
        (const void *)pg_extent(&PE_SLOT(generation).layout,i),pg_extent_bytes(i));
    prto_compare(&prto_wire.window_scan,prto_wire.window,(const void *)pcw.address,PAGE);
    prto_copy(prto_wire.terminal_directory,(const void *)pe.domain.directory,LI2_JD_DOMAIN_BYTES);
    prto_lifetime(&prto_wire.completion.rseq);prto_memory(1);prto_active=0;prto_busy=0;
}
/* Capture-only phase callbacks. They never provide a runtime capability. */
static void prto_phase(unsigned index,unsigned phase) {
    uint64_t *h=prto_wire.h;struct prto_phase *p=&prto_wire.phase[index];
    pe_need(index<5 && h[19] && h[34] && !p->complete && prr.run.phase==phase &&
        prr.run.serial==h[63] && prr.run.loaded.complete==1 &&
        prto_wire.raw_ingress[0]==h[35]+(index<3?1U:2U),PE_STATE,187);
    *p=(struct prto_phase){.complete=1,.ordinal=prto_wire.raw_ingress[0],.phase=prr.run.phase,
        .pending=prr_pending,.busy=prr_busy,.pe_active=pe_active,.pe_busy=pe_busy,
        .resuming=pe.resuming,.handling=handling,.route=selected_pending_route,
        .step_pending=selected_step_pending,.serial=prr.run.serial,.completion_id=prr.run.completion_id,
        .last_consumed=prr.last_consumed,.cell_value=prr.cell_value,.cell_serial=prr.cell_serial};
}
static void prto_loaded(void) {
    prto_callback();if(!prto_active)return;
    uint64_t *h=prto_wire.h;const struct pda_ret_exit *e=&prr.run.loaded;
    const struct li2_rd_recovered *r=&e->recovered;
    pe_need(h[19] && !prto_busy && h[34]==1 && !h[36] && !handling &&
        prr.run.phase==PRR_LOADED && prr_busy==1 && !prr_pending && pe_active && pe_busy &&
        pe.p.phase==LI2_PG_RECOVERING && e->complete==1 && e->member==0 && e->head==6 && e->heads==7 &&
        e->landing==h[81] && e->original.decoded.pc==h[25] &&
        r->complete==1 && r->target_valid==1 && r->phase==LI2_RD_LOADED_MISS &&
        r->original_pc==h[25] && r->original_rsp==h[30]-8 && r->gpr[4]==h[30]-8 &&
        r->target==h[23] && !(h[30]&7) && pe.after.complete && !pe.after.tls_complete &&
        (uintptr_t)pe.after.frame.greg[REG_RIP]==h[81] &&
        (uintptr_t)pe.after.frame.greg[REG_RSP]==h[30]-8,PE_STATE,188);
    prto_busy=1;prto_copy(&prto_wire.loaded,e,sizeof *e);
    prto_copy(&prto_wire.loaded_ingress,&pe.after,sizeof pe.after);
    prto_phase(0,PRR_LOADED);prto_memory(3);
    struct prto_poison *p=&prto_wire.poison;
    p->original_rsp=r->original_rsp;p->word_address=r->original_rsp;p->target=r->target;
    for(unsigned i=0;i<8;i++)p->before|=(uint64_t)prto_wire.memory[3].stack[248+i]<<(8U*i);
    pe_need(p->before==r->target && !p->complete && !p->applied,PE_FRAME,183);
    if(h[19]==2) {
        volatile unsigned char *word=(void *)p->word_address;
        const uint64_t poison=UINT64_C(0xa5a55a5af0f00f0f);
        for(unsigned i=0;i<8;i++)word[i]=(unsigned char)(poison>>(8U*i));
        p->applied=1;
    }
    __asm__ volatile("":::"memory");prto_memory(4);
    for(unsigned i=0;i<8;i++)p->after|=(uint64_t)prto_wire.memory[4].stack[248+i]<<(8U*i);
    for(unsigned i=0;i<PRTO_STACK_BYTES;i++) {
        unsigned changed=prto_wire.memory[3].stack[i]!=prto_wire.memory[4].stack[i];
        pe_need(changed==(unsigned)(h[19]==2 && i>=248 && i<256),PE_FRAME,184);p->changed_bytes+=changed;
    }
    pe_need(p->after==(h[19]==2?UINT64_C(0xa5a55a5af0f00f0f):p->target) &&
        p->changed_bytes==(h[19]==2?8U:0U) &&
        equal(&prto_wire.loaded,&prr.run.loaded,sizeof prto_wire.loaded),PE_FRAME,185);
    p->complete=1;prto_busy=0;
}
static void prto_drained(void) {
    prto_callback();if(!prto_active)return;
    pe_need(prto_wire.h[19] && prto_wire.phase[0].complete==1 && prto_wire.poison.complete==1 &&
        prr.run.phase==PRR_DRAINED && prr_busy==1 && !prr_pending && handling==1 &&
        equal(&prto_wire.loaded,&prr.run.loaded,sizeof prto_wire.loaded),PE_STATE,189);
    prto_terminal();prto_phase(1,PRR_DRAINED);
    pe_need(prto_wire.h[36]==1 &&
        equal(&prto_wire.loaded,&prto_wire.completion.ret_exit,sizeof prto_wire.loaded),PE_FRAME,186);
}
static void prto_armed(void) {
    prto_callback();if(!prto_ready || !prto_wire.h[19] || !prto_wire.h[36] || prto_wire.phase[2].complete)return;
    uint64_t *h=prto_wire.h;
    pe_need(!prto_busy && prto_wire.phase[1].complete==1 && prr.run.phase==PRR_ARMED &&
        prr_pending==1 && prr_busy==1 && pe_active && pe_busy && pe.resuming && handling==1 &&
        selected_pending_route==SELECTED_RET_RESUME && selected_step_pending==1 &&
        prr.cell_value==h[23] && prr.cell_serial==h[63] &&
        equal(&prto_wire.loaded,&prr.run.loaded,sizeof prto_wire.loaded),PE_STATE,190);
    prto_phase(2,PRR_ARMED);
    prto_compare(&prto_wire.private_scan,prto_wire.private_state.code_page,(const void *)prr.allocation,PAGE);
    prto_copy(prto_wire.private_state.operand_page,(const void *)(prr.allocation+PAGE),PAGE);
}
static void prto_observed(void) {
    prto_callback();if(!prto_ready || !prto_wire.h[19] || !prto_wire.phase[2].complete || prto_wire.phase[3].complete)return;
    uint64_t *h=prto_wire.h;
    pe_need(!prto_busy && prr.run.phase==PRR_OBSERVED && prr.run.event==1 &&
        !prr.run.terminal && !prr.run.consumed && prr_pending==1 && prr_busy==1 &&
        !pe_active && !pe_busy && pe.resuming && !handling &&
        prr.run.after.complete && prr.run.after.tls_complete &&
        (uintptr_t)prr.run.after.frame.greg[REG_RIP]==h[23] &&
        (uintptr_t)prr.run.after.frame.greg[REG_RSP]==prr.cell+8 &&
        prr.run.logical.complete==1 && prr.run.logical.phase==LI2_RD_COMMITTED &&
        prr.run.logical.gpr[4]==h[30] && prr.run.logical.target==h[23] &&
        equal(&prto_wire.loaded,&prr.run.loaded,sizeof prto_wire.loaded),PE_STATE,191);
    prto_phase(3,PRR_OBSERVED);
}
static void prto_consumed(const ucontext_t *uc) {
    prto_callback();if(!prto_ready || !prto_wire.h[19] || !prto_wire.phase[3].complete || prto_wire.phase[4].complete)return;
    uint64_t *h=prto_wire.h;
    pe_need(!prto_busy && uc && !h[38] && prr.run.phase==PRR_CONSUMED && prr.run.event==1 &&
        prr.run.consumed==1 && !prr.run.terminal && prr.last_consumed==h[63] &&
        !prr_pending && !prr_busy && !pe_active && !pe_busy && !pe.resuming && handling==1 &&
        selected_pending_route==SELECTED_NO_STEP && !selected_step_pending &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h[23] &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==h[30] &&
        equal(&prto_wire.loaded,&prr.run.loaded,sizeof prto_wire.loaded),PE_STATE,192);
    prto_phase(4,PRR_CONSUMED);prto_copy(&prto_wire.resume,&prr.run,sizeof prr.run);
    prto_copy(&prto_wire.committed,uc,sizeof *uc);h[82]=prto_wire.raw_ingress[0];h[38]=h[82]+1;
}
void li2_prto_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    prto_callback();if(!prto_ready || !prto_wire.h[38] || prto_wire.h[41])return;
    uint64_t *h=prto_wire.h;
    /* For misses the first post-consume event is a genuine NX, followed by
       the actual target ADD's TRACE. Neither event is synthesized by PRR. */
    unsigned selected=(unsigned)(h[19]?h[85]:h[40]);
    struct le_frame *frame=h[19]?&prto_wire.following:&prto_wire.next;
    pe_need(!prto_busy && h[36]==1 && h[39]==h[38] && selected<2 &&
        (h[19]?(h[84]==h[83] && h[84]==prto_wire.raw_ingress[0] && h[84]==h[39]+1):
                 h[39]==prto_wire.raw_ingress[0]) &&
        chain==&selected_chain && slot==&chain->slots[selected] && chain->active==(int)selected &&
        chain->in_handler==1 && chain->pending==1 && handling==1 && chain->event_id>slot->event_id &&
        !chain->first_error && !chain->unexpected_events && slot->phase==LI2_CHAIN_CLOSED &&
        !slot->unexpected_frame_observed && slot->decoded.pc==(h[19]?h[23]:h[29]) &&
        slot->owner.actual_post_pc==(h[19]?h[80]:h[31]) && frame->complete &&
        (uintptr_t)frame->frame.greg[REG_RIP]==(h[19]?h[80]:h[31]),PE_STATE,163);
    prto_busy=1;prto_copy(prto_wire.next_closed,slot,sizeof prto_wire.next_closed);
    prto_compare(&prto_wire.unexpected_scan,0,&slot->unexpected,sizeof slot->unexpected);
    pe_tls(frame);prto_memory(2);h[41]=1;h[42]=chain->event_id;h[43]=frame->tls_complete;prto_busy=0;
}
static void prto_finish(unsigned status,unsigned code,long detail) {
    if(!prto_ready || prto_finished)return;
    prto_finished=1;
    uint64_t *h=prto_wire.h;unsigned incomplete=!h[32] || !h[34] || !h[36] || !h[41] ||
        !h[43] || h[45] || h[46] || prto_active || prto_busy ||
        (h[19] && (!prto_wire.phase[4].complete || !h[84] || !prto_wire.poison.complete));
    unsigned forced=!status && incomplete;
    if(forced){status=125;code=PE_STATE;detail=164;}
    h[44]=incomplete;h[47]=1;h[48]=status;h[49]=code;h[50]=(uint64_t)detail;
    prto_counts(&prto_wire.final_counts);
    const uint64_t row[]={1,status,code,detail<0?0ULL-(uint64_t)detail:(uint64_t)detail,detail<0,
        pe.p.phase,pe.p.serial,pe.selected_slot<2?PE_SLOT(generation).generation:0,pe.selected_slot<2?PE_SLOT(generation).build_serial:0,
        pe.offers,pe.cold_attempts,pe.publications,pe.hits,pe.cancelled,pe.retirements,pe.permit_claims,
        pe.entries,pe.completed,pe.unexpected,pe.selected_slot<2?PE_SLOT(claim).valid:0,pe.p.opened_pages,pe.p.closed_pages,
        pe.p.anchor_released,pe.p.registration_rechecked,pe.guest_data_fault,pe.recovery_complete,
        pe.p.first_error,pe_active,pe_busy,pe.selected_slot,
        pe.retained[0].identity.generation,pe.retained[1].identity.generation,
        pe.retained[0].claim.valid,pe.retained[1].claim.valid,
        pe.retained[0].last_completed,pe.retained[1].last_completed,
        pe.domain.work.view.count,pe.domain.dual_entries,pe.domain.dual_completed};
    const uint64_t sub[]={1,status,code,pe.subentry_selections,pe.subentry_hits,
        pe.subentry_entries,pe.subentry_completed,pe.entry.token.serial,pe.entry.generation,
        pe.entry.target.root,pe.entry.target.pc,pe.entry.target.head,pe.entry.slot,pe.entry.bank,pe.entry.complete};
    _Static_assert(sizeof row==sizeof prto_wire.final_row && sizeof sub==sizeof prto_wire.final_subentry,"literal final rows");
    prto_copy(prto_wire.final_row,row,sizeof row);prto_copy(prto_wire.final_subentry,sub,sizeof sub);
    _Static_assert(LI2_PGD_REASON_COUNT==18,"whole literal terminal miss population");
    for(unsigned i=0;i<18;i++)prto_wire.final_misses[i]=PGC_MISS_VALUE(i);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&prto_wire.sink_terminal,0,0,0,0);h[51]=(uint64_t)flags;h[52]=(uint64_t)result;
    const struct stat *a=&prto_wire.sink_initial,*b=&prto_wire.sink_terminal;
    unsigned sink_ok=!result && flags==(long)h[16] && a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid &&
        a->st_nlink==b->st_nlink && !b->st_size;
    if(sink_ok) {
        h[53]=1;prto_frozen=1;__asm__ volatile("":::"memory");
        size_t at=0;uint64_t calls=0;result=0;
        while(at<sizeof prto_wire && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)&prto_wire+at),sizeof prto_wire-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof prto_wire-at)goto done;
            at+=(size_t)result;
        }
        if(at!=sizeof prto_wire)goto done;
        const uint64_t footer[]={PRTO_FOOTER,1,sizeof prto_wire,at,calls,(uint64_t)result,status,code};
        at=0;calls=0;
        while(at<sizeof footer && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof footer-at)goto done;
            at+=(size_t)result;
        }
    }
done:
    if(forced || !sink_ok){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
