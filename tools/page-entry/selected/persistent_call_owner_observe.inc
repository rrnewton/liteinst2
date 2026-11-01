/* One cold CALL graph and its genuine ordinary successor. This is a bounded
   observation of real owners, not an alternate authority or whole-pool wire. */
#include "persistent_call_owner_memory.h"
#include "persistent_call_owner_config.h"
#if LI2_PCLO_VERSION != 1 || LI2_PCLO_PAGE_RVA != 0x410000 || LI2_PCLO_U_PAGE_RVA != 0x412000
#error "exact independent CALL fixture binding required"
#endif
#define PCLO_MAGIC UINT64_C(0x314f4c435049324c)
#define PCLO_FOOTER UINT64_C(0x31464c435049324c)
#define PCLO_CLOSED_BYTES offsetof(struct li2_tf_chain_slot,unexpected)
struct pclo_counts {
    uint64_t offers,publications,hits,cold_attempts,cancelled,retirements,permit_claims,entries,completed,unexpected;
};
struct pclo_scan { uint64_t compared,differences,first_offset,expected,actual; };
struct pclo_wire {
    uint64_t h[96],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct pclo_counts prior_counts,entered_counts,terminal_counts,final_counts;
    struct li2_span_transfer_progress predecessor;
    struct le_frame before,terminal,next;
    struct li2_pclo_memory memory[3];
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
    struct pclo_scan proof_scan,code_scan,window_scan,unexpected_scan;
    unsigned char next_closed[PCLO_CLOSED_BYTES];
    struct li2_pg_recovered recovered;
    uint64_t final_row[39],final_subentry[15],final_misses[18];
};
static struct pclo_wire pclo_wire;
static unsigned pclo_ready,pclo_frozen,pclo_busy,pclo_finished,pclo_active;
static const uint64_t pclo_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct pclo_wire)+64<4U*1024U*1024U,"strict original record bound");
static void pclo_callback(void) {
    if(pclo_frozen){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
static void pclo_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void pclo_counts(struct pclo_counts *o) {
#define C(n) o->n=pe.n
    C(offers);C(publications);C(hits);C(cold_attempts);C(cancelled);C(retirements);
    C(permit_claims);C(entries);C(completed);C(unexpected);
#undef C
}
static void pclo_compare(struct pclo_scan *o,const void *expected,const void *actual,size_t bytes) {
    const unsigned char *a=expected;const volatile unsigned char *b=actual;
    for(size_t i=0;i<bytes;i++) {
        unsigned char x=b[i],y=a?a[i]:0;
        if(x!=y){if(!o->differences){o->first_offset=o->compared;o->expected=y;o->actual=x;}++o->differences;}
        ++o->compared;
    }
    pe_need(!o->differences,PE_STATE,180);
}
static void pclo_lifetime(const struct li2_pg_rseq_progress *r) {
    pe_need(r && li2_pgu_progress_valid(r) && r->lifetime_mode==LI2_PGU_UNREGISTERED &&
        !r->registration_epoch && !r->registration_calls && !r->word_observed && r->tls_complete==1,PE_STATE,181);
}
static void pclo_memory(unsigned site) {
    struct li2_pclo_memory *m=&pclo_wire.memory[site];
    pe_need(!li2_lifecycle_pclo_memory(pclo_wire.h[30],site,m),PE_STATE,182);
    const struct li2_maps_call_stack *a=&pclo_wire.bound_stack,*b=&m->stack_origin;
    pe_need(a->anchor==b->anchor && a->origin_first==b->origin_first && a->origin_end==b->origin_end &&
        a->origin_acquisition==b->origin_acquisition && a->first==b->first && a->end==b->end,PE_STATE,183);
}
static void pclo_initialize(void) {
    pclo_callback();__asm__ volatile(""::"r"(&pclo_step_frame_fp_alignment):"memory");
    pe_need(!pclo_ready && !pclo_finished && !pe.p.serial && !original_main.bias,PE_STATE,150);
    uint64_t *h=pclo_wire.h;
    h[0]=PCLO_MAGIC;h[1]=1;h[2]=sizeof pclo_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)&pe;
    h[10]=(uintptr_t)&pclo_wire;h[11]=(uintptr_t)&selected_chain;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&pclo_wire,sizeof pclo_wire),PE_STATE,151);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pclo_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(pclo_wire.sink_initial.st_mode) && (pclo_wire.sink_initial.st_mode&07777)==0600 &&
        pclo_wire.sink_initial.st_nlink==1 && !pclo_wire.sink_initial.st_size,PE_STATE,152);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_CALL_OWNER_APP_MODE");
    pe_need(mode && mode[0]>='0' && mode[0]<='1' && !mode[1],PE_STATE,153);h[19]=(unsigned)(mode[0]-'0');
    h[20]=LI2_PCLO_PAGE_RVA;h[21]=LI2_PCLO_A_RVA;h[22]=LI2_PCLO_CALL_RVA;h[23]=LI2_PCLO_RETURN_RVA;
    h[24]=LI2_PCLO_B_RVA;h[25]=LI2_PCLO_B_EXIT_RVA;h[26]=LI2_PCLO_U_RVA;h[27]=LI2_PCLO_CAPTURE_RVA;
    h[28]=h[h[19]?26:24];h[29]=h[h[19]?22:25];h[31]=h[h[19]?26:27];
    h[54]=LI2_PTR_SLOTS;h[55]=LI2_PGD_MEMBERS;h[56]=LI2_PGD_RECEIPTS;h[57]=PCLO_CLOSED_BYTES;
    pclo_copy(&pclo_wire.main,&original_main,sizeof original_main);
    pclo_copy(&pclo_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    pclo_copy(&pclo_wire.hardware,&selected_hardware,sizeof selected_hardware);
    pclo_copy(&pclo_wire.session,&selected_session,sizeof selected_session);pclo_ready=1;
}
static void pclo_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    pclo_callback();if(!pclo_ready)return;
    pe_need(!pclo_busy && pclo_wire.raw_ingress[0]!=UINT64_MAX,PE_STATE,154);
    ++pclo_wire.raw_ingress[0];unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    pe_need(pclo_wire.raw_ingress[i]!=UINT64_MAX,PE_STATE,155);++pclo_wire.raw_ingress[i];
    uint64_t *h=pclo_wire.h;
    if(h[38] && !h[39]) {
        pe_need(h[38]==pclo_wire.raw_ingress[0] && !h[40],PE_STATE,156);
        h[39]=pclo_wire.raw_ingress[0];h[40]=(uint64_t)selected_chain.active;
        pe_need(!le_capture(&pclo_wire.next,sig,si,uc),PE_FRAME,150);
    }
}
static void pclo_declined(const ucontext_t *uc) {
    pclo_callback();if(!pclo_ready || !uc)return;
    if((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==pclo_wire.h[21]) {
        pclo_wire.h[45]=1;pe_need(0,PE_STATE,157);
    }
}
static void pclo_begin(int sig,siginfo_t *si,ucontext_t *uc,unsigned proposed_slot) {
    pclo_callback();if(!pclo_ready || (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=pclo_wire.h[21])return;
    uint64_t *h=pclo_wire.h;
    pe_need(!pclo_busy && !pclo_active && !h[32] && !h[34] && proposed_slot<LI2_PTR_SLOTS &&
        sig==SIGTRAP && si && si->si_code==TRAP_TRACE && selected_chain.active>=0 && selected_chain.active<2,
        PE_STATE,158);
    pclo_busy=1;h[32]=1;h[33]=pclo_wire.raw_ingress[0];h[30]=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    h[58]=proposed_slot;h[59]=(unsigned)selected_chain.active;h[60]=selected_chain.event_id;
    pe_need((uintptr_t)uc->uc_mcontext.gregs[REG_R12]==h[28],PE_STATE,159);
    pclo_counts(&pclo_wire.prior_counts);pclo_active=1;pclo_busy=0;
}
static void pclo_miss(void) {
    pclo_callback();if(pclo_active){pclo_wire.h[46]=1;pe_need(0,PE_PLAN,150);}
}
static void pclo_entered(void) {
    pclo_callback();if(!pclo_active)return;
    uint64_t *h=pclo_wire.h;const struct pda_work *w=&pe.domain.work;
    pe_need(!pclo_busy && h[32]==1 && !h[34] && pe_ready() && pe.p.phase==LI2_PG_EXECUTING &&
        pe_active && pe_busy && pe.warm==0 && !pe.subentry_selected && pe.close_complete &&
        w->bound==1 && w->view.count==1 && w->peer==LI2_PTR_SLOTS && !w->completion &&
        w->view.member[0].identity.slot==pe.selected_slot && pe.selected_slot==h[58] &&
        pe_payload()->source.entry==h[21] && pcw.prepared==1 && pcw.bound==1 && pcw_equal(),PE_STATE,160);
    pclo_busy=1;h[34]=1;h[35]=pclo_wire.raw_ingress[0];h[61]=pe.selected_slot;h[62]=pe.selected_bank;
    h[63]=pe.p.serial;h[64]=PE_SLOT(generation).generation;h[65]=pcw.address;h[66]=pe.domain.directory;
    h[67]=(uintptr_t)pe_payload();h[68]=pe_payload()->header.table;h[69]=w->receipt;
    pe_need(h[35]==h[33] && h[35]<UINT64_MAX-1 && pe.before.complete && pe.before.tls_complete &&
        (uintptr_t)pe.before.frame.greg[REG_RIP]==h[21] && (uintptr_t)pe.before.frame.greg[REG_RSP]==h[30] &&
        pe.transfer.previous==h[59] && pe.transfer.phase==LI2_ST_CONSUMED,PE_STATE,161);
    pclo_copy(&pclo_wire.before,&pe.before,sizeof pe.before);
    pclo_copy(&pclo_wire.predecessor,&pe.transfer,sizeof pe.transfer);
    pclo_copy(&pclo_wire.payload,pe_payload(),sizeof pclo_wire.payload);
    pclo_copy(pclo_wire.proof_tail,(const unsigned char *)pe_payload()+sizeof(struct pe_payload),sizeof pclo_wire.proof_tail);
    for(unsigned i=0;i<3;i++)pclo_copy(pclo_wire.code+i*LI2_PE_IMAGE_BYTES,
        (const void *)pg_extent(&PE_SLOT(generation).layout,i),pg_extent_bytes(i));
    pclo_copy(&pclo_wire.entered_generation,&PE_SLOT(generation),sizeof pclo_wire.entered_generation);
    pclo_copy(&pclo_wire.entered_progress,&pe.p,sizeof pe.p);
    pclo_copy(&pclo_wire.entered_source,li2_pg_source_progress(),sizeof pclo_wire.entered_source);
    pclo_copy(&pclo_wire.entered_rseq,li2_pg_rseq_progress(),sizeof pclo_wire.entered_rseq);
    pclo_copy(&pclo_wire.entered_work,w,sizeof *w);pclo_counts(&pclo_wire.entered_counts);
    pclo_copy(&pclo_wire.window_seed,&pcw.seed,sizeof pcw.seed);
    pclo_copy(&pclo_wire.prepared_stack,&pcw.prepared_stack,sizeof pcw.prepared_stack);
    pclo_copy(&pclo_wire.bound_stack,&pcw.bound_stack,sizeof pcw.bound_stack);
    pclo_copy(&pclo_wire.expected_window,&pcw.expected,sizeof pcw.expected);
    pclo_copy(&pclo_wire.window_write,&pcw.write,sizeof pcw.write);
    pclo_copy(&pclo_wire.window_seal,&pcw.seal,sizeof pcw.seal);
    pclo_copy(pclo_wire.window,(const void *)pcw.address,PAGE);
    pclo_copy(pclo_wire.initial_directory,(const void *)pe.domain.directory,LI2_JD_DOMAIN_BYTES);
    pclo_lifetime(&pclo_wire.entered_rseq);pclo_memory(0);pclo_busy=0;
}
static void pclo_terminal(void) {
    pclo_callback();if(!pclo_active)return;
    uint64_t *h=pclo_wire.h;const struct pda_work *w=&pe.domain.work;
    pe_need(!pclo_busy && h[34]==1 && !h[36] && pe.p.phase==LI2_PG_CLOSED && pe_active && pe_busy &&
        w->bound==1 && w->completion==1 && w->view.count==1 && w->receipt<LI2_PGD_RECEIPTS &&
        w->receipt==h[69] && w->exit_member==0 && pe.selected_slot==h[61] && pe.p.serial==h[63] &&
        pe.after.complete && pe.after.tls_complete && (uintptr_t)pe.after.frame.greg[REG_RIP]==h[29] &&
        pclo_wire.raw_ingress[0]==h[35]+1 && !pe.guest_data_fault,PE_STATE,162);
    pclo_busy=1;h[36]=1;h[37]=pclo_wire.raw_ingress[0];h[38]=h[37]+1;
    h[70]=pe.exit_index;h[71]=pe.recovery_complete;h[72]=pe.p.opened_pages;h[73]=pe.p.closed_pages;
    h[74]=pe.p.anchor_released;h[75]=pe.p.completion_permit;h[76]=pe.gpr_written;h[77]=pe.flags_written;
    pclo_copy(&pclo_wire.terminal,&pe.after,sizeof pe.after);
    pclo_copy(&pclo_wire.terminal_progress,&pe.p,sizeof pe.p);
    pclo_copy(&pclo_wire.terminal_work,w,sizeof *w);
    pclo_copy(&pclo_wire.completion,&pe.domain.completion[w->receipt],sizeof pclo_wire.completion);
    pclo_copy(&pclo_wire.claim,&PE_SLOT(claim),sizeof pclo_wire.claim);
    pclo_copy(&pclo_wire.recovered,&pe.recovered,sizeof pe.recovered);
    pclo_counts(&pclo_wire.terminal_counts);
    pclo_compare(&pclo_wire.proof_scan,&pclo_wire.payload,pe_payload(),sizeof pclo_wire.payload);
    pclo_compare(&pclo_wire.proof_scan,pclo_wire.proof_tail,(const unsigned char *)pe_payload()+sizeof(struct pe_payload),sizeof pclo_wire.proof_tail);
    for(unsigned i=0;i<3;i++)pclo_compare(&pclo_wire.code_scan,pclo_wire.code+i*LI2_PE_IMAGE_BYTES,
        (const void *)pg_extent(&PE_SLOT(generation).layout,i),pg_extent_bytes(i));
    pclo_compare(&pclo_wire.window_scan,pclo_wire.window,(const void *)pcw.address,PAGE);
    pclo_copy(pclo_wire.terminal_directory,(const void *)pe.domain.directory,LI2_JD_DOMAIN_BYTES);
    pclo_lifetime(&pclo_wire.completion.rseq);pclo_memory(1);pclo_active=0;pclo_busy=0;
}
void li2_pclo_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    pclo_callback();if(!pclo_ready || !pclo_wire.h[38] || pclo_wire.h[41])return;
    uint64_t *h=pclo_wire.h;
    pe_need(!pclo_busy && h[36]==1 && h[39]==h[38] && h[39]==pclo_wire.raw_ingress[0] && h[40]<2 &&
        chain==&selected_chain && slot==&chain->slots[h[40]] && chain->active==(int)h[40] &&
        chain->in_handler==1 && chain->pending==1 && handling==1 && chain->event_id>slot->event_id &&
        !chain->first_error && !chain->unexpected_events && slot->phase==LI2_CHAIN_CLOSED &&
        !slot->unexpected_frame_observed && slot->decoded.pc==h[29] && slot->owner.actual_post_pc==h[31] &&
        pclo_wire.next.complete && (uintptr_t)pclo_wire.next.frame.greg[REG_RIP]==h[31],PE_STATE,163);
    pclo_busy=1;pclo_copy(pclo_wire.next_closed,slot,sizeof pclo_wire.next_closed);
    pclo_compare(&pclo_wire.unexpected_scan,0,&slot->unexpected,sizeof slot->unexpected);
    pe_tls(&pclo_wire.next);pclo_memory(2);h[41]=1;h[42]=chain->event_id;h[43]=pclo_wire.next.tls_complete;pclo_busy=0;
}
static void pclo_finish(unsigned status,unsigned code,long detail) {
    if(!pclo_ready || pclo_finished)return;
    pclo_finished=1;
    uint64_t *h=pclo_wire.h;unsigned incomplete=!h[32] || !h[34] || !h[36] || !h[41] ||
        !h[43] || h[45] || h[46] || pclo_active || pclo_busy;
    unsigned forced=!status && incomplete;
    if(forced){status=125;code=PE_STATE;detail=164;}
    h[44]=incomplete;h[47]=1;h[48]=status;h[49]=code;h[50]=(uint64_t)detail;
    pclo_counts(&pclo_wire.final_counts);
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
    _Static_assert(sizeof row==sizeof pclo_wire.final_row && sizeof sub==sizeof pclo_wire.final_subentry,"literal final rows");
    pclo_copy(pclo_wire.final_row,row,sizeof row);pclo_copy(pclo_wire.final_subentry,sub,sizeof sub);
    _Static_assert(LI2_PGD_REASON_COUNT==18,"whole literal terminal miss population");
    for(unsigned i=0;i<18;i++)pclo_wire.final_misses[i]=PGC_MISS_VALUE(i);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&pclo_wire.sink_terminal,0,0,0,0);h[51]=(uint64_t)flags;h[52]=(uint64_t)result;
    const struct stat *a=&pclo_wire.sink_initial,*b=&pclo_wire.sink_terminal;
    unsigned sink_ok=!result && flags==(long)h[16] && a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid &&
        a->st_nlink==b->st_nlink && !b->st_size;
    if(sink_ok) {
        h[53]=1;pclo_frozen=1;__asm__ volatile("":::"memory");
        size_t at=0;uint64_t calls=0;result=0;
        while(at<sizeof pclo_wire && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)&pclo_wire+at),sizeof pclo_wire-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof pclo_wire-at)goto done;
            at+=(size_t)result;
        }
        if(at!=sizeof pclo_wire)goto done;
        const uint64_t footer[]={PCLO_FOOTER,1,sizeof pclo_wire,at,calls,(uint64_t)result,status,code};
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
