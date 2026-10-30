/* Distinct three-subject cut-failure capture. Retains actual generated drain,
   then actual original-PC ordinary fault; revoke stimulus is real munmap only. */
#include "linked_preedge_failure_observe_memory.h"
#include "linked_preedge_failure_capture_config.h"
#if LI2_LINKED_PREEDGE_FAILURE_CAPTURE != 1 || LI2_LINKED_PREEDGE != 1 || LI2_LINKED_NATIVE_HINT != 1 || defined(LI2_LINKED_EPOCH_CAPTURE)
#error "dedicated pre-edge v2 capture only"
#endif
#define LPEC_MAGIC UINT64_C(0x324f43454c49324c)
#define LPEC_FOOTER UINT64_C(0x324643454c49324c)
#define LPEC_ENTRIES 1U
struct lpec_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct lpec_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct lpec_entry {
    uint64_t present,closed,source_ready,redirected,completed,terminal;
    uint64_t source_bytes,generated_bytes,terminal_source_bytes,proof_bytes,proof_final_bytes;
    uint64_t ingress_event,redirect_event,terminal_event,frontier_closed;
    struct le_record owner;
    struct le_slot slot;
    struct le_proof_publication proof_publication;
    struct ler_permit permit;
    struct li2_preedge_epoch_progress epoch_held,epoch_opened,epoch_terminal;
    struct li2_lpec_memory before_memory,after_memory;
    struct lpec_owners source_owners,redirected_owners,completed_owners;
    struct li2_tf_chain predecessor,closed_chain;
    uint64_t counts_before[10],counts_after[10],ready_generation;
    unsigned char source_page[PAGE],generated_page[PAGE],terminal_source_page[PAGE];
    struct li2_preedge_proof proof,proof_final;
    unsigned char proof_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
    unsigned char proof_final_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
};
struct lpec_wire {
    uint64_t h[64],control[24],counts[39],events[18],raw_ingress[6],storage[8];
    struct li2_private_code_query initial_code[2],initial_proof[16];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct lpec_registry initial_registry,terminal_registry;
    struct lpec_entry entries[1];
    uint64_t post[8];
    struct le_frame post_cut;
    struct li2_tf_chain post_before,post_after;
    unsigned char post_data[8192],post_stack[224];
    struct lpec_owners terminal_owners;
    struct li2_fetch_progress terminal_fetch;
    struct li2_native_close terminal_global_close;
    struct li2_native_counts terminal_native_counts;
    struct li2_tf_chain terminal_chain;
    struct le_record terminal_record;
    struct li2_span_transfer_progress terminal_transfer;
    struct li2_current_custody_stats terminal_current;
    struct li2_preedge_epoch_progress terminal_epoch;
    struct li2_link_native_hint_progress terminal_hint;
    unsigned char original_source[PAGE];
};
static struct lpec_wire lpec_wire;
static unsigned lpec_ready,lpec_finished,lpec_active,lpec_index;
static uintptr_t lpec_head,lpec_page,lpec_cut,lpec_target;
static const uint64_t lpec_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct lpec_wire)+64<(16U<<20),"dedicated v2 full-state wire and footer under original cap");
static void lpec_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void lpec_registry(struct lpec_registry *out) {
    le_need(!out->complete && protected_count && protected_count<=RANGES,LE_STATE,100);
    const struct image *b=bridge_runtime_image();
    le_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,LE_STATE,101);
    lpec_copy(&out->bridge,b,sizeof *b);lpec_copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    lpec_copy(out->ranges,protected,protected_count*sizeof(*protected));
    lpec_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void lpec_owners(struct lpec_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    lpec_copy(&out->rseq,r,sizeof(*r));lpec_copy(&out->rseq_native,n,sizeof(*n));
    lpec_copy(&out->pair,p,sizeof(*p));lpec_copy(&out->lifecycle,l,sizeof(*l));
    lpec_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}
static int lpec_same_sink(const struct stat *s) {
    const struct stat *a=&lpec_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}
static void lpec_initialize(void) {
    __asm__ volatile(""::"r"(&lpec_step_frame_fp_alignment):"memory");
    le_need(!lpec_ready && !lpec_finished,LE_STATE,102);
    uint64_t *h=lpec_wire.h;
    h[0]=LPEC_MAGIC;h[1]=2;h[2]=sizeof lpec_wire;h[3]=sizeof(struct lpec_entry);
    h[4]=sizeof(struct le_record);h[5]=sizeof(struct le_slot);h[6]=sizeof(struct le_frame);
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    le_need(!selected_run_protect_add(0,(uintptr_t)&lpec_wire,sizeof lpec_wire),LE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpec_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    le_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(lpec_wire.sink_initial.st_mode) && (lpec_wire.sink_initial.st_mode&07777)==0600 &&
        lpec_wire.sink_initial.st_nlink==1 && lpec_wire.sink_initial.st_size==0,LE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_LINKED_PREEDGE_FAILURE_APP_MODE");
    le_need(mode && mode[0]>='0' && mode[0]<='1' && !mode[1],LE_STATE,105);h[24]=(unsigned)(mode[0]-'0');
    lpec_copy(&lpec_wire.main,&original_main,sizeof original_main);
    lpec_copy(&lpec_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    lpec_copy(&lpec_wire.hardware,&selected_hardware,sizeof selected_hardware);
    lpec_copy(&lpec_wire.session,&selected_session,sizeof selected_session);
    const uintptr_t heads[]={LI2_PREEDGE_FAILURE_APP_HEAD_RVA,LI2_PREEDGE_FAILURE_APP_REVOKE_HEAD_RVA};
    const uintptr_t cuts[]={LI2_PREEDGE_FAILURE_APP_CUT_RVA,LI2_PREEDGE_FAILURE_APP_REVOKE_CUT_RVA};
    const uintptr_t targets[]={LI2_PREEDGE_FAILURE_APP_CUT_RVA,LI2_PREEDGE_FAILURE_APP_REVOKE_TARGET_RVA};
    uintptr_t rva=heads[h[24]];
    le_need(original_main.bias<=UINTPTR_MAX-cuts[h[24]] && original_main.bias<=UINTPTR_MAX-targets[h[24]],LE_STATE,106);
    lpec_cut=original_main.bias+cuts[h[24]];lpec_target=original_main.bias+targets[h[24]];
    le_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-rva,LE_STATE,107);
    lpec_head=original_main.bias+rva;lpec_page=lpec_head&~(uintptr_t)(PAGE-1);
    le_need(lpec_head>=PAGE && lpec_head<(UINT64_C(1)<<31) && (lpec_head&(PAGE-1))==(h[24]?4060U:4063U) &&
        lpec_cut==lpec_head+30 && lpec_target==(h[24]?lpec_page+3968:lpec_cut),LE_STATE,108);
    lpec_wire.control[0]=h[24]; /* Exact separate actual revoke stimulus, not old control4. */
    unsigned found=0;size_t offset=0;uintptr_t page_rva=rva&~(uintptr_t)(PAGE-1);
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || page_rva<p->p_vaddr || page_rva-p->p_vaddr>=p->p_filesz)continue;
        le_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(page_rva-p->p_vaddr)>=PAGE,LE_STATE,109);
        offset=(size_t)(p->p_offset+page_rva-p->p_vaddr);found=1;
    }
    le_need(found,LE_STATE,110);lpec_copy(lpec_wire.original_source,original_main.source+offset,PAGE);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&lpec_wire.main_backing,0,0,0,0);
    h[19]=(uint64_t)result;le_need(!result && S_ISREG(lpec_wire.main_backing.st_mode),LE_STATE,111);
    h[20]=lpec_head;h[21]=offset;h[22]=dependency_count;h[23]=1;
    h[52]=(uintptr_t)&selected_linked_epoch;h[53]=(uintptr_t)li2_tf_chain_span_progress();
    h[54]=(uintptr_t)&ler;h[55]=(uintptr_t)&selected_chain;h[56]=(uintptr_t)&lpec_wire;
    lpec_registry(&lpec_wire.initial_registry);
    const uint64_t storage[]={selected_linked_epoch.arena,selected_linked_epoch.low_arena,LE_BYTES,lep.arena,LE_PROOF_TOTAL,(uintptr_t)&lep,(uintptr_t)li2_lifecycle_preedge_progress(),(uintptr_t)&ler};
    lpec_copy(lpec_wire.storage,storage,sizeof storage);
    lpec_copy(&lpec_wire.initial_code[0],&selected_linked_epoch.initial,sizeof selected_linked_epoch.initial);
    lpec_copy(&lpec_wire.initial_code[1],&selected_linked_epoch.low_initial,sizeof selected_linked_epoch.low_initial);
    lpec_copy(lpec_wire.initial_proof,lep.initial,sizeof lep.initial);lpec_ready=1;
}
static void lpec_fd_guard(long n,const long a[6]) {
    if(!lpec_ready)return;
    le_need(!lpec_finished,LE_STATE,110);
    le_count(&lpec_wire.h[43]);
    if(n==SYS_openat) {
        le_count(&lpec_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)lpec_wire.h[49]=1;
        le_need(!writable,LE_STATE,111);
    }
    long fd=-1;
    switch(n) {
    case SYS_read:case SYS_write:case SYS_readv:case SYS_writev:case SYS_close:
    case SYS_fstat:case SYS_fstatfs:case SYS_lseek:case SYS_pread64:case SYS_getdents64:
    case SYS_fgetxattr:case SYS_flistxattr:case SYS_fcntl:case SYS_openat:
    case SYS_newfstatat:case SYS_statx:case SYS_faccessat:case SYS_faccessat2:case SYS_readlinkat:
    case SYS_dup:case SYS_dup2:case SYS_dup3:fd=a[0];break;
    case SYS_mmap:if(!(a[3]&MAP_ANONYMOUS))fd=a[4];break;
    default:break;
    }
    if(n==SYS_dup2 || n==SYS_dup3)le_need((unsigned)a[1]!=3,LE_STATE,112);
    if((int)fd<0)return;
    if((unsigned)fd==3)lpec_wire.h[48]=1;
    le_need((unsigned)fd!=3,LE_STATE,113);le_count(&lpec_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    le_need(!result || result==-9,LE_STATE,121);
    if(result)le_count(&lpec_wire.h[45]);
    if(!result && observed.st_dev==lpec_wire.sink_initial.st_dev &&
       observed.st_ino==lpec_wire.sink_initial.st_ino)lpec_wire.h[48]=1;
    le_need(result || observed.st_dev!=lpec_wire.sink_initial.st_dev ||
        observed.st_ino!=lpec_wire.sink_initial.st_ino,LE_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}
static void lpec_ingress(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!lpec_ready || lpec_finished)return;
    le_event_count(&lpec_wire.raw_ingress[0]);unsigned k=sig==SIGSEGV?1:sig==SIGTRAP?2:sig==SIGILL?3:sig==SIGSYS?4:5;
    le_event_count(&lpec_wire.raw_ingress[k]);struct lpec_entry *e=&lpec_wire.entries[0];
    if(e->redirected && !e->terminal_event)e->terminal_event=lpec_wire.raw_ingress[0];
    if(!e->completed || lpec_wire.post[0])return;
    le_need(!lpec_wire.h[24] && uc && si && sig==SIGSEGV && si->si_signo==SIGSEGV &&
        si->si_code==SEGV_ACCERR && !si->si_errno && (uintptr_t)si->si_addr==LPEC_DATA_BASE+LPEC_DATA_BYTES &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==lpec_cut &&
        lpec_wire.raw_ingress[0]==e->terminal_event+1,LE_EVENT,170);
    le_need(!le_capture(&lpec_wire.post_cut,sig,si,uc),LE_FRAME,170);
    lpec_wire.post[0]=1;lpec_wire.post[1]=lpec_wire.raw_ingress[0];lpec_wire.post[2]=selected_pending_route;
    lpec_copy(&lpec_wire.post_before,&selected_chain,sizeof selected_chain);
    /* The failed whole load has no write/TLS effect. Read only the already
       observed accessible data/stack ranges, never the unreadable load target. */
    le_need(e->after_memory.complete && (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==LPEC_STACK_RSP,LE_STATE,170);
    lpec_copy(lpec_wire.post_data,(void *)LPEC_DATA_BASE,sizeof lpec_wire.post_data);
    lpec_copy(lpec_wire.post_stack,(void *)(LPEC_STACK_RSP-128),sizeof lpec_wire.post_stack);lpec_wire.post[3]=1;
}
static void lpec_end(int sig,const siginfo_t *si,const ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    /* Both declared gated failures are nonreturning. A returned dispatch is an
       explicit failed witness, never a substitute for terminal chain cleanup. */
    if(lpec_ready && lpec_wire.post[0])lpec_wire.post[6]=1;
}
static int lpec_focal(void) {
    return lpec_ready && lpec_active && lpec_index<LPEC_ENTRIES &&
        selected_linked_epoch.current.transfer.pc==lpec_head;
}
static void lpec_counts(uint64_t out[10]) {
    out[0]=selected_linked_epoch.entries;out[1]=selected_linked_epoch.completed;
    out[2]=selected_linked_epoch.plan_checks;out[3]=selected_linked_epoch.rseq_checks;
    out[4]=selected_linked_epoch.live_checks;out[5]=selected_linked_epoch.proof_checks;
    out[6]=selected_linked_epoch.publications;out[7]=selected_linked_epoch.hits;
    out[8]=ler.retirement_attempts;out[9]=ler.retirements;
}
static void lpec_save(void) {
    if(!lpec_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpec_entry *e=&lpec_wire.entries[lpec_index];
    lpec_copy(&e->owner,r,sizeof *r);
    if(r->slot_present && r->slot<selected_linked_epoch.used && r->slot<LE_PAGES) {
        const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
        lpec_copy(&e->slot,s,sizeof *s);lpec_copy(&e->proof_publication,&lep.slot_publication[r->slot],sizeof e->proof_publication);
        lpec_copy(&e->permit,&ler.permits[r->slot],sizeof e->permit);e->ready_generation=lep.ready_generation[r->slot];
    }
    lpec_copy(&e->epoch_terminal,li2_lifecycle_preedge_progress(),sizeof e->epoch_terminal);lpec_counts(e->counts_after);
}
static void lpec_begin(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    lpec_active=lpec_ready && r->ingress.complete && (uintptr_t)r->ingress.frame.greg[REG_RIP]==lpec_head;
    if(!lpec_active)return;
    le_need(!lpec_wire.h[25],LE_STATE,130);lpec_wire.h[25]=1;lpec_index=0;
    struct lpec_entry *e=&lpec_wire.entries[0];le_need(!e->present,LE_STATE,131);
    e->present=1;e->ingress_event=lpec_wire.raw_ingress[0];lpec_counts(e->counts_before);
    lpec_wire.control[5]=selected_linked_epoch.cut_exits;
    lpec_copy(&e->predecessor,&selected_chain,sizeof selected_chain);
}
static void lpec_closed(void) {
    if(!lpec_focal())return;
    struct lpec_entry *e=&lpec_wire.entries[0];
    le_need(selected_linked_epoch.current.close_complete && !e->closed,LE_STATE,133);
    e->closed=1;lpec_copy(&e->closed_chain,&selected_chain,sizeof selected_chain);lpec_save();
}
static void lpec_source(void) {
    if(!lpec_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpec_entry *e=&lpec_wire.entries[lpec_index];
    le_need(r->source.ready==1 && r->source.key.page.object==dependency_count && r->source.key.page.address==lpec_page &&
        r->source.key.entry==lpec_head && r->source.key.backing.stat.st_dev==lpec_wire.main_backing.st_dev &&
        r->source.key.backing.stat.st_ino==lpec_wire.main_backing.st_ino && r->source.key.backing.stat.st_size==lpec_wire.main_backing.st_size &&
        equal(r->source.key.bytes,lpec_wire.original_source,PAGE),LE_SOURCE,130);
    le_need(!e->source_ready,LE_STATE,134);e->source_ready=1;
    lpec_copy(e->source_page,(void *)lpec_page,PAGE);e->source_bytes=PAGE;lpec_owners(&e->source_owners,0);
    int error=li2_lifecycle_preedge_failure_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,&e->before_memory);
    le_need(!error && e->before_memory.complete,LE_STATE,135);lpec_save();
}
static void lpec_held(void) {
    if(!lpec_focal())return;
    struct lpec_entry *e=&lpec_wire.entries[lpec_index];const struct le_record *r=&selected_linked_epoch.current;
    lpec_copy(&e->epoch_held,li2_lifecycle_preedge_progress(),sizeof e->epoch_held);
    const struct le_slot *slot=&selected_linked_epoch.slots[r->slot];
    lpec_copy(&e->proof,(void *)slot->proof,sizeof e->proof);
    lpec_copy(e->proof_tail,(const unsigned char *)slot->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpec_copy(e->generated_page,(void *)slot->generated,PAGE);e->generated_bytes=PAGE;lpec_save();
}
static void lpec_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    if(!lpec_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpec_entry *e=&lpec_wire.entries[lpec_index];
    le_need(e->source_ready && r->slot_present && r->redirected && !e->redirected,LE_STATE,139);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    e->redirected=1;e->redirect_event=lpec_wire.raw_ingress[0];lpec_owners(&e->redirected_owners,1);
    lpec_copy(e->generated_page,(void *)s->generated,PAGE);e->generated_bytes=PAGE;
    lpec_copy(&e->proof,(void *)s->proof,sizeof e->proof);
    lpec_copy(e->proof_tail,(const unsigned char *)s->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpec_copy(&e->epoch_opened,li2_lifecycle_preedge_progress(),sizeof e->epoch_opened);lpec_save();
}
static void lpec_before_close(void) {
    if(!lpec_focal() || lpec_wire.h[24]!=1)return;
    const struct le_record *r=&selected_linked_epoch.current;
    le_need(r->exit_seen && r->after.complete && !r->close.started && !lpec_wire.control[1],LE_STATE,140);
    lpec_wire.control[1]=1;lpec_wire.control[2]=1;
    long result=raw(SYS_munmap,selected_linked_epoch.slots[r->slot].generated,PAGE,0,0,0,0);
    lpec_wire.control[3]=1;lpec_wire.control[4]=(uint64_t)result;le_need(!result,LE_STATE,141);
    /* The unchanged real mprotect+sync+query now must record ENOMEM. No saved
       frame, permission result, source epoch or completion field is changed. */
}
static void lpec_memory_terminal(unsigned after_abort) {
    if(!lpec_focal())return;
    struct lpec_entry *e=&lpec_wire.entries[lpec_index];const struct le_record *r=&selected_linked_epoch.current;
    if(!e->after_memory.attempted) {
        int error=li2_lifecycle_preedge_failure_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],after_abort,&e->after_memory);
        if(error || !e->after_memory.complete)lpec_wire.h[39]=3;
    }
    lpec_copy(e->terminal_source_page,(void *)lpec_page,PAGE);e->terminal_source_bytes=PAGE;
}
static void lpec_complete(void) {
    if(!lpec_focal())return;
    struct lpec_entry *e=&lpec_wire.entries[lpec_index];const struct le_record *r=&selected_linked_epoch.current;
    le_need(!e->completed && r->completed && !ler.pending && r->epoch_final.phase==LI2_PREEDGE_RELEASED,LE_STATE,142);
    lpec_owners(&e->completed_owners,0);e->completed=1;lpec_memory_terminal(0);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    lpec_copy(&e->proof_final,(void *)s->proof,sizeof e->proof_final);
    lpec_copy(e->proof_final_tail,(const unsigned char *)s->proof+sizeof e->proof_final,sizeof e->proof_final_tail);
    e->proof_final_bytes=LI2_LINK_PROOF_BYTES;le_need(!lpec_wire.h[39],LE_STATE,143);lpec_save();
}
static void lpec_abort_observe(void) {
    if(!lpec_focal())return;
    if(selected_linked_epoch.current.before.complete)lpec_memory_terminal(1);
    lpec_save();
}
static void lpec_finish(unsigned status,unsigned code,long detail) {
    if(lpec_finished || !lpec_wire.h[18])return;
    lpec_finished=1;uint64_t *h=lpec_wire.h;
    h[26]=1;h[27]=status;h[28]=code;h[29]=(uint64_t)detail;
    lpec_wire.control[6]=selected_linked_epoch.cut_exits;
    h[30]=lpec_active;h[31]=selected_linked_epoch_active;h[32]=selected_linked_epoch_busy;
    h[33]=selected_linked_epoch_failing;h[34]=handling;h[35]=selected_step_pending;
    h[36]=selected_pending_route;h[37]=selected_flags_known;h[38]=selected_logical_flags;
    if(lpec_focal())lpec_save();
    /* Finalized retained focal observation; later unrelated offers may have
       replaced the live current record, never this completed by-value copy. */
    for(unsigned i=0;i<lpec_wire.h[25] && i<LPEC_ENTRIES;i++)lpec_wire.entries[i].terminal=1;
    const uint64_t counts[]={selected_linked_epoch.initialized,selected_linked_epoch.used,
        selected_linked_epoch.offers,selected_linked_epoch.closed,selected_linked_epoch.resumed,
        selected_linked_epoch.hash_misses,selected_linked_epoch.candidates,selected_linked_epoch.source_misses,
        selected_linked_epoch.plan_misses,selected_linked_epoch.capacity_misses,selected_linked_epoch.publications,
        selected_linked_epoch.hits,selected_linked_epoch.entries,selected_linked_epoch.completed,
        selected_linked_epoch.unexpected,selected_linked_epoch.plan_checks,selected_linked_epoch.rseq_checks,
        ler.generation,ler.retirement_attempts,ler.retirements,ler.claims,ler.permits_issued,
        ler.pending,ler.retiring,ler.cursor,selected_linked_epoch.first_error,
        (uint64_t)selected_linked_epoch.first_detail,selected_linked_epoch_decoding,
        selected_linked_epoch_closing,selected_linked_epoch_resuming,selected_linked_epoch.live_checks,selected_linked_epoch.proof_checks,
        lep.pending,lep.arena,LE_PROOF_TOTAL,(uintptr_t)&lep,selected_linked_epoch.refaults
#ifdef LI2_LINKED_NATIVE_HINT
        ,selected_linked_epoch.graph_refaults,selected_linked_epoch.cut_exits
#endif
    };
    lpec_copy(lpec_wire.counts,counts,sizeof counts);
#ifdef LI2_LINKED_NATIVE_HINT
    lpec_copy(&lpec_wire.terminal_hint,li2_lifecycle_link_native_hint_progress(),sizeof lpec_wire.terminal_hint);
#endif
    lpec_wire.events[0]=selected_linked_epoch.events;
    lpec_copy(lpec_wire.events+1,selected_linked_epoch.signals,sizeof selected_linked_epoch.signals);
    lpec_copy(lpec_wire.events+6,selected_linked_epoch.refusals,sizeof selected_linked_epoch.refusals);
    lpec_copy(lpec_wire.events+10,selected_linked_epoch.exit_counts,sizeof selected_linked_epoch.exit_counts);
    lpec_copy(&lpec_wire.terminal_record,&selected_linked_epoch.current,sizeof selected_linked_epoch.current);
    lpec_copy(&lpec_wire.terminal_transfer,li2_tf_chain_span_progress(),sizeof lpec_wire.terminal_transfer);
    lpec_owners(&lpec_wire.terminal_owners,0);
    li2_current_custody_snapshot(&lpec_wire.terminal_current);
    lpec_copy(&lpec_wire.terminal_epoch,li2_lifecycle_preedge_progress(),sizeof lpec_wire.terminal_epoch);
    lpec_copy(&lpec_wire.terminal_chain,&selected_chain,sizeof selected_chain);
    if(lpec_wire.post[0]) {
        lpec_copy(&lpec_wire.post_after,&selected_chain,sizeof selected_chain);
        lpec_wire.post[4]=1;lpec_wire.post[5]=selected_pending_route;
    }
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    const struct li2_native_close *g=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(f){lpec_copy(&lpec_wire.terminal_fetch,f,sizeof *f);h[50]=1;}
    if(g){lpec_copy(&lpec_wire.terminal_global_close,g,sizeof *g);h[51]=1;}
    if(n){lpec_copy(&lpec_wire.terminal_native_counts,n,sizeof *n);h[57]=1;}
    /* Wire v2 captures every remaining LI2_NATIVE operand, independently of
       its text report. These five words were required-zero in wire v1. */
    const struct li2_native_epoch *ne=li2_native_epoch_progress();
    h[58]=native_main_admissions;h[59]=native_main_refaults;
    h[60]=ne->ready;h[61]=ne->retries;h[62]=ne->first_error;
    lpec_registry(&lpec_wire.terminal_registry);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpec_wire.sink_terminal,0,0,0,0);
    h[41]=(uint64_t)flags;h[42]=(uint64_t)result;
    if(result || flags!=(long)h[16] || !lpec_same_sink(&lpec_wire.sink_terminal) || lpec_wire.sink_terminal.st_size){h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof lpec_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lpec_wire+at),sizeof lpec_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lpec_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lpec_wire)return;
    const uint64_t footer[]={LPEC_FOOTER,2,sizeof lpec_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
