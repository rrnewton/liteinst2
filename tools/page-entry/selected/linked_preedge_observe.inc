/* Distinct primitive-only pre-edge capture. Copies actual owner/kernel state;
   no gate bypass, guest-state edits, substitute NX or invented completion. */
#include "linked_preedge_observe_memory.h"
#include "linked_preedge_capture_config.h"
#if LI2_LINKED_PREEDGE_CAPTURE != 1 || LI2_LINKED_PREEDGE != 1 || LI2_LINKED_NATIVE_HINT != 1 || defined(LI2_LINKED_EPOCH_CAPTURE)
#error "dedicated pre-edge v2 capture only"
#endif
#define LPEO_MAGIC UINT64_C(0x324f45504c49324c)
#define LPEO_FOOTER UINT64_C(0x324645504c49324c)
#define LPEO_ENTRIES 1U
struct lpeo_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct lpeo_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct lpeo_entry {
    uint64_t present,closed,source_ready,redirected,completed,terminal;
    uint64_t source_bytes,generated_bytes,terminal_source_bytes,proof_bytes,proof_final_bytes;
    uint64_t ingress_event,redirect_event,terminal_event,frontier_closed;
    struct le_record owner;
    struct le_slot slot;
    struct le_proof_publication proof_publication;
    struct ler_permit permit;
    struct li2_preedge_epoch_progress epoch_held,epoch_opened,epoch_terminal;
    struct li2_lpeo_memory before_memory,after_memory;
    struct lpeo_owners source_owners,redirected_owners,completed_owners;
    struct li2_tf_chain predecessor,closed_chain;
    uint64_t counts_before[10],counts_after[10],ready_generation;
    unsigned char source_page[PAGE],generated_page[PAGE],terminal_source_page[PAGE];
    struct li2_preedge_proof proof,proof_final;
    unsigned char proof_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
    unsigned char proof_final_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
};
struct lpeo_wire {
    uint64_t h[64],control[24],counts[39],events[18],raw_ingress[6],storage[8];
    struct li2_private_code_query initial_code[2],initial_proof[16];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct lpeo_registry initial_registry,terminal_registry;
    struct lpeo_entry entries[1];
    uint64_t post[8];
    struct le_frame post_cut;
    struct li2_tf_chain post_before,post_after;
    unsigned char post_data[8192],post_stack[224];
    struct lpeo_owners terminal_owners;
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
static struct lpeo_wire lpeo_wire;
static unsigned lpeo_ready,lpeo_finished,lpeo_active,lpeo_index;
static uintptr_t lpeo_head,lpeo_page,lpeo_cut,lpeo_target;
static const uint64_t lpeo_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct lpeo_wire)+64<(16U<<20),"dedicated v2 full-state wire and footer under original cap");
static void lpeo_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void lpeo_registry(struct lpeo_registry *out) {
    le_need(!out->complete && protected_count && protected_count<=RANGES,LE_STATE,100);
    const struct image *b=bridge_runtime_image();
    le_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,LE_STATE,101);
    lpeo_copy(&out->bridge,b,sizeof *b);lpeo_copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    lpeo_copy(out->ranges,protected,protected_count*sizeof(*protected));
    lpeo_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void lpeo_owners(struct lpeo_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    lpeo_copy(&out->rseq,r,sizeof(*r));lpeo_copy(&out->rseq_native,n,sizeof(*n));
    lpeo_copy(&out->pair,p,sizeof(*p));lpeo_copy(&out->lifecycle,l,sizeof(*l));
    lpeo_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}
static int lpeo_same_sink(const struct stat *s) {
    const struct stat *a=&lpeo_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}
static void lpeo_initialize(void) {
    __asm__ volatile(""::"r"(&lpeo_step_frame_fp_alignment):"memory");
    le_need(!lpeo_ready && !lpeo_finished,LE_STATE,102);
    uint64_t *h=lpeo_wire.h;
    h[0]=LPEO_MAGIC;h[1]=2;h[2]=sizeof lpeo_wire;h[3]=sizeof(struct lpeo_entry);
    h[4]=sizeof(struct le_record);h[5]=sizeof(struct le_slot);h[6]=sizeof(struct le_frame);
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    le_need(!selected_run_protect_add(0,(uintptr_t)&lpeo_wire,sizeof lpeo_wire),LE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpeo_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    le_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(lpeo_wire.sink_initial.st_mode) && (lpeo_wire.sink_initial.st_mode&07777)==0600 &&
        lpeo_wire.sink_initial.st_nlink==1 && lpeo_wire.sink_initial.st_size==0,LE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_LINKED_PREEDGE_APP_MODE");
    le_need(mode && mode[0]>='0' && mode[0]<='3' && !mode[1],LE_STATE,105);h[24]=(unsigned)(mode[0]-'0');
    lpeo_copy(&lpeo_wire.main,&original_main,sizeof original_main);
    lpeo_copy(&lpeo_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    lpeo_copy(&lpeo_wire.hardware,&selected_hardware,sizeof selected_hardware);
    lpeo_copy(&lpeo_wire.session,&selected_session,sizeof selected_session);
    const uintptr_t heads[]={LI2_PREEDGE_APP_HEAD_RVA,LI2_PREEDGE_APP_HEAD_RVA,LI2_PREEDGE_APP_NEXT_HEAD_RVA,LI2_PREEDGE_APP_UNSUPPORTED_HEAD_RVA};
    const uintptr_t cuts[]={LI2_PREEDGE_APP_CUT_RVA,LI2_PREEDGE_APP_CUT_RVA,LI2_PREEDGE_APP_NEXT_CUT_RVA,LI2_PREEDGE_APP_UNSUPPORTED_CUT_RVA};
    const uintptr_t targets[]={LI2_PREEDGE_APP_TAKEN_RVA,LI2_PREEDGE_APP_FALLTHROUGH_RVA,LI2_PREEDGE_APP_NEXT_TARGET_RVA,LI2_PREEDGE_APP_UNSUPPORTED_TARGET_RVA};
    uintptr_t rva=heads[h[24]];
    le_need(original_main.bias<=UINTPTR_MAX-cuts[h[24]] && original_main.bias<=UINTPTR_MAX-targets[h[24]],LE_STATE,106);
    lpeo_cut=original_main.bias+cuts[h[24]];lpeo_target=original_main.bias+targets[h[24]];
    le_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-rva,LE_STATE,107);
    lpeo_head=original_main.bias+rva;lpeo_page=lpeo_head&~(uintptr_t)(PAGE-1);
    le_need(lpeo_head>=PAGE && lpeo_head<(UINT64_C(1)<<31) && (lpeo_head&(PAGE-1))==(h[24]<2?4060U:4064U) && lpeo_cut==lpeo_head+30 && lpeo_target==(h[24]?lpeo_page+PAGE:lpeo_page+3968),LE_STATE,108);
    unsigned found=0;size_t offset=0;uintptr_t page_rva=rva&~(uintptr_t)(PAGE-1);
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || page_rva<p->p_vaddr || page_rva-p->p_vaddr>=p->p_filesz)continue;
        le_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(page_rva-p->p_vaddr)>=PAGE,LE_STATE,109);
        offset=(size_t)(p->p_offset+page_rva-p->p_vaddr);found=1;
    }
    le_need(found,LE_STATE,110);lpeo_copy(lpeo_wire.original_source,original_main.source+offset,PAGE);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&lpeo_wire.main_backing,0,0,0,0);
    h[19]=(uint64_t)result;le_need(!result && S_ISREG(lpeo_wire.main_backing.st_mode),LE_STATE,111);
    h[20]=lpeo_head;h[21]=offset;h[22]=dependency_count;h[23]=1;
    h[52]=(uintptr_t)&selected_linked_epoch;h[53]=(uintptr_t)li2_tf_chain_span_progress();
    h[54]=(uintptr_t)&ler;h[55]=(uintptr_t)&selected_chain;h[56]=(uintptr_t)&lpeo_wire;
    lpeo_registry(&lpeo_wire.initial_registry);
    const uint64_t storage[]={selected_linked_epoch.arena,selected_linked_epoch.low_arena,LE_BYTES,lep.arena,LE_PROOF_TOTAL,(uintptr_t)&lep,(uintptr_t)li2_lifecycle_preedge_progress(),(uintptr_t)&ler};
    lpeo_copy(lpeo_wire.storage,storage,sizeof storage);
    lpeo_copy(&lpeo_wire.initial_code[0],&selected_linked_epoch.initial,sizeof selected_linked_epoch.initial);
    lpeo_copy(&lpeo_wire.initial_code[1],&selected_linked_epoch.low_initial,sizeof selected_linked_epoch.low_initial);
    lpeo_copy(lpeo_wire.initial_proof,lep.initial,sizeof lep.initial);lpeo_ready=1;
}
static void lpeo_fd_guard(long n,const long a[6]) {
    if(!lpeo_ready)return;
    le_need(!lpeo_finished,LE_STATE,110);
    le_count(&lpeo_wire.h[43]);
    if(n==SYS_openat) {
        le_count(&lpeo_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)lpeo_wire.h[49]=1;
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
    if((unsigned)fd==3)lpeo_wire.h[48]=1;
    le_need((unsigned)fd!=3,LE_STATE,113);le_count(&lpeo_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    le_need(!result || result==-9,LE_STATE,121);
    if(result)le_count(&lpeo_wire.h[45]);
    if(!result && observed.st_dev==lpeo_wire.sink_initial.st_dev &&
       observed.st_ino==lpeo_wire.sink_initial.st_ino)lpeo_wire.h[48]=1;
    le_need(result || observed.st_dev!=lpeo_wire.sink_initial.st_dev ||
        observed.st_ino!=lpeo_wire.sink_initial.st_ino,LE_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}
static void lpeo_ingress(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!lpeo_ready || lpeo_finished)return;
    le_event_count(&lpeo_wire.raw_ingress[0]);unsigned k=sig==SIGSEGV?1:sig==SIGTRAP?2:sig==SIGILL?3:sig==SIGSYS?4:5;
    le_event_count(&lpeo_wire.raw_ingress[k]);struct lpeo_entry *e=&lpeo_wire.entries[0];
    if(e->redirected && !e->terminal_event)e->terminal_event=lpeo_wire.raw_ingress[0];
    if(!e->completed || lpeo_wire.post[0])return;
    le_need(uc && si && sig==SIGTRAP && si->si_signo==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==lpeo_target &&
        lpeo_wire.raw_ingress[0]==e->terminal_event+1,LE_EVENT,170);
    le_need(!le_capture(&lpeo_wire.post_cut,sig,si,uc),LE_FRAME,170);
    lpeo_wire.post[0]=1;lpeo_wire.post[1]=lpeo_wire.raw_ingress[0];lpeo_wire.post[2]=selected_pending_route;
    lpeo_copy(&lpeo_wire.post_before,&selected_chain,sizeof selected_chain);
    /* The just-executed whole cut is register/flags/control-only. Its unchanged
       protected full-page description and the preceding real map observation
       authenticate these fixed bytes; no new maps/TLS RAW occurs with old TF live. */
    le_need(e->after_memory.complete && (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==LPEO_STACK_RSP,LE_STATE,170);
    lpeo_copy(lpeo_wire.post_data,(void *)LPEO_DATA_BASE,sizeof lpeo_wire.post_data);
    lpeo_copy(lpeo_wire.post_stack,(void *)(LPEO_STACK_RSP-128),sizeof lpeo_wire.post_stack);lpeo_wire.post[3]=1;
}
static void lpeo_end(int sig,const siginfo_t *si,const ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    if(!lpeo_ready || !lpeo_wire.post[0] || lpeo_wire.post[4])return;
    le_need(lpeo_wire.post[1]==lpeo_wire.raw_ingress[0],LE_STATE,171);
    lpeo_copy(&lpeo_wire.post_after,&selected_chain,sizeof selected_chain);
    lpeo_wire.post[4]=1;lpeo_wire.post[5]=selected_pending_route;
}
static int lpeo_focal(void) {
    return lpeo_ready && lpeo_active && lpeo_index<LPEO_ENTRIES &&
        selected_linked_epoch.current.transfer.pc==lpeo_head;
}
static void lpeo_counts(uint64_t out[10]) {
    out[0]=selected_linked_epoch.entries;out[1]=selected_linked_epoch.completed;
    out[2]=selected_linked_epoch.plan_checks;out[3]=selected_linked_epoch.rseq_checks;
    out[4]=selected_linked_epoch.live_checks;out[5]=selected_linked_epoch.proof_checks;
    out[6]=selected_linked_epoch.publications;out[7]=selected_linked_epoch.hits;
    out[8]=ler.retirement_attempts;out[9]=ler.retirements;
}
static void lpeo_save(void) {
    if(!lpeo_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpeo_entry *e=&lpeo_wire.entries[lpeo_index];
    lpeo_copy(&e->owner,r,sizeof *r);
    if(r->slot_present && r->slot<selected_linked_epoch.used && r->slot<LE_PAGES) {
        const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
        lpeo_copy(&e->slot,s,sizeof *s);lpeo_copy(&e->proof_publication,&lep.slot_publication[r->slot],sizeof e->proof_publication);
        lpeo_copy(&e->permit,&ler.permits[r->slot],sizeof e->permit);e->ready_generation=lep.ready_generation[r->slot];
    }
    lpeo_copy(&e->epoch_terminal,li2_lifecycle_preedge_progress(),sizeof e->epoch_terminal);lpeo_counts(e->counts_after);
}
static void lpeo_begin(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    lpeo_active=lpeo_ready && r->ingress.complete && (uintptr_t)r->ingress.frame.greg[REG_RIP]==lpeo_head;
    if(!lpeo_active)return;
    le_need(!lpeo_wire.h[25],LE_STATE,130);lpeo_wire.h[25]=1;lpeo_index=0;
    struct lpeo_entry *e=&lpeo_wire.entries[0];le_need(!e->present,LE_STATE,131);
    e->present=1;e->ingress_event=lpeo_wire.raw_ingress[0];lpeo_counts(e->counts_before);
    lpeo_copy(&e->predecessor,&selected_chain,sizeof selected_chain);
}
static void lpeo_closed(void) {
    if(!lpeo_focal())return;
    struct lpeo_entry *e=&lpeo_wire.entries[0];
    le_need(selected_linked_epoch.current.close_complete && !e->closed,LE_STATE,133);
    e->closed=1;lpeo_copy(&e->closed_chain,&selected_chain,sizeof selected_chain);lpeo_save();
}
static void lpeo_source(void) {
    if(!lpeo_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpeo_entry *e=&lpeo_wire.entries[lpeo_index];
    le_need(r->source.ready==1 && r->source.key.page.object==dependency_count && r->source.key.page.address==lpeo_page &&
        r->source.key.entry==lpeo_head && r->source.key.backing.stat.st_dev==lpeo_wire.main_backing.st_dev &&
        r->source.key.backing.stat.st_ino==lpeo_wire.main_backing.st_ino && r->source.key.backing.stat.st_size==lpeo_wire.main_backing.st_size &&
        equal(r->source.key.bytes,lpeo_wire.original_source,PAGE),LE_SOURCE,130);
    le_need(!e->source_ready,LE_STATE,134);e->source_ready=1;
    lpeo_copy(e->source_page,(void *)lpeo_page,PAGE);e->source_bytes=PAGE;lpeo_owners(&e->source_owners,0);
    int error=li2_lifecycle_preedge_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,&e->before_memory);
    le_need(!error && e->before_memory.complete,LE_STATE,135);lpeo_save();
}
static void lpeo_held(void) {
    if(!lpeo_focal())return;
    struct lpeo_entry *e=&lpeo_wire.entries[lpeo_index];const struct le_record *r=&selected_linked_epoch.current;
    lpeo_copy(&e->epoch_held,li2_lifecycle_preedge_progress(),sizeof e->epoch_held);
    const struct le_slot *slot=&selected_linked_epoch.slots[r->slot];
    lpeo_copy(&e->proof,(void *)slot->proof,sizeof e->proof);
    lpeo_copy(e->proof_tail,(const unsigned char *)slot->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpeo_copy(e->generated_page,(void *)slot->generated,PAGE);e->generated_bytes=PAGE;lpeo_save();
}
static void lpeo_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    if(!lpeo_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpeo_entry *e=&lpeo_wire.entries[lpeo_index];
    le_need(e->source_ready && r->slot_present && r->redirected && !e->redirected,LE_STATE,139);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    e->redirected=1;e->redirect_event=lpeo_wire.raw_ingress[0];lpeo_owners(&e->redirected_owners,1);
    lpeo_copy(e->generated_page,(void *)s->generated,PAGE);e->generated_bytes=PAGE;
    lpeo_copy(&e->proof,(void *)s->proof,sizeof e->proof);
    lpeo_copy(e->proof_tail,(const unsigned char *)s->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpeo_copy(&e->epoch_opened,li2_lifecycle_preedge_progress(),sizeof e->epoch_opened);lpeo_save();
}
static void lpeo_memory_terminal(unsigned after_abort) {
    if(!lpeo_focal())return;
    struct lpeo_entry *e=&lpeo_wire.entries[lpeo_index];const struct le_record *r=&selected_linked_epoch.current;
    if(!e->after_memory.attempted) {
        int error=li2_lifecycle_preedge_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],after_abort,&e->after_memory);
        if(error || !e->after_memory.complete)lpeo_wire.h[39]=3;
    }
    lpeo_copy(e->terminal_source_page,(void *)lpeo_page,PAGE);e->terminal_source_bytes=PAGE;
}
static void lpeo_complete(void) {
    if(!lpeo_focal())return;
    struct lpeo_entry *e=&lpeo_wire.entries[lpeo_index];const struct le_record *r=&selected_linked_epoch.current;
    le_need(!e->completed && r->completed && !ler.pending && r->epoch_final.phase==LI2_PREEDGE_RELEASED,LE_STATE,142);
    lpeo_owners(&e->completed_owners,0);e->completed=1;lpeo_memory_terminal(0);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    lpeo_copy(&e->proof_final,(void *)s->proof,sizeof e->proof_final);
    lpeo_copy(e->proof_final_tail,(const unsigned char *)s->proof+sizeof e->proof_final,sizeof e->proof_final_tail);
    e->proof_final_bytes=LI2_LINK_PROOF_BYTES;le_need(!lpeo_wire.h[39],LE_STATE,143);lpeo_save();
}
static void lpeo_abort_observe(void) {
    if(!lpeo_focal())return;
    if(selected_linked_epoch.current.before.complete)lpeo_memory_terminal(1);
    lpeo_save();
}
static void lpeo_finish(unsigned status,unsigned code,long detail) {
    if(lpeo_finished || !lpeo_wire.h[18])return;
    lpeo_finished=1;uint64_t *h=lpeo_wire.h;
    h[26]=1;h[27]=status;h[28]=code;h[29]=(uint64_t)detail;
    h[30]=lpeo_active;h[31]=selected_linked_epoch_active;h[32]=selected_linked_epoch_busy;
    h[33]=selected_linked_epoch_failing;h[34]=handling;h[35]=selected_step_pending;
    h[36]=selected_pending_route;h[37]=selected_flags_known;h[38]=selected_logical_flags;
    if(lpeo_focal())lpeo_save();
    /* Finalized retained focal observation; later unrelated offers may have
       replaced the live current record, never this completed by-value copy. */
    for(unsigned i=0;i<lpeo_wire.h[25] && i<LPEO_ENTRIES;i++)lpeo_wire.entries[i].terminal=1;
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
    lpeo_copy(lpeo_wire.counts,counts,sizeof counts);
#ifdef LI2_LINKED_NATIVE_HINT
    lpeo_copy(&lpeo_wire.terminal_hint,li2_lifecycle_link_native_hint_progress(),sizeof lpeo_wire.terminal_hint);
#endif
    lpeo_wire.events[0]=selected_linked_epoch.events;
    lpeo_copy(lpeo_wire.events+1,selected_linked_epoch.signals,sizeof selected_linked_epoch.signals);
    lpeo_copy(lpeo_wire.events+6,selected_linked_epoch.refusals,sizeof selected_linked_epoch.refusals);
    lpeo_copy(lpeo_wire.events+10,selected_linked_epoch.exit_counts,sizeof selected_linked_epoch.exit_counts);
    lpeo_copy(&lpeo_wire.terminal_record,&selected_linked_epoch.current,sizeof selected_linked_epoch.current);
    lpeo_copy(&lpeo_wire.terminal_transfer,li2_tf_chain_span_progress(),sizeof lpeo_wire.terminal_transfer);
    lpeo_owners(&lpeo_wire.terminal_owners,0);
    li2_current_custody_snapshot(&lpeo_wire.terminal_current);
    lpeo_copy(&lpeo_wire.terminal_epoch,li2_lifecycle_preedge_progress(),sizeof lpeo_wire.terminal_epoch);
    lpeo_copy(&lpeo_wire.terminal_chain,&selected_chain,sizeof selected_chain);
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    const struct li2_native_close *g=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(f){lpeo_copy(&lpeo_wire.terminal_fetch,f,sizeof *f);h[50]=1;}
    if(g){lpeo_copy(&lpeo_wire.terminal_global_close,g,sizeof *g);h[51]=1;}
    if(n){lpeo_copy(&lpeo_wire.terminal_native_counts,n,sizeof *n);h[57]=1;}
    /* Wire v2 captures every remaining LI2_NATIVE operand, independently of
       its text report. These five words were required-zero in wire v1. */
    const struct li2_native_epoch *ne=li2_native_epoch_progress();
    h[58]=native_main_admissions;h[59]=native_main_refaults;
    h[60]=ne->ready;h[61]=ne->retries;h[62]=ne->first_error;
    lpeo_registry(&lpeo_wire.terminal_registry);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpeo_wire.sink_terminal,0,0,0,0);
    h[41]=(uint64_t)flags;h[42]=(uint64_t)result;
    if(result || flags!=(long)h[16] || !lpeo_same_sink(&lpeo_wire.sink_terminal) || lpeo_wire.sink_terminal.st_size){h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof lpeo_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lpeo_wire+at),sizeof lpeo_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lpeo_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lpeo_wire)return;
    const uint64_t footer[]={LPEO_FOOTER,2,sizeof lpeo_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
