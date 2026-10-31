/* Qualification-only actual linked-epoch observations. The output grants no
   runtime authority; all execution and cleanup remain the production calls. */
#include "linked_preedge_full_observe_memory.h"
#include "unrolled_hash_nested_fp.h"
#include "linked_preedge_full_capture_config.h"
#if LI2_LINKED_PREEDGE_FULL_CAPTURE != 1 || LI2_LINKED_EPOCH != 1
#error "literal linked-epoch capture profile"
#endif
#ifndef LI2_PREEDGE_FULL_APP_HEAD_RVA
#error "fresh emitted fixture head required"
#endif
#define LPEF_MAGIC UINT64_C(0x32464f455049324c)
#define LPEF_FOOTER UINT64_C(0x324646455049324c)
#define LPEF_ENTRIES 6U
struct lpef_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct lpef_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
#include "linked_preedge_full_refault_observe.h"
#ifdef LI2_LINKED_NATIVE_HINT
#include "linked_preedge_full_hint_observe.h"
#endif
struct lpef_entry {
    uint64_t present,closed,source_ready,redirected,completed,terminal;
    uint64_t source_bytes,generated_bytes,terminal_source_bytes,proof_bytes,proof_final_bytes;
    uint64_t ingress_event,redirect_event,terminal_event,frontier_closed;
    struct le_record owner;
    struct le_slot slot;
    struct le_proof_publication proof_publication;
    struct ler_permit permit;
    struct li2_preedge_epoch_progress epoch_held,epoch_opened,epoch_terminal;
    struct li2_lpef_memory before_memory,after_memory;
    struct lpef_owners source_owners,redirected_owners,completed_owners;
    struct li2_tf_chain predecessor,closed_chain;
    uint64_t counts_before[10],counts_after[10],ready_generation;
    unsigned char source_page[PAGE],generated_page[PAGE],terminal_source_page[PAGE];
    struct li2_preedge_proof proof,proof_final;
    unsigned char proof_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
    unsigned char proof_final_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
};
struct lpef_wire {
    #ifdef LI2_LINKED_NATIVE_HINT
    uint64_t h[64],control[24],counts[39],events[18],raw_ingress[6],storage[8];
#else
    uint64_t h[64],control[24],counts[37],events[18],raw_ingress[6],storage[8];
#endif
    struct li2_private_code_query initial_code[2],initial_proof[16];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct lpef_registry initial_registry,terminal_registry;
    struct lpef_entry entries[LPEF_ENTRIES];
    struct le_frame frontier_exit;
    struct li2_tf_chain frontier_before,frontier_after;
    struct lpef_owners terminal_owners;
    struct li2_fetch_progress terminal_fetch;
    struct li2_native_close terminal_global_close;
    struct li2_native_counts terminal_native_counts;
    struct li2_tf_chain terminal_chain;
    struct le_record terminal_record;
    struct li2_span_transfer_progress terminal_transfer;
    struct li2_current_custody_stats terminal_current;
    struct li2_preedge_epoch_progress terminal_epoch;
    struct uho_nested_fp nested_fp;
    unsigned char original_source[PAGE];
    struct lpef_refault refault;
#ifdef LI2_LINKED_NATIVE_HINT
    struct lpef_hint hint;
    struct li2_link_native_hint_progress terminal_hint;
#endif
};
static struct lpef_wire lpef_wire;
static unsigned lpef_ready,lpef_finished,lpef_active,lpef_frontier,lpef_index;
static uintptr_t lpef_head,lpef_page;
static const uint64_t lpef_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
static const uint64_t lpef_nested_zero_alignment __attribute__((used))=__alignof__(((struct uho_nested_fp *)0)->zero);
static const uint64_t lpef_nested_ones_alignment __attribute__((used))=__alignof__(((struct uho_nested_fp *)0)->ones);
_Static_assert(sizeof(struct lpef_wire)+64<(16U<<20),"whole actual finite wire under original16MiB");
static void lpef_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}

static void lpef_registry(struct lpef_registry *out) {
    le_need(!out->complete && protected_count && protected_count<=RANGES,LE_STATE,100);
    const struct image *b=bridge_runtime_image();
    le_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,LE_STATE,101);
    lpef_copy(&out->bridge,b,sizeof *b);lpef_copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    lpef_copy(out->ranges,protected,protected_count*sizeof(*protected));
    lpef_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}

static void lpef_owners(struct lpef_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    lpef_copy(&out->rseq,r,sizeof(*r));lpef_copy(&out->rseq_native,n,sizeof(*n));
    lpef_copy(&out->pair,p,sizeof(*p));lpef_copy(&out->lifecycle,l,sizeof(*l));
    lpef_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}

#include "linked_preedge_full_refault_observe.inc"
#ifdef LI2_LINKED_NATIVE_HINT
#include "linked_preedge_full_hint_observe.inc"
#endif

static int lpef_same_sink(const struct stat *s) {
    const struct stat *a=&lpef_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}

static void lpef_initialize(void) {
    __asm__ volatile(""::"r"(&lpef_step_frame_fp_alignment),"r"(&lpef_nested_zero_alignment),"r"(&lpef_nested_ones_alignment):"memory");
    le_need(!lpef_ready && !lpef_finished,LE_STATE,102);
    uint64_t *h=lpef_wire.h;
    #ifdef LI2_LINKED_NATIVE_HINT
    h[0]=LPEF_MAGIC;h[1]=2;h[2]=sizeof lpef_wire;h[3]=sizeof(struct lpef_entry);
#else
    h[0]=LPEF_MAGIC;h[1]=2;h[2]=sizeof lpef_wire;h[3]=sizeof(struct lpef_entry);
#endif
    h[4]=sizeof(struct le_record);h[5]=sizeof(struct le_slot);h[6]=sizeof(struct le_frame);
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    le_need(!selected_run_protect_add(0,(uintptr_t)&lpef_wire,sizeof lpef_wire),LE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpef_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    le_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(lpef_wire.sink_initial.st_mode) && (lpef_wire.sink_initial.st_mode&07777)==0600 &&
        lpef_wire.sink_initial.st_nlink==1 && lpef_wire.sink_initial.st_size==0,LE_STATE,104);h[18]=1;
    const char *control=fork_env("LI2_LINKED_PREEDGE_FULL_CAPTURE_CONTROL"),*mode=fork_env("LI2_LINKED_PREEDGE_FULL_APP_MODE");
    le_need(control && control[0]>='0' && control[0]<='4' && !control[1] &&
        mode && mode[0]>='0' && mode[0]<='5' && !mode[1],LE_STATE,105);
    lpef_wire.control[0]=(unsigned)(control[0]-'0');h[24]=(unsigned)(mode[0]-'0');
    const char *retry=fork_env("LI2_LINKED_PREEDGE_FULL_REFAULT_CONTROL");
    le_need(retry && retry[0]>='0' && retry[0]<='4' && !retry[1],LE_STATE,152);
    lpef_wire.refault.h[0]=(unsigned)(retry[0]-'0');
#ifdef LI2_LINKED_NATIVE_HINT
    const char *hint=fork_env("LI2_LINKED_PREEDGE_FULL_HINT_CONTROL");
    le_need(hint && hint[0]>='0' && hint[0]<='3' && !hint[1],LE_STATE,160);
    lpef_wire.hint.h[0]=(unsigned)(hint[0]-'0');
    le_need(!lpef_wire.hint.h[0] || (!lpef_wire.control[0] && !lpef_wire.refault.h[0] && !h[24]),LE_STATE,161);
#endif
    le_need(!lpef_wire.refault.h[0] || (!lpef_wire.control[0] && !h[24]),LE_STATE,153);
    le_need(!lpef_wire.control[0] || h[24]==(lpef_wire.control[0]==2?5U:0U),LE_STATE,106);
    lpef_copy(&lpef_wire.main,&original_main,sizeof original_main);
    lpef_copy(&lpef_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    lpef_copy(&lpef_wire.hardware,&selected_hardware,sizeof selected_hardware);
    lpef_copy(&lpef_wire.session,&selected_session,sizeof selected_session);
    uintptr_t rva=LI2_PREEDGE_FULL_APP_HEAD_RVA;
    le_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-rva,LE_STATE,107);
    lpef_head=original_main.bias+rva;lpef_page=lpef_head&~(uintptr_t)(PAGE-1);
    le_need(lpef_head>=PAGE && lpef_head<(UINT64_C(1)<<31) && (lpef_head&(PAGE-1))==0x200U,LE_STATE,108);
    unsigned found=0;size_t offset=0;uintptr_t page_rva=rva&~(uintptr_t)(PAGE-1);
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || page_rva<p->p_vaddr || page_rva-p->p_vaddr>=p->p_filesz)continue;
        le_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(page_rva-p->p_vaddr)>=PAGE,LE_STATE,109);
        offset=(size_t)(p->p_offset+page_rva-p->p_vaddr);found=1;
    }
    le_need(found,LE_STATE,110);lpef_copy(lpef_wire.original_source,original_main.source+offset,PAGE);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&lpef_wire.main_backing,0,0,0,0);
    h[19]=(uint64_t)result;le_need(!result && S_ISREG(lpef_wire.main_backing.st_mode),LE_STATE,111);
    h[20]=lpef_head;h[21]=offset;h[22]=dependency_count;h[23]=1;
    h[52]=(uintptr_t)&selected_linked_epoch;h[53]=(uintptr_t)li2_tf_chain_span_progress();
    h[54]=(uintptr_t)&ler;h[55]=(uintptr_t)&selected_chain;h[56]=(uintptr_t)&lpef_wire;
    lpef_registry(&lpef_wire.initial_registry);
    const uint64_t storage[]={selected_linked_epoch.arena,selected_linked_epoch.low_arena,LE_BYTES,lep.arena,LE_PROOF_TOTAL,(uintptr_t)&lep,(uintptr_t)li2_lifecycle_preedge_progress(),(uintptr_t)&ler};
    lpef_copy(lpef_wire.storage,storage,sizeof storage);
    lpef_copy(&lpef_wire.initial_code[0],&selected_linked_epoch.initial,sizeof selected_linked_epoch.initial);
    lpef_copy(&lpef_wire.initial_code[1],&selected_linked_epoch.low_initial,sizeof selected_linked_epoch.low_initial);
    lpef_copy(lpef_wire.initial_proof,lep.initial,sizeof lep.initial);lpef_ready=1;
}

static void lpef_fd_guard(long n,const long a[6]) {
    if(!lpef_ready)return;
    le_need(!lpef_finished,LE_STATE,110);
    le_count(&lpef_wire.h[43]);
    if(n==SYS_openat) {
        le_count(&lpef_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)lpef_wire.h[49]=1;
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
    if((unsigned)fd==3)lpef_wire.h[48]=1;
    le_need((unsigned)fd!=3,LE_STATE,113);le_count(&lpef_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    le_need(!result || result==-9,LE_STATE,121);
    if(result)le_count(&lpef_wire.h[45]);
    if(!result && observed.st_dev==lpef_wire.sink_initial.st_dev &&
       observed.st_ino==lpef_wire.sink_initial.st_ino)lpef_wire.h[48]=1;
    le_need(result || observed.st_dev!=lpef_wire.sink_initial.st_dev ||
        observed.st_ino!=lpef_wire.sink_initial.st_ino,LE_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}

static void lpef_ingress(int sig) {
    if(!lpef_ready || lpef_finished)return;
    le_event_count(&lpef_wire.raw_ingress[0]);
    unsigned k=sig==SIGSEGV?1:sig==SIGTRAP?2:sig==SIGILL?3:sig==SIGSYS?4:5;
    le_event_count(&lpef_wire.raw_ingress[k]);
    if(lpef_active && lpef_index<LPEF_ENTRIES && lpef_wire.entries[lpef_index].redirected &&
       !lpef_wire.entries[lpef_index].terminal_event)
        lpef_wire.entries[lpef_index].terminal_event=lpef_wire.raw_ingress[0];
}
static int lpef_focal(void) {
    return lpef_ready && lpef_active && lpef_index<LPEF_ENTRIES &&
        selected_linked_epoch.current.transfer.pc==lpef_head;
}
static void lpef_counts(uint64_t out[10]) {
    out[0]=selected_linked_epoch.entries;out[1]=selected_linked_epoch.completed;
    out[2]=selected_linked_epoch.plan_checks;out[3]=selected_linked_epoch.rseq_checks;
    out[4]=selected_linked_epoch.live_checks;out[5]=selected_linked_epoch.proof_checks;
    out[6]=selected_linked_epoch.publications;out[7]=selected_linked_epoch.hits;
    out[8]=ler.retirement_attempts;out[9]=ler.retirements;
}
static void lpef_save(void) {
    if(!lpef_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpef_entry *e=&lpef_wire.entries[lpef_index];
    lpef_copy(&e->owner,r,sizeof *r);
    if(r->slot_present && r->slot<selected_linked_epoch.used && r->slot<LE_PAGES) {
        const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
        lpef_copy(&e->slot,s,sizeof *s);lpef_copy(&e->proof_publication,&lep.slot_publication[r->slot],sizeof e->proof_publication);
        lpef_copy(&e->permit,&ler.permits[r->slot],sizeof e->permit);e->ready_generation=lep.ready_generation[r->slot];
    }
    lpef_copy(&e->epoch_terminal,li2_lifecycle_preedge_progress(),sizeof e->epoch_terminal);lpef_counts(e->counts_after);
}
static void lpef_begin(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    lpef_frontier=lpef_ready && lpef_wire.h[24]==4 && lpef_wire.h[25]==1 &&
        lpef_wire.entries[0].completed && !lpef_wire.entries[0].frontier_closed &&
        r->ingress.complete && (uintptr_t)r->ingress.frame.greg[REG_RIP]==lpef_page+0x602;
    if(lpef_frontier) {
        lpef_copy(&lpef_wire.frontier_exit,&r->ingress,sizeof r->ingress);
        lpef_copy(&lpef_wire.frontier_before,&selected_chain,sizeof selected_chain);
    }
    lpef_active=lpef_ready && r->ingress.complete && (uintptr_t)r->ingress.frame.greg[REG_RIP]==lpef_head;
    if(!lpef_active)return;
    le_need(lpef_wire.h[25]<LPEF_ENTRIES && (lpef_wire.h[24]==5 || !lpef_wire.h[25]),LE_STATE,130);
    lpef_index=(unsigned)lpef_wire.h[25]++;struct lpef_entry *e=&lpef_wire.entries[lpef_index];
    le_need(!e->present,LE_STATE,131);e->present=1;e->ingress_event=lpef_wire.raw_ingress[0];lpef_counts(e->counts_before);
    lpef_copy(&e->predecessor,&selected_chain,sizeof selected_chain);
}
static void lpef_closed(void) {
    if(lpef_frontier) {
        le_need(selected_linked_epoch.current.close_complete && !lpef_wire.entries[0].frontier_closed,LE_STATE,132);
        lpef_copy(&lpef_wire.frontier_after,&selected_chain,sizeof selected_chain);
        lpef_wire.entries[0].frontier_closed=1;lpef_frontier=0;
    }
    if(!lpef_focal())return;
    struct lpef_entry *e=&lpef_wire.entries[lpef_index];
    le_need(selected_linked_epoch.current.close_complete && !e->closed,LE_STATE,133);
    e->closed=1;lpef_copy(&e->closed_chain,&selected_chain,sizeof selected_chain);lpef_save();
}
static void lpef_source(void) {
    if(!lpef_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpef_entry *e=&lpef_wire.entries[lpef_index];
    le_need(r->source.ready==1 && r->source.key.page.object==dependency_count && r->source.key.page.address==lpef_page &&
        r->source.key.entry==lpef_head && r->source.key.backing.stat.st_dev==lpef_wire.main_backing.st_dev &&
        r->source.key.backing.stat.st_ino==lpef_wire.main_backing.st_ino && r->source.key.backing.stat.st_size==lpef_wire.main_backing.st_size &&
        equal(r->source.key.bytes,lpef_wire.original_source,PAGE),LE_SOURCE,130);
    le_need(!e->source_ready,LE_STATE,134);e->source_ready=1;
    lpef_copy(e->source_page,(void *)lpef_page,PAGE);e->source_bytes=PAGE;lpef_owners(&e->source_owners,0);
    int error=li2_lifecycle_preedge_full_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,&e->before_memory);
    le_need(!error && e->before_memory.complete,LE_STATE,135);lpef_save();
}
static void lpef_held(void) {
    if(!lpef_focal())return;
    struct lpef_entry *e=&lpef_wire.entries[lpef_index];const struct le_record *r=&selected_linked_epoch.current;
    lpef_copy(&e->epoch_held,li2_lifecycle_preedge_progress(),sizeof e->epoch_held);
    const struct le_slot *slot=&selected_linked_epoch.slots[r->slot];
    lpef_copy(&e->proof,(void *)slot->proof,sizeof e->proof);
    lpef_copy(e->proof_tail,(const unsigned char *)slot->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpef_copy(e->generated_page,(void *)slot->generated,PAGE);e->generated_bytes=PAGE;lpef_save();
    if(lpef_wire.control[0]==2 && lpef_index==1) {
        const struct lpef_entry *old=&lpef_wire.entries[0];
        le_need(old->completed && old->owner.epoch.owner && old->epoch_terminal.phase==LI2_PREEDGE_RELEASED &&
            e->epoch_held.phase==LI2_PREEDGE_HELD && e->epoch_held.serial>old->epoch_terminal.serial &&
            r->source.key.page.generation>old->owner.source.key.page.generation,LE_STATE,136);
        lpef_wire.control[1]=1;lpef_wire.control[2]=1;
        int result=li2_lifecycle_preedge_opened(&old->owner.epoch,&old->owner.source,&old->proof.plan);
        lpef_wire.control[3]=1;lpef_wire.control[4]=(uint64_t)(unsigned)result;
        lpef_save();selected_linked_epoch_abort(LE_SOURCE,result);
    }
    if(lpef_wire.control[0]==3) {
        le_need(e->epoch_held.phase==LI2_PREEDGE_HELD && !r->open.started,LE_STATE,137);
        lpef_wire.control[1]=1;lpef_wire.control[2]=1;
        int result=li2_lifecycle_admit(lpef_head,lpef_head);
        lpef_wire.control[3]=1;lpef_wire.control[4]=(uint64_t)(unsigned)result;
        selected_linked_epoch_abort(LE_STATE,138); /* Actual lifecycle must terminate before returning. */
    }
}
static void lpef_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    if(!lpef_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpef_entry *e=&lpef_wire.entries[lpef_index];
    le_need(e->source_ready && r->slot_present && r->redirected && !e->redirected,LE_STATE,139);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    e->redirected=1;e->redirect_event=lpef_wire.raw_ingress[0];lpef_owners(&e->redirected_owners,1);
    lpef_copy(e->generated_page,(void *)s->generated,PAGE);e->generated_bytes=PAGE;
    lpef_copy(&e->proof,(void *)s->proof,sizeof e->proof);
    lpef_copy(e->proof_tail,(const unsigned char *)s->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpef_copy(&e->epoch_opened,li2_lifecycle_preedge_progress(),sizeof e->epoch_opened);lpef_save();
    if(lpef_wire.control[0]==1) {
        le_need(!lpef_wire.control[2],LE_STATE,135);lpef_wire.control[1]=1;lpef_wire.control[2]=1;
        /* Actual pre-arm CPUID facts are already protected in wire.hardware.
           CPUID itself is disabled now. Guard XGETBV and then read live handler
           PKRU; neither instruction changes PKRU, FP state or a saved frame. */
        const struct li2_selected_hardware *h=&lpef_wire.hardware;
        le_need(h->abi_version==1 && !h->reserved && h->leaf0[0]>=7 &&
            (h->leaf1[2]&UINT32_C(0x0c000000))==UINT32_C(0x0c000000),LE_STATE,124);
        uint32_t a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
        uint64_t xcr0=(uint64_t)a|((uint64_t)d<<32);
        lpef_wire.control[21]=xcr0;lpef_wire.control[22]=1;
        if(xcr0&(UINT64_C(1)<<9)) {
            le_need((h->leaf7[2]&24U)==24U,LE_STATE,125);
            __asm__ volatile("rdpkru":"=a"(a),"=d"(d):"c"(0):"memory");
            lpef_wire.control[18]=a;lpef_wire.control[19]=d;lpef_wire.control[20]=1;
        }
        lpef_wire.control[6]=selected_session.pid;lpef_wire.control[7]=selected_session.tid;
        lpef_wire.control[8]=SIGTRAP;lpef_wire.control[12]=1;
        /* Qualification injects a real nested owner event outside a maps RAW
           transaction. Use the same registered kernel gateway directly: this
           pointer-free tgkill changes no mappings. The terminal reader still
           requires the whole nested frame, nonreturn and complete cleanup. */
        struct uho_nested_fp *f=&lpef_wire.nested_fp;
        le_need((xcr0==UINT64_C(0xe7) || xcr0==UINT64_C(0x2e7)) &&
            !f->h[0] && fork_gate_stack.ss_size==sizeof f->stack &&
            (uintptr_t)fork_gate_stack.ss_sp<=UINTPTR_MAX-fork_gate_stack.ss_size,
            LE_STATE,126); /* Fixed nondynamic user-state profile only. */
        f->h[0]=1;f->h[3]=(uintptr_t)fork_gate_stack.ss_sp;f->h[4]=fork_gate_stack.ss_size;
        f->h[7]=xcr0;f->h[8]=selected_session.pid;f->h[9]=selected_session.tid;
        f->h[10]=SIGTRAP;f->h[11]=xcr0;
        long result=uho_nested_raw(f,selected_session.pid,selected_session.tid,SIGTRAP,0,0,0);
        lpef_wire.control[13]=1;lpef_wire.control[14]=(uint64_t)result;
        le_need(0,LE_STATE,119); /* A real nested terminal event must not return. */
    }
}

static void lpef_before_close(void) {
    if(!lpef_focal() || lpef_wire.control[0]!=4)return;
    const struct le_record *r=&selected_linked_epoch.current;
    le_need(r->exit_seen && r->after.complete && !r->close.started && !lpef_wire.control[1],LE_STATE,140);
    lpef_wire.control[1]=1;lpef_wire.control[2]=1;
    long result=raw(SYS_munmap,selected_linked_epoch.slots[r->slot].generated,PAGE,0,0,0,0);
    lpef_wire.control[3]=1;lpef_wire.control[4]=(uint64_t)result;le_need(!result,LE_STATE,141);
    /* Return to the unchanged real revoke+sync+query. ENOMEM must remain a
       failed close and cleanup; there is no synthetic completed permission. */
}
static void lpef_memory_terminal(unsigned after_abort) {
    if(!lpef_focal())return;
    struct lpef_entry *e=&lpef_wire.entries[lpef_index];const struct le_record *r=&selected_linked_epoch.current;
    if(!e->after_memory.attempted) {
        int error=li2_lifecycle_preedge_full_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],after_abort,&e->after_memory);
        if(error || !e->after_memory.complete)lpef_wire.h[39]=3;
    }
    lpef_copy(e->terminal_source_page,(void *)lpef_page,PAGE);e->terminal_source_bytes=PAGE;
}
static void lpef_complete(void) {
    if(!lpef_focal())return;
    struct lpef_entry *e=&lpef_wire.entries[lpef_index];const struct le_record *r=&selected_linked_epoch.current;
    le_need(!e->completed && r->completed && !ler.pending && r->epoch_final.phase==LI2_PREEDGE_RELEASED,LE_STATE,142);
    lpef_owners(&e->completed_owners,0);e->completed=1;lpef_memory_terminal(0);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    lpef_copy(&e->proof_final,(void *)s->proof,sizeof e->proof_final);
    lpef_copy(e->proof_final_tail,(const unsigned char *)s->proof+sizeof e->proof_final,sizeof e->proof_final_tail);
    e->proof_final_bytes=LI2_LINK_PROOF_BYTES;le_need(!lpef_wire.h[39],LE_STATE,143);lpef_save();
}
static void lpef_abort_observe(void) {
    lpef_refault_abort();
#ifdef LI2_LINKED_NATIVE_HINT
    lpef_hint_abort();
#endif
    if(!lpef_focal())return;
    struct le_frame *f=&selected_linked_epoch.current.unexpected;
    if(f->complete) {
        f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
        f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
        f->tls_complete=!f->fs_result && !f->gs_result;
    }
    if(selected_linked_epoch.current.before.complete)lpef_memory_terminal(1);
    lpef_save();
}
static void lpef_finish(unsigned status,unsigned code,long detail) {
    if(lpef_finished || !lpef_wire.h[18])return;
    lpef_finished=1;uint64_t *h=lpef_wire.h;
    h[26]=1;h[27]=status;h[28]=code;h[29]=(uint64_t)detail;
    h[30]=lpef_active;h[31]=selected_linked_epoch_active;h[32]=selected_linked_epoch_busy;
    h[33]=selected_linked_epoch_failing;h[34]=handling;h[35]=selected_step_pending;
    h[36]=selected_pending_route;h[37]=selected_flags_known;h[38]=selected_logical_flags;
    if(lpef_focal())lpef_save();
    /* Finalized retained focal observation; later unrelated offers may have
       replaced the live current record, never this completed by-value copy. */
    for(unsigned i=0;i<lpef_wire.h[25] && i<LPEF_ENTRIES;i++)lpef_wire.entries[i].terminal=1;
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
    lpef_copy(lpef_wire.counts,counts,sizeof counts);
#ifdef LI2_LINKED_NATIVE_HINT
    lpef_copy(&lpef_wire.terminal_hint,li2_lifecycle_link_native_hint_progress(),sizeof lpef_wire.terminal_hint);
#endif
    lpef_wire.events[0]=selected_linked_epoch.events;
    lpef_copy(lpef_wire.events+1,selected_linked_epoch.signals,sizeof selected_linked_epoch.signals);
    lpef_copy(lpef_wire.events+6,selected_linked_epoch.refusals,sizeof selected_linked_epoch.refusals);
    lpef_copy(lpef_wire.events+10,selected_linked_epoch.exit_counts,sizeof selected_linked_epoch.exit_counts);
    lpef_copy(&lpef_wire.terminal_record,&selected_linked_epoch.current,sizeof selected_linked_epoch.current);
    lpef_copy(&lpef_wire.terminal_transfer,li2_tf_chain_span_progress(),sizeof lpef_wire.terminal_transfer);
    lpef_owners(&lpef_wire.terminal_owners,0);
    li2_current_custody_snapshot(&lpef_wire.terminal_current);
    lpef_copy(&lpef_wire.terminal_epoch,li2_lifecycle_preedge_progress(),sizeof lpef_wire.terminal_epoch);
    lpef_copy(&lpef_wire.terminal_chain,&selected_chain,sizeof selected_chain);
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    const struct li2_native_close *g=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(f){lpef_copy(&lpef_wire.terminal_fetch,f,sizeof *f);h[50]=1;}
    if(g){lpef_copy(&lpef_wire.terminal_global_close,g,sizeof *g);h[51]=1;}
    if(n){lpef_copy(&lpef_wire.terminal_native_counts,n,sizeof *n);h[57]=1;}
    /* Wire v2 captures every remaining LI2_NATIVE operand, independently of
       its text report. These five words were required-zero in wire v1. */
    const struct li2_native_epoch *ne=li2_native_epoch_progress();
    h[58]=native_main_admissions;h[59]=native_main_refaults;
    h[60]=ne->ready;h[61]=ne->retries;h[62]=ne->first_error;
    lpef_registry(&lpef_wire.terminal_registry);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpef_wire.sink_terminal,0,0,0,0);
    h[41]=(uint64_t)flags;h[42]=(uint64_t)result;
    if(result || flags!=(long)h[16] || !lpef_same_sink(&lpef_wire.sink_terminal) || lpef_wire.sink_terminal.st_size){h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof lpef_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lpef_wire+at),sizeof lpef_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lpef_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lpef_wire)return;
#ifdef LI2_LINKED_NATIVE_HINT
    const uint64_t footer[]={LPEF_FOOTER,2,sizeof lpef_wire,at,calls,(uint64_t)result,status,code};
#else
    const uint64_t footer[]={LPEF_FOOTER,2,sizeof lpef_wire,at,calls,(uint64_t)result,status,code};
#endif
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
