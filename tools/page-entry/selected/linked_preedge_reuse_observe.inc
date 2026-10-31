/* Qualification-only actual linked-epoch observations. The output grants no
   runtime authority; all execution and cleanup remain the production calls. */
#include "linked_preedge_observe_memory.h"
#include "linked_preedge_reuse_capture_config.h"
#if LI2_LINKED_PREEDGE_REUSE_CAPTURE != 1 || LI2_LINKED_PREEDGE != 1 || LI2_LINKED_NATIVE_HINT != 1 || defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_LINKED_PREEDGE_CAPTURE)
#error "literal linked-epoch capture profile"
#endif
#ifndef LI2_PREEDGE_REUSE_APP_HEAD_RVA
#error "fresh emitted fixture head required"
#endif
#define LPERO_MAGIC UINT64_C(0x325255504c49324c)
#define LPERO_FOOTER UINT64_C(0x324655504c49324c)
#define LPERO_ENTRIES 65U
struct lpero_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct lpero_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct lpero_record {
    unsigned slot_present,slot,redirected,exit_seen,completed,release_started,release_complete;
    unsigned cleanup_started,cleanup_complete,unexpected_seen,build_started,build_returned;
    int release_result,map_result,build_result;
    uint64_t flags,gpr_written,flags_written;
    unsigned exit_index;
    struct li2_span_source source;
    struct le_frame before,after;
    struct li2_span_transfer_progress transfer;
    unsigned close_started,close_complete,prepare_started,prepare_complete;
    unsigned miss_release_started,miss_release_complete,resume_started,resume_complete;
    int prepare_result,miss_release_result,resume_result;
    unsigned hint_checked,hint_hit;
    uint64_t hint_publication;
    enum li2_chain_result resumed_route;
    struct li2_fetch_progress miss_fetch;
    struct li2_region_pc original;
    struct li2_private_code_query idle,live;
    size_t idle_bytes,live_bytes,closed_bytes;
    struct le_permission open,close,cleanup;
    struct li2_fetch_progress final_fetch;
    uint64_t publication_generation,cold_plan_proof,cold_none_proof;
    struct li2_preedge_epoch_token epoch;
    struct li2_preedge_epoch_progress epoch_final;
    struct li2_link_rseq_live live_rseq[4];
    struct li2_private_code_query proof_before,proof_enter,proof_exit;
};
struct lpero_entry {
    uint64_t present,closed,source_ready,redirected,completed,terminal,generated_bytes,terminal_source_bytes,proof_bytes,ingress_event,redirect_event,terminal_event;
    struct lpero_record owner;
    struct le_slot slot;
    struct le_proof_publication proof_publication;
    struct ler_permit permit;
    struct li2_preedge_epoch_progress epoch_held,epoch_opened;
    struct li2_lpeo_memory before_memory,after_memory;
    struct li2_rseq_state source_rseq,redirected_rseq,completed_rseq;
    uint64_t counts_before[10],counts_after[10],closed_owner[18],ready_generation;
    unsigned char generated_page[PAGE],terminal_source_page[PAGE];
    struct li2_preedge_proof proof;
    unsigned char proof_tail[LI2_LINK_PROOF_BYTES-sizeof(struct li2_preedge_proof)];
};
struct lpero_retirement {
    uint64_t present,old_focal,held,opened,completed;
    struct ler_retirement retirement;
    struct ler_permit claimed,permit;
    struct le_permission proof_close,proof_writable;
    struct le_slot new_slot;
    struct le_proof_publication publication;
    struct li2_preedge_epoch_progress held_epoch,opened_epoch,terminal_epoch;
    struct le_permission close;
    unsigned char new_payload[LI2_LINK_PROOF_BYTES],generated_page[PAGE];
};
struct lpero_wire {
    uint64_t h[64],control[24],counts[39],events[18],raw_ingress[6],storage[8];
    struct li2_private_code_query initial_code[2],initial_proof[16];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct lpero_registry initial_registry,terminal_registry;
    struct lpero_owners terminal_owners;
    struct li2_fetch_progress terminal_fetch;
    struct li2_native_close terminal_global_close;
    struct li2_native_counts terminal_native_counts;
    struct li2_tf_chain terminal_chain;
    struct li2_span_transfer_progress terminal_transfer;
    struct li2_current_custody_stats terminal_current;
    struct li2_preedge_epoch_progress terminal_epoch;
    unsigned char original_source[PAGE];
    struct lpero_entry entries[LPERO_ENTRIES];
    struct li2_tf_chain_slot first_closed;
    struct lpero_retirement retirement;
    uint64_t terminal_current_fields[37];
    struct li2_link_native_hint_progress terminal_hint;
    uint64_t terminal_hint_fields[3];
};
static struct lpero_wire lpero_wire;
static unsigned lpero_ready,lpero_finished,lpero_active,lpero_index;
static uintptr_t lpero_head,lpero_page;
static const uint64_t lpero_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct lpero_wire)+64<(16U<<20),"whole actual65-entry wire under original16MiB");
static void lpero_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void lpero_registry(struct lpero_registry *out) {
    le_need(!out->complete && protected_count && protected_count<=RANGES,LE_STATE,100);
    const struct image *b=bridge_runtime_image();
    le_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,LE_STATE,101);
    lpero_copy(&out->bridge,b,sizeof *b);lpero_copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    lpero_copy(out->ranges,protected,protected_count*sizeof(*protected));
    lpero_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}

static void lpero_owners(struct lpero_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    lpero_copy(&out->rseq,r,sizeof(*r));lpero_copy(&out->rseq_native,n,sizeof(*n));
    lpero_copy(&out->pair,p,sizeof(*p));lpero_copy(&out->lifecycle,l,sizeof(*l));
    lpero_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}

static int lpero_same_sink(const struct stat *s) {
    const struct stat *a=&lpero_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}

static void lpero_initialize(void) {
    __asm__ volatile(""::"r"(&lpero_step_frame_fp_alignment):"memory");
    le_need(!lpero_ready && !lpero_finished,LE_STATE,102);
    uint64_t *h=lpero_wire.h;
    h[0]=LPERO_MAGIC;h[1]=2;h[2]=sizeof lpero_wire;h[3]=sizeof(struct lpero_entry);
    h[4]=sizeof(struct lpero_record);h[5]=sizeof(struct le_slot);h[6]=sizeof(struct le_frame);
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    le_need(!selected_run_protect_add(0,(uintptr_t)&lpero_wire,sizeof lpero_wire),LE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpero_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    le_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(lpero_wire.sink_initial.st_mode) && (lpero_wire.sink_initial.st_mode&07777)==0600 &&
        lpero_wire.sink_initial.st_nlink==1 && lpero_wire.sink_initial.st_size==0,LE_STATE,104);h[18]=1;
    const char *control=fork_env("LI2_LINKED_EPOCH_CAPTURE_CONTROL"),*mode=fork_env("LI2_LINKED_EPOCH_APP_MODE");
    le_need(control && control[0]=='0' && !control[1] && mode && mode[0]=='6' && !mode[1],LE_STATE,105);
    h[24]=6;
    lpero_copy(&lpero_wire.main,&original_main,sizeof original_main);
    lpero_copy(&lpero_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    lpero_copy(&lpero_wire.hardware,&selected_hardware,sizeof selected_hardware);
    lpero_copy(&lpero_wire.session,&selected_session,sizeof selected_session);
    uintptr_t rva=LI2_PREEDGE_REUSE_APP_HEAD_RVA;
    le_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-rva,LE_STATE,107);
    lpero_head=original_main.bias+rva;lpero_page=lpero_head&~(uintptr_t)(PAGE-1);
    le_need(lpero_head>=PAGE && lpero_head<(UINT64_C(1)<<31) && (lpero_head&(PAGE-1))==0x200U,LE_STATE,108);
    unsigned found=0;size_t offset=0;uintptr_t page_rva=rva&~(uintptr_t)(PAGE-1);
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || page_rva<p->p_vaddr || page_rva-p->p_vaddr>=p->p_filesz)continue;
        le_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(page_rva-p->p_vaddr)>=PAGE,LE_STATE,109);
        offset=(size_t)(p->p_offset+page_rva-p->p_vaddr);found=1;
    }
    le_need(found,LE_STATE,110);lpero_copy(lpero_wire.original_source,original_main.source+offset,PAGE);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&lpero_wire.main_backing,0,0,0,0);
    h[19]=(uint64_t)result;le_need(!result && S_ISREG(lpero_wire.main_backing.st_mode),LE_STATE,111);
    h[20]=lpero_head;h[21]=offset;h[22]=dependency_count;h[23]=1;
    h[52]=(uintptr_t)&selected_linked_epoch;h[53]=(uintptr_t)li2_tf_chain_span_progress();
    h[54]=(uintptr_t)&ler;h[55]=(uintptr_t)&selected_chain;h[56]=(uintptr_t)&lpero_wire;
    lpero_registry(&lpero_wire.initial_registry);
    const uint64_t storage[]={selected_linked_epoch.arena,selected_linked_epoch.low_arena,LE_BYTES,lep.arena,LE_PROOF_TOTAL,(uintptr_t)&lep,(uintptr_t)li2_lifecycle_preedge_progress(),(uintptr_t)&ler};
    lpero_copy(lpero_wire.storage,storage,sizeof storage);
    lpero_copy(&lpero_wire.initial_code[0],&selected_linked_epoch.initial,sizeof selected_linked_epoch.initial);
    lpero_copy(&lpero_wire.initial_code[1],&selected_linked_epoch.low_initial,sizeof selected_linked_epoch.low_initial);
    lpero_copy(lpero_wire.initial_proof,lep.initial,sizeof lep.initial);lpero_ready=1;
}

static void lpero_fd_guard(long n,const long a[6]) {
    if(!lpero_ready)return;
    le_need(!lpero_finished,LE_STATE,110);
    le_count(&lpero_wire.h[43]);
    if(n==SYS_openat) {
        le_count(&lpero_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)lpero_wire.h[49]=1;
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
    if((unsigned)fd==3)lpero_wire.h[48]=1;
    le_need((unsigned)fd!=3,LE_STATE,113);le_count(&lpero_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    le_need(!result || result==-9,LE_STATE,121);
    if(result)le_count(&lpero_wire.h[45]);
    if(!result && observed.st_dev==lpero_wire.sink_initial.st_dev &&
       observed.st_ino==lpero_wire.sink_initial.st_ino)lpero_wire.h[48]=1;
    le_need(result || observed.st_dev!=lpero_wire.sink_initial.st_dev ||
        observed.st_ino!=lpero_wire.sink_initial.st_ino,LE_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}

static void lpero_ingress(int sig) {
    if(!lpero_ready || lpero_finished)return;
    le_event_count(&lpero_wire.raw_ingress[0]);
    unsigned k=sig==SIGSEGV?1:sig==SIGTRAP?2:sig==SIGILL?3:sig==SIGSYS?4:5;
    le_event_count(&lpero_wire.raw_ingress[k]);
    if(lpero_active && lpero_index<LPERO_ENTRIES && lpero_wire.entries[lpero_index].redirected &&
       !lpero_wire.entries[lpero_index].terminal_event)
        lpero_wire.entries[lpero_index].terminal_event=lpero_wire.raw_ingress[0];
}
static int lpero_root(uintptr_t pc) {
    return pc>=lpero_head && pc-lpero_head<65U*32U && !((pc-lpero_head)%32U);
}
static int lpero_focal(void) {
    return lpero_ready && lpero_active && lpero_index<LPERO_ENTRIES &&
        selected_linked_epoch.current.transfer.pc==lpero_head+lpero_index*32U;
}
static void lpero_counts(uint64_t out[10]) {
    out[0]=selected_linked_epoch.entries;out[1]=selected_linked_epoch.completed;
    out[2]=selected_linked_epoch.plan_checks;out[3]=selected_linked_epoch.rseq_checks;
    out[4]=selected_linked_epoch.live_checks;out[5]=selected_linked_epoch.proof_checks;
    out[6]=selected_linked_epoch.publications;out[7]=selected_linked_epoch.hits;
    out[8]=ler.retirement_attempts;out[9]=ler.retirements;
}
static void lpero_record(struct lpero_record *d,const struct le_record *s) {
    lpero_copy(&d->slot_present,&s->slot_present,sizeof d->slot_present);
    lpero_copy(&d->slot,&s->slot,sizeof d->slot);
    lpero_copy(&d->redirected,&s->redirected,sizeof d->redirected);
    lpero_copy(&d->exit_seen,&s->exit_seen,sizeof d->exit_seen);
    lpero_copy(&d->completed,&s->completed,sizeof d->completed);
    lpero_copy(&d->release_started,&s->release_started,sizeof d->release_started);
    lpero_copy(&d->release_complete,&s->release_complete,sizeof d->release_complete);
    lpero_copy(&d->cleanup_started,&s->cleanup_started,sizeof d->cleanup_started);
    lpero_copy(&d->cleanup_complete,&s->cleanup_complete,sizeof d->cleanup_complete);
    lpero_copy(&d->unexpected_seen,&s->unexpected_seen,sizeof d->unexpected_seen);
    lpero_copy(&d->build_started,&s->build_started,sizeof d->build_started);
    lpero_copy(&d->build_returned,&s->build_returned,sizeof d->build_returned);
    lpero_copy(&d->release_result,&s->release_result,sizeof d->release_result);
    lpero_copy(&d->map_result,&s->map_result,sizeof d->map_result);
    lpero_copy(&d->build_result,&s->build_result,sizeof d->build_result);
    lpero_copy(&d->flags,&s->flags,sizeof d->flags);
    lpero_copy(&d->gpr_written,&s->gpr_written,sizeof d->gpr_written);
    lpero_copy(&d->flags_written,&s->flags_written,sizeof d->flags_written);
    lpero_copy(&d->exit_index,&s->exit_index,sizeof d->exit_index);
    lpero_copy(&d->source,&s->source,sizeof d->source);
    lpero_copy(&d->before,&s->before,sizeof d->before);
    lpero_copy(&d->after,&s->after,sizeof d->after);
    lpero_copy(&d->transfer,&s->transfer,sizeof d->transfer);
    lpero_copy(&d->close_started,&s->close_started,sizeof d->close_started);
    lpero_copy(&d->close_complete,&s->close_complete,sizeof d->close_complete);
    lpero_copy(&d->prepare_started,&s->prepare_started,sizeof d->prepare_started);
    lpero_copy(&d->prepare_complete,&s->prepare_complete,sizeof d->prepare_complete);
    lpero_copy(&d->miss_release_started,&s->miss_release_started,sizeof d->miss_release_started);
    lpero_copy(&d->miss_release_complete,&s->miss_release_complete,sizeof d->miss_release_complete);
    lpero_copy(&d->resume_started,&s->resume_started,sizeof d->resume_started);
    lpero_copy(&d->resume_complete,&s->resume_complete,sizeof d->resume_complete);
    lpero_copy(&d->prepare_result,&s->prepare_result,sizeof d->prepare_result);
    lpero_copy(&d->miss_release_result,&s->miss_release_result,sizeof d->miss_release_result);
    lpero_copy(&d->resume_result,&s->resume_result,sizeof d->resume_result);
    lpero_copy(&d->hint_checked,&s->hint_checked,sizeof d->hint_checked);
    lpero_copy(&d->hint_hit,&s->hint_hit,sizeof d->hint_hit);
    lpero_copy(&d->hint_publication,&s->hint_publication,sizeof d->hint_publication);
    lpero_copy(&d->resumed_route,&s->resumed_route,sizeof d->resumed_route);
    lpero_copy(&d->miss_fetch,&s->miss_fetch,sizeof d->miss_fetch);
    lpero_copy(&d->original,&s->original,sizeof d->original);
    lpero_copy(&d->idle,&s->idle,sizeof d->idle);
    lpero_copy(&d->live,&s->live,sizeof d->live);
    lpero_copy(&d->idle_bytes,&s->idle_bytes,sizeof d->idle_bytes);
    lpero_copy(&d->live_bytes,&s->live_bytes,sizeof d->live_bytes);
    lpero_copy(&d->closed_bytes,&s->closed_bytes,sizeof d->closed_bytes);
    lpero_copy(&d->open,&s->open,sizeof d->open);
    lpero_copy(&d->close,&s->close,sizeof d->close);
    lpero_copy(&d->cleanup,&s->cleanup,sizeof d->cleanup);
    lpero_copy(&d->final_fetch,&s->final_fetch,sizeof d->final_fetch);
    lpero_copy(&d->publication_generation,&s->publication_generation,sizeof d->publication_generation);
    lpero_copy(&d->cold_plan_proof,&s->cold_plan_proof,sizeof d->cold_plan_proof);
    lpero_copy(&d->cold_none_proof,&s->cold_none_proof,sizeof d->cold_none_proof);
    lpero_copy(&d->epoch,&s->epoch,sizeof d->epoch);
    lpero_copy(&d->epoch_final,&s->epoch_final,sizeof d->epoch_final);
    lpero_copy(&d->live_rseq,&s->live_rseq,sizeof d->live_rseq);
    lpero_copy(&d->proof_before,&s->proof_before,sizeof d->proof_before);
    lpero_copy(&d->proof_enter,&s->proof_enter,sizeof d->proof_enter);
    lpero_copy(&d->proof_exit,&s->proof_exit,sizeof d->proof_exit);
}
static void lpero_save(void) {
    if(!lpero_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpero_entry *e=&lpero_wire.entries[lpero_index];
    lpero_record(&e->owner,r);
    if(r->slot_present && r->slot<selected_linked_epoch.used && r->slot<LE_PAGES) {
        const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
        lpero_copy(&e->slot,s,sizeof *s);lpero_copy(&e->proof_publication,&lep.slot_publication[r->slot],sizeof e->proof_publication);
        lpero_copy(&e->permit,&ler.permits[r->slot],sizeof e->permit);e->ready_generation=lep.ready_generation[r->slot];
    }
    lpero_counts(e->counts_after);
}
static void lpero_begin(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    lpero_active=lpero_ready && r->ingress.complete && lpero_root((uintptr_t)r->ingress.frame.greg[REG_RIP]);
    if(!lpero_active)return;
    unsigned index=(unsigned)(((uintptr_t)r->ingress.frame.greg[REG_RIP]-lpero_head)/32U);
    le_need(index==lpero_wire.h[25] && index<LPERO_ENTRIES,LE_STATE,130);
    lpero_index=index;++lpero_wire.h[25];struct lpero_entry *e=&lpero_wire.entries[index];
    le_need(!e->present,LE_STATE,131);e->present=1;e->ingress_event=lpero_wire.raw_ingress[0];lpero_counts(e->counts_before);
}
static void lpero_closed(void) {
    if(!lpero_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpero_entry *e=&lpero_wire.entries[lpero_index];
    le_need(r->close_complete && !e->closed && r->transfer.previous<2,LE_STATE,133);
    if(!lpero_index)lpero_copy(&lpero_wire.first_closed,&selected_chain.slots[r->transfer.previous],sizeof lpero_wire.first_closed);
    const struct li2_tf_chain_slot *p=&selected_chain.slots[r->transfer.previous];
    const uint64_t closed[]={p->index,p->generation,p->event_id,p->phase,p->prepare_complete,
        p->owner.step.phase,p->owner.step.trace_seen,p->owner.step.revoke_sync_started,
        p->owner.continuation_started,p->owner.continuation_complete,p->release.started,p->release.complete,
        p->query.complete,p->owner.actual_post_pc,p->fetch.ref.sequence,
        (uint64_t)(unsigned)p->release.result,(uint64_t)(unsigned)p->query.result,selected_chain.event_id};
    lpero_copy(e->closed_owner,closed,sizeof closed);e->closed=1;lpero_save();
}
static void lpero_source(void) {
    if(!lpero_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpero_entry *e=&lpero_wire.entries[lpero_index];
    le_need(r->source.ready==1 && r->source.key.page.object==dependency_count && r->source.key.page.address==lpero_page &&
        r->source.key.entry==lpero_head+lpero_index*32U && r->source.key.backing.stat.st_dev==lpero_wire.main_backing.st_dev &&
        r->source.key.backing.stat.st_ino==lpero_wire.main_backing.st_ino && r->source.key.backing.stat.st_size==lpero_wire.main_backing.st_size &&
        equal(r->source.key.bytes,lpero_wire.original_source,PAGE),LE_SOURCE,130);
    le_need(!e->source_ready,LE_STATE,134);e->source_ready=1;
    lpero_copy(&e->source_rseq,li2_rseq_snapshot(),sizeof e->source_rseq);
    int error=li2_lifecycle_preedge_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,&e->before_memory);
    le_need(!error && e->before_memory.complete,LE_STATE,135);lpero_save();
}
/* Observe the first real retirement of an already completed focal generation,
   including intervening nonfocal publications. No supplied permit or key. */
static void lpero_retired(void) {
    if(!lpero_ready || lpero_wire.retirement.present)return;
    const struct ler_retirement *t=&ler.retirement;const struct le_record *r=&selected_linked_epoch.current;
    if(!t->started || !t->consumed || !t->old_verified || !t->target_ready || !t->replaced ||
       !r->slot_present || t->slot!=r->slot || t->new_generation!=r->publication_generation)return;
    for(unsigned i=0;i<lpero_wire.h[25];i++) {
        const struct lpero_entry *old=&lpero_wire.entries[i];
        if(!old->completed || old->owner.slot!=t->slot || old->owner.publication_generation!=t->old_generation)continue;
        struct lpero_retirement *w=&lpero_wire.retirement;w->present=1;w->old_focal=i;w->held=1;
        lpero_copy(&w->retirement,t,sizeof *t);lpero_copy(&w->claimed,&ler.claimed,sizeof w->claimed);
        lpero_copy(&w->proof_close,&lep.close,sizeof w->proof_close);lpero_copy(&w->proof_writable,&lep.writable,sizeof w->proof_writable);
        const struct le_slot *slot=&selected_linked_epoch.slots[r->slot];
        lpero_copy(&w->new_slot,slot,sizeof *slot);lpero_copy(&w->publication,&lep.slot_publication[r->slot],sizeof w->publication);
        lpero_copy(&w->held_epoch,li2_lifecycle_preedge_progress(),sizeof w->held_epoch);
        lpero_copy(w->new_payload,(const void *)slot->proof,sizeof w->new_payload);
        lpero_copy(w->generated_page,(const void *)slot->generated,PAGE);break;
    }
}
static int lpero_witness(void) {
    return lpero_wire.retirement.present && !lpero_wire.retirement.completed && selected_linked_epoch.current.slot_present &&
        selected_linked_epoch.current.slot==lpero_wire.retirement.retirement.slot &&
        selected_linked_epoch.current.publication_generation==lpero_wire.retirement.retirement.new_generation;
}
static void lpero_held(void) {
    lpero_retired();if(!lpero_focal())return;
    struct lpero_entry *e=&lpero_wire.entries[lpero_index];const struct le_record *r=&selected_linked_epoch.current;
    lpero_copy(&e->epoch_held,li2_lifecycle_preedge_progress(),sizeof e->epoch_held);
    const struct le_slot *slot=&selected_linked_epoch.slots[r->slot];
    lpero_copy(&e->proof,(void *)slot->proof,sizeof e->proof);
    lpero_copy(e->proof_tail,(const unsigned char *)slot->proof+sizeof e->proof,sizeof e->proof_tail);e->proof_bytes=LI2_LINK_PROOF_BYTES;
    lpero_copy(e->generated_page,(void *)slot->generated,PAGE);e->generated_bytes=PAGE;lpero_save();
}
static void lpero_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    if(lpero_witness()) {lpero_wire.retirement.opened=1;lpero_copy(&lpero_wire.retirement.opened_epoch,li2_lifecycle_preedge_progress(),sizeof lpero_wire.retirement.opened_epoch);}
    if(!lpero_focal())return;
    const struct le_record *r=&selected_linked_epoch.current;struct lpero_entry *e=&lpero_wire.entries[lpero_index];
    le_need(e->source_ready && r->slot_present && r->redirected && !e->redirected,LE_STATE,139);
    e->redirected=1;e->redirect_event=lpero_wire.raw_ingress[0];lpero_copy(&e->redirected_rseq,li2_rseq_snapshot(),sizeof e->redirected_rseq);
    lpero_copy(&e->epoch_opened,li2_lifecycle_preedge_progress(),sizeof e->epoch_opened);lpero_save();
}
static void lpero_before_close(void) { }
static void lpero_complete(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    if(lpero_witness()) {
        struct lpero_retirement *w=&lpero_wire.retirement;w->completed=1;
        lpero_copy(&w->permit,&ler.permits[r->slot],sizeof w->permit);lpero_copy(&w->close,&r->close,sizeof w->close);
        lpero_copy(&w->terminal_epoch,li2_lifecycle_preedge_progress(),sizeof w->terminal_epoch);
    }
    if(!lpero_focal())return;
    struct lpero_entry *e=&lpero_wire.entries[lpero_index];
    le_need(!e->completed && r->completed && !ler.pending && r->epoch_final.phase==LI2_PREEDGE_RELEASED,LE_STATE,142);
    lpero_copy(&e->completed_rseq,li2_rseq_snapshot(),sizeof e->completed_rseq);e->completed=1;
    int error=li2_lifecycle_preedge_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,&e->after_memory);
    le_need(!error && e->after_memory.complete,LE_STATE,143);
    lpero_copy(e->terminal_source_page,(void *)lpero_page,PAGE);e->terminal_source_bytes=PAGE;lpero_save();
}
static void lpero_abort_observe(void) {if(lpero_focal())lpero_save();}
static void lpero_finish(unsigned status,unsigned code,long detail) {
    if(lpero_finished || !lpero_wire.h[18])return;
    lpero_finished=1;uint64_t *h=lpero_wire.h;
    h[26]=1;h[27]=status;h[28]=code;h[29]=(uint64_t)detail;
    h[30]=lpero_active;h[31]=selected_linked_epoch_active;h[32]=selected_linked_epoch_busy;
    h[33]=selected_linked_epoch_failing;h[34]=handling;h[35]=selected_step_pending;
    h[36]=selected_pending_route;h[37]=selected_flags_known;h[38]=selected_logical_flags;
    if(lpero_focal())lpero_save();
    /* Finalized retained focal observation; later unrelated offers may have
       replaced the live current record, never this completed by-value copy. */
    for(unsigned i=0;i<lpero_wire.h[25] && i<LPERO_ENTRIES;i++)lpero_wire.entries[i].terminal=1;
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
        ,selected_linked_epoch.graph_refaults,selected_linked_epoch.cut_exits
    };
    lpero_copy(lpero_wire.counts,counts,sizeof counts);
    lpero_wire.events[0]=selected_linked_epoch.events;
    lpero_copy(lpero_wire.events+1,selected_linked_epoch.signals,sizeof selected_linked_epoch.signals);
    lpero_copy(lpero_wire.events+6,selected_linked_epoch.refusals,sizeof selected_linked_epoch.refusals);
    lpero_copy(lpero_wire.events+10,selected_linked_epoch.exit_counts,sizeof selected_linked_epoch.exit_counts);
    const struct le_record *r=&selected_linked_epoch.current;
    const uint64_t current[]={r->slot_present,r->slot,r->redirected,r->exit_seen,r->completed,r->exit_index,
        r->open.started,r->open.returned,r->open.complete,r->close.started,r->close.returned,r->close.complete,
        r->release_started,r->release_complete,r->cleanup_started,r->cleanup_complete,r->before.complete,r->after.complete,
        r->unexpected_seen,r->unexpected.complete,r->original.ready,r->original.kind,r->original.head_index,r->original.source_offset,
        r->idle_bytes,r->live_bytes,r->closed_bytes,r->final_fetch.held,r->final_fetch.complete,
        r->build_started,r->build_returned,(uint64_t)(unsigned)r->build_result,r->gpr_written,r->flags_written,
        r->refault_started,r->refault_complete,(uint64_t)(unsigned)r->refault_result};
    lpero_copy(lpero_wire.terminal_current_fields,current,sizeof current);
    lpero_copy(&lpero_wire.terminal_hint,li2_lifecycle_link_native_hint_progress(),sizeof lpero_wire.terminal_hint);
    lpero_wire.terminal_hint_fields[0]=r->hint_checked;
    lpero_wire.terminal_hint_fields[1]=r->hint_hit;
    lpero_wire.terminal_hint_fields[2]=r->hint_publication;
    lpero_copy(&lpero_wire.terminal_transfer,li2_tf_chain_span_progress(),sizeof lpero_wire.terminal_transfer);
    lpero_owners(&lpero_wire.terminal_owners,0);
    li2_current_custody_snapshot(&lpero_wire.terminal_current);
    lpero_copy(&lpero_wire.terminal_epoch,li2_lifecycle_preedge_progress(),sizeof lpero_wire.terminal_epoch);
    lpero_copy(&lpero_wire.terminal_chain,&selected_chain,sizeof selected_chain);
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    const struct li2_native_close *g=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(f){lpero_copy(&lpero_wire.terminal_fetch,f,sizeof *f);h[50]=1;}
    if(g){lpero_copy(&lpero_wire.terminal_global_close,g,sizeof *g);h[51]=1;}
    if(n){lpero_copy(&lpero_wire.terminal_native_counts,n,sizeof *n);h[57]=1;}
    /* Retain every remaining LI2_NATIVE operand independently of its text
       report; the separate reuse wire has its own exact version/extent. */
    const struct li2_native_epoch *ne=li2_native_epoch_progress();
    h[58]=native_main_admissions;h[59]=native_main_refaults;
    h[60]=ne->ready;h[61]=ne->retries;h[62]=ne->first_error;
    lpero_registry(&lpero_wire.terminal_registry);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&lpero_wire.sink_terminal,0,0,0,0);
    h[41]=(uint64_t)flags;h[42]=(uint64_t)result;
    if(result || flags!=(long)h[16] || !lpero_same_sink(&lpero_wire.sink_terminal) || lpero_wire.sink_terminal.st_size){h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof lpero_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lpero_wire+at),sizeof lpero_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lpero_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lpero_wire)return;
    const uint64_t footer[]={LPERO_FOOTER,2,sizeof lpero_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
