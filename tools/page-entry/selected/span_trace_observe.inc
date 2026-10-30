/* Qualification-only actual TRACE owner observations. This finite capture
   qualifies one fixed focal transfer, not all loader regions or a full app. */
#include "span_trace_observe_memory.h"
#include "unrolled_hash_nested_fp.h"
#include "scalar_span_trace_capture_config.h"
#if LI2_SCALAR_SPAN_CAPTURE != 1 || LI2_SCALAR_SPAN_TRACE != 1
#error "literal genuine TRACE capture profile"
#endif
#ifndef LI2_SPAN_APP_HEAD_RVA
#error "fresh emitted fixture head required"
#endif
#ifndef LI2_SPAN_APP_MISS_RVA
#error "fresh emitted fixture refusal head required"
#endif
#define SPTO_MAGIC UINT64_C(0x314f54535049324c)
#define SPTO_FOOTER UINT64_C(0x314654535049324c)
struct spto_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct spto_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct spto_entry {
    uint64_t present,closed,source_ready,redirected,resumed,completed,terminal;
    uint64_t source_bytes,generated_bytes,terminal_source_bytes,resumed_closed;
    struct sp_record owner;
    struct sp_slot slot;
    struct sp_frame resumed_frame,resumed_exit;
    struct li2_spto_memory before_memory,after_memory;
    struct spto_owners source_owners,redirected_owners,completed_owners;
    struct li2_tf_chain predecessor,closed_chain,resumed_chain,resumed_closed_chain;
    unsigned char source_page[PAGE],generated_page[PAGE],terminal_source_page[PAGE];
};
struct spto_wire {
    uint64_t h[64],control[24],counts[32],events[18];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct spto_registry initial_registry,terminal_registry;
    struct spto_entry entry;
    struct spto_owners terminal_owners;
    struct li2_fetch_progress terminal_fetch;
    struct li2_native_close terminal_global_close;
    struct li2_native_counts terminal_native_counts;
    struct li2_tf_chain terminal_chain;
    struct sp_record terminal_record;
    struct li2_span_transfer_progress terminal_transfer;
    struct li2_current_custody_stats terminal_current;
    struct uho_nested_fp nested_fp;
    unsigned char original_source[PAGE];
};
static struct spto_wire spto_wire;
static unsigned spto_ready,spto_finished,spto_active,spto_resume_exit;
static uintptr_t spto_head,spto_page;
static const uint64_t spto_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
static const uint64_t spto_nested_zero_alignment __attribute__((used))=__alignof__(((struct uho_nested_fp *)0)->zero);
static const uint64_t spto_nested_ones_alignment __attribute__((used))=__alignof__(((struct uho_nested_fp *)0)->ones);
_Static_assert(sizeof(struct spto_wire)+64<(16U<<20),"complete actual fixture wire under unchanged16MiB");
static void spto_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void spto_registry(struct spto_registry *out) {
    sp_need(!out->complete && protected_count && protected_count<=RANGES,SP_STATE,100);
    const struct image *b=bridge_runtime_image();
    sp_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,SP_STATE,101);
    spto_copy(&out->bridge,b,sizeof *b);spto_copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    spto_copy(out->ranges,protected,protected_count*sizeof(*protected));
    spto_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void spto_owners(struct spto_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    spto_copy(&out->rseq,r,sizeof(*r));spto_copy(&out->rseq_native,n,sizeof(*n));
    spto_copy(&out->pair,p,sizeof(*p));spto_copy(&out->lifecycle,l,sizeof(*l));
    spto_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}
static int spto_same_sink(const struct stat *s) {
    const struct stat *a=&spto_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}
static void spto_initialize(void) {
    __asm__ volatile(""::"r"(&spto_step_frame_fp_alignment),"r"(&spto_nested_zero_alignment),"r"(&spto_nested_ones_alignment):"memory");
    sp_need(!spto_ready && !spto_finished,SP_STATE,102);
    uint64_t *h=spto_wire.h;
    h[0]=SPTO_MAGIC;h[1]=2;h[2]=sizeof spto_wire;h[3]=sizeof(struct spto_entry);
    h[4]=sizeof(struct sp_record);h[5]=sizeof(struct sp_slot);h[6]=sizeof(struct sp_frame);
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    sp_need(!selected_run_protect_add(0,(uintptr_t)&spto_wire,sizeof spto_wire),SP_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&spto_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    sp_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(spto_wire.sink_initial.st_mode) && (spto_wire.sink_initial.st_mode&07777)==0600 &&
        spto_wire.sink_initial.st_nlink==1 && spto_wire.sink_initial.st_size==0,SP_STATE,104);h[18]=1;
    const char *control=fork_env("LI2_SCALAR_SPAN_CAPTURE_CONTROL"),*mode=fork_env("LI2_SCALAR_SPAN_APP_MODE");
    sp_need(control && (control[0]=='0' || control[0]=='1') && !control[1] &&
        mode && mode[0]>='0' && mode[0]<='3' && !mode[1],SP_STATE,105);
    spto_wire.control[0]=(unsigned)(control[0]-'0');h[24]=(unsigned)(mode[0]-'0');
    sp_need(!spto_wire.control[0] || !h[24],SP_STATE,106);
    spto_copy(&spto_wire.main,&original_main,sizeof original_main);
    spto_copy(&spto_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    spto_copy(&spto_wire.hardware,&selected_hardware,sizeof selected_hardware);
    spto_copy(&spto_wire.session,&selected_session,sizeof selected_session);
    uintptr_t rva=h[24]==2?LI2_SPAN_APP_MISS_RVA:LI2_SPAN_APP_HEAD_RVA;
    sp_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-rva,SP_STATE,107);
    spto_head=original_main.bias+rva;spto_page=spto_head&~(uintptr_t)(PAGE-1);
    sp_need(spto_head>=PAGE && spto_head<(UINT64_C(1)<<31) && (spto_head&(PAGE-1))==(h[24]==2?0x300U:0x200U),SP_STATE,108);
    unsigned found=0;size_t offset=0;uintptr_t page_rva=rva&~(uintptr_t)(PAGE-1);
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || page_rva<p->p_vaddr || page_rva-p->p_vaddr>=p->p_filesz)continue;
        sp_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(page_rva-p->p_vaddr)>=PAGE,SP_STATE,109);
        offset=(size_t)(p->p_offset+page_rva-p->p_vaddr);found=1;
    }
    sp_need(found,SP_STATE,110);spto_copy(spto_wire.original_source,original_main.source+offset,PAGE);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&spto_wire.main_backing,0,0,0,0);
    h[19]=(uint64_t)result;sp_need(!result && S_ISREG(spto_wire.main_backing.st_mode),SP_STATE,111);
    h[20]=spto_head;h[21]=offset;h[22]=dependency_count;h[23]=1;
    h[52]=(uintptr_t)&selected_scalar_span;h[53]=(uintptr_t)li2_tf_chain_span_progress();
    h[54]=(uintptr_t)&spr;h[55]=(uintptr_t)&selected_chain;h[56]=(uintptr_t)&spto_wire;
    spto_registry(&spto_wire.initial_registry);spto_ready=1;
}
static void spto_fd_guard(long n,const long a[6]) {
    if(!spto_ready)return;
    sp_need(!spto_finished,SP_STATE,110);
    sp_count(&spto_wire.h[43]);
    if(n==SYS_openat) {
        sp_count(&spto_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)spto_wire.h[49]=1;
        sp_need(!writable,SP_STATE,111);
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
    if(n==SYS_dup2 || n==SYS_dup3)sp_need((unsigned)a[1]!=3,SP_STATE,112);
    if((int)fd<0)return;
    if((unsigned)fd==3)spto_wire.h[48]=1;
    sp_need((unsigned)fd!=3,SP_STATE,113);sp_count(&spto_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    sp_need(!result || result==-9,SP_STATE,121);
    if(result)sp_count(&spto_wire.h[45]);
    if(!result && observed.st_dev==spto_wire.sink_initial.st_dev &&
       observed.st_ino==spto_wire.sink_initial.st_ino)spto_wire.h[48]=1;
    sp_need(result || observed.st_dev!=spto_wire.sink_initial.st_dev ||
        observed.st_ino!=spto_wire.sink_initial.st_ino,SP_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}
static int spto_focal(void) {
    return spto_ready && spto_active && selected_scalar_span.current.transfer.pc==spto_head;
}
static void spto_save(void) {
    if(!spto_focal())return;
    const struct sp_record *r=&selected_scalar_span.current;struct spto_entry *e=&spto_wire.entry;
    spto_copy(&e->owner,r,sizeof *r);
    if(r->slot_present && r->slot<selected_scalar_span.used && r->slot<SP_PAGES)
        spto_copy(&e->slot,&selected_scalar_span.slots[r->slot],sizeof e->slot);
}
static void spto_begin(void) {
    const struct sp_record *r=&selected_scalar_span.current;
    spto_resume_exit=spto_ready && spto_wire.h[24]==2 && spto_wire.entry.resumed &&
        !spto_wire.entry.resumed_closed && r->ingress.complete &&
        (uintptr_t)r->ingress.frame.greg[REG_RIP]==spto_head+2;
    if(spto_resume_exit)
        spto_copy(&spto_wire.entry.resumed_exit,&r->ingress,sizeof r->ingress);
    spto_active=spto_ready && r->ingress.complete && (uintptr_t)r->ingress.frame.greg[REG_RIP]==spto_head;
    if(!spto_active)return;
    sp_need(!spto_wire.entry.present,SP_STATE,130);spto_wire.entry.present=1;
    spto_copy(&spto_wire.entry.predecessor,&selected_chain,sizeof selected_chain);
}
static void spto_closed(void) {
    if(spto_resume_exit) {
        sp_need(selected_scalar_span.current.close_complete &&
            !spto_wire.entry.resumed_closed,SP_STATE,142);
        spto_copy(&spto_wire.entry.resumed_closed_chain,&selected_chain,sizeof selected_chain);
        spto_wire.entry.resumed_closed=1;spto_resume_exit=0;
    }
    if(!spto_focal())return;
    sp_need(selected_scalar_span.current.close_complete && !spto_wire.entry.closed,SP_STATE,131);
    spto_wire.entry.closed=1;spto_copy(&spto_wire.entry.closed_chain,&selected_chain,sizeof selected_chain);spto_save();
}
static void spto_source(void) {
    if(!spto_focal())return;
    const struct sp_record *r=&selected_scalar_span.current;struct spto_entry *e=&spto_wire.entry;
    sp_need(r->source.ready==1 && r->source.key.page.object==dependency_count &&
        r->source.key.page.address==spto_page && r->source.key.entry==spto_head &&
        r->source.key.backing.stat.st_dev==spto_wire.main_backing.st_dev &&
        r->source.key.backing.stat.st_ino==spto_wire.main_backing.st_ino &&
        r->source.key.backing.stat.st_size==spto_wire.main_backing.st_size &&
        equal(r->source.key.bytes,spto_wire.original_source,PAGE),SP_SOURCE,130);
    sp_need(!e->source_ready,SP_STATE,132);e->source_ready=1;
    spto_copy(e->source_page,(void *)spto_page,PAGE);e->source_bytes=PAGE;
    spto_owners(&e->source_owners,0);
    int error=li2_lifecycle_span_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,&e->before_memory);
    sp_need(!error && e->before_memory.complete,SP_STATE,133);spto_save();
}
static void spto_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    (void)sig;(void)si;(void)uc;
    if(!spto_focal())return;
    const struct sp_record *r=&selected_scalar_span.current;struct spto_entry *e=&spto_wire.entry;
    sp_need(e->source_ready && r->slot_present && r->redirected && !e->redirected,SP_STATE,134);
    e->redirected=1;spto_owners(&e->redirected_owners,1);
    spto_copy(e->generated_page,(void *)selected_scalar_span.slots[r->slot].plan.generated,PAGE);e->generated_bytes=PAGE;spto_save();
    if(spto_wire.control[0]==1) {
        sp_need(!spto_wire.control[2],SP_STATE,135);spto_wire.control[1]=1;spto_wire.control[2]=1;
        /* Actual pre-arm CPUID facts are already protected in wire.hardware.
           CPUID itself is disabled now. Guard XGETBV and then read live handler
           PKRU; neither instruction changes PKRU, FP state or a saved frame. */
        const struct li2_selected_hardware *h=&spto_wire.hardware;
        sp_need(h->abi_version==1 && !h->reserved && h->leaf0[0]>=7 &&
            (h->leaf1[2]&UINT32_C(0x0c000000))==UINT32_C(0x0c000000),SP_STATE,124);
        uint32_t a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
        uint64_t xcr0=(uint64_t)a|((uint64_t)d<<32);
        spto_wire.control[21]=xcr0;spto_wire.control[22]=1;
        if(xcr0&(UINT64_C(1)<<9)) {
            sp_need((h->leaf7[2]&24U)==24U,SP_STATE,125);
            __asm__ volatile("rdpkru":"=a"(a),"=d"(d):"c"(0):"memory");
            spto_wire.control[18]=a;spto_wire.control[19]=d;spto_wire.control[20]=1;
        }
        spto_wire.control[6]=selected_session.pid;spto_wire.control[7]=selected_session.tid;
        spto_wire.control[8]=SIGTRAP;spto_wire.control[12]=1;
        /* Qualification injects a real nested owner event outside a maps RAW
           transaction. Use the same registered kernel gateway directly: this
           pointer-free tgkill changes no mappings. The terminal reader still
           requires the whole nested frame, nonreturn and complete cleanup. */
        struct uho_nested_fp *f=&spto_wire.nested_fp;
        sp_need((xcr0==UINT64_C(0xe7) || xcr0==UINT64_C(0x2e7)) &&
            !f->h[0] && fork_gate_stack.ss_size==sizeof f->stack &&
            (uintptr_t)fork_gate_stack.ss_sp<=UINTPTR_MAX-fork_gate_stack.ss_size,
            SP_STATE,126); /* Fixed nondynamic user-state profile only. */
        f->h[0]=1;f->h[3]=(uintptr_t)fork_gate_stack.ss_sp;f->h[4]=fork_gate_stack.ss_size;
        f->h[7]=xcr0;f->h[8]=selected_session.pid;f->h[9]=selected_session.tid;
        f->h[10]=SIGTRAP;f->h[11]=xcr0;
        long result=uho_nested_raw(f,selected_session.pid,selected_session.tid,SIGTRAP,0,0,0);
        spto_wire.control[13]=1;spto_wire.control[14]=(uint64_t)result;
        sp_need(0,SP_STATE,119); /* A real nested terminal event must not return. */
    }
}
static void spto_memory_terminal(unsigned after_abort) {
    if(!spto_focal())return;
    struct spto_entry *e=&spto_wire.entry;const struct sp_record *r=&selected_scalar_span.current;
    if(!e->after_memory.attempted) {
        int error=li2_lifecycle_span_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],after_abort,&e->after_memory);
        if(error || !e->after_memory.complete)spto_wire.h[39]=3;
    }
    spto_copy(e->terminal_source_page,(void *)spto_page,PAGE);e->terminal_source_bytes=PAGE;
}
static void spto_resumed(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!spto_focal())return;
    struct spto_entry *e=&spto_wire.entry;
    sp_need(e->source_ready && !e->resumed && selected_scalar_span.current.resume_complete,SP_STATE,136);
    sp_need(!sp_capture(&e->resumed_frame,sig,si,uc),SP_FRAME,130);sp_tls(&e->resumed_frame);
    spto_copy(&e->resumed_chain,&selected_chain,sizeof selected_chain);
    e->resumed=1;spto_memory_terminal(0);sp_need(!spto_wire.h[39],SP_STATE,137);spto_save();
}
static void spto_complete(void) {
    if(!spto_focal())return;
    struct spto_entry *e=&spto_wire.entry;
    sp_need(!e->completed && selected_scalar_span.current.completed && !spr.pending,SP_STATE,138);
    spto_owners(&e->completed_owners,0);e->completed=1;spto_memory_terminal(0);
    sp_need(!spto_wire.h[39],SP_STATE,139);spto_save();
}
static void spto_abort_observe(void) {
    if(!spto_focal())return;
    struct sp_frame *f=&selected_scalar_span.current.unexpected;
    if(f->complete) {
        f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
        f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
        f->tls_complete=!f->fs_result && !f->gs_result;
    }
    if(selected_scalar_span.current.before.complete)spto_memory_terminal(1);
    spto_save();
}
static void spto_finish(unsigned status,unsigned code,long detail) {
    if(spto_finished || !spto_wire.h[18])return;
    spto_finished=1;uint64_t *h=spto_wire.h;
    h[26]=1;h[27]=status;h[28]=code;h[29]=(uint64_t)detail;
    h[30]=spto_active;h[31]=selected_scalar_span_active;h[32]=selected_scalar_span_busy;
    h[33]=selected_scalar_span_failing;h[34]=handling;h[35]=selected_step_pending;
    h[36]=selected_pending_route;h[37]=selected_flags_known;h[38]=selected_logical_flags;
    if(spto_focal())spto_save();
    /* Finalized retained focal observation; later unrelated offers may have
       replaced the live current record, never this completed by-value copy. */
    if(spto_wire.entry.present)spto_wire.entry.terminal=1;
    const uint64_t counts[]={selected_scalar_span.initialized,selected_scalar_span.used,
        selected_scalar_span.offers,selected_scalar_span.closed,selected_scalar_span.resumed,
        selected_scalar_span.hash_misses,selected_scalar_span.candidates,selected_scalar_span.source_misses,
        selected_scalar_span.plan_misses,selected_scalar_span.capacity_misses,selected_scalar_span.publications,
        selected_scalar_span.hits,selected_scalar_span.entries,selected_scalar_span.completed,
        selected_scalar_span.unexpected,selected_scalar_span.plan_checks,selected_scalar_span.rseq_checks,
        spr.generation,spr.retirement_attempts,spr.retirements,spr.claims,spr.permits_issued,
        spr.pending,spr.retiring,spr.cursor,selected_scalar_span.first_error,
        (uint64_t)selected_scalar_span.first_detail,selected_scalar_span_decoding,
        selected_scalar_span_closing,selected_scalar_span_resuming,0,0};
    spto_copy(spto_wire.counts,counts,sizeof counts);
    spto_wire.events[0]=selected_scalar_span.events;
    spto_copy(spto_wire.events+1,selected_scalar_span.signals,sizeof selected_scalar_span.signals);
    spto_copy(spto_wire.events+6,selected_scalar_span.refusals,sizeof selected_scalar_span.refusals);
    spto_copy(spto_wire.events+10,selected_scalar_span.exit_counts,sizeof selected_scalar_span.exit_counts);
    spto_copy(&spto_wire.terminal_record,&selected_scalar_span.current,sizeof selected_scalar_span.current);
    spto_copy(&spto_wire.terminal_transfer,li2_tf_chain_span_progress(),sizeof spto_wire.terminal_transfer);
    spto_owners(&spto_wire.terminal_owners,0);
    li2_current_custody_snapshot(&spto_wire.terminal_current);
    spto_copy(&spto_wire.terminal_chain,&selected_chain,sizeof selected_chain);
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    const struct li2_native_close *g=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(f){spto_copy(&spto_wire.terminal_fetch,f,sizeof *f);h[50]=1;}
    if(g){spto_copy(&spto_wire.terminal_global_close,g,sizeof *g);h[51]=1;}
    if(n){spto_copy(&spto_wire.terminal_native_counts,n,sizeof *n);h[57]=1;}
    /* Wire v2 captures every remaining LI2_NATIVE operand, independently of
       its text report. These five words were required-zero in wire v1. */
    const struct li2_native_epoch *ne=li2_native_epoch_progress();
    h[58]=native_main_admissions;h[59]=native_main_refaults;
    h[60]=ne->ready;h[61]=ne->retries;h[62]=ne->first_error;
    spto_registry(&spto_wire.terminal_registry);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&spto_wire.sink_terminal,0,0,0,0);
    h[41]=(uint64_t)flags;h[42]=(uint64_t)result;
    if(result || flags!=(long)h[16] || !spto_same_sink(&spto_wire.sink_terminal) || spto_wire.sink_terminal.st_size){h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof spto_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&spto_wire+at),sizeof spto_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof spto_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof spto_wire)return;
    const uint64_t footer[]={SPTO_FOOTER,2,sizeof spto_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
