/* Private actual-owner qualification profile only. Included after the complete
   controller; exact guarded seams are separately inverse-bound. Fixed fixture
   memory snapshots are diagnostic only and give no execution authority. */
#if LI2_UNROLLED_HASH_CAPTURE != 1 || LI2_UNROLLED_HASH != 1
#error "capture requires the literal unrolled qualification profile"
#endif
#include "unrolled_hash_capture_config.h"
#ifndef LI2_UNROLLED_APP_HEAD_RVA
#error "actual retained application ELF symbol RVA is required"
#endif
#ifdef LI2_UNROLLED_HASH_OBSERVE_ONLY
#error "actual-owner qualification is separate from observation-only timing"
#endif
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "unrolled_hash_observe_memory.h"
#define UHO_ROWS 2U
#define UHO_MAGIC UINT64_C(0x314f48554c49324c)
#define UHO_FOOTER UINT64_C(0x31464f48554c4932)
enum { UHO_NORMAL=0,UHO_NESTED=1,UHO_OPEN_ERROR=2,UHO_CLOSE_ERROR=3,
    UHO_SYNC_ERROR=4,UHO_SLOT_IDENTITY=5,UHO_ENTRY_INTERIOR=6,UHO_EXIT_INTERIOR=7 };
struct uho_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct uho_entry {
    uint64_t present,ordinal,committed,terminal,source_bytes,generated_bytes;
    struct uh_record owner;
    struct uh_frame redirected;
    struct li2_uho_memory before_memory,after_memory;
    struct uho_owners redirected_owners,completed_owners;
    unsigned char source_page[PAGE],generated_page[PAGE],terminal_source_page[PAGE];
    uint64_t terminal_source_bytes;
};
struct uho_wire {
    uint64_t h[64],control[24];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    __typeof__(selected_unrolled) owner;
    struct uho_owners terminal_owners;
    struct li2_fetch_progress terminal_fetch;
    struct li2_native_close terminal_global_close;
    struct li2_native_counts terminal_native_counts;
    struct uho_entry entries[UHO_ROWS];
    struct uh_frame supplied_before;
    struct uh_record control_before;
    unsigned char original_source[LI2_UNROLLED_HASH_SOURCE];
    unsigned char generated[UH_PAGES][PAGE];
};
static struct uho_wire uho_wire;
static unsigned uho_ready,uho_finished,uho_current=UHO_ROWS;
static uintptr_t uho_head;
static const uint64_t uho_step_frame_fp_alignment __attribute__((used))=
    __alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct uho_wire)<4*1024*1024,"fixed private owner record below unchanged16MiB ceiling");
static void uho_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void uho_owners(struct uho_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    uho_copy(&out->rseq,r,sizeof(*r));uho_copy(&out->rseq_native,n,sizeof(*n));
    uho_copy(&out->pair,p,sizeof(*p));uho_copy(&out->lifecycle,l,sizeof(*l));
    uho_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    /* Only redirected follows the existing final successful source/rseq
       guard with no intervening RAW. Completion/terminal never dereference a
       possibly historical application pointer or invent a new guard result. */
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}
static int uho_same_sink(const struct stat *s) {
    const struct stat *a=&uho_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}
static void uho_initialize(void) {
    __asm__ volatile(""::"r"(&uho_step_frame_fp_alignment):"memory");
    uh_need(!uho_ready && !uho_finished,UH_STATE,101);
    uho_wire.h[0]=UHO_MAGIC;uho_wire.h[1]=1;uho_wire.h[2]=sizeof uho_wire;
    uho_wire.h[3]=sizeof selected_unrolled;uho_wire.h[4]=sizeof(struct uho_entry);
    uho_wire.h[5]=sizeof(struct uh_record);uho_wire.h[6]=sizeof(struct uh_frame);
    uho_wire.h[7]=sizeof(ucontext_t);uho_wire.h[8]=sizeof(siginfo_t);
    uho_wire.h[9]=(uintptr_t)li2_raw6;uho_wire.h[10]=(uintptr_t)li2_gateway_start;
    uho_wire.h[11]=(uintptr_t)li2_gateway_end;
    uho_wire.h[12]=(uintptr_t)fork_gate_stack.ss_sp;uho_wire.h[13]=fork_gate_stack.ss_size;
    uh_need(!selected_run_protect_add(0,(uintptr_t)&uho_wire,sizeof uho_wire),UH_STATE,102);
    uho_wire.h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&uho_wire.sink_initial,0,0,0,0);
    uho_wire.h[15]=(uint64_t)fdflags;uho_wire.h[16]=(uint64_t)flags;uho_wire.h[17]=(uint64_t)result;
    uh_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(uho_wire.sink_initial.st_mode) && (uho_wire.sink_initial.st_mode&07777)==0600 &&
        uho_wire.sink_initial.st_nlink==1 && uho_wire.sink_initial.st_size==0,UH_STATE,103);
    uho_wire.h[18]=1;
    const char *control=fork_env("LI2_UNROLLED_CAPTURE_CONTROL");
    uh_need(control && control[0]>='0' && control[0]<='7' && !control[1],UH_STATE,104);
    uho_wire.control[0]=(unsigned)(control[0]-'0');
    uho_wire.main=original_main;uho_wire.interpreter=original_interpreter;
    uho_copy(&uho_wire.hardware,&selected_hardware,sizeof selected_hardware);
    uh_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-LI2_UNROLLED_APP_HEAD_RVA,
        UH_STATE,105);
    uho_head=original_main.bias+LI2_UNROLLED_APP_HEAD_RVA;
    uh_need(uho_head>=PAGE && uho_head<(UINT64_C(1)<<47)-39 &&
        (uho_head&(PAGE-1))<=PAGE-39,UH_STATE,106);
    unsigned found=0;size_t offset=0;
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];uint64_t rva=LI2_UNROLLED_APP_HEAD_RVA;
        if(p->p_type!=PT_LOAD || rva<p->p_vaddr || rva-p->p_vaddr>=p->p_filesz)continue;
        uh_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(rva-p->p_vaddr)>=39,UH_STATE,107);
        offset=(size_t)(p->p_offset+rva-p->p_vaddr);found=1;
    }
    uh_need(found,UH_STATE,108);
    uho_copy(uho_wire.original_source,original_main.source+offset,39);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&uho_wire.main_backing,0,0,0,0);
    uho_wire.h[19]=(uint64_t)result;uh_need(!result && S_ISREG(uho_wire.main_backing.st_mode),UH_STATE,109);
    uho_wire.h[20]=uho_head;uho_wire.h[21]=offset;uho_wire.h[22]=dependency_count;
    __asm__ volatile("":::"memory");uho_ready=1;uho_wire.h[23]=1;
}
/* Only the fixed diagnostic application profile is narrowed here. FD3 and
   actual aliases are not application channels. Write-capable openat cannot
   truncate this private regular-file sink through /proc/self/fd/3. */
static void uho_fd_guard(long n,const long a[6]) {
    if(!uho_ready)return;
    uh_need(!uho_finished,UH_STATE,110);
    uh_count(&uho_wire.h[43]);
    if(n==SYS_openat) {
        uh_count(&uho_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)uho_wire.h[49]=1;
        uh_need(!writable,UH_STATE,111);
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
    if(n==SYS_dup2 || n==SYS_dup3)uh_need((unsigned)a[1]!=3,UH_STATE,112);
    if((int)fd<0)return;
    if((unsigned)fd==3)uho_wire.h[48]=1;
    uh_need((unsigned)fd!=3,UH_STATE,113);uh_count(&uho_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    uh_need(!result || result==-9,UH_STATE,121);
    if(result)uh_count(&uho_wire.h[45]);
    if(!result && observed.st_dev==uho_wire.sink_initial.st_dev &&
       observed.st_ino==uho_wire.sink_initial.st_ino)uho_wire.h[48]=1;
    uh_need(result || observed.st_dev!=uho_wire.sink_initial.st_dev ||
        observed.st_ino!=uho_wire.sink_initial.st_ino,UH_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}
static int uho_focal(void) {return uho_ready && selected_unrolled.current.source.pc==uho_head;}
static int uho_start(unsigned kind,unsigned stage) {
    if(!uho_ready || uho_wire.control[0]!=kind || uho_wire.control[2])return 0;
    uho_wire.control[1]=stage;uho_wire.control[2]=1;
    uho_copy(&uho_wire.control_before,&selected_unrolled.current,sizeof uho_wire.control_before);
    return 1;
}
static void uho_mutate_si(int sig,siginfo_t *si,ucontext_t *uc,unsigned kind,unsigned stage) {
    if(!uho_start(kind,stage))return;
    uh_need(!uh_capture(&uho_wire.supplied_before,sig,si,uc),UH_FRAME,100);
    uho_wire.control[6]=(uintptr_t)si->si_addr;
    si->si_addr=(void *)((uintptr_t)si->si_addr+1);
    uho_wire.control[7]=(uintptr_t)si->si_addr;uho_wire.control[3]=1;
}
static void uho_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    if(uho_focal() && selected_unrolled_active && !selected_unrolled_busy &&
       !handling && uh_range(si,sizeof(*si)) && uh_range(uc,sizeof(*uc)) && sig==SIGSEGV &&
       ((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==uho_head ||
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==uho_head+24) &&
       (uintptr_t)si->si_addr==(uintptr_t)uc->uc_mcontext.gregs[REG_RIP])
        uho_mutate_si(sig,si,uc,UHO_EXIT_INTERIOR,7);
}
static void uho_entry_frame(int sig,siginfo_t *si,ucontext_t *uc) {
    uho_current=UHO_ROWS;
    if(uho_ready && uh_range(uc,sizeof(*uc)) && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==uho_head)
        uho_mutate_si(sig,si,uc,UHO_ENTRY_INTERIOR,6);
}
static void uho_source(void) {
    struct uh_record *r=&selected_unrolled.current;if(!uho_focal())return;
    uh_need(r->source.ready==1 && r->source.page.object==dependency_count &&
        r->source.backing.stat.st_dev==uho_wire.main_backing.st_dev &&
        r->source.backing.stat.st_ino==uho_wire.main_backing.st_ino &&
        r->source.backing.stat.st_size==uho_wire.main_backing.st_size &&
        equal(r->source.bytes,uho_wire.original_source,39),UH_SOURCE,100);
    uh_need(uho_wire.h[24]<UHO_ROWS,UH_STATE,115);
    uho_current=(unsigned)uho_wire.h[24]++;struct uho_entry *e=&uho_wire.entries[uho_current];
    e->present=1;e->ordinal=uho_current;
    uho_copy(e->source_page,(void *)r->source.page.address,PAGE);e->source_bytes=PAGE;
    int error=li2_lifecycle_unrolled_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],0,
        &e->before_memory);
    uh_need(!error && e->before_memory.complete,UH_STATE,122);
}
static void uho_slot(struct uh_slot *s) {
    if(uho_focal() && uho_start(UHO_SLOT_IDENTITY,5)) {
        uho_wire.control[6]=s->identity;s->identity^=UINT64_C(0x8000000000000000);
        uho_wire.control[7]=s->identity;uho_wire.control[3]=1;
    }
}
static void uho_filter(unsigned kind,uintptr_t entry) {
    /* Fixed exact address, length and protection; existing native seccomp
       already authenticates architecture/private gateway. No fake result. */
    uint32_t prot=kind==UHO_OPEN_ERROR?PROT_READ|PROT_EXEC:PROT_READ;
    struct sock_filter protect[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,13),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)entry,0,11),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,20),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(entry>>32),0,9),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,24),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PAGE,0,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,28),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,32),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,prot,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,36),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|13),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_filter sync[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_membarrier,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,32,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,20),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|13),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog p={.len=(unsigned short)(kind==UHO_SYNC_ERROR?8:16),
        .filter=kind==UHO_SYNC_ERROR?sync:protect};
    uho_wire.control[8]=entry;uho_wire.control[9]=PAGE;uho_wire.control[10]=prot;
    uho_wire.control[11]=kind==UHO_SYNC_ERROR?SYS_membarrier:SYS_mprotect;
    uho_wire.control[12]=1;long result=raw(SYS_prctl,38,1,0,0,0,0);
    uho_wire.control[13]=1;uho_wire.control[14]=(uint64_t)result;uh_need(!result,UH_STATE,116);
    uho_wire.control[15]=1;result=raw(SYS_prctl,22,2,(long)&p,0,0,0);
    uho_wire.control[16]=1;uho_wire.control[17]=(uint64_t)result;uh_need(!result,UH_STATE,117);
    uho_wire.control[3]=1;
}
static void uho_before_open(struct uh_slot *s) {
    unsigned c=(unsigned)uho_wire.control[0];
    if(uho_focal() && c>=UHO_OPEN_ERROR && c<=UHO_SYNC_ERROR && uho_start(c,2))
        uho_filter(c,s->plan.entry);
}
static void uho_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!uho_focal())return;
    uh_need(uho_current<UHO_ROWS,UH_STATE,118);struct uho_entry *e=&uho_wire.entries[uho_current];
    uh_need(!uh_capture(&e->redirected,sig,si,uc),UH_FRAME,101);
    const struct uh_record *r=&selected_unrolled.current;
    uho_owners(&e->redirected_owners,1);
    uho_copy(e->generated_page,(void *)selected_unrolled.slots[r->slot].plan.entry,PAGE);
    e->generated_bytes=PAGE;uho_copy(&e->owner,r,sizeof(*r));
    if(uho_start(UHO_NESTED,1)) {
        /* Actual pre-arm CPUID facts are already protected in wire.hardware.
           CPUID itself is disabled now. Guard XGETBV and then read live handler
           PKRU; neither instruction changes PKRU, FP state or a saved frame. */
        const struct li2_selected_hardware *h=&uho_wire.hardware;
        uh_need(h->abi_version==1 && !h->reserved && h->leaf0[0]>=7 &&
            (h->leaf1[2]&UINT32_C(0x0c000000))==UINT32_C(0x0c000000),UH_STATE,124);
        uint32_t a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
        uint64_t xcr0=(uint64_t)a|((uint64_t)d<<32);
        uho_wire.control[21]=xcr0;uho_wire.control[22]=1;
        if(xcr0&(UINT64_C(1)<<9)) {
            uh_need((h->leaf7[2]&24U)==24U,UH_STATE,125);
            __asm__ volatile("rdpkru":"=a"(a),"=d"(d):"c"(0):"memory");
            uho_wire.control[18]=a;uho_wire.control[19]=d;uho_wire.control[20]=1;
        }
        uho_wire.control[6]=selected_session.pid;uho_wire.control[7]=selected_session.tid;
        uho_wire.control[8]=SIGTRAP;uho_wire.control[12]=1;
        /* Qualification injects a real nested owner event outside a maps RAW
           transaction. Use the same registered kernel gateway directly: this
           pointer-free tgkill changes no mappings. The terminal reader still
           requires the whole nested frame, nonreturn and complete cleanup. */
        long result=li2_raw6(SYS_tgkill,selected_session.pid,selected_session.tid,SIGTRAP,0,0,0);
        uho_wire.control[13]=1;uho_wire.control[14]=(uint64_t)result;
        uh_need(0,UH_STATE,119); /* A real nested terminal event must not return. */
    }
}
static void uho_complete(void) {
    if(!uho_focal())return;
    uh_need(uho_current<UHO_ROWS,UH_STATE,120);struct uho_entry *e=&uho_wire.entries[uho_current];
    uho_owners(&e->completed_owners,0);
    int error=li2_lifecycle_unrolled_observe_memory(
        (uintptr_t)selected_unrolled.current.after.frame.greg[REG_RSP],0,&e->after_memory);
    uh_need(!error && e->after_memory.complete,UH_STATE,123);
    uho_copy(e->terminal_source_page,(void *)selected_unrolled.current.source.page.address,PAGE);
    e->terminal_source_bytes=PAGE;
    uho_copy(&e->owner,&selected_unrolled.current,sizeof e->owner);e->committed=1;
    ++uho_wire.h[25];
}
static void uho_abort_observe(void) {
    if(!uho_ready)return;
    struct uh_record *r=&selected_unrolled.current;struct uh_frame *f=&r->unexpected;
    /* Existing pure unsafe-rseq guard has already returned. These actual
       diagnostic queries follow full unexpected-frame capture and the original
       first-error publication. Any observation error stays diagnostic only. */
    if(f->complete) {
        f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
        f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
        f->tls_complete=!f->fs_result && !f->gs_result;
    }
    if(uho_current<UHO_ROWS && uho_focal() && r->before.complete) {
        struct uho_entry *e=&uho_wire.entries[uho_current];
        if(!e->after_memory.attempted) {
            int error=li2_lifecycle_unrolled_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],1,
                &e->after_memory);
            if(error || !e->after_memory.complete)uho_wire.h[39]=3;
        }
        uho_copy(e->terminal_source_page,(void *)r->source.page.address,PAGE);
        e->terminal_source_bytes=PAGE;
    }
}
static void uho_finish(unsigned status,unsigned code,long detail) {
    if(uho_finished || !uho_wire.h[18])return;
    uho_finished=1;uho_wire.h[26]=1;uho_wire.h[27]=status;uho_wire.h[28]=code;
    uho_wire.h[29]=(uint64_t)detail;uho_wire.h[30]=uho_current;
    uho_wire.h[31]=selected_unrolled_active;uho_wire.h[32]=selected_unrolled_busy;
    uho_wire.h[33]=selected_unrolled_failing;uho_wire.h[34]=handling;
    uho_wire.h[35]=selected_step_pending;uho_wire.h[36]=selected_pending_route;
    uho_wire.h[37]=selected_flags_known;uho_wire.h[38]=selected_logical_flags;
    uho_copy(&uho_wire.owner,&selected_unrolled,sizeof selected_unrolled);
    uho_owners(&uho_wire.terminal_owners,0);
    const struct li2_native_close *global_close=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *native_counts=li2_lifecycle_native_counts();
    if(global_close){uho_copy(&uho_wire.terminal_global_close,global_close,sizeof(*global_close));uho_wire.h[51]=1;}
    if(native_counts){uho_copy(&uho_wire.terminal_native_counts,native_counts,sizeof(*native_counts));uho_wire.h[52]=1;}
    const struct li2_fetch_progress *fetch=li2_lifecycle_fetch_progress();
    if(fetch){uho_copy(&uho_wire.terminal_fetch,fetch,sizeof(*fetch));uho_wire.h[50]=1;}
    if(uho_current<UHO_ROWS && uho_focal()) {
        uho_copy(&uho_wire.entries[uho_current].owner,&selected_unrolled.current,sizeof(struct uh_record));
        uho_wire.entries[uho_current].terminal=1;
    }
    /* Every used page was exclusively allocated and never unmapped. Partial
       publication/open cleanup may leave RW/RX; all are still readable. */
    for(size_t i=0;i<selected_unrolled.used;i++) {
        if(i>=UH_PAGES){uho_wire.h[39]=1;break;}
        uho_copy(uho_wire.generated[i],(void *)selected_unrolled.slots[i].plan.entry,PAGE);
        ++uho_wire.h[40];
    }
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&uho_wire.sink_terminal,0,0,0,0);
    uho_wire.h[41]=(uint64_t)flags;uho_wire.h[42]=(uint64_t)result;
    if(result || flags!=(long)uho_wire.h[16] || !uho_same_sink(&uho_wire.sink_terminal) ||
       uho_wire.sink_terminal.st_size){uho_wire.h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof uho_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&uho_wire+at),sizeof uho_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof uho_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof uho_wire)return;
    const uint64_t footer[]={UHO_FOOTER,1,sizeof uho_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
    /* Exact complete record+footer length is independently required. A short
       write or diagnostic error is never converted into accepted ownership. */
}
