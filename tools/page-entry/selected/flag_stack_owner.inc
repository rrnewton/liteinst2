/* One actual flag-stack instruction, with TF clear and all original code NX.
   A fresh held fetch owns each activation. The sealed copied instruction uses
   the original RSP; a flag-neutral absolute JMP reaches original-next NX.
   The old TF classifier, owner and comparison contracts are untouched. */
#include "flag_stack.h"
#include "flag_stack_storage.h"
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#if LI2_FLAG_STACK != 1 || LI2_RESIDENT_SOURCE_LEASE != 1 || LI2_SCALAR_REGION != 1 || \
    LI2_PERSISTENT_SEALED_GENERATION != 1 || LI2_RSEQ_INACTIVE != 1 || \
    LI2_TF_HANDOFF != 1 || LI2_REGISTER_RUN != 1 || LI2_MAPS_PHASE_REUSE != 1 || \
    defined(LI2_EVENT_PROFILE)
#error "flag stack requires the protected source-lease and full-frame profile"
#endif
#define FS_SLOTS 64U
#define FS_ARENA_BYTES (FS_SLOTS*2U*PAGE)
#define FS_UNSUPPORTED_FLAGS UINT64_C(0x1e7100) /* TF, IOPL, NT, VM, AC, VIF, VIP */
enum fs_error { FS_STATE=5200,FS_FRAME,FS_SOURCE,FS_STORAGE,FS_EVENT,FS_RESULT,FS_GUARD };
struct fs_slot {
    struct li2_fs_descriptor descriptor;
    struct li2_sealed_identity identity;
    unsigned installed;
};
struct fs_owner {
    unsigned initialized,busy,active,used,current,first_error;
    long first_detail;
    uintptr_t arena;
    uint64_t serial,entries,completions,publications,hits,unexpected;
    struct li2_step_session session;
    struct li2_fetch_ref held;
    struct li2_fetch_page source[2];
    size_t source_pages;
    struct fs_slot slots[FS_SLOTS];
    struct sr_frame before,after,unplanned;
    struct li2_fetch_progress released;
    unsigned opened,drained,redirected,completed;
};
static union {
    struct fs_owner owner;
    unsigned char bytes[(sizeof(struct fs_owner)+PAGE-1)&~(PAGE-1)];
} fs_memory __attribute__((aligned(PAGE)));
#define fso fs_memory.owner
static int fs_permission(int prot) {
    return raw(SYS_mprotect,(long)&fs_memory,sizeof fs_memory,prot,0,0,0)?FS_STORAGE:0;
}
static _Noreturn void selected_flag_stack_abort(unsigned code,long detail) {
    if(selected_flag_stack_failing) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    selected_flag_stack_failing=1;
    if(!fs_permission(PROT_READ|PROT_WRITE)) {
        if(!fso.first_error){fso.first_error=code;fso.first_detail=detail;}
        fso.busy=1;
        /* Drain the complete reserved code/proof arena even on a partial
           publication. Failure never releases a successful continuation. */
        if(fso.arena) {
            long closed=raw(SYS_mprotect,fso.arena,FS_ARENA_BYTES,PROT_READ,0,0,0);
            long synced=raw(SYS_membarrier,32,0,0,0,0,0);
            fso.drained=!closed && !synced;
        }
        (void)fs_permission(PROT_READ);
    }
    li2_maps_phase_fail();li2_lifecycle_abort();report(125,code,detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void fs_need(int yes,unsigned code,long detail) {
    if(!yes)selected_flag_stack_abort(code,detail);
}
static void fs_tls(struct sr_frame *frame) {
    frame->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&frame->fs,0,0,0,0);
    frame->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&frame->gs,0,0,0,0);
    fs_need(!frame->fs_result && !frame->gs_result,FS_FRAME,4);
    frame->tls_complete=1;
}
static int fs_identity(void) {
    return fso.initialized && equal(&fso.session,&selected_session,sizeof fso.session) &&
        fso.session.initialized && fso.session.self_test_complete &&
        fso.session.pid>0 && fso.session.pid==fso.session.tid &&
        raw(SYS_getpid,0,0,0,0,0,0)==fso.session.pid &&
        raw(SYS_gettid,0,0,0,0,0,0)==fso.session.tid &&
        selected_run_protect_contains(0,(uintptr_t)&fs_memory,sizeof fs_memory)==1 &&
        selected_run_protect_contains(0,fso.arena,FS_ARENA_BYTES)==1;
}
static int fs_source(void) {
    struct li2_fetch_view view={0};
    if(!fso.held.owner || !fso.held.sequence || fso.source_pages<1 || fso.source_pages>2 ||
       fso.current>=fso.used || fso.used>FS_SLOTS ||
       selected_borrow.owner!=fso.held.owner || selected_borrow.sequence!=fso.held.sequence ||
       li2_lifecycle_run_reuse_quiet(&fso.held) ||
       li2_lifecycle_fetch_view(&fso.held,&view))return FS_SOURCE;
    const struct li2_fs_descriptor *d=&fso.slots[fso.current].descriptor;
    if(view.pc!=d->decoded.pc || view.length!=d->decoded.available || view.length<2 ||
       view.page_count!=fso.source_pages || !view.identity_observed ||
       view.pid!=fso.session.pid || view.tid!=fso.session.tid ||
       !equal(view.bytes,d->decoded.bytes,view.length) ||
       !equal(view.pages,fso.source,view.page_count*sizeof fso.source[0]))return FS_SOURCE;
    for(size_t i=0;i<view.page_count;i++)
        if(li2_lifecycle_fetch_validate(&fso.held,i,PROT_READ))return FS_SOURCE;
    return 0;
}
static int fs_bytes(const struct fs_slot *s) {
    unsigned char image[LI2_FS_IMAGE_BYTES];
    if(li2_fs_emit(&s->descriptor,image))return FS_STORAGE;
    const volatile unsigned char *code=(const void *)s->identity.code;
    const volatile unsigned char *proof=(const void *)s->identity.proof;
    const unsigned char *expected=(const void *)&s->descriptor;
    for(size_t i=0;i<PAGE;i++)
        if(code[i]!=(i<sizeof image?image[i]:0xcc) ||
           proof[i]!=(i<sizeof s->descriptor?expected[i]:0))return FS_STORAGE;
    return 0;
}
static int fs_query(const struct fs_slot *s,int prot) {
    const struct li2_sealed_identity *id=&s->identity;
    if(!s->installed || id->fd<0 || id->fd>INT32_MAX || !id->generation ||
       id->code_bytes!=PAGE || id->proof_bytes!=PAGE || id->bytes!=2U*PAGE ||
       id->code_live!=1 || id->proof_live!=1 || id->proof!=id->code+PAGE)return FS_STORAGE;
    for(unsigned i=0;i<2;i++) {
        struct li2_sealed_code_query q={0};int want=i?PROT_READ:prot;
        if(li2_lifecycle_flag_stack_query(id,id->code+i*PAGE,PAGE,want,&q) ||
           q.complete!=1 || q.pages_checked!=1 || q.actual_prot!=want ||
           q.sealed.kind!=LI2_SEALED_QUERY_KIND || q.sealed.version!=LI2_SEALED_QUERY_VERSION ||
           !equal(&q.sealed.identity,id,sizeof *id) ||
           q.sealed.alias_complete!=1 || q.sealed.alias_pages!=2 ||
           q.sealed.seals_result!=LI2_SEALED_REQUIRED_SEALS || q.sealed.stat_result)
            return FS_STORAGE;
    }
    return fs_bytes(s);
}
static int fs_code_permission(const struct fs_slot *s,int prot) {
    if(raw(SYS_mprotect,s->identity.code,PAGE,prot,0,0,0) ||
       raw(SYS_membarrier,32,0,0,0,0,0))return FS_STORAGE;
    return fs_query(s,prot);
}
static int fs_publish(struct fs_slot *s,unsigned index) {
    if(index>=FS_SLOTS || s!=&fso.slots[index] || s->installed || s->identity.fd!=-1)
        return FS_STORAGE;
    unsigned char image[2U*PAGE];
    for(size_t i=0;i<sizeof image;i++)image[i]=i<PAGE?0xcc:0;
    if(li2_fs_emit(&s->descriptor,image))return FS_STORAGE;
    copy(image+PAGE,&s->descriptor,sizeof s->descriptor);
    long fd=raw(SYS_memfd_create,(long)"li2-flag-stack",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    if(fd<0 || fd>INT32_MAX)return FS_STORAGE;
    s->identity.fd=fd;
    if(raw(SYS_ftruncate,fd,sizeof image,0,0,0,0))return FS_STORAGE;
    size_t offset=0;
    while(offset<sizeof image) {
        long n=raw(SYS_pwrite64,fd,(long)(image+offset),sizeof image-offset,offset,0,0);
        if(n<=0 || (unsigned long)n>sizeof image-offset)return FS_STORAGE;
        offset+=(size_t)n;
    }
    struct stat st={0};
    if(raw(SYS_fcntl,fd,F_ADD_SEALS,LI2_SEALED_REQUIRED_SEALS,0,0,0) ||
       raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)!=LI2_SEALED_REQUIRED_SEALS ||
       raw(SYS_fstat,fd,(long)&st,0,0,0,0) || st.st_size!=2U*PAGE ||
       (st.st_mode&S_IFMT)!=S_IFREG || !st.st_ino)return FS_STORAGE;
    uintptr_t code=fso.arena+index*2U*PAGE;
    s->identity=(struct li2_sealed_identity){.fd=fd,.device=st.st_dev,.inode=st.st_ino,
        .bytes=2U*PAGE,.generation=index+1,.code=code,.proof=code+PAGE,
        .code_bytes=PAGE,.proof_bytes=PAGE};
    long mapped=raw(SYS_mmap,code,2U*PAGE,PROT_READ,MAP_SHARED|MAP_FIXED,fd,0);
    if((uintptr_t)mapped!=code)return FS_STORAGE;
    s->identity.code_live=1;s->identity.proof_live=1;s->installed=1;
    return fs_query(s,PROT_READ);
}
static void selected_flag_stack_initialize(void) {
    fs_need(!fso.initialized && !fso.busy && !fso.active && !selected_flag_stack_failing &&
        !li2_lifecycle_fetch_interlock() && protected_count<=RANGES-3,FS_STATE,1);
    fso.session=selected_session;
    fs_need(!selected_run_protect_add(0,(uintptr_t)&fs_memory,sizeof fs_memory) &&
        !selected_run_protect_add(0,(uintptr_t)&selected_flag_stack_failing,sizeof selected_flag_stack_failing),FS_STATE,2);
    long at=raw(SYS_mmap,0,FS_ARENA_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    fs_need(at>0 && !((uintptr_t)at&(PAGE-1)) &&
        (uintptr_t)at<(UINT64_C(1)<<47)-FS_ARENA_BYTES,FS_STORAGE,at);
    fso.arena=(uintptr_t)at;
    fs_need(!selected_run_protect_add(0,fso.arena,FS_ARENA_BYTES) &&
        !raw(SYS_prctl,PR_SET_DUMPABLE,0,0,0,0,0) &&
        !raw(SYS_prctl,PR_GET_DUMPABLE,0,0,0,0,0),FS_STORAGE,1);
    for(unsigned i=0;i<FS_SLOTS;i++)fso.slots[i].identity.fd=-1;
    fso.initialized=1;fs_need(fs_identity(),FS_STATE,3);
    fs_need(!fs_permission(PROT_READ),FS_STORAGE,2);
}
static int selected_flag_stack_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    if(selected_decoded.length!=1 ||
       (selected_decoded.bytes[0]!=0x9c && selected_decoded.bytes[0]!=0x9d))return 0;
    fs_need(fso.initialized && !fso.active && !fso.busy && !fso.first_error &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP && fs_identity(),FS_STATE,4);
    fs_need(!fs_permission(PROT_READ|PROT_WRITE),FS_STORAGE,3);fso.busy=1;
    fs_need(fso.serial<UINT64_MAX,FS_STATE,5);++fso.serial;
    sr_zero(&fso.before,sizeof fso.before);sr_zero(&fso.after,sizeof fso.after);
    sr_zero(&fso.unplanned,sizeof fso.unplanned);fso.released=(struct li2_fetch_progress){0};
    fso.opened=fso.drained=fso.redirected=fso.completed=0;
    fs_need(!sr_capture(&fso.before,sig,si,uc),FS_FRAME,1);fs_tls(&fso.before);
    const greg_t *g=fso.before.frame.greg;
    fs_need(sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
        g[REG_TRAPNO]==14 && g[REG_ERR]==21 && (uintptr_t)si->si_addr==selected_decoded.pc &&
        (uintptr_t)g[REG_CR2]==selected_decoded.pc && (uintptr_t)g[REG_RIP]==selected_decoded.pc &&
        fso.before.frame.mask==SELECTED_MASK && !(flags&(FS_UNSUPPORTED_FLAGS|SELECTED_RF)) &&
        (uint64_t)g[REG_EFL]==(flags|SELECTED_RF),FS_FRAME,2);
    /* This owner keeps the existing signal mask. Refuse an operand/result
       stack pointer outside its low-canonical domain before opening code;
       a #SS/SIGBUS is not a captured successful continuation here. */
    fs_need((uint64_t)g[REG_RSP]>=8 &&
        (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47)-8,FS_FRAME,5);
    /* A one-byte instruction at the end of a page needs a new two-byte fetch
       covering the actual original-next page as well. This retains the genuine
       saved NX frame and obtains fresh source authority after releasing the old
       borrow; no synthetic admission or guessed successor permission is used. */
    if(selected_view.length==1) {
        uintptr_t pc=selected_decoded.pc;
        fs_need(!li2_lifecycle_fetch_release(&selected_borrow) &&
            !li2_lifecycle_fetch_prepare(pc,2,&selected_borrow) &&
            !li2_lifecycle_fetch_view(&selected_borrow,&selected_view) &&
            !li2_decoder_decode(pc,selected_view.bytes,selected_view.length,&selected_decoded),FS_SOURCE,1);
    }
    struct li2_fs_descriptor descriptor={0};
    fs_need(!li2_fs_describe(selected_view.pc,selected_view.bytes,selected_view.length,&descriptor) &&
        equal(&descriptor.decoded,&selected_decoded,sizeof selected_decoded) &&
        selected_view.length>=2 && selected_view.page_count>=1 && selected_view.page_count<=2,
        FS_SOURCE,2);
    unsigned index=0;
    while(index<fso.used && !equal(&fso.slots[index].descriptor,&descriptor,sizeof descriptor))++index;
    fs_need(index<FS_SLOTS && fso.used<=FS_SLOTS,FS_STORAGE,4);
    if(index==fso.used) {fso.slots[index].descriptor=descriptor;++fso.used;}
    fso.current=index;fso.held=selected_borrow;fso.source_pages=selected_view.page_count;
    copy(fso.source,selected_view.pages,fso.source_pages*sizeof fso.source[0]);
    fs_need(!fs_source() && !li2_rseq_check_flag_stack(&descriptor,uc),FS_GUARD,1);
    struct fs_slot *s=&fso.slots[index];
    if(!s->installed) {fs_need(!fs_publish(s,index),FS_STORAGE,5);++fso.publications;}
    else {fs_need(fso.hits<UINT64_MAX,FS_STATE,6);++fso.hits;}
    fs_need(!fs_query(s,PROT_READ) && !fs_source() &&
        !li2_rseq_check_flag_stack(&descriptor,uc),FS_GUARD,2);
    selected_pending_route=SELECTED_FLAG_STACK;selected_step_pending=1;
    fs_need(!fs_code_permission(s,PROT_READ|PROT_EXEC),FS_STORAGE,6);fso.opened=1;
    fs_need(!fs_source() && !li2_rseq_check_flag_stack(&descriptor,uc) &&
        sr_unchanged(&fso.before,si,uc) && fso.entries<UINT64_MAX,FS_GUARD,3);
    ++fso.entries;fso.active=1;fso.redirected=1;fso.busy=0;
    fs_need(!fs_permission(PROT_READ),FS_STORAGE,7);
    /* Hardware PUSHFQ/POPFQ uses the untouched original RSP and flags. */
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)s->identity.code;
    return 1;
}
static _Noreturn void fs_unexpected(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!fs_permission(PROT_READ|PROT_WRITE)) {
        if(!fso.unplanned.started)(void)sr_capture(&fso.unplanned,sig,si,uc);
        if(fso.unexpected<UINT64_MAX)++fso.unexpected;
    }
    selected_flag_stack_abort(FS_EVENT,sig);
}
static void selected_flag_stack_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    int routed=selected_pending_route==SELECTED_FLAG_STACK;
    if(!fso.active && !fso.busy && !routed)return;
    if(fso.busy || !fso.active || !routed || handling || !selected_step_pending ||
       fso.first_error || fso.current>=fso.used || fso.used>FS_SLOTS ||
       !sr_range(si,sizeof *si) || !sr_range(uc,sizeof *uc))fs_unexpected(sig,si,uc);
    const struct fs_slot *s=&fso.slots[fso.current];const greg_t *g=uc->uc_mcontext.gregs;
    uintptr_t next=s->descriptor.decoded.next_pc;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,8);
    if(!fso.opened || !fso.redirected || fso.completed || sig!=SIGSEGV ||
       si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 || (uintptr_t)g[REG_RIP]!=next ||
       (uintptr_t)si->si_addr!=next || (uintptr_t)g[REG_CR2]!=next ||
       ((uint64_t)g[REG_EFL]&(FS_UNSUPPORTED_FLAGS|SELECTED_RF))!=SELECTED_RF ||
       mask!=SELECTED_MASK)fs_unexpected(sig,si,uc);
}
static void selected_flag_stack_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    fs_need(!fs_permission(PROT_READ|PROT_WRITE),FS_STORAGE,8);
    fs_need(fso.active && !fso.busy && fso.current<fso.used && selected_step_pending &&
        selected_pending_route==SELECTED_FLAG_STACK && fs_identity(),FS_STATE,7);fso.busy=1;
    struct fs_slot *s=&fso.slots[fso.current];
    fs_need(!sr_capture(&fso.after,sig,si,uc),FS_FRAME,3);fs_tls(&fso.after);
    /* Close generated execution before semantic validation or any release. */
    fs_need(!fs_code_permission(s,PROT_READ),FS_STORAGE,9);fso.drained=1;
    fs_need(!fs_source(),FS_SOURCE,3);
    const greg_t *a=fso.before.frame.greg,*b=fso.after.frame.greg;
    uint64_t rsp=(uint64_t)a[REG_RSP];
    fs_need(s->descriptor.operation==LI2_FS_PUSHFQ?rsp>=8:rsp<=UINT64_MAX-8,FS_RESULT,1);
    uint64_t expected_rsp=s->descriptor.operation==LI2_FS_PUSHFQ?rsp-8:rsp+8;
    fs_need((uint64_t)b[REG_RSP]==expected_rsp &&
        ((uint64_t)b[REG_EFL]&2)==2 &&
        ((uint64_t)b[REG_EFL]&(FS_UNSUPPORTED_FLAGS|SELECTED_RF))==SELECTED_RF,FS_RESULT,2);
    for(unsigned i=0;i<NGREG;i++)
        if(i!=REG_RSP && i!=REG_RIP && i!=REG_EFL && i!=REG_CR2)
            fs_need(a[i]==b[i],FS_RESULT,i+10);
    if(s->descriptor.operation==LI2_FS_PUSHFQ)fs_need(a[REG_EFL]==b[REG_EFL],FS_RESULT,3);
    fs_need(fso.before.frame.mask==fso.after.frame.mask &&
        equal(&fso.before.uc.uc_stack,&fso.after.uc.uc_stack,sizeof uc->uc_stack) &&
        fso.before.uc.uc_flags==fso.after.uc.uc_flags && fso.before.uc.uc_link==fso.after.uc.uc_link &&
        fso.before.fs==fso.after.fs && fso.before.gs==fso.after.gs &&
        fso.before.frame.fp_bytes==fso.after.frame.fp_bytes &&
        equal(fso.before.frame.fp,fso.after.frame.fp,LI2_STEP_FP_BYTES) &&
        sr_unchanged(&fso.after,si,uc),FS_RESULT,4);
    fs_need(!li2_rseq_check_flag_stack(&s->descriptor,&fso.before.uc) && !fs_source(),FS_GUARD,4);
    fs_need(!li2_lifecycle_fetch_release(&fso.held),FS_SOURCE,4);
    fso.released=*li2_lifecycle_fetch_progress();
    fs_need(fso.released.complete && !fso.released.held && !fso.released.first_error &&
        fso.released.sequence==fso.held.sequence && !li2_lifecycle_fetch_interlock() &&
        fso.completions<UINT64_MAX && sr_unchanged(&fso.after,si,uc),FS_SOURCE,5);
    ++fso.completions;fso.completed=1;fso.active=0;fso.busy=0;
    selected_logical_flags=(uint64_t)b[REG_EFL]&~SELECTED_RF;selected_flags_known=1;
    selected_pending_route=SELECTED_NO_STEP;selected_step_pending=0;
    fs_need(!fs_permission(PROT_READ),FS_STORAGE,10);
    selected_fetch(sig,si,uc);
}
static void fs_fd_guard(long number,const long args[6]) {
    if(!fso.initialized)return;
    fs_need(!fso.busy && !fso.active && fso.used<=FS_SLOTS,FS_STATE,8);
    for(unsigned i=0;i<fso.used;i++) {
        int64_t fd=fso.slots[i].identity.fd;if(fd<0)continue;
        if(((number==SYS_close || number==SYS_write || number==SYS_writev || number==SYS_fcntl) &&
            (unsigned)args[0]==(unsigned)fd) ||
           (number==SYS_mmap && !(args[3]&MAP_ANONYMOUS) && (unsigned)args[4]==(unsigned)fd))
            selected_flag_stack_abort(FS_GUARD,number);
    }
}
static void selected_flag_stack_report(void) {
    struct writer w={.used=0};text(&w,"LI2_FLAG_STACK {\"version\":1");
    field(&w,",\"entries\":",fso.entries);field(&w,",\"completed\":",fso.completions);
    field(&w,",\"publications\":",fso.publications);field(&w,",\"hits\":",fso.hits);
    field(&w,",\"unexpected\":",fso.unexpected);field(&w,",\"failure_code\":",fso.first_error);
    field(&w,",\"before_pc\":",(uint64_t)fso.before.frame.greg[REG_RIP]);
    field(&w,",\"after_pc\":",(uint64_t)fso.after.frame.greg[REG_RIP]);
    field(&w,",\"unplanned_pc\":",(uint64_t)fso.unplanned.frame.greg[REG_RIP]);
    text(&w,"}\n");raw(SYS_write,2,(long)w.bytes,w.used,0,0,0);
}

#undef fso
