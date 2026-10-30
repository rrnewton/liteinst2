/* Distinct maintained-view experiment; the original maps-phase profile stays
   unchanged. Only an actual successful gateway mprotect updates permissions.
   Other mapping changes invalidate BEFORE execution, including partial errors.
   All source/byte/seal/alias/owner predicates still run against this projection.
   Bootstrap keeps raw VMA boundaries for exact projection/auxv checks. */
#include "maps_view.h"
#include <asm/prctl.h>
#include <linux/prctl.h>
#include <sys/personality.h>
_Static_assert(__atomic_always_lock_free(4,0),"signal-safe maps flags");
_Static_assert(__atomic_always_lock_free(8,0),"signal-safe maps counters");
#define MV_LOAD(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define MV_STORE(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
static struct li2_maps_stats maps_stats;
static struct li2_maps_view_stats mv;
static struct li2_fetch_map_progress mv_receipt;
static struct map_row mv_scratch[MAP_ROWS];
static uintptr_t mv_stack_anchor,mv_stack_first,mv_stack_end;
static unsigned mv_stack_pending,mv_stack_retired,mv_depth,mv_saved;
static long mv_call[7];
static unsigned char mv_residency;
#ifdef LI2_MAPS_CURRENT_TF
#include "maps_current_ticket.h"
static struct li2_fetch_map_progress mct_physical_receipt;
static uint64_t mct_physical_id;
static void mct_raw_boundary(void);
#endif
#ifdef LI2_RUN_TIMING
static uintptr_t maps_clock_observer;
#endif
static void mv_poison(void) {
    MV_STORE(&mv.poisoned,1);MV_STORE(&maps_stats.poisoned,1);MV_STORE(&maps_stats.valid,0);
}
static int mv_inc(uint64_t *p) {
    uint64_t old=MV_LOAD(p);
    do {
        if(old==UINT64_MAX){mv_poison();return 0;}
    } while(!__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    return 1;
}
static void mv_invalidate(void) {
    MV_STORE(&maps_stats.valid,0);__atomic_thread_fence(__ATOMIC_SEQ_CST);
    (void)mv_inc(&maps_stats.invalidations);
    (void)mv_inc(&maps_stats.mutation_epoch);
    (void)mv_inc(&mv.invalidations);
}
#if defined(LI2_MAPS_DIFFERENTIAL) || defined(LI2_MAPS_CURRENT_TF)
/* A differential hit observes private maps scratch only. Authenticate the
   complete open/read/close transaction so the extra observer does not discard
   a retained source-custody proof. Ordinary fresh acquisitions still use their
   old gateway effects, as do all unrelated RAW calls. */
static unsigned mv_compare_io,mv_observer_active,mv_observer_phase;
#ifdef LI2_MAPS_CURRENT_TF
/* The only additional observer scope is the old physical cold commit while
   the maintained stack view is retired. The predicate is defined after the
   unchanged physical custody implementation and performs no RAW or mutation. */
static unsigned mv_custody_io;
static int cc_physical_refresh(void);
#endif
static long mv_observer_fd,mv_observer_call[7];
static size_t mv_observer_offset;
static int mv_observer_matches(long n,long a,long b,long c,long d,long e,long f) {
    if(!MV_LOAD(&mv_observer_active))return 0;
    const long call[7]={n,a,b,c,d,e,f};
    for(unsigned i=0;i<7;i++)if(call[i]!=mv_observer_call[i])return 0;
    return 1;
}
static long mv_observer_raw(long n,long a,long b,long c,long d,long e,long f) {
#ifdef LI2_MAPS_CURRENT_TF
    if(!MV_LOAD(&mv_compare_io) && !MV_LOAD(&mv_custody_io))return RAW(n,a,b,c,d,e,f);
#else
    if(!MV_LOAD(&mv_compare_io))return RAW(n,a,b,c,d,e,f);
#endif
    unsigned phase=MV_LOAD(&mv_observer_phase);int allowed=0;
    if(n==SYS_openat)allowed=!phase && a==AT_FDCWD && (uintptr_t)b==(uintptr_t)mv_maps_path &&
        c==(O_RDONLY|O_CLOEXEC) && !d && !e && !f;
    else if(n==SYS_read)allowed=phase==1 && a==mv_observer_fd && mv_observer_offset<MAP_BYTES &&
        (uintptr_t)b==(uintptr_t)maps_bytes+mv_observer_offset &&
        c==(long)(MAP_BYTES-mv_observer_offset) && !d && !e && !f;
    else if(n==SYS_close)allowed=(phase==1 || phase==2) && a==mv_observer_fd &&
        !b && !c && !d && !e && !f;
    if(!allowed || MV_LOAD(&mv_observer_active) || MV_LOAD(&mv_depth)) {
        mv_poison();return -EINVAL;
    }
    const long call[7]={n,a,b,c,d,e,f};
    for(unsigned i=0;i<7;i++)mv_observer_call[i]=call[i];
#ifdef LI2_MAPS_CURRENT_TF
    /* Failed reads can revoke the owner before the reader closes its actual
       observed descriptor. Permit only that exact cleanup close without an
       exemption; every other stale call refuses, and no authority is restored. */
    unsigned preserve=!MV_LOAD(&mv_custody_io) || cc_physical_refresh();
    if(!preserve && n!=SYS_close){mv_poison();return -EINVAL;}
    MV_STORE(&mv_observer_active,preserve);
#else
    MV_STORE(&mv_observer_active,1);
#endif
    long result=RAW(n,a,b,c,d,e,f);
    MV_STORE(&mv_observer_active,0);
    if(n==SYS_openat && result>=0) {
        mv_observer_fd=result;mv_observer_offset=0;MV_STORE(&mv_observer_phase,1);
    } else if(n==SYS_read && result>=0) {
        if((unsigned long)result>MAP_BYTES-mv_observer_offset)mv_poison();
        else {mv_observer_offset+=(size_t)result;if(!result)MV_STORE(&mv_observer_phase,2);}
    } else if(n==SYS_close && !result)MV_STORE(&mv_observer_phase,phase==2?3:4);
    return result;
}
#endif
void li2_maps_view_stack(uintptr_t anchor) {
    if(!anchor || mv_stack_anchor || MV_LOAD(&mv.enabled)){mv_poison();return;}
    mv_stack_anchor=anchor;
}
int li2_maps_view_enable(void) {
    if(!active || !hooks.raw || MV_LOAD(&mv.enabled) || MV_LOAD(&mv.poisoned) || !mv_stack_anchor ||
       tx.guard || MV_LOAD(&mv_depth))return LI2_FETCH_STATE;
    /* Linux may add EXEC to a READ request with this personality bit. Never
       infer the effective protection from requested bits in that case. */
    long persona=RAW(SYS_personality,0xffffffffUL,0,0,0,0,0);
    if(persona<0 || (persona&READ_IMPLIES_EXEC))return LI2_FETCH_STATE;
    MV_STORE(&mv.enabled,1);
#ifdef LI2_MAPS_DIFFERENTIAL
    MV_STORE(&mv.differential,1);
#endif
    MV_STORE(&mv_stack_pending,1);mv_invalidate();return 0;
}
void li2_maps_view_unexplained(void) {
    (void)mv_inc(&mv.unexplained);mv_invalidate();
}
void li2_maps_view_require_fresh(void) { mv_invalidate(); }
void li2_maps_view_snapshot(struct li2_maps_view_stats *out) {
    if(!out)return;
#define MV_COPY(f) out->f=MV_LOAD(&mv.f)
    MV_COPY(queries);MV_COPY(hits);MV_COPY(refreshes);MV_COPY(updates);
    MV_COPY(invalidations);MV_COPY(comparisons);MV_COPY(mismatches);
    MV_COPY(unexplained);MV_COPY(stack_probes);MV_COPY(enabled);
    MV_COPY(differential);MV_COPY(poisoned);MV_COPY(reserved);
#undef MV_COPY
}
void li2_maps_stats_read(struct li2_maps_stats *out) {
    if(!out)return;
#define MV_COPY(f) out->f=MV_LOAD(&maps_stats.f)
    MV_COPY(fresh_calls);MV_COPY(acquisitions);MV_COPY(reuses);MV_COPY(invalidations);
    MV_COPY(handler_id);MV_COPY(mutation_epoch);MV_COPY(active);MV_COPY(valid);
    MV_COPY(poisoned);MV_COPY(reserved);
#undef MV_COPY
}
void li2_maps_phase_end(void) { MV_STORE(&maps_stats.active,0); }
void li2_maps_phase_fail(void) {
#ifdef LI2_REPEAT_RX_LEASE
    li2_repeat_custody_invalidate(LI2_REP_CUSTODY_ERROR);
#endif
#ifdef LI2_TF_SEALED_CUSTODY
    li2_page_custody_discard(LI2_CUSTODY_ERROR);
#endif
    MV_STORE(&maps_stats.active,0);mv_invalidate();
}
void li2_maps_event_boundary(void) {
#ifdef LI2_TF_SEALED_CUSTODY
    li2_page_custody_boundary();
#endif
    MV_STORE(&maps_stats.active,0);MV_STORE(&mv_stack_pending,1);
}
int li2_maps_phase_begin(void) {
    if(MV_LOAD(&maps_stats.active) || MV_LOAD(&mv.poisoned) || !active || tx.guard || !hooks.raw)
        return LI2_FETCH_STATE;
    long pid=RAW(SYS_getpid,0,0,0,0,0,0),tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(pid<=0 || pid!=tid)return LI2_FETCH_IDENTITY;
    if(!mv_inc(&maps_stats.handler_id))return LI2_FETCH_STATE;
    MV_STORE(&maps_stats.active,1);return 0;
}
#ifdef LI2_RUN_TIMING
int li2_maps_clock_observer_register(const void *buffer,size_t bytes) {
    uintptr_t p=(uintptr_t)buffer;
    if(!active || tx.guard || MV_LOAD(&maps_stats.active) || MV_LOAD(&mv.poisoned) ||
       maps_clock_observer || !p || (p&7) || bytes!=16 || p>UINTPTR_MAX-bytes)
        return LI2_FETCH_ARGUMENT;
    maps_clock_observer=p;return 0;
}
#endif
/* Preserve every old source-custody branch and add only the exact private
   stack observer below. Other nonmapping syscalls can still write
   application/source/custody bytes. */
static __attribute__((unused)) int maps_nonmutating(long n,long a,long b,long c,long d,long e,long f) {
#if defined(LI2_MAPS_DIFFERENTIAL) || defined(LI2_MAPS_CURRENT_TF)
    if(mv_observer_matches(n,a,b,c,d,e,f))return 1;
#endif
    /* Exact private write destination and current stack-boundary query. This
       observer neither accesses application bytes nor changes the mapping. */
    if(n==SYS_mincore && mv_stack_first>=PAGE && (uintptr_t)a==mv_stack_first-PAGE &&
       b==PAGE && (uintptr_t)c==(uintptr_t)&mv_residency && !d && !e && !f)return 1;
#ifdef LI2_RUN_TIMING
    if(n==SYS_clock_gettime && a==4 && maps_clock_observer &&
       (uintptr_t)b==maps_clock_observer && !c && !d && !e && !f)return 1;
#endif
    if(n==SYS_getpid || n==SYS_gettid || n==SYS_fstat)return 1;
    if(n==SYS_fcntl && b==F_GET_SEALS && !c && !d && !e && !f)return 1;
    if(n==SYS_membarrier && a==MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE &&
       !b && !c && !d && !e && !f)return 1;
    if(n==SYS_arch_prctl && a==ARCH_SET_CPUID && (b==0 || b==1) &&
       !c && !d && !e && !f)return 1;
    if(n==SYS_prctl && a==PR_SET_TSC && (b==PR_TSC_ENABLE || b==PR_TSC_SIGSEGV) &&
       !c && !d && !e && !f)return 1;
    return 0;
}
/* Ordinary runtime dispatch already rejects shared-mm threads, exec, remap,
   pkeys, foreign mapping writers and MAP_GROWSDOWN. Unknown raw operations
   also invalidate here: the cache never expands that syscall allowlist. */
static int mv_stable_call(long n) {
    switch(n) {
    case SYS_read:case SYS_write:case SYS_readv:case SYS_writev:
    case SYS_openat:case SYS_close:case SYS_fstat:case SYS_newfstatat:
    case SYS_statx:case SYS_statfs:case SYS_fstatfs:case SYS_lseek:case SYS_pread64:
    case SYS_pwrite64:case SYS_getdents64:case SYS_access:case SYS_faccessat:
    case SYS_faccessat2:case SYS_readlink:case SYS_readlinkat:case SYS_getcwd:
    case SYS_getuid:case SYS_geteuid:case SYS_getgid:case SYS_getegid:
    case SYS_getpid:case SYS_gettid:case SYS_uname:case SYS_sysinfo:
    case SYS_getrandom:case SYS_clock_gettime:case SYS_gettimeofday:
    case SYS_getxattr:case SYS_lgetxattr:case SYS_fgetxattr:case SYS_listxattr:
    case SYS_llistxattr:case SYS_flistxattr:case SYS_futex:case SYS_fcntl:
    case SYS_prlimit64:case SYS_set_tid_address:case SYS_set_robust_list:
    case SYS_rseq:case SYS_rt_sigaction:case SYS_rt_sigprocmask:
    case SYS_sigaltstack:case SYS_arch_prctl:case SYS_prctl:case SYS_ioctl:
    case SYS_membarrier:case SYS_memfd_create:case SYS_ftruncate:
    case SYS_mincore:case SYS_personality:return 1;
    default:return 0;
    }
}
#ifdef LI2_MAPS_DIFFERENTIAL
static int mv_same(const struct map_row *a,const struct map_row *b) {
    return a->first==b->first && a->end==b->end && a->offset==b->offset &&
        a->major==b->major && a->minor==b->minor && a->inode==b->inode &&
        a->prot==b->prot && a->private==b->private;
}
#endif
static int mv_join(const struct map_row *a,const struct map_row *b) {
    if(a->end!=b->first || a->prot!=b->prot || a->private!=b->private ||
       a->major!=b->major || a->minor!=b->minor || a->inode!=b->inode)return 0;
    if(!a->inode && !a->major && !a->minor)return !a->offset && !b->offset;
    return a->offset<=UINT64_MAX-(a->end-a->first) &&
        a->offset+a->end-a->first==b->offset;
}
static size_t mv_normalize(struct map_row *v,size_t n) {
    size_t out=0;
    for(size_t i=0;i<n;i++) {
        if(out && mv_join(&v[out-1],&v[i]))v[out-1].end=v[i].end;
        else v[out++]=v[i];
    }
    return out;
}
static int mv_emit(size_t *n,const struct map_row *r,uintptr_t first,uintptr_t end,unsigned prot) {
    if(first==end)return 1;
    if(*n==MAP_ROWS || first<r->first || end>r->end)return 0;
    struct map_row out=*r;out.first=first;out.end=end;out.prot=prot;
    if(r->inode || r->major || r->minor) {
        if(out.offset>UINT64_MAX-(first-r->first))return 0;
        out.offset+=first-r->first;
    } else if(out.offset)return 0;
    mv_scratch[(*n)++]=out;return 1;
}
static int mv_protect(uintptr_t first,size_t bytes,unsigned prot) {
    if(!bytes || (first&(PAGE-1)) || bytes>SIZE_MAX-(PAGE-1) ||
       (prot&~(PROT_READ|PROT_WRITE|PROT_EXEC)))return 0;
    size_t extent=(bytes+PAGE-1)&~(PAGE-1);
    if(first>UINTPTR_MAX-extent)return 0;
    uintptr_t end=first+extent,covered=first;size_t n=0;
    for(size_t i=0;i<row_count;i++) {
        const struct map_row *r=&rows[i];
        if(!overlaps(first,end,r->first,r->end)) {
            if(!mv_emit(&n,r,r->first,r->end,r->prot))return 0;
        } else {
            uintptr_t lo=first>r->first?first:r->first,hi=end<r->end?end:r->end;
            if(lo!=covered || !mv_emit(&n,r,r->first,lo,r->prot) ||
               !mv_emit(&n,r,lo,hi,prot) || !mv_emit(&n,r,hi,r->end,r->prot))return 0;
            covered=hi;
        }
    }
    if(covered!=end)return 0;
    row_count=mv_normalize(mv_scratch,n);
    for(size_t i=0;i<row_count;i++)rows[i]=mv_scratch[i];
    mv_receipt.rows=row_count;mv_receipt.observation.mutation_epoch=MV_LOAD(&maps_stats.mutation_epoch);
    return mv_inc(&mv.updates);
}
void li2_maps_before_raw(long n,long a,long b,long c,long d,long e,long f) {
#ifdef LI2_MAPS_CURRENT_TF
    mct_raw_boundary();
#endif
#ifdef LI2_REPEAT_RX_LEASE
    if(!maps_nonmutating(n,a,b,c,d,e,f))li2_repeat_custody_invalidate(LI2_REP_CUSTODY_RAW);
#endif
#ifdef LI2_TF_SEALED_CUSTODY
    if(!maps_nonmutating(n,a,b,c,d,e,f))li2_page_custody_discard(LI2_CUSTODY_EFFECT);
#endif
    const long call[7]={n,a,b,c,d,e,f};
    unsigned depth=MV_LOAD(&mv_depth);
    if(depth) {
        for(unsigned i=0;i<7;i++)if(call[i]!=mv_call[i])mv_poison();
        if(depth==8){mv_poison();return;}
        (void)__atomic_add_fetch(&mv_depth,1,__ATOMIC_ACQ_REL);return;
    }
    if(MV_LOAD(&mv.enabled) && !mv_stack_retired && !mv_stable_call(n)) {
        /* Observe before a mapping operation can split an as-yet-unobserved
           grown stack into fragments. Such growth retires reuse conservatively;
           a later fresh anchor row must not forget another grow-down fragment.
           The nested private probe completes before we record this RAW call. */
        if(!mv_stack_first)mv_stack_retired=1;
        else if(MV_LOAD(&mv_stack_pending)) {
            MV_STORE(&mv_stack_pending,0);
            if(!mv_inc(&mv.stack_probes))mv_poison();
            long probe=RAW(SYS_mincore,mv_stack_first-PAGE,PAGE,&mv_residency,0,0,0);
            if(!probe){mv_stack_retired=1;li2_maps_view_unexplained();}
            else if(probe!=-ENOMEM)mv_poison();
        }
    }
    for(unsigned i=0;i<7;i++)mv_call[i]=call[i];
    mv_saved=MV_LOAD(&maps_stats.valid);
    /* Publish the complete call tuple last. A nested terminal event before
       publication never resumes this outer writer. */
    MV_STORE(&mv_depth,1);
    if(!mv_stable_call(n)) {
        if(MV_LOAD(&mv.enabled) && mv_stack_first &&
           (n==SYS_mprotect || n==SYS_munmap || n==SYS_mmap || n==SYS_madvise)) {
            uintptr_t first=(uintptr_t)a;size_t bytes=(size_t)b;
            if(bytes>UINTPTR_MAX-first ||
               (bytes && overlaps(first,first+bytes,mv_stack_first,mv_stack_end)))
                mv_stack_retired=1;
        }
        if(n==SYS_mremap || n==SYS_execve || n==SYS_execveat)mv_stack_retired=1;
        mv_invalidate();
    }
}
void li2_maps_after_raw(long n,long a,long b,long c,long d,long e,long f,long result) {
    const long call[7]={n,a,b,c,d,e,f};
    if(!MV_LOAD(&mv_depth)){mv_poison();return;}
    for(unsigned i=0;i<7;i++)if(call[i]!=mv_call[i])mv_poison();
    if(__atomic_sub_fetch(&mv_depth,1,__ATOMIC_ACQ_REL))return;
    if(MV_LOAD(&mv.poisoned))return;
    /* A kernel access to an application buffer can expand the original stack
       within this same handler. Recheck before the next consumer, even after
       errors. Only pointer-free queries and exact private observer calls are
       exempt; fstat is deliberately NOT exempt here. */
    if(mv_stable_call(n) && n!=SYS_getpid && n!=SYS_gettid &&
       !(n==SYS_mincore && mv_stack_first>=PAGE && (uintptr_t)a==mv_stack_first-PAGE &&
         b==PAGE && (uintptr_t)c==(uintptr_t)&mv_residency && !d && !e && !f) &&
       !(n!=SYS_fstat && maps_nonmutating(n,a,b,c,d,e,f)))MV_STORE(&mv_stack_pending,1);
    if(n==SYS_mprotect && !result && mv_saved && MV_LOAD(&mv.enabled) && !mv_stack_retired &&
       mv_protect((uintptr_t)a,(size_t)b,(unsigned)c))MV_STORE(&maps_stats.valid,1);
    if(kernel_error(result) && !(n==SYS_mincore && result==-ENOMEM &&
       mv_stack_first>=PAGE && (uintptr_t)a==mv_stack_first-PAGE &&
       b==PAGE && (uintptr_t)c==(uintptr_t)&mv_residency && !d && !e && !f))
        li2_maps_phase_fail();
}
static int mv_fresh(struct check_error *e,struct li2_fetch_map_progress *p) {
    MV_STORE(&maps_stats.valid,0);__atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(!mv_inc(&maps_stats.fresh_calls))return check_error(e,LI2_FETCH_STATE,0);
    int result=read_maps_fresh(e,p);
    if(result)return result;
    if(MV_LOAD(&mv.poisoned))return check_error(e,LI2_FETCH_STATE,0);
    if(!mv_inc(&maps_stats.acquisitions))return check_error(e,LI2_FETCH_STATE,0);
    p->observation=(struct li2_maps_observation){.acquisition_id=MV_LOAD(&maps_stats.acquisitions),
        .handler_id=MV_LOAD(&maps_stats.active)?MV_LOAD(&maps_stats.handler_id):0,
        .mutation_epoch=MV_LOAD(&maps_stats.mutation_epoch),
        .kind=MV_LOAD(&maps_stats.active)?LI2_MAPS_FRESH:LI2_MAPS_DIRECT,.io_performed=1};
    if(MV_LOAD(&mv.enabled)) {
        /* Capture raw stack boundaries before canonicalization can merge an
           adjacent anonymous interval. A removed/split stack retires reuse. */
        const struct map_row *s=mapping(mv_stack_anchor);
        if(!s || !s->private || s->inode || s->major || s->minor || s->first<PAGE)
            mv_stack_retired=1;
        else {mv_stack_first=s->first;mv_stack_end=s->end;}
        row_count=mv_normalize(rows,row_count);p->rows=row_count;
    }
#ifdef LI2_MAPS_CURRENT_TF
    /* Preserve the actual physical baseline before mprotect can project rows
       or change mv_receipt's epoch/count. This is never a new query receipt. */
    MV_STORE(&mct_physical_id,0);mct_physical_receipt=*p;
    MV_STORE(&mct_physical_id,p->observation.acquisition_id);
#endif
    /* A complete physical snapshot remains a valid observation after cache
       retirement. Retirement disables reuse, not the old fresh-owner guards. */
    mv_receipt=*p;MV_STORE(&maps_stats.valid,MV_LOAD(&mv.enabled));
    MV_STORE(&mv_stack_pending,0);
    return 0;
}
static int read_maps_checked(struct check_error *e,struct li2_fetch_map_progress *p) {
    *p=(struct li2_fetch_map_progress){.fd=-1};
    if(MV_LOAD(&mv.poisoned) || MV_LOAD(&mv_depth) || !mv_inc(&mv.queries))return check_error(e,LI2_FETCH_STATE,0);
    if(MV_LOAD(&mv.enabled) && !mv_stack_retired && MV_LOAD(&maps_stats.valid) && MV_LOAD(&mv_stack_pending)) {
        MV_STORE(&mv_stack_pending,0);
        if(!mv_stack_first || !mv_inc(&mv.stack_probes))return check_error(e,LI2_FETCH_STATE,0);
        long r=RAW(SYS_mincore,mv_stack_first-PAGE,PAGE,&mv_residency,0,0,0);
        if(!r)li2_maps_view_unexplained();
        else if(r!=-ENOMEM){mv_poison();return check_error(e,LI2_FETCH_STATE,r);}
    }
    if(!mv_stack_retired && MV_LOAD(&maps_stats.valid)) {
#ifdef LI2_MAPS_DIFFERENTIAL
        size_t count=row_count;
        for(size_t i=0;i<count;i++)mv_scratch[i]=rows[i];
        if(!mv_inc(&mv.comparisons))return check_error(e,LI2_FETCH_STATE,0);
        if(MV_LOAD(&mv_compare_io) || MV_LOAD(&mv_observer_active)) {
            mv_poison();return check_error(e,LI2_FETCH_STATE,0);
        }
        mv_observer_fd=-1;mv_observer_offset=0;MV_STORE(&mv_observer_phase,0);
        MV_STORE(&mv_compare_io,1);
        int result=mv_fresh(e,p);
        MV_STORE(&mv_compare_io,0);
        if(result){mv_poison();return result;}
        if(MV_LOAD(&mv_observer_active) || MV_LOAD(&mv_observer_phase)!=3) {
            mv_poison();return check_error(e,LI2_FETCH_STATE,0);
        }
        unsigned same=count==row_count;
        for(size_t i=0;same && i<count;i++)same=mv_same(&mv_scratch[i],&rows[i]);
        if(!same){(void)mv_inc(&mv.mismatches);mv_poison();return check_error(e,LI2_FETCH_STATE,0);}
        p->observation.kind=LI2_MAPS_VERIFIED;
#else
        *p=mv_receipt;p->observation.kind=LI2_MAPS_PROJECTED;p->observation.io_performed=0;
#endif
        p->observation.handler_id=MV_LOAD(&maps_stats.handler_id);
        p->observation.mutation_epoch=MV_LOAD(&maps_stats.mutation_epoch);
        if(!mv_inc(&mv.hits) || !mv_inc(&maps_stats.reuses))return check_error(e,LI2_FETCH_STATE,0);
        return 0;
    }
    if(!mv_inc(&mv.refreshes))return check_error(e,LI2_FETCH_STATE,0);
#ifdef LI2_MAPS_CURRENT_TF
    int result;
    if(cc_physical_refresh()) {
        /* This is a new physical acquisition, never a maintained hit or a
           differential comparison. Only its exact private I/O tuple preserves
           the already-staged physical source owner. Every original validator
           still observes the new table, backing and complete source bytes. */
        if(MV_LOAD(&mv_custody_io) || MV_LOAD(&mv_compare_io) ||
           MV_LOAD(&mv_observer_active) || MV_LOAD(&mv_depth)) {
            mv_poison();return check_error(e,LI2_FETCH_STATE,0);
        }
        mv_observer_fd=-1;mv_observer_offset=0;MV_STORE(&mv_observer_phase,0);
        MV_STORE(&mv_custody_io,1);
        result=mv_fresh(e,p);
        MV_STORE(&mv_custody_io,0);
        if(!result && (MV_LOAD(&mv_observer_active) || MV_LOAD(&mv_observer_phase)!=3 ||
                      !cc_physical_refresh())) {
            mv_poison();result=check_error(e,LI2_FETCH_STALE,0);
        }
    } else
    result=mv_fresh(e,p);
#else
    int result=mv_fresh(e,p);
#endif
    if(result){li2_maps_phase_fail();return result;}
    MV_STORE(&mv_stack_pending,0);return 0;
}
#ifdef LI2_MAPS_CURRENT_TF
#include "maps_current_ticket.inc"
#endif
#undef MV_LOAD
#undef MV_STORE
