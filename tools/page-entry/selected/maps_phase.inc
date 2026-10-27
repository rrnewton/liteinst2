/* Included after the unchanged read_maps_fresh body. No allocation, TLS, lock,
   decoder or callback. Only the already-owned rows/maps_bytes are shared. */
#include <asm/prctl.h>
#include <linux/prctl.h>
_Static_assert(__atomic_always_lock_free(4,0),"signal-safe phase flags");
_Static_assert(__atomic_always_lock_free(8,0),"signal-safe phase counters");
static struct li2_maps_stats maps_stats;
static struct li2_fetch_map_progress maps_receipt;
static uint64_t maps_receipt_handler,maps_receipt_epoch;
#define MAPS_LOAD(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define MAPS_STORE(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
static void maps_poison(void) {
    MAPS_STORE(&maps_stats.valid,0);
    MAPS_STORE(&maps_stats.active,0);
    MAPS_STORE(&maps_stats.poisoned,1);
}
static uint64_t maps_increment(uint64_t *p) {
    uint64_t old=MAPS_LOAD(p);
    do {
        if(old==UINT64_MAX){maps_poison();return 0;}
    } while(!__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    return old+1;
}
static void maps_invalidate(void) {
    /* Invalidation precedes every row/receipt write and every uncertain raw
       operation. seq_cst fence prevents subsequent accesses moving before it. */
    MAPS_STORE(&maps_stats.valid,0);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    (void)maps_increment(&maps_stats.invalidations);
    (void)maps_increment(&maps_stats.mutation_epoch);
}
void li2_maps_phase_end(void) {
    MAPS_STORE(&maps_stats.active,0);
    maps_invalidate();
}
void li2_maps_phase_fail(void) { li2_maps_phase_end(); }
void li2_maps_event_boundary(void) { li2_maps_phase_end(); }
int li2_maps_phase_begin(void) {
    /* Caller has only established nonnested runtime routing. This is NOT a
       substitute for the subsequent actual frame/session/owner checks. */
    if(MAPS_LOAD(&maps_stats.active) || MAPS_LOAD(&maps_stats.poisoned) ||
       !active || tx.guard || !hooks.raw)return LI2_FETCH_STATE;
    long pid=RAW(SYS_getpid,0,0,0,0,0,0),tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(pid<=0 || pid!=tid)return LI2_FETCH_IDENTITY;
    maps_invalidate();
    if(!maps_increment(&maps_stats.handler_id) || MAPS_LOAD(&maps_stats.poisoned))
        return LI2_FETCH_STATE;
    MAPS_STORE(&maps_stats.active,1);
    return 0;
}
static int maps_nonmutating(long n,long a,long b,long c,long d,long e,long f) {
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
void li2_maps_before_raw(long n,long a,long b,long c,long d,long e,long f) {
    if(!maps_nonmutating(n,a,b,c,d,e,f))maps_invalidate();
}
void li2_maps_after_raw(long n,long a,long b,long c,long d,long e,long f,long result) {
    if(!maps_nonmutating(n,a,b,c,d,e,f))maps_invalidate();
    /* Even an ordinarily harmless query error disables reuse for cleanup. */
    if(result<0 && result>=-4095)li2_maps_phase_fail();
}
void li2_maps_stats_read(struct li2_maps_stats *out) {
    /* Observational receipt only. A nested event is terminal in this profile;
       no claim of a multi-thread atomic aggregate is made. */
    if(!out)return;
    out->fresh_calls=MAPS_LOAD(&maps_stats.fresh_calls);
    out->acquisitions=MAPS_LOAD(&maps_stats.acquisitions);
    out->reuses=MAPS_LOAD(&maps_stats.reuses);
    out->invalidations=MAPS_LOAD(&maps_stats.invalidations);
    out->handler_id=MAPS_LOAD(&maps_stats.handler_id);
    out->mutation_epoch=MAPS_LOAD(&maps_stats.mutation_epoch);
    out->active=MAPS_LOAD(&maps_stats.active);
    out->valid=MAPS_LOAD(&maps_stats.valid);
    out->poisoned=MAPS_LOAD(&maps_stats.poisoned);out->reserved=0;
}
static int read_maps_checked(struct check_error *e,struct li2_fetch_map_progress *p) {
    if(MAPS_LOAD(&maps_stats.poisoned)) {
        *p=(struct li2_fetch_map_progress){.fd=-1};
        return check_error(e,LI2_FETCH_STATE,0);
    }
    uint64_t handler=MAPS_LOAD(&maps_stats.handler_id);
    if(MAPS_LOAD(&maps_stats.active) && !MAPS_LOAD(&maps_stats.poisoned) &&
       MAPS_LOAD(&maps_stats.valid) && maps_receipt_handler==handler &&
       maps_receipt_epoch==MAPS_LOAD(&maps_stats.mutation_epoch)) {
        if(!maps_increment(&maps_stats.reuses)) {
            *p=(struct li2_fetch_map_progress){.fd=-1};
            return check_error(e,LI2_FETCH_STATE,0);
        }
        *p=maps_receipt;
        p->observation.kind=LI2_MAPS_REUSED;p->observation.io_performed=0;
        return 0;
    }
    maps_invalidate(); /* BEFORE read_maps_fresh writes either scratch buffer. */
    if(MAPS_LOAD(&maps_stats.poisoned) || !maps_increment(&maps_stats.fresh_calls)) {
        *p=(struct li2_fetch_map_progress){.fd=-1};
        return check_error(e,LI2_FETCH_STATE,0);
    }
    int result=read_maps_fresh(e,p);
    p->observation=(struct li2_maps_observation){.kind=LI2_MAPS_DIRECT,.io_performed=1};
    if(result){li2_maps_phase_fail();return result;}
    if(MAPS_LOAD(&maps_stats.poisoned))return check_error(e,LI2_FETCH_STATE,0);
    uint64_t id=maps_increment(&maps_stats.acquisitions);
    if(!id)return check_error(e,LI2_FETCH_STATE,0);
    p->observation.acquisition_id=id;
    p->observation.mutation_epoch=MAPS_LOAD(&maps_stats.mutation_epoch);
    if(MAPS_LOAD(&maps_stats.active) && !MAPS_LOAD(&maps_stats.poisoned) &&
       MAPS_LOAD(&maps_stats.handler_id)==handler) {
        p->observation.kind=LI2_MAPS_FRESH;p->observation.handler_id=handler;
        /* All rows are already parsed. Install EVERY associated field before
           the sole release-store of valid. No query result/ownership cached. */
        maps_receipt_handler=handler;
        maps_receipt_epoch=p->observation.mutation_epoch;
        maps_receipt=*p;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        MAPS_STORE(&maps_stats.valid,1);
    }
    return 0;
}
#ifdef LI2_MAPS_PHASE_TEST
/* Explicit supplied-state boundary controls, absent from product builds. No
   successful read or capability is manufactured; subsequent real query must
   refuse. Only the two actual saturating counters can be injected. */
int li2_maps_test_saturate(unsigned which) {
    if(!MAPS_LOAD(&maps_stats.active) || !MAPS_LOAD(&maps_stats.valid) ||
       MAPS_LOAD(&maps_stats.poisoned) || which>1)return LI2_FETCH_ARGUMENT;
    MAPS_STORE(which?&maps_stats.mutation_epoch:&maps_stats.invalidations,UINT64_MAX);
    return 0;
}
#endif
#undef MAPS_LOAD
#undef MAPS_STORE
