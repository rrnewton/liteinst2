/* Included after the actual lifecycle source owners. No numeric source list
   or claimed owner counts enter this provider. Its whole state is R while
   guest code runs and while guest syscalls are forwarded. */
#include "resident_source_lease.h"
#include "readonly_query.h"
#ifdef LI2_RESIDENT_SOURCE_PROBE
#include "resident_source_probe.h"
#endif
#include <asm/prctl.h>
#include <linux/futex.h>
#include <linux/stat.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
_Static_assert(sizeof(struct stat)==144 && sizeof(struct statx)==256 && sizeof(struct statfs)==120,
    "exact native metadata output extents");
_Static_assert(sizeof(struct utsname)==390 && sizeof(struct sysinfo)==112 &&
    sizeof(struct timespec)==16 && sizeof(struct timeval)==16 && sizeof(struct rlimit)==16,
    "exact native query output extents");
struct rsl_page {
    struct owned_page original;
    struct li2_fetch_page identity;
    struct li2_fetch_backing backing;
    unsigned char bytes[PAGE];
};
struct li2_rsl_owner {
    struct li2_rsl_progress p;
    struct rsl_page page[LI2_RSL_PAGES];
#ifdef LI2_RESIDENT_THREE
    struct li2_rsl_resident_progress resident;
#endif
};
static union {
    struct li2_rsl_owner owner;
    unsigned char bytes[(sizeof(struct li2_rsl_owner)+PAGE-1)&~(PAGE-1)];
} rsl __attribute__((aligned(PAGE)));
#ifdef LI2_RESIDENT_THREE
_Static_assert(sizeof(struct li2_rsl_resident_progress)==176,"literal resident source observation");
_Static_assert(sizeof rsl==70U*PAGE,"resident metadata fits the existing source-owner allocation");
static void rsl_resident_clear(void) {
    rsl.owner.resident.bound=(struct li2_r3_token){0};
    rsl.owner.resident.seed=(struct li2_r3_seed){0};
    rsl.owner.resident.epoch=0;
}
#endif
_Static_assert(LI2_PGD_MEMBERS==2 && LI2_MG_RANGES==131 && LI2_RSL_PAGES==64,
    "new source retention does not enlarge old execution/guard bounds");
static int rsl_permission(int prot) {
    return RAW(SYS_mprotect,(uintptr_t)&rsl,sizeof rsl,prot,0,0,0)?LI2_FETCH_STATE:0;
}
static int rsl_finish(int error) {
    int seal=rsl_permission(PROT_READ);return error?error:seal;
}
static int rsl_identity(void) {
    long pid=RAW(SYS_getpid,0,0,0,0,0,0),tid=RAW(SYS_gettid,0,0,0,0,0,0);
    return active && !tx.guard && pid>0 && pid==tid &&
        RAW(SYS_prctl,PR_GET_DUMPABLE,0,0,0,0,0)==0;
}
static int rsl_no_deferred_writer(uint64_t observed[9]) {
    /* Trusted startup, before the original interpreter or application runs.
       Establish zero in the kernel; an unavailable PR_GET_TID_ADDRESS query
       is never accepted as evidence. No guest registration is permitted here. */
    long pid=RAW(SYS_getpid,0,0,0,0,0,0),tid=RAW(SYS_gettid,0,0,0,0,0,0);
    observed[0]=(uint64_t)pid;observed[1]=(uint64_t)tid;
    if(pid<=0 || pid!=tid)return 0;
    long result=RAW(SYS_set_tid_address,0,0,0,0,0,0);
    long after_pid=RAW(SYS_getpid,0,0,0,0,0,0),after_tid=RAW(SYS_gettid,0,0,0,0,0,0);
    observed[2]=(uint64_t)result;observed[3]=(uint64_t)after_pid;observed[4]=(uint64_t)after_tid;
    if(result!=tid || after_pid!=pid || after_tid!=tid)return 0;
    uintptr_t robust=UINTPTR_MAX;size_t bytes=0;
    result=RAW(SYS_get_robust_list,0,&robust,&bytes,0,0,0);
    observed[5]=(uint64_t)result;observed[6]=robust;observed[7]=bytes;
    if(result || robust || bytes!=3*sizeof(uintptr_t))return 0;
    observed[8]=1;return 1;
}
static int rsl_initial(const struct owned_page *p) {
    return p && p->live==1 && p->allocation && p->generation && !p->admitted &&
        p->backing==SEALED && p->object<object_count && initial_sealed_object[p->object]==1 &&
        (p->logical==PROT_READ || p->logical==(PROT_READ|PROT_EXEC)) && p->actual==PROT_READ &&
        p->address>=PAGE && !(p->address&(PAGE-1)) && p->address<(UINT64_C(1)<<47)-PAGE;
}
static int rsl_maps(struct li2_fetch_map_progress *maps) {
    struct check_error error={0};
#ifdef LI2_MAPS_MAINTAINED
    li2_maps_view_require_fresh();
#endif
    return read_maps_checked(&error,maps)?(int)error.code:0;
}
static int rsl_page_check(const struct owned_page *p,struct li2_fetch_backing *backing) {
    if(!rsl_initial(p))return LI2_FETCH_PAGE;
    const struct map_row *m=mapping(p->address);struct check_error error={0};
    if(!m || p->address<m->first || m->prot!=PROT_READ ||
       verify_page_checked(p,m,&error) ||
       alias_check_checked(p->object,p->offset,PAGE,PROT_READ|PROT_EXEC,p->address,p->address+PAGE,&error))
        return error.code?(int)error.code:LI2_FETCH_PAGE;
    return fetch_backing_check(p,backing);
}
static struct li2_fetch_page rsl_describe(const struct owned_page *p) {
    const struct map_row *m=mapping(p->address);
    return (struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=p->actual,
        .vma_first=m->first,.vma_end=m->end,.vma_major=m->major,.vma_minor=m->minor,
        .vma_inode=m->inode,.vma_offset=m->offset};
}
static int rsl_storage_readonly(void) {
    uintptr_t first=(uintptr_t)&rsl,end=first+sizeof rsl;
    for(uintptr_t at=first;at<end;at+=PAGE) {
        const struct map_row *m=mapping(at);
        if(!m || !m->private || m->prot!=PROT_READ || m->end-at<PAGE)return 0;
    }
    return 1;
}
static int rsl_authenticate(unsigned refresh) {
    if(refresh>1 || !rsl.owner.p.initialized || !rsl.owner.p.pages ||
       rsl.owner.p.pages>LI2_RSL_PAGES || !rsl_identity())return LI2_FETCH_STATE;
    struct li2_fetch_map_progress maps={0};int error=rsl_maps(&maps);if(error)return error;
    if(!refresh && !rsl_storage_readonly())return LI2_FETCH_STATE;
    unsigned actual=0;
    for(size_t i=0;i<used;i++)if(records[i].live && records[i].backing==SEALED &&
        records[i].object<object_count && initial_sealed_object[records[i].object]) {
        unsigned found=0;
        for(unsigned j=0;j<rsl.owner.p.pages;j++)found+=
            rsl.owner.page[j].original.address==records[i].address;
        if(found>1 || (!found && (records[i].logical&PROT_EXEC)))return LI2_FETCH_STALE;
        if(found) {if(actual==LI2_RSL_PAGES)return LI2_FETCH_STALE;++actual;}
    }
    if(actual!=rsl.owner.p.pages)return LI2_FETCH_STALE;
    /* Authenticate all backing/permission rows before dereferencing any
       source byte. Refresh accepts a new actual page generation only after
       epoch invalidation; the predeclared address/object/offset never grows. */
    for(unsigned i=0;i<rsl.owner.p.pages;i++) {
        struct rsl_page *saved=&rsl.owner.page[i];const struct owned_page *p=current(saved->original.address);
        struct li2_fetch_backing observed={0};
        if((error=rsl_page_check(p,&observed)))return error;
        if(p->address!=saved->original.address || p->allocation!=saved->original.allocation ||
           p->object!=saved->original.object || p->offset!=saved->original.offset ||
           !span_source_backing_equal(&saved->backing,&observed) ||
           (!refresh && !fetch_owned_equal(p,&saved->original)))return LI2_FETCH_STALE;
        struct li2_fetch_page identity=rsl_describe(p);
        if(!refresh && !span_source_page_equal(&saved->identity,&identity))return LI2_FETCH_STALE;
        if(refresh) {saved->original=*p;saved->identity=identity;}
    }
    for(unsigned i=0;i<rsl.owner.p.pages;i++) {
        const struct rsl_page *saved=&rsl.owner.page[i];
        if(!equal((const void *)saved->original.address,saved->bytes,PAGE))return LI2_FETCH_SOURCE;
    }
    return rsl_identity()?0:LI2_FETCH_IDENTITY;
}
int li2_rsl_initialize(uint64_t observed[9]) {
    if(!observed || rsl.owner.p.initialized || rsl.owner.p.pages || rsl.owner.p.epoch ||
       rsl.owner.p.bindings || rsl.owner.p.invalidations || !active || tx.guard || !hooks.protected_range ||
       li2_lifecycle_fetch_interlock() || ((uintptr_t)&rsl&(PAGE-1)))return LI2_FETCH_STATE;
    for(size_t i=0;i<sizeof rsl;i++)if(!hooks.protected_range((uintptr_t)&rsl+i,1))return LI2_FETCH_STATE;
    for(size_t i=0;i<9*sizeof *observed;i++)
        if(!hooks.protected_range((uintptr_t)observed+i,1))return LI2_FETCH_STATE;
    for(unsigned i=0;i<9;i++)if(observed[i])return LI2_FETCH_STATE;
    if(RAW(SYS_prctl,PR_SET_DUMPABLE,0,0,0,0,0) || !rsl_identity() ||
       !rsl_no_deferred_writer(observed))return LI2_FETCH_IDENTITY;
    struct li2_fetch_map_progress maps={0};int error=rsl_maps(&maps);if(error)return error;
    for(size_t i=0;i<used;i++)if(records[i].live && records[i].backing==SEALED &&
        records[i].object<object_count && initial_sealed_object[records[i].object] &&
        (records[i].logical&PROT_EXEC)) {
        if(rsl.owner.p.pages==LI2_RSL_PAGES)return rsl_finish(LI2_FETCH_ARGUMENT);
        const struct owned_page *p=&records[i];
        for(unsigned j=0;j<rsl.owner.p.pages;j++)if(rsl.owner.page[j].original.address==p->address)
            return rsl_finish(LI2_FETCH_STALE);
        struct rsl_page *out=&rsl.owner.page[rsl.owner.p.pages];
        if((error=rsl_page_check(p,&out->backing)))return rsl_finish(error);
        out->original=*p;out->identity=rsl_describe(p);++rsl.owner.p.pages;
    }
    if(!rsl.owner.p.pages)return rsl_finish(LI2_FETCH_ARGUMENT);
    for(unsigned i=0;i<rsl.owner.p.pages;i++)
        copy(rsl.owner.page[i].bytes,(const void *)rsl.owner.page[i].original.address,PAGE);
    rsl.owner.p.initialized=1;rsl.owner.p.epoch=1;rsl.owner.p.valid=0;
    return rsl_finish(0);
}
static int rsl_token(const struct li2_pg_token *t) {
    return t && rsl.owner.p.initialized==1 && rsl.owner.p.valid==1 &&
        t->owner==rsl.owner.p.bound.owner && t->serial && t->serial==rsl.owner.p.bound.serial &&
        li2_pg_owner_phase(t)!=0;
}
int li2_rsl_bind(const struct li2_pg_token *t) {
    if(!t || li2_pg_owner_phase(t)!=LI2_PG_HELD || !rsl.owner.p.initialized ||
       rsl.owner.p.bindings==UINT64_MAX)return LI2_FETCH_STATE;
    const struct li2_pg_sources *source=li2_pg_source_view(t);
    if(!source || !source->complete || source->serial!=t->serial)return LI2_FETCH_STATE;
    if(rsl.owner.p.valid) {
        int error=rsl_authenticate(0);if(error)return error;
    }
#ifdef LI2_RESIDENT_SOURCE_PROBE
    struct li2_rsl_progress before=rsl.owner.p;
#endif
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    rsl.owner.p.bound=(struct li2_pg_token){0};
#ifdef LI2_RESIDENT_THREE
    rsl_resident_clear();
#endif
    int error=rsl_authenticate(1);
    if(!error) {rsl.owner.p.valid=1;rsl.owner.p.bound=*t;++rsl.owner.p.bindings;}
    else rsl.owner.p.valid=0;
    error=rsl_finish(error);
#ifdef LI2_RESIDENT_SOURCE_PROBE
    if(!error)li2_rso_lease_bound(t,&before);
#endif
    return error;
}
int li2_rsl_current(const struct li2_pg_token *t,struct li2_rsl_ref *out) {
    if(!out || !rsl_token(t))return LI2_FETCH_STALE;
    *out=(struct li2_rsl_ref){&rsl.owner,rsl.owner.p.epoch};return 0;
}
int li2_rsl_ref_live(const struct li2_rsl_ref *ref) {
    return ref && ref->owner==&rsl.owner && ref->epoch && ref->epoch==rsl.owner.p.epoch &&
        rsl.owner.p.initialized==1 && rsl.owner.p.valid==1;
}
int li2_rsl_validate(const struct li2_pg_token *t) {
    return rsl_token(t)?rsl_authenticate(0):LI2_FETCH_STALE;
}
int li2_rsl_snapshot(const struct li2_pg_token *t,struct li2_rsl_ref *out,unsigned *pages) {
    if(!out || !pages)return LI2_FETCH_ARGUMENT;
    int error=li2_rsl_validate(t);if(error)return error;
    error=li2_rsl_current(t,out);if(error)return error;
    *pages=rsl.owner.p.pages;return 0;
}
int li2_rsl_page_at(const struct li2_rsl_ref *ref,unsigned at,struct li2_pg_source_page *out) {
    if(!out || !li2_rsl_ref_live(ref) || at>=rsl.owner.p.pages)return LI2_FETCH_STALE;
    const struct rsl_page *page=&rsl.owner.page[at];
    out->identity=page->identity;out->backing=page->backing;copy(out->bytes,page->bytes,PAGE);return 0;
}
int li2_rsl_covers(const struct li2_rsl_ref *ref,const struct li2_mg_table *table) {
    if(!li2_rsl_ref_live(ref) || !table || li2_mg_table_validate(table))return LI2_FETCH_STALE;
    for(unsigned i=0;i<rsl.owner.p.pages;i++) {
        uintptr_t page=rsl.owner.page[i].original.address;unsigned covered=0;
        for(unsigned j=0;j<table->count;j++)covered+=
            table->node[j].first<=page && page+PAGE<=table->node[j].end;
        if(covered!=1)return LI2_FETCH_SOURCE;
    }
    return 0;
}
int li2_rsl_plan(const struct li2_pg_token *t,const struct li2_pg_compact *plan) {
    if(!rsl_token(t) || !plan)return LI2_FETCH_STALE;
    const struct li2_pgd_view *view=li2_pgd_owner_view(t);unsigned found=0;
    if(!view || !view->count || view->count>LI2_PGD_MEMBERS)return LI2_FETCH_STATE;
    for(unsigned i=0;i<view->count;i++)found+=view->member[i].plan==plan;
    if(found!=1)return LI2_FETCH_STATE;
    struct li2_rsl_ref ref={&rsl.owner,rsl.owner.p.epoch};
    int error=li2_rsl_covers(&ref,&plan->table);if(error)return error;
    for(unsigned i=0;i<2;i++) {
        unsigned matches=0;
        for(unsigned j=0;j<rsl.owner.p.pages;j++)if(plan->page[i]==rsl.owner.page[j].original.address) {
            if(!equal(plan->source[i],rsl.owner.page[j].bytes,PAGE))return LI2_FETCH_SOURCE;
            ++matches;
        }
        if(matches!=1)return LI2_FETCH_SOURCE;
    }
    return 0;
}
static int rsl_output(uintptr_t first,size_t bytes) {
    if(!bytes)return 0;
    return first>UINTPTR_MAX-bytes || hooks.protected_range(first,bytes)?LI2_FETCH_ARGUMENT:0;
}
static int rsl_optional_output(long first,size_t bytes) {
    return first?rsl_output((uintptr_t)first,bytes):0;
}
static int rsl_effect(long n,const long a[6]) {
    /* These are the actual kernel output extents, checked against the complete
       real private/source/rseq registry before RAW. No guest descriptor is
       read here. Unknown, vector or ioctl output forms refuse in this subset. */
    struct li2_readonly_query q={0};
    if(li2_readonly_query(n,a,&q)) {
        for(unsigned i=0;i<q.count;i++) {
            int error=rsl_output(q.write[i].address,q.write[i].bytes);if(error)return error;
        }
        return 0;
    }
    switch(n) {
    case SYS_read:case SYS_pread64:return rsl_output((uintptr_t)a[1],(size_t)a[2]);
    case SYS_getrandom:return rsl_output((uintptr_t)a[0],(size_t)a[1]);
    case SYS_getdents64:return rsl_output((uintptr_t)a[1],(unsigned int)a[2]);
    case SYS_readlink:
        return (int)a[2]<0?LI2_FETCH_ARGUMENT:rsl_output((uintptr_t)a[1],(unsigned int)a[2]);
    case SYS_readlinkat:
        return (int)a[3]<0?LI2_FETCH_ARGUMENT:rsl_output((uintptr_t)a[2],(unsigned int)a[3]);
    case SYS_getcwd:return rsl_output((uintptr_t)a[0],(size_t)a[1]);
    case SYS_getxattr:case SYS_lgetxattr:case SYS_fgetxattr:return rsl_output((uintptr_t)a[2],(size_t)a[3]);
    case SYS_listxattr:case SYS_llistxattr:case SYS_flistxattr:return rsl_output((uintptr_t)a[1],(size_t)a[2]);
    case SYS_fstat:return rsl_output((uintptr_t)a[1],sizeof(struct stat));
    case SYS_newfstatat:return rsl_output((uintptr_t)a[2],sizeof(struct stat));
    case SYS_statx:return rsl_output((uintptr_t)a[4],sizeof(struct statx));
    case SYS_statfs:case SYS_fstatfs:return rsl_output((uintptr_t)a[1],sizeof(struct statfs));
    case SYS_uname:return rsl_output((uintptr_t)a[0],sizeof(struct utsname));
    case SYS_sysinfo:return rsl_output((uintptr_t)a[0],sizeof(struct sysinfo));
    case SYS_clock_gettime:return rsl_output((uintptr_t)a[1],sizeof(struct timespec));
    case SYS_clock_getres:return rsl_optional_output(a[1],sizeof(struct timespec));
    case SYS_gettimeofday: {
        int error=rsl_optional_output(a[0],sizeof(struct timeval));
        return error?error:rsl_optional_output(a[1],8);
    }
    case SYS_prlimit64:return rsl_optional_output(a[3],sizeof(struct rlimit));
    case SYS_rt_sigaction:return a[1]?LI2_FETCH_ARGUMENT:rsl_optional_output(a[2],32);
    case SYS_arch_prctl:
        if(a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS)return 0;
        if(a[0]==ARCH_GET_FS || a[0]==ARCH_GET_GS || a[0]==0x5005)return rsl_output((uintptr_t)a[1],8);
        return LI2_FETCH_ARGUMENT;
    case SYS_futex: {
        int op=(int)a[1]&FUTEX_CMD_MASK;
        return op==FUTEX_WAIT || op==FUTEX_WAKE || op==FUTEX_WAIT_BITSET || op==FUTEX_WAKE_BITSET?
            0:LI2_FETCH_ARGUMENT;
    }
    case SYS_set_tid_address:case SYS_set_robust_list:return a[0]?LI2_FETCH_ARGUMENT:0;
    case SYS_brk:return a[0]?LI2_FETCH_ARGUMENT:0;
    case SYS_rseq: /* The existing typed owner still authenticates every registration/output. */
    case SYS_mmap:case SYS_mprotect:case SYS_munmap:case SYS_madvise:
    case SYS_exit:case SYS_exit_group:
    case SYS_write:case SYS_writev:case SYS_openat:case SYS_close:case SYS_lseek:
    case SYS_access:case SYS_faccessat:case SYS_faccessat2:
    case SYS_getuid:case SYS_geteuid:case SYS_getgid:case SYS_getegid:case SYS_getpid:case SYS_gettid:
    case SYS_fcntl:case SYS_prctl:
        return 0; /* All original fd/suboperation/mapping/source/procfs predicates still run. */
    default:return LI2_FETCH_ARGUMENT;
    }
}
int li2_rsl_before_effect(long number,const long args[6]) {
    if(!args || !rsl.owner.p.initialized || !li2_rsl_owner_quiet() ||
       li2_lifecycle_fetch_interlock() || !rsl_identity() || rsl.owner.p.epoch==UINT64_MAX ||
       rsl.owner.p.invalidations==UINT64_MAX)return LI2_FETCH_BUSY;
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    rsl.owner.p.valid=0;rsl.owner.p.bound=(struct li2_pg_token){0};
#ifdef LI2_RESIDENT_THREE
    rsl_resident_clear();
#endif
    ++rsl.owner.p.epoch;++rsl.owner.p.invalidations;
    int error=rsl_finish(0);if(error)return error;
    return rsl_effect(number,args);
}
const struct li2_rsl_progress *li2_rsl_progress(void) {return &rsl.owner.p;}
#ifdef LI2_RESIDENT_THREE
#include "resident_source_resident.inc"
#endif

#ifdef LI2_RESIDENT_SOURCE_PROBE
/* Read-only test observation of the real predeclared source object. The caller
   receives no mutable source/entry capability; the actual fd guards still run. */
int li2_rso_backing(uintptr_t address,uint64_t out[20]) {
    if(!out || rsl_authenticate(0))return LI2_FETCH_STATE;
    const struct owned_page *p=current(address);struct li2_fetch_backing b={0};
    int error=rsl_page_check(p,&b);if(error)return error;
    const struct object *o=&objects[p->object];
    if(b.retained_fd!=o->retained_fd || b.seals!=15 || b.stat_result ||
       !b.seals_observed || !b.stat_observed)return LI2_FETCH_STATE;
    const struct rsl_page *other=0;
    for(unsigned i=0;i<rsl.owner.p.pages;i++) {
        const struct rsl_page *candidate=&rsl.owner.page[i];
        if(candidate->original.object!=p->object &&
           (!other || candidate->original.address<other->original.address))other=candidate;
    }
    if(!other || rsl.owner.p.valid || rsl.owner.p.bindings || rsl.owner.p.bound.owner ||
       rsl.owner.p.bound.serial || rsl.owner.p.epoch!=1)return LI2_FETCH_STATE;
    const struct li2_rsl_ref declared={&rsl.owner,rsl.owner.p.epoch};
    const uint64_t v[]={b.retained_fd,p->offset,p->object,b.stat.st_dev,b.stat.st_ino,
        b.stat.st_size,b.seals,b.seals_observed,b.stat_observed,p->allocation,p->generation,p->address,
        (uintptr_t)declared.owner,declared.epoch,rsl.owner.p.valid,li2_rsl_ref_live(&declared),
        other->original.address,other->original.generation,other->original.object,other->original.allocation};
    copy(out,v,sizeof v);return 0;
}
#endif
