/* Included by lifecycle_loader.c. This is an unchanged-byte page owner;
   selected source publication is a separate, still required capability. */
#include "native_pages.h"
#ifdef LI2_NATIVE_PAIR
#include "native_pair.h"
#endif
#include "native_policy.h"
#ifdef LI2_RSEQ_NATIVE
#include "rseq_guard.h"
#endif
#define NATIVE_LOW_LIMIT UINT64_C(0x200000000)
#ifdef LI2_PERSISTENT_GROUP_COUNTERS
#include "persistent_group_counters.h"
#define native_counts (li2_pgc_current->native)
#else
static struct li2_native_counts native_counts;
#endif
static uintptr_t native_timed_page;
static uint64_t native_timed_allocation,native_timed_generation;
static uint64_t native_clock(void) {
    struct { long sec,nsec; } now;
    long result=RAW(SYS_clock_gettime,4,&now,0,0,0,0);
    if(result || now.sec<0 || now.nsec<0 || now.nsec>=1000000000L ||
       (uint64_t)now.sec>(UINT64_MAX-999999999)/1000000000)DIE(1435,result);
    return (uint64_t)now.sec*1000000000+(uint64_t)now.nsec;
}
/* Negative facts only: a stale negative can reduce admission, never grant it.
   Record slots are append-only and each slot denotes one allocation generation. */
static unsigned char native_blocked[RECORDS];
static unsigned char native_window[PAGE+28],native_backing[PAGE+28];
const struct li2_native_counts *li2_lifecycle_native_counts(void) { return &native_counts; }
#ifdef LI2_PERSISTENT_GROUP_COUNTERS
static void native_increment(uint64_t *count) {
    uint64_t value=__atomic_load_n(count,__ATOMIC_ACQUIRE);
    if(value==UINT64_MAX)DIE(1430,0);
    __atomic_store_n(count,value+1,__ATOMIC_RELEASE);
}
#else
static void native_increment(uint64_t *count) {
    if(*count==UINT64_MAX)DIE(1430,0);
    ++*count;
}
#endif

static void native_copy(const struct owned_page *p,uintptr_t first,size_t length,
                        size_t destination) {
    const struct map_row *r=mapping(p->address);
    verify_page(p,r);
    if(p->backing!=SEALED || p->logical!=(PROT_READ|PROT_EXEC) ||
       p->actual!=PROT_READ || p->admitted || r->prot!=PROT_READ ||
       first<p->address || length>PAGE-(first-p->address) ||
       destination>sizeof(native_window)-length) DIE(1420,0);
    const struct object *o=&objects[p->object];
    struct stat st;
    long seals=RAW(SYS_fcntl,o->retained_fd,F_GET_SEALS,0,0,0,0);
    if(seals<0 || (seals&SEALS)!=SEALS ||
       RAW(SYS_fstat,o->retained_fd,&st,0,0,0,0) ||
       st.st_dev!=o->stat.st_dev || st.st_ino!=o->stat.st_ino ||
       st.st_size!=o->stat.st_size || st.st_mode!=o->stat.st_mode) DIE(1421,0);
    uint64_t offset=p->offset+(first-p->address);
    if(offset<p->offset || offset>(uint64_t)st.st_size ||
       length>(uint64_t)st.st_size-offset) DIE(1422,0);
    alias_check(p->object,offset,length,PROT_READ|PROT_EXEC,first,first+length);
    long result=RAW(SYS_pread64,o->retained_fd,native_backing+destination,length,offset,0,0);
    if(result!=(long)length)DIE(1423,result);
    const volatile unsigned char *source=(const volatile unsigned char *)first;
    for(size_t i=0;i<length;i++)native_window[destination+i]=source[i];
    if(!equal(native_window+destination,native_backing+destination,length))DIE(1424,0);
}
static int native_neighbor(uintptr_t address) {
    const struct owned_page *p=current(address);
    const struct map_row *r=mapping(address);
    if(p && (p->logical&PROT_EXEC))return 1;
    /* Absence is a logical nonexecute fact, never just the current NX gate. */
    if(r && (r->prot&PROT_EXEC))DIE(1425,0);
    return 0;
}
int li2_lifecycle_native_admit(uintptr_t pc) {
#ifdef LI2_LINKED_EPOCH
    if(li2_lifecycle_link_interlock())DIE(LI2_FETCH_BUSY,441);
#endif
    uint64_t started=native_clock();
    if(!active || tx.guard || li2_lifecycle_fetch_interlock() ||
       native_counts.admissions!=native_counts.closed)DIE(1426,0);
    native_increment(&native_counts.attempts);
    uintptr_t address=pc&~(PAGE-1);
    if(address<NATIVE_LOW_LIMIT || address>UINTPTR_MAX-2*PAGE) {
        native_increment(&native_counts.low_address_refusals);return 0;
    }
    const struct owned_page *p=current(address);
    if(!p || p->backing!=SEALED || p->logical!=(PROT_READ|PROT_EXEC) ||
       p->actual!=PROT_READ || p->admitted)return 0;
    size_t record=(size_t)(p-records);
    if(native_blocked[record]) { native_increment(&native_counts.blocked);return 0; }
    long pid=RAW(SYS_getpid,0,0,0,0,0,0),tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(pid<=0 || pid!=tid)DIE(1427,0);
    read_maps();
    /* All mappings count, including the private runtime, generated code and
       vDSO. Even with a nonzero compatibility segment base, base+EIP<8GiB.
       Native code cannot mutate maps without leaving this epoch first. */
    for(size_t i=0;i<row_count;i++)if(rows[i].first<NATIVE_LOW_LIMIT &&
                                      (rows[i].prot&PROT_EXEC)) {
        native_increment(&native_counts.low_address_refusals);return 0;
    }
    int before=native_neighbor(address-PAGE),after=native_neighbor(address+PAGE);
    size_t start=before?14:0,length=start+PAGE+(after?14:0);
    if(before)native_copy(current(address-PAGE),address-14,14,0);
    native_copy(p,address,PAGE,start);
    if(after)native_copy(current(address+PAGE),address+PAGE,14,start+PAGE);
    native_counts.last_block=li2_native_policy(native_window,length);
    if(native_counts.last_block) {
        native_blocked[record]=(unsigned char)native_counts.last_block;
        native_increment(&native_counts.blocked);return 0;
    }
    /* No bytes changed between authentication and permission publication;
       the singleton handler owns execution and all mapping mutation paths. */
#ifdef LI2_RSEQ_NATIVE
    int rseq_result=li2_rseq_native_prepare(pc);
    if(rseq_result)DIE((unsigned)rseq_result,li2_rseq_native_snapshot()->first_detail);
#endif
    if(!li2_lifecycle_admit(pc,pc))DIE(1428,0);
    read_maps();p=current(address);const struct map_row *r=mapping(address);
    verify_page(p,r);
    if(!p->admitted || p->actual!=(PROT_READ|PROT_EXEC) || r->prot!=p->actual ||
       !equal((const void *)address,native_window+start,PAGE))DIE(1429,0);
    uint64_t ended=native_clock();
    if(ended<started)DIE(1435,1);
    if(!native_counts.admissions) {
        native_counts.first_admission_ns=ended-started;
        native_counts.first_source_offset=p->offset;
        native_timed_page=address;native_timed_allocation=p->allocation;
        native_timed_generation=p->generation;
    } else if(address==native_timed_page && p->allocation==native_timed_allocation &&
              p->generation==native_timed_generation && native_counts.revisit_count<16) {
        native_counts.revisit_ns[native_counts.revisit_count++]=ended-started;
    }
    native_increment(&native_counts.admissions);
#ifdef LI2_RSEQ_NATIVE
    rseq_result=li2_rseq_native_publish(pc);
    if(rseq_result)DIE((unsigned)rseq_result,li2_rseq_native_snapshot()->first_detail);
#endif
    return 1;
}

/* Native-epoch close owner: appended to native_lifecycle.inc. Uses actual
   retained lifecycle records, never a supplied list or closure assertion.
   The fatal route calls native_close_abort before the original abort/exit. */
#include "native_epoch.h"
static struct li2_native_close native_close;
static int native_close_error(unsigned code,long detail,uintptr_t address) {
    if(!native_close.first_error) {
        native_close.first_error=code;native_close.first_detail=detail;
        native_close.first_error_address=address;
    }
    return (int)native_close.first_error;
}
static int native_close_check(const struct check_error *e,uintptr_t address) {
    return native_close_error(e->code,e->detail,address);
}
const struct li2_native_close *li2_lifecycle_native_close_progress(void) { return &native_close; }
static int native_close_all(void);
void li2_lifecycle_native_close_abort(void) {
    if(!active || !hooks.raw || native_close.cleanup_started)return;
    /* Ordinary terminal native events still get a fully verified close. An
       already partial/reentrant failure can only use best-effort termination;
       it never changes the failed prefix into successful closure. */
    if(!native_close.busy && !native_close.first_error && !tx.guard &&
       !li2_lifecycle_fetch_interlock() && !native_close_all())return;
    native_close.cleanup_started=1;
    /* On fatal reentry, the interrupted ordinary loop never resumes. Retain
       all records until exit; no successful old borrow follows this cleanup. */
    for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];
        if(!p->live || !p->admitted)continue;
        ++native_close.cleanup_attempted;
        long r=RAW(SYS_mprotect,p->address,PAGE,PROT_READ,0,0,0);
        ++native_close.cleanup_returned;
        if(r && !native_close.cleanup_first_result)native_close.cleanup_first_result=r;
    }
    native_close.cleanup_sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    native_close.cleanup_complete=1; /* attempted cleanup, not verified closure */
}
static int native_close_all(void) {
    if(native_close.first_error)return (int)native_close.first_error;
    if(native_close.busy)return native_close_error(LI2_NATIVE_REENTRY,0,0);
    if(!active || !hooks.raw || tx.guard || li2_lifecycle_fetch_interlock() ||
       (tx.phase!=IDLE && tx.phase!=REVOKED && tx.phase!=ADMITTED))
        return native_close_error(LI2_NATIVE_STATE,tx.phase,0);
    if(native_close.sequence==UINT64_MAX || counts.sync_core==UINT64_MAX)
        return native_close_error(LI2_NATIVE_OVERFLOW,0,0);
    uint64_t sequence=native_close.sequence+1;
    native_close=(struct li2_native_close){.sequence=sequence,.busy=1,
        .allocation_epoch=allocation_id,.generation_epoch=generation,
        .transactions_epoch=counts.transactions,.records_epoch=used};
    __asm__ volatile("" ::: "memory");
    native_close.pid=RAW(SYS_getpid,0,0,0,0,0,0);
    native_close.tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(native_close.pid<=0 || native_close.pid!=native_close.tid)
        return native_close_error(LI2_NATIVE_IDENTITY,0,0);
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end(); /* mandatory fresh rows before/after this transition */
#endif
    struct check_error e={0};
    if(read_maps_checked(&e,&native_close.before))return native_close_check(&e,0);
    for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];
        if(!p->live || !(p->logical&PROT_EXEC))continue;
        const struct map_row *r=mapping(p->address);
        if(verify_page_checked(p,r,&e))return native_close_check(&e,p->address);
        if(p->admitted>1 || p->logical!=(PROT_READ|PROT_EXEC) ||
           p->actual!=(p->admitted?(PROT_READ|PROT_EXEC):PROT_READ) || r->prot!=p->actual)
            return native_close_error(LI2_NATIVE_MAPPING,0,p->address);
        if(p->backing==SEALED && alias_check_checked(p->object,p->offset,PAGE,p->logical,
                                                    p->address,p->address+PAGE,&e))
            return native_close_check(&e,p->address);
        if(p->admitted)++native_close.pages;
    }
    if(native_close.pages>UINT64_MAX-native_counts.closed)
        return native_close_error(LI2_NATIVE_OVERFLOW,1,0);
    for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];if(!p->live || !p->admitted)continue;
        native_close.last_address=p->address;++native_close.attempted;
        native_close.last_result=RAW(SYS_mprotect,p->address,PAGE,PROT_READ,0,0,0);
        ++native_close.returned;
        if(native_close.last_result)native_close_error(LI2_NATIVE_CLOSE,native_close.last_result,p->address);
        else ++native_close.closed;
    }
    if(native_close.pages) {
        native_close.sync_started=1;
        native_close.sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
        native_close.sync_returned=1;
        if(native_close.sync_result)native_close_error(LI2_NATIVE_SYNC,native_close.sync_result,0);
    }
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end();
#endif
    e=(struct check_error){0};
    if(read_maps_checked(&e,&native_close.after))native_close_check(&e,0);
    if(!native_close.first_error)for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];
        if(!p->live || !(p->logical&PROT_EXEC))continue;
        const struct map_row *r=mapping(p->address);
        if(verify_page_checked(p,r,&e)){native_close_check(&e,p->address);break;}
        if(r->prot!=PROT_READ){native_close_error(LI2_NATIVE_MAPPING,1,p->address);break;}
        if(p->backing==SEALED && alias_check_checked(p->object,p->offset,PAGE,p->logical,
                                                    p->address,p->address+PAGE,&e)) {
            native_close_check(&e,p->address);break;
        }
        if(p->admitted)++native_close.verified;
    }
    if(RAW(SYS_getpid,0,0,0,0,0,0)!=native_close.pid ||
       RAW(SYS_gettid,0,0,0,0,0,0)!=native_close.tid ||
       allocation_id!=native_close.allocation_epoch || generation!=native_close.generation_epoch ||
       counts.transactions!=native_close.transactions_epoch || used!=native_close.records_epoch)
        native_close_error(LI2_NATIVE_IDENTITY,1,0);
    if(native_close.first_error)return (int)native_close.first_error;
    if(native_close.pages!=native_close.attempted || native_close.pages!=native_close.returned ||
       native_close.pages!=native_close.closed || native_close.pages!=native_close.verified)
        return native_close_error(LI2_NATIVE_STATE,1,0);
    for(size_t i=0;i<used;i++)if(records[i].live && records[i].admitted) {
#ifdef LI2_PERSISTENT_GROUP_COUNTERS
        records[i].actual=PROT_READ;records[i].admitted=0;native_increment(&native_counts.closed);
#else
        records[i].actual=PROT_READ;records[i].admitted=0;++native_counts.closed;
#endif
    }
    if(native_close.pages)++counts.sync_core;
    native_close.complete=1;native_close.busy=0;
    return 0;
}

void li2_lifecycle_native_close(void) {
#ifdef LI2_NATIVE_PAIR
    if(li2_native_pair_effect_guard())DIE(LI2_NP_STATE,65);
#endif
    int result=native_close_all();
    if(result)DIE(native_close.first_error,native_close.first_detail);
}
