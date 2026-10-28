#ifndef LI2_LOADER_LIFECYCLE_H
#define LI2_LOADER_LIFECYCLE_H
#include <stddef.h>
#include <stdint.h>
#ifdef LI2_MAPS_PHASE_REUSE
#include "maps_phase.h"
#endif

/* Raw-only, singleton module. initialize runs before SUD/NX activation. */
struct li2_lifecycle_hooks {
    long (*raw)(long,long,long,long,long,long,long);
    void (*fail)(unsigned,long) __attribute__((noreturn));
    int (*protected_range)(uintptr_t,size_t);
};
struct li2_lifecycle_counts {
    uint64_t enabled, transactions, mappings, generations, retired, admissions;
    uint64_t reconciliations, kernel_errors, partial_errors, materialized;
    uint64_t sync_core, live_pages, retained_records;
    uint64_t last_operation,last_syscall, last_result_abs, last_result_negative, last_phase;
};
struct li2_lifecycle_page_view {
    uint64_t allocation,generation,offset;
    unsigned backing,logical,actual,admitted;
};
int li2_lifecycle_query(uintptr_t address,struct li2_lifecycle_page_view *out);
void li2_lifecycle_initialize(const int *fds,size_t count,const struct li2_lifecycle_hooks *hooks);
/* Candidate-only preactivation fault control, never armed by the default mode. */
void li2_lifecycle_fault_control(unsigned enabled);
int li2_lifecycle_enabled(void);
int li2_lifecycle_known_code(uintptr_t first,size_t bytes);
int li2_lifecycle_admit(uintptr_t pc,uintptr_t fault_address);
int li2_lifecycle_dispatch(long n,const long args[6],long *result);
void li2_lifecycle_before_other(long n,const long args[6]);
void li2_lifecycle_abort(void);
void li2_lifecycle_snapshot(struct li2_lifecycle_counts *out);
/* Actual fork boundary: no active materialization, every retained live page
   agrees with this process mm, and every source still has its sealed owner. */
struct li2_fork_range { uintptr_t first,end; };
void li2_lifecycle_fork_capture(const struct li2_fork_range *,size_t);
void li2_lifecycle_fork_verify(void);
#endif
/* Bridge-authenticated initial images are registered before SUD activation. */
struct image;
void li2_lifecycle_register_initial(const struct image *image);
void li2_lifecycle_verify_kernel_code(uintptr_t first,size_t bytes);

#ifndef LI2_LIFECYCLE_FETCH_H
#define LI2_LIFECYCLE_FETCH_H
#include <sys/stat.h>
/* Non-authoritative fetch observation. No API below changes permissions.
   The opaque borrow belongs to this module, not the caller; it is valid only
   until successful release. Controller/step owners copy their needed facts
   before release. No syscall/fork/mapping dispatch may overlap that borrow. */
enum li2_fetch_error {
    LI2_FETCH_ARGUMENT=300, LI2_FETCH_BUSY, LI2_FETCH_STALE, LI2_FETCH_STATE,
    LI2_FETCH_IDENTITY, LI2_FETCH_PAGE, LI2_FETCH_SOURCE, LI2_FETCH_BACKING
};
struct li2_fetch;
struct li2_fetch_ref {
    const struct li2_fetch *owner;
    uint64_t sequence; /* stale-borrow check only; never execution authority */
};
struct li2_fetch_map_progress {
    long fd,last_read,close_result;
    size_t bytes,rows;
    unsigned opened,close_started,closed;
#ifdef LI2_MAPS_PHASE_REUSE
    /* I/O fields describe this acquisition, not new I/O on a reused query. */
    struct li2_maps_observation observation;
#endif
};
struct li2_fetch_page {
    uintptr_t address;
    uint64_t allocation,generation,offset,initial_extent;
    unsigned backing,object,logical,closed_prot;
    uintptr_t vma_first,vma_end;
    uint64_t vma_major,vma_minor,vma_inode,vma_offset;
};
struct li2_fetch_backing {
    int retained_fd;
    long seals,stat_result;
    struct stat stat;
    unsigned seals_observed,stat_observed;
};
struct li2_fetch_view {
    uintptr_t pc;
    const unsigned char *bytes;
    size_t length,page_count;
    const struct li2_fetch_page *pages;
    const struct li2_fetch_backing *backing;
    const struct li2_fetch_backing *last_backing;
    long pid,tid;
    unsigned identity_observed;
};
struct li2_fetch_progress {
    unsigned held,complete,first_error,identity_observed;
    long first_detail;
    size_t pages_copied,bytes_copied;
    uint64_t sequence,validation_calls;
    size_t last_backing_page;
    unsigned last_backing_observed;
    struct li2_fetch_map_progress preparation,validation;
};
/* Exact requested window, 1..15 bytes, entirely owned logical R-X/actual R.
   Install before all I/O. Failure retains the occupied prefix and returns an
   error; neither this function nor any pending validation invokes hooks.fail. */
int li2_lifecycle_fetch_prepare(uintptr_t pc,size_t bytes,struct li2_fetch_ref *out);
int li2_lifecycle_fetch_view(const struct li2_fetch_ref *,struct li2_fetch_view *out);
/* Read-only actual maps/source/identity/seal check. expected_prot is a
   comparison operand (R or RX), not a permit or permission transition. */
int li2_lifecycle_fetch_validate(const struct li2_fetch_ref *,size_t page,int expected_prot);
/* Only succeeds once all owned pages are actually back at R/NX. */
int li2_lifecycle_fetch_release(const struct li2_fetch_ref *);
/* Mandatory controller check before every ordinary syscall, fork, legacy
   admission and lifecycle mutation entry. A busy result goes to the existing
   step owner's error/cleanup path, never hooks.fail from a pending callback. */
int li2_lifecycle_fetch_interlock(void);
/* Borrowed prefix diagnostics; no allocation, payload copy or authority. */
const struct li2_fetch_progress *li2_lifecycle_fetch_progress(void);
void li2_lifecycle_fetch_partial_view(struct li2_fetch_view *out);
#endif
