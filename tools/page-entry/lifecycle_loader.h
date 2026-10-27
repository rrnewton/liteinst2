#ifndef LI2_LOADER_LIFECYCLE_H
#define LI2_LOADER_LIFECYCLE_H
#include <stddef.h>
#include <stdint.h>
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
#endif
/* Bridge-authenticated initial images are registered before SUD activation. */
struct image;
void li2_lifecycle_register_initial(const struct image *image);
void li2_lifecycle_verify_kernel_code(uintptr_t first,size_t bytes);
