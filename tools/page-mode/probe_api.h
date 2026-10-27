#ifndef LI2_DYNAMIC_PROBE_API_H
#define LI2_DYNAMIC_PROBE_API_H
#include <stdint.h>

/* Read-only, single-thread diagnostic observation; no authority or syscall. */
struct li2_dynamic_counters {
    uint64_t nx_faults;
    uint64_t syscall_traps;
    uint64_t forwarded_syscalls;
};
typedef void (*li2_dynamic_snapshot_fn)(struct li2_dynamic_counters *);
#endif
