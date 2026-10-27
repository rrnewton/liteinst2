#ifndef LI2_PAGE_DECODER_H
#define LI2_PAGE_DECODER_H
#include <stddef.h>
#include <stdint.h>

enum li2_decoder_status {
    LI2_OK=0, LI2_BAD_ARGUMENT=1, LI2_NOT_READY=2, LI2_BUSY=3,
    LI2_ALREADY_INITIALIZED=4, LI2_ADDRESS_OVERFLOW=5,
    LI2_MISSING_BOUNDARY=6, LI2_OUTPUT_CAPACITY=7
};
enum li2_decode_status { LI2_VALID=0, LI2_INVALID=1, LI2_TRUNCATED=2 };
enum li2_selected_kind {
    LI2_NONE=0, LI2_CPUID=1, LI2_RDRAND=2, LI2_RDSEED=3, LI2_RDPID=4,
    LI2_RDTSC=5, LI2_RDTSCP=6, LI2_SYSCALL=7, LI2_SYSENTER=8, LI2_INT80=9
};
enum li2_step_disposition {
    LI2_STEP_UNSUPPORTED=0, LI2_STEP_CANDIDATE=1, LI2_STEP_FLAGS_OBSERVED=2,
    LI2_STEP_FLAGS_RESTORED=3, LI2_STEP_DEBUG_INHIBITION=4,
    LI2_STEP_KERNEL_TRANSFER=5, LI2_STEP_RSP_WRITE=6,
    LI2_STEP_PREFIX_UNQUALIFIED=7, LI2_STEP_SELECTED=8, LI2_STEP_INVALID=9,
    LI2_STEP_TRANSACTION=10, LI2_STEP_CONTROL_STATE=11
};
struct li2_decoder_stats {
    uint32_t abi_version, phase, first_fatal_reason, reserved;
    uint64_t arena_bytes, retained_high_water, allocation_calls, deallocation_calls;
};
struct li2_decoded {
    uint64_t pc, next_pc;
    uint32_t abi_version, decode_status, code, kind, destination, width_bits;
    uint32_t step_disposition, available, length, reserved;
    unsigned char bytes[16];
};
struct li2_scan {
    uint64_t page, dependency_first, dependency_end;
    uint32_t abi_version, complete, starts, invalid_starts, truncated_starts;
    uint32_t candidates, written, reserved, by_class[7], padding;
};

/* All pointers are valid, aligned, disjoint owned allocations for the call;
   arena remains mapped/immutable to callers for process lifetime after init.
   No API authenticates a live mapping, a generation, or instruction entries. */
uint32_t li2_decoder_initialize(unsigned char *,size_t,struct li2_decoder_stats *);
uint32_t li2_decoder_stats(struct li2_decoder_stats *);
uint32_t li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t li2_decoder_scan_page(uint64_t,const unsigned char *,size_t,uint64_t,
                             uint32_t,uint32_t,struct li2_decoded *,size_t,struct li2_scan *);

/* Initialization exhaustion, post-seal allocator use, or Rust panic calls this
   linked nonreturning raw hook. The supplied example writes reason then exits.
   A real owner must retain its pending failure prefix and never resume target. */
_Noreturn void li2_decoder_abort(uint32_t);

_Static_assert(sizeof(struct li2_decoder_stats)==48,"stats C ABI");
_Static_assert(sizeof(struct li2_decoded)==72,"decode C ABI");
_Static_assert(sizeof(struct li2_scan)==88,"scan C ABI");
#endif
