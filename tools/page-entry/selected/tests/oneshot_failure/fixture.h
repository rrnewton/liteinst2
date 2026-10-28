#ifndef LI2_ONESHOT_FAILURE_FIXTURE_H
#define LI2_ONESHOT_FAILURE_FIXTURE_H
#include "oneshot.h"
#include "lifecycle_loader.h"

#define LI2_FAILURE_MODES 49U
#define LI2_FAILURE_RAW_ROWS 32U
#define LI2_FAILURE_BACKEND_ROWS 16U
struct failure_raw {
    uint64_t number,cleanup,started,returned,injected;
    int64_t syscall_number,requested[6],issued[6],result;
};
struct failure_backend {
    uint64_t number,kind,started,returned,injected;
    int64_t actual_result,returned_result;
};
struct failure_event {
    uint64_t received,authenticated,signal,frame_address,si_address,fp_address,fp_bytes,after_observed;
    siginfo_t original_si,after_si;
    ucontext_t original_uc,after_uc;
    unsigned char original_fp[LI2_STEP_FP_BYTES],after_fp[LI2_STEP_FP_BYTES];
};
struct failure_record {
    uint64_t magic,version,bytes,mode,oracle_error,emitted,verified;
    uint64_t pid,tid,initializations,nx_calls,ud_calls,injected,cleanup;
    int64_t initialize_result,nx_result,ud_result,repeat_result;
    uint64_t raw_count,backend_count,owner_result_observed;
    uint64_t source_page,source_pc,source_bytes,source_before_observed,source_after_observed;
    int64_t source_protection_before,source_protection_after;
    uint64_t fetch_busy_before,fetch_busy_after,backend_observed;
    struct li2_oneshot_plan request;
    struct li2_oneshot_handoff handoff;
    struct failure_raw raw[LI2_FAILURE_RAW_ROWS];
    struct failure_backend backend[LI2_FAILURE_BACKEND_ROWS];
    struct failure_event event[2];
    struct li2_oneshot_owner owner_before_cleanup,owner_after_cleanup;
    struct li2_oneshot_lifecycle_progress backend_after;
    unsigned char source_before[LI2_ONESHOT_PAGE],source_after[LI2_ONESHOT_PAGE];
    uint64_t data_address,data_before_observed,data_after_observed;
    unsigned char data_before[LI2_ONESHOT_PAGE],data_after[LI2_ONESHOT_PAGE];
};
#endif
