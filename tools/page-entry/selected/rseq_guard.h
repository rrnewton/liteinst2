#ifndef LI2_RSEQ_GUARD_H
#define LI2_RSEQ_GUARD_H
#if defined(LI2_RSEQ_NATIVE_BOUNDARY) && (!defined(LI2_RSEQ_NATIVE) || LI2_RSEQ_NATIVE_BOUNDARY != 1)
#error "Registered boundary retry requires its explicit native profile"
#endif
#ifdef LI2_RSEQ_TIOCGWINSZ_BTRFS
#if LI2_RSEQ_TIOCGWINSZ_BTRFS != 1 || !defined(LI2_RSEQ_TCGETS_BTRFS) || LI2_RSEQ_TCGETS_BTRFS != 1
#error "TIOCGWINSZ requires the explicit TCGETS btrfs capture profile"
#endif
#endif
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include "decoder.h"
#include "lifecycle_loader.h"
#include "write_footprint.h"

/* Explicit registered-but-inactive profile. No API permits an active rseq
   critical section or changes an application byte to manufacture inactivity. */
enum li2_rseq_error {
    LI2_RSEQ_ARGUMENT=1200,LI2_RSEQ_STATE,LI2_RSEQ_IDENTITY,LI2_RSEQ_AREA,
    LI2_RSEQ_MAPPING,LI2_RSEQ_OVERLAP,LI2_RSEQ_FOOTPRINT,LI2_RSEQ_UNSUPPORTED,
    LI2_RSEQ_OVERFLOW,LI2_RSEQ_WORD,LI2_RSEQ_TLS,LI2_RSEQ_PLAN
};
enum li2_rseq_phase { LI2_RSEQ_IDLE,LI2_RSEQ_PREPARING,LI2_RSEQ_ISSUING,
    LI2_RSEQ_ACTIVE,LI2_RSEQ_UNREGISTERING };
struct li2_rseq_data {
    uintptr_t address,page;
    uint64_t allocation,generation,offset;
    long pid,tid;
    unsigned attempted,complete,error;
    long detail;
    struct li2_fetch_map_progress maps;
};
/* Read-only actual owned anonymous RW/NX page observation. No permission
   changes, no allocation and no hooks.fail, including errors while pending. */
int li2_lifecycle_rseq_data(uintptr_t,struct li2_rseq_data *);
struct li2_rseq_transaction {
    long args[6],result;
    unsigned attempted,issued,returned,prior_registered,input_word_observed;
    uint64_t input_word;
    struct li2_rseq_data before,after;
};
struct li2_rseq_state {
    unsigned initialized,registered,held,first_error;
    volatile sig_atomic_t phase;
    long first_detail,pid,tid;
    uintptr_t address,page;
    uint32_t length,signature;
    uint64_t epoch,fs_base,gs_base;
    long fs_result,gs_result;
    unsigned tls_attempted,tls_complete;
    uint64_t calls,registrations,unregistrations,kernel_errors;
    uint64_t instruction_checks,range_checks,repeat_checks,run_checks,syscall_checks;
    uint64_t last_first,last_end,last_pc,last_code,last_policy;
    struct li2_write_footprint last_footprint;
    struct li2_rseq_data data;
    struct li2_rseq_transaction transaction;
};
/* Private callback excludes runtime/altstack/cache/source ranges. It must
   exclude this owner's dynamic pin from its own test. */
int li2_rseq_initialize(int (*private_range)(uintptr_t,size_t));
const struct li2_rseq_state *li2_rseq_snapshot(void);
int li2_rseq_mapping_overlap(uintptr_t,size_t);
int li2_rseq_dispatch(const long[6],long *);
int li2_rseq_before_syscall(long,const long[6]);
int li2_rseq_after_syscall(long,const long[6]);
/* Caller authenticates genuine entry/source/frame before these guards, then
   keeps it unchanged until the original instruction. Errors return to that
   actual cleanup owner; they never call hooks.fail recursively. */
int li2_rseq_check_instruction(const struct li2_decoded *,const ucontext_t *);
struct li2_run_plan;
int li2_rseq_check_run(const struct li2_run_plan *,const ucontext_t *);
#ifdef LI2_UNROLLED_HASH
struct li2_unrolled_hash_plan;
int li2_rseq_check_unrolled(const struct li2_unrolled_hash_plan *,const ucontext_t *);
#endif
#ifdef LI2_SCALAR_REGION
#if LI2_SCALAR_REGION != 1 || !defined(LI2_NATIVE_PAIR) || LI2_NATIVE_PAIR != 1 || \
    !defined(LI2_RSEQ_NATIVE) || LI2_RSEQ_NATIVE != 1
#error "Scalar regions require the explicit native-pair registered-rseq profile"
#endif
struct li2_region_plan;
/* Separate typed no-write proof. The caller first validates the complete plan
   and held full-page source ticket, authenticates the actual current kernel
   frame/session/TLS, and serializes decoder use. This helper grants neither
   source nor executable authority and does not synthesize a run/unroll plan. */
int li2_rseq_check_region(const struct li2_region_plan *,const ucontext_t *);
#endif

#ifdef LI2_RSEQ_TCGETS_BTRFS
#include "rseq_tcgets_btrfs.h"

#endif
#ifdef LI2_RSEQ_NATIVE
#if LI2_RSEQ_NATIVE != 1 || !defined(LI2_NATIVE_PAGES) || !defined(LI2_RSEQ_INACTIVE) || \
    !defined(LI2_MAPS_PHASE_REUSE) || !defined(LI2_TF_HANDOFF) || \
    !defined(LI2_REGISTER_RUN) || !defined(LI2_CPUID_NX_ONLY)
#error "Registered native epochs require the complete CPUID-NX native-page profile"
#endif
#if defined(LI2_ONESHOT_PUBLICATION) && (!defined(LI2_ONESHOT_REUSABLE) ||     LI2_ONESHOT_REUSABLE != 1 || !defined(LI2_EFFECT_PROVIDER) || LI2_EFFECT_PROVIDER != 1)
#error "Registered native epochs require the distinct reusable publication owner"
#endif
enum li2_rseq_native_phase { LI2_RN_IDLE,LI2_RN_PREPARED,LI2_RN_EXECUTING,
    LI2_RN_CLOSING,LI2_RN_FAILED };
enum li2_rseq_native_error { LI2_RN_STATE=1470,LI2_RN_PIN,LI2_RN_WORD,
    LI2_RN_ENTRY,LI2_RN_CLOSE,LI2_RN_TLS,LI2_RN_OVERFLOW,LI2_RN_REENTRY };
/* Separate private epoch. The old inactive-owner layout and every old guard
   remain unchanged; exit zero does not prove nonpublication during execution. */
struct li2_rseq_native_state {
    volatile sig_atomic_t phase,checking;
    unsigned first_error,unsafe_terminal,entry_checked;
    long first_detail,pid,tid;
    uint64_t attempts,admissions,preentries,entries,closed,tls_refreshes;
    uintptr_t pc,address,page;
    uint64_t registration_epoch,native_admissions_before,native_closed_before;
    uint32_t length,signature;
    uint64_t word_before,word_entry,word_after;
    uint64_t fs_before,gs_before,fs_after,gs_after;
    uint16_t fs_selector_entry,gs_selector_entry,fs_selector_after,gs_selector_after;
    struct li2_rseq_data before,after;
};
const struct li2_rseq_native_state *li2_rseq_native_snapshot(void);
/* First handler statement, before even generic checked()/fatal cleanup. Pure
   retained-pin/word observation; contradictions use only nonreturning exit. */
void li2_rseq_native_preentry(void);
int li2_rseq_native_prepare(uintptr_t);
int li2_rseq_native_publish(uintptr_t);
int li2_rseq_native_enter(int,siginfo_t *,const ucontext_t *);
int li2_rseq_native_closed(void);
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
#include "rseq_native_boundary.h"
#endif
#endif
#ifdef LI2_EFFECT_PROVIDER
#include "rseq_selected.h"
#endif
#ifdef LI2_ONESHOT_REUSABLE
#include "rseq_publication.h"
#endif
#endif
