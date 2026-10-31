#ifndef LI2_INDEXED_DSO_CALLER_H
#define LI2_INDEXED_DSO_CALLER_H

#include "witness.h"

typedef uint64_t (*Li2UwWorkFunction)(const uint8_t *, size_t, uint64_t, uint64_t *);
typedef uint64_t (*Li2UwReferenceFunction)(uint64_t);
typedef int (*Li2UwConfigureFunction)(const struct Li2UwConfig *);
typedef struct Li2UwStatus (*Li2UwStatusFunction)(void);

/* Values are distinct in all six DWARF callee-preserved columns. */
#define LI2_UW_CANARY_RBX UINT64_C(0x13579bdf2468ace1)
#define LI2_UW_CANARY_RBP UINT64_C(0x2468ace113579bdf)
#define LI2_UW_CANARY_R12 UINT64_C(0x3141592653589793)
#define LI2_UW_CANARY_R13 UINT64_C(0x2718281828459045)
#define LI2_UW_CANARY_R14 UINT64_C(0x55aa33cc77ee1199)
#define LI2_UW_CANARY_R15 UINT64_C(0xaa55cc33ee779911)
#define LI2_UW_OUTPUT_POISON UINT64_C(0xc3c35a5a96966969)

enum {
    LI2_UW_CALL_WORK = 1,
    LI2_UW_CALL_REFERENCE = 2,
    LI2_UW_CALL_BAD_REQUEST = 1,
    LI2_UW_CALL_BAD_STATUS = 2,
    LI2_UW_CALL_CONFIG_FAILED = 4,
    LI2_UW_CALL_BAD_RSP = 8,
    LI2_UW_CALL_BAD_CANARY = 16,
    LI2_UW_CALL_BAD_GUARD = 32
};

/* All pointers, ranges and function identities are admitted by the future
 * driver, not by this numeric wrapper. return_pc is the decoded target CALL's
 * next_ip, never the address of a label after a C expression. The wrapper copies
 * config and replaces only caller_memory/bytes, caller_return_slot/return with
 * the sampled eight-byte hardware return slot and this authenticated PC. */
struct Li2UwCallerControl {
    struct Li2UwConfig config;
    Li2UwConfigureFunction configure;
    Li2UwStatusFunction status, end;
    uintptr_t return_pc;
};

struct Li2UwCallerObservation {
    uintptr_t rsp_sample, rsp_configured, rsp_pre, rsp_post;
    uintptr_t caller_return_slot, caller_return;
    uint64_t callee_before[6], callee_after[6];
    uint64_t guard_before[4], guard_after[4];
    uint64_t output_before, output_after, result;
    struct Li2UwStatus status_before, status_configured, status_after;
    struct Li2UwStatus status_end, status_final;
    int32_t configure_result;
    uint32_t kind, failures, configure_attempted, invocation_dispatched;
    uint32_t normal_returned, end_attempted;
};

/* These two functions have different target types and paths. The reference
 * path never receives or invokes the selected-work function. Return 1 means
 * only that the local comparisons passed; it is not unwinder qualification.
 * Raw status/observations remain available on every ordinary return. */
LI2_UW_NOINLINE int li2_uw_call_work(
    const struct Li2UwCallerControl *, Li2UwWorkFunction,
    const uint8_t *, size_t, uint64_t, struct Li2UwCallerObservation *);
LI2_UW_NOINLINE int li2_uw_call_reference(
    const struct Li2UwCallerControl *, Li2UwReferenceFunction,
    uint64_t, struct Li2UwCallerObservation *);

extern const uint8_t li2_uw_caller_work_sample[], li2_uw_caller_work_configured[];
extern const uint8_t li2_uw_caller_work_pre[], li2_uw_caller_work_post[];
extern const uint8_t li2_uw_caller_work_canary_before[], li2_uw_caller_work_canary_after[];
extern const uint8_t li2_uw_caller_reference_sample[];
extern const uint8_t li2_uw_caller_reference_configured[];
extern const uint8_t li2_uw_caller_reference_pre[], li2_uw_caller_reference_post[];
extern const uint8_t li2_uw_caller_reference_canary_before[];
extern const uint8_t li2_uw_caller_reference_canary_after[];

/* FUTURE DRIVER REQUIREMENTS -- all compiled/native admission is UNRUN.
 * Compile ordinary GNU C with -O2 -fomit-frame-pointer -fno-lto
 * -fno-optimize-sibling-calls -fcf-protection=none -fno-stack-protector and
 * -fasynchronous-unwind-tables, without instrumentation/sanitizers. The DSO
 * requirements in README.md also remain mandatory. No naked or assembly-only
 * caller, stack switching, CFI registration, concurrent entry or handler is
 * supplied here. Use authenticated RTLD_NOW functions and the declared separate
 * reference walk for readiness before any selected invocation.
 *
 * Decode the complete actual caller CFG/CFI, including configuration/status
 * calls and all incoming edges. Each path from pre that reaches post must make
 * exactly the intended ordinary indirect CALL and return, with four SysV
 * register arguments for work. Bind return_pc to that CALL.next_ip(). Labels
 * mark proof boundaries, not hardware return addresses. Prove the caller's RSP
 * is constant from sample through target CALL and post, except for balanced
 * ordinary CALL/RET edges; callees and owned stack mappings need their own
 * admission. Equality of sampled RSPs does not prove the unsampled interval.
 *
 * GNU register variables do not reserve registers. Read/write empty asm keeps
 * the six values live but can still permit spills/reloads; output-only asm
 * would instead let pre-call values die and permit reuse. Reject any compiled
 * local overwrite/reload of the six columns between canary_before and the
 * target CALL or between its return and canary_after. The canary labels emit
 * no instruction; their read/write operands delimit the observations. Do not
 * change the expected canaries or substitute an assembly trampoline if
 * compilation fails.
 *
 * Independently prove exact input/output/observation/config/record ownership
 * and disjointness, executable ranges, stack validity, CPU/CET, immutable maps,
 * source CFI and loaded-consumer identity/readiness. The protected return slot
 * is eight bytes; the separately observed output guards are not a whole-stack
 * preservation claim. Retain all raw traces/status, compare the independent
 * work/reference result and exact capture counts (original work 0, installed
 * work 1, reference 1), and require the intended frame order/recovered state.
 * These wrappers provide no map authority, supervisor, exception support or
 * performance/normal-backtrace qualification. A failed proof is a refusal.
 */

#endif
