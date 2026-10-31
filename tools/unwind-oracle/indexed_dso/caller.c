#include "caller.h"

/* Only observations/labels use inline asm. Both target invocations below are
 * ordinary C function-pointer calls with compiler-generated call/return code. */
#define LI2_SAMPLE(label, destination) \
    __asm__ volatile(".global " label "\n.hidden " label "\n" label ":\n" \
                     "movq %%rsp, %0" : "=r"(destination) : : "memory")

#define LI2_DECLARE_CANARIES \
    register uint64_t c_bx __asm__("rbx") = LI2_UW_CANARY_RBX; \
    register uint64_t c_bp __asm__("rbp") = LI2_UW_CANARY_RBP; \
    register uint64_t c_12 __asm__("r12") = LI2_UW_CANARY_R12; \
    register uint64_t c_13 __asm__("r13") = LI2_UW_CANARY_R13; \
    register uint64_t c_14 __asm__("r14") = LI2_UW_CANARY_R14; \
    register uint64_t c_15 __asm__("r15") = LI2_UW_CANARY_R15

#define LI2_OBSERVE_CANARIES(label) \
    __asm__ volatile(".global " label "\n.hidden " label "\n" label ":\n" \
                     : "+r"(c_bx), "+r"(c_bp), "+r"(c_12), \
                     "+r"(c_13), "+r"(c_14), "+r"(c_15) : : "memory")

#define LI2_SAVE_CANARIES(destination) do { \
    (destination)[0] = c_bx; (destination)[1] = c_bp; \
    (destination)[2] = c_12; (destination)[3] = c_13; \
    (destination)[4] = c_14; (destination)[5] = c_15; \
} while (0)

/* Explicit nonzero initializers keep both complete cells in file-backed data.
 * Runtime ownership can then use the retained file's inode and offset. Every
 * call still resets all 64 bytes before capturing eight fresh physical values. */
LI2_UW_HIDDEN volatile struct Li2UwRawReturn li2_uw_work_raw = {
    .result = UINT64_C(0x776f726b72617731)
};
LI2_UW_HIDDEN volatile struct Li2UwRawReturn li2_uw_reference_raw = {
    .result = UINT64_C(0x7265667261773031)
};
_Static_assert(sizeof(struct Li2UwRawReturn) == 64, "raw return ABI");
_Static_assert(offsetof(struct Li2UwRawReturn, rsp) == 8, "raw RSP ABI");
_Static_assert(offsetof(struct Li2UwRawReturn, callee) == 16, "raw callee ABI");

/* Capture first, then let C export its ordinary observations. The RAX input
 * ties the actual C return value to RAX without changing any callee register.
 * The machine-code gate must still prove no reload/rematerialization between
 * CALL and this block, and exact physical-register stores at all eight cells.
 * A damaged RSP can therefore never choose the capture destination. */
#define LI2_CAPTURE_RETURN(label, raw, returned, destination) \
    __asm__ volatile(".global " label "\n.hidden " label "\n" label ":\n" \
                     "movq %%rsp, %0\n" \
                     "movq %%rax, " #raw "(%%rip)\n" \
                     "movq %%rsp, " #raw "+8(%%rip)\n" \
                     "movq %%rbx, " #raw "+16(%%rip)\n" \
                     "movq %%rbp, " #raw "+24(%%rip)\n" \
                     "movq %%r12, " #raw "+32(%%rip)\n" \
                     "movq %%r13, " #raw "+40(%%rip)\n" \
                     "movq %%r14, " #raw "+48(%%rip)\n" \
                     "movq %%r15, " #raw "+56(%%rip)\n" \
                     : "=&d"(destination) : "a"(returned) : "memory")

static void observe_box(const uint64_t box[5], uint64_t guard[4], uint64_t *value) {
    /* Volatile reads retain the actual guarded memory, not inferred constants.
     * The writable output is one element of this real five-element C array. */
    const volatile uint64_t *p = box;
    guard[0] = p[0]; guard[1] = p[1];
    *value = p[2];
    guard[2] = p[3]; guard[3] = p[4];
}

static int control_ready(const struct Li2UwCallerControl *control,
                         struct Li2UwCallerObservation *out) {
    if (!control || !control->configure || !control->status || !control->end ||
        !control->return_pc) {
        out->failures |= LI2_UW_CALL_BAD_REQUEST;
        return 0;
    }
    out->status_before = control->status();
    if (out->status_before.configured || out->status_before.failure ||
        out->status_before.busy) {
        out->failures |= LI2_UW_CALL_BAD_STATUS;
        return 0;
    }
    return 1;
}

static int configure(const struct Li2UwCallerControl *control,
                     struct Li2UwConfig *config,
                     struct Li2UwCallerObservation *out) {
    if (out->rsp_sample < sizeof(uint64_t) || out->rsp_sample % 16) {
        out->failures |= LI2_UW_CALL_BAD_RSP;
        return 0;
    }
    out->caller_return_slot = out->rsp_sample - sizeof(uint64_t);
    out->caller_return = control->return_pc;
    config->caller_memory = out->caller_return_slot;
    config->caller_bytes = sizeof(uint64_t);
    config->caller_return_slot = out->caller_return_slot;
    config->caller_return = out->caller_return;
    out->configure_attempted = 1;
    out->configure_result = control->configure(config);
    out->status_configured = control->status();
    if (out->configure_result != 1) {
        out->failures |= LI2_UW_CALL_CONFIG_FAILED;
        return 0;
    }
    if (out->status_configured.configured != 1 || out->status_configured.count ||
        out->status_configured.failure || out->status_configured.busy)
        out->failures |= LI2_UW_CALL_BAD_STATUS;
    return 1;
}

static void finish(const struct Li2UwCallerControl *control,
                   struct Li2UwCallerObservation *out) {
    out->status_after = control->status();
    out->end_attempted = 1;
    out->status_end = control->end();
    out->status_final = control->status();
    if (out->status_after.configured != 1 || out->status_after.failure ||
        out->status_after.busy || out->status_end.configured != 1 ||
        out->status_end.failure || out->status_end.busy ||
        out->status_final.configured || out->status_final.failure ||
        out->status_final.busy ||
        out->status_after.count != out->status_end.count ||
        out->status_end.count != out->status_final.count)
        out->failures |= LI2_UW_CALL_BAD_STATUS;
}

static void compare_observations(struct Li2UwCallerObservation *out) {
    const uint64_t expected[6] = {
        LI2_UW_CANARY_RBX, LI2_UW_CANARY_RBP, LI2_UW_CANARY_R12,
        LI2_UW_CANARY_R13, LI2_UW_CANARY_R14, LI2_UW_CANARY_R15
    };
    for (size_t i = 0; i < 6; ++i)
        if (out->callee_before[i] != expected[i] || out->callee_after[i] != expected[i])
            out->failures |= LI2_UW_CALL_BAD_CANARY;
    for (size_t i = 0; i < 4; ++i)
        if (out->guard_before[i] != out->guard_after[i])
            out->failures |= LI2_UW_CALL_BAD_GUARD;
    if (out->rsp_post != out->rsp_pre)
        out->failures |= LI2_UW_CALL_BAD_RSP;
}

LI2_UW_NOINLINE
int li2_uw_call_work(const struct Li2UwCallerControl *control, Li2UwWorkFunction work,
                    const uint8_t *input, size_t length, uint64_t seed,
                    struct Li2UwCallerObservation *out) {
    if (!out)
        return 0;
    *out = (struct Li2UwCallerObservation){0};
    out->kind = LI2_UW_CALL_WORK;
    if (!work || !input) {
        out->failures = LI2_UW_CALL_BAD_REQUEST;
        return 0;
    }
    if (!control_ready(control, out))
        return 0;
    uint64_t box[5] = {
        UINT64_C(0x1122334455667788), UINT64_C(0x8877665544332211),
        LI2_UW_OUTPUT_POISON,
        UINT64_C(0x123456789abcdef0), UINT64_C(0xfedcba9876543210)
    };
    observe_box(box, out->guard_before, &out->output_before);
    struct Li2UwConfig config = control->config;
    LI2_SAMPLE("li2_uw_caller_work_sample", out->rsp_sample);
    if (!configure(control, &config, out))
        return 0;
    LI2_SAMPLE("li2_uw_caller_work_configured", out->rsp_configured);
    if (out->rsp_configured != out->rsp_sample)
        out->failures |= LI2_UW_CALL_BAD_RSP;
    if (out->failures) {
        finish(control, out);
        return 0;
    }

    LI2_DECLARE_CANARIES;
    LI2_OBSERVE_CANARIES("li2_uw_caller_work_canary_before");
    LI2_SAVE_CANARIES(out->callee_before);
    LI2_SAMPLE("li2_uw_caller_work_pre", out->rsp_pre);
    if (out->rsp_pre != out->rsp_sample) {
        out->failures |= LI2_UW_CALL_BAD_RSP;
        finish(control, out);
        return 0;
    }
    li2_uw_work_raw = (struct Li2UwRawReturn){0};
    out->invocation_dispatched = 1;
    uint64_t result = work(input, length, seed, &box[2]);
    LI2_CAPTURE_RETURN("li2_uw_caller_work_post", li2_uw_work_raw, result, out->rsp_post);
    LI2_OBSERVE_CANARIES("li2_uw_caller_work_canary_after");
    LI2_SAVE_CANARIES(out->callee_after);
    out->result = result;
    out->normal_returned = 1;
    observe_box(box, out->guard_after, &out->output_after);
    compare_observations(out);
    finish(control, out);
    return out->failures == 0;
}

LI2_UW_NOINLINE
int li2_uw_call_reference(const struct Li2UwCallerControl *control,
                         Li2UwReferenceFunction reference, uint64_t value,
                         struct Li2UwCallerObservation *out) {
    if (!out)
        return 0;
    *out = (struct Li2UwCallerObservation){0};
    out->kind = LI2_UW_CALL_REFERENCE;
    if (!reference) {
        out->failures = LI2_UW_CALL_BAD_REQUEST;
        return 0;
    }
    if (!control_ready(control, out))
        return 0;
    uint64_t box[5] = {
        UINT64_C(0x1122334455667788), UINT64_C(0x8877665544332211),
        LI2_UW_OUTPUT_POISON,
        UINT64_C(0x123456789abcdef0), UINT64_C(0xfedcba9876543210)
    };
    observe_box(box, out->guard_before, &out->output_before);
    struct Li2UwConfig config = control->config;
    LI2_SAMPLE("li2_uw_caller_reference_sample", out->rsp_sample);
    if (!configure(control, &config, out))
        return 0;
    LI2_SAMPLE("li2_uw_caller_reference_configured", out->rsp_configured);
    if (out->rsp_configured != out->rsp_sample)
        out->failures |= LI2_UW_CALL_BAD_RSP;
    if (out->failures) {
        finish(control, out);
        return 0;
    }

    LI2_DECLARE_CANARIES;
    LI2_OBSERVE_CANARIES("li2_uw_caller_reference_canary_before");
    LI2_SAVE_CANARIES(out->callee_before);
    LI2_SAMPLE("li2_uw_caller_reference_pre", out->rsp_pre);
    if (out->rsp_pre != out->rsp_sample) {
        out->failures |= LI2_UW_CALL_BAD_RSP;
        finish(control, out);
        return 0;
    }
    li2_uw_reference_raw = (struct Li2UwRawReturn){0};
    out->invocation_dispatched = 1;
    uint64_t result = reference(value);
    LI2_CAPTURE_RETURN("li2_uw_caller_reference_post", li2_uw_reference_raw, result, out->rsp_post);
    LI2_OBSERVE_CANARIES("li2_uw_caller_reference_canary_after");
    LI2_SAVE_CANARIES(out->callee_after);
    out->result = result;
    out->normal_returned = 1;
    observe_box(box, out->guard_after, &out->output_after);
    compare_observations(out);
    if (out->output_after != out->output_before)
        out->failures |= LI2_UW_CALL_BAD_GUARD;
    finish(control, out);
    return out->failures == 0;
}
