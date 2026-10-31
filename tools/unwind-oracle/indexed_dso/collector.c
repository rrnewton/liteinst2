#include "witness.h"
#include <string.h>
#include <unwind.h>

/* This GNU consumer ABI must be joined to the actual loaded libgcc build. */
struct Li2UwBases { void *text, *data, *function; };
extern const void *_Unwind_Find_FDE(const void *, struct Li2UwBases *);

static struct Li2UwConfig config;
static struct Li2UwStatus status;
static const int columns[6] = {3, 6, 12, 13, 14, 15};
static const struct Li2UwLayout layout = {
    176, 0, 8, {104, 96, 40, 32, 24, 16}, 144
};

static int span(uintptr_t begin, size_t bytes, struct Li2UwRange *out) {
    if (!begin || !bytes || bytes > UINTPTR_MAX - begin)
        return 0;
    *out = (struct Li2UwRange){begin, begin + bytes};
    return 1;
}
static int valid(struct Li2UwRange r) { return r.begin && r.begin < r.end; }
static int covers(struct Li2UwRange outer, struct Li2UwRange inner) {
    return valid(outer) && valid(inner) && outer.begin <= inner.begin && inner.end <= outer.end;
}
static int overlap(struct Li2UwRange a, struct Li2UwRange b) {
    return a.begin < b.end && b.begin < a.end;
}
static int contains(struct Li2UwRange range, uintptr_t pc) {
    return range.begin <= pc && pc < range.end;
}
static uint64_t word(const void *p) {
    uint64_t value;
    memcpy(&value, p, sizeof value);
    return value;
}

LI2_UW_PUBLIC int li2_uw_configure(const struct Li2UwConfig *next) {
    struct Li2UwRange records, caller, slot, input, control, counters;
    if (status.busy || status.configured || status.failure || !next) {
        status.failure |= LI2_UW_BAD_CONFIG;
        return 0;
    }
    if (!next->capacity || next->capacity > LI2_UW_MAX_CAPTURES || next->reserved ||
        !next->caller_bytes || next->caller_bytes > LI2_UW_CALLER_BYTES ||
        memcmp(&next->layout, &layout, sizeof layout) ||
        !span((uintptr_t)next->records, next->capacity * sizeof *next->records, &records) ||
        !span((uintptr_t)next, sizeof *next, &input) ||
        !span((uintptr_t)&config, sizeof config, &control) ||
        !span((uintptr_t)&status, sizeof status, &counters) ||
        !span(next->caller_memory, next->caller_bytes, &caller) ||
        !span(next->caller_return_slot, sizeof(uint64_t), &slot) ||
        !covers(next->stack, caller) || !covers(caller, slot) ||
        overlap(records, next->stack) || overlap(records, input) ||
        overlap(records, control) || overlap(records, counters) ||
        !valid(next->source) || !valid(next->reference) || !valid(next->caller) ||
        !contains(next->source, next->selected) ||
        next->source.end - next->selected < 5 ||
        !(next->caller.begin < next->caller_return && next->caller_return <= next->caller.end) ||
        ((next->generated.begin || next->generated.end) && !valid(next->generated))) {
        status.failure |= LI2_UW_BAD_CONFIG;
        return 0;
    }
    const struct Li2UwRange code[4] = {
        next->source, next->reference, next->caller, next->generated
    };
    for (size_t i = 0; i < 4; ++i) {
        if (valid(code[i]) && (overlap(records, code[i]) || overlap(next->stack, code[i]))) {
            status.failure |= LI2_UW_BAD_CONFIG;
            return 0;
        }
        for (size_t j = 0; j < i; ++j) {
            if (valid(code[i]) && overlap(code[i], code[j])) {
                status.failure |= LI2_UW_BAD_CONFIG;
                return 0;
            }
        }
    }
    config = *next;
    status.configured = 1;
    status.count = 0;
    return 1;
}

LI2_UW_PUBLIC struct Li2UwStatus li2_uw_capture_status(void) { return status; }
LI2_UW_PUBLIC struct Li2UwStatus li2_uw_capture_end(void) {
    if (status.busy || !status.configured) {
        status.failure |= LI2_UW_BAD_CONFIG;
        return status;
    }
    struct Li2UwStatus result = status;
    status.configured = 0;
    memset(&config, 0, sizeof config);
    return result;
}

static _Unwind_Reason_Code step(struct _Unwind_Context *context, void *opaque) {
    struct Li2UwTrace *trace = opaque;
    if (trace->frame_count == LI2_UW_MAX_FRAMES) {
        trace->overflow = 1;
        trace->flags |= LI2_UW_BAD_FRAME;
        return _URC_NORMAL_STOP;
    }
    struct Li2UwFrame *frame = &trace->frames[trace->frame_count++];
    int before = -1;
    frame->ip = _Unwind_GetIPInfo(context, &before);
    frame->cfa = _Unwind_GetCFA(context);
    frame->before_instruction = before;
    if (before != 0 && before != 1) {
        trace->flags |= LI2_UW_BAD_FRAME;
        return _URC_NORMAL_STOP;
    }
    uintptr_t pc = frame->ip && !before ? frame->ip - 1 : frame->ip;
    frame->owned =
        (contains(config.source, pc) ? LI2_UW_SOURCE_FRAME : 0) |
        (contains(config.reference, pc) ? LI2_UW_REFERENCE_FRAME : 0) |
        (contains(config.generated, pc) ? LI2_UW_GENERATED_FRAME : 0) |
        (contains(config.caller, pc) ? LI2_UW_CALLER_FRAME : 0);
    if (frame->owned)
        for (size_t i = 0; i < 6; ++i)
            frame->callee[i] = _Unwind_GetGR(context, columns[i]);
    if (frame->ip == config.caller_return) {
        if (frame->owned == LI2_UW_CALLER_FRAME && before == 0)
            trace->reached_caller = 1;
        else
            trace->flags |= LI2_UW_BAD_FRAME;
        return _URC_NORMAL_STOP;
    }
    return _URC_NO_REASON;
}

static LI2_UW_NOINLINE void collect(void *context) {
    if (!status.configured) { status.failure |= LI2_UW_NOT_CONFIGURED; return; }
    if (status.busy) { status.failure |= LI2_UW_REENTRY; return; }
    if (status.count == config.capacity) { status.failure |= LI2_UW_CAPTURE_OVERFLOW; return; }
    status.busy = 1;
    struct Li2UwTrace *trace = &config.records[status.count++];
    memset(trace, 0, sizeof *trace);
    trace->result = -1; /* No unwinder invocation yet. */
    trace->kind = context ? LI2_UW_GENERATED : LI2_UW_ORIGINAL;
    trace->context_address = (uintptr_t)context;
    trace->caller_address = config.caller_memory;
    struct Li2UwRange region;
    if (context && (!valid(config.generated) ||
                    !span((uintptr_t)context, layout.bytes, &region) ||
                    !covers(config.stack, region))) {
        trace->flags |= LI2_UW_BAD_CONTEXT;
        goto done;
    }
    memcpy(trace->caller_before, (const void *)config.caller_memory, config.caller_bytes);
    trace->original_return_before = word((const void *)config.caller_return_slot);
    if (context) {
        memcpy(trace->context_before, context, layout.bytes);
        trace->saved_pc = word(trace->context_before + layout.pc);
        trace->saved_rsp = word(trace->context_before + layout.rsp);
        for (size_t i = 0; i < 6; ++i)
            trace->saved_callee[i] = word(trace->context_before + layout.callee[i]);
        for (size_t i = 0; i < 4; ++i)
            trace->saved_xstate[i] = word(trace->context_before + layout.xstate + 8 * i);
        if (trace->saved_pc != config.selected || trace->saved_rsp != config.caller_return_slot)
            trace->flags |= LI2_UW_BAD_CONTEXT;
    }
    if (trace->original_return_before != config.caller_return)
        trace->flags |= LI2_UW_BAD_CALLER;
    if (!trace->flags)
        trace->result = (int32_t)_Unwind_Backtrace(step, trace);
    memcpy(trace->caller_after, (const void *)config.caller_memory, config.caller_bytes);
    trace->original_return_after = word((const void *)config.caller_return_slot);
    trace->caller_changed = memcmp(trace->caller_before, trace->caller_after, config.caller_bytes) != 0;
    if (context) {
        memcpy(trace->context_after, context, layout.bytes);
        trace->context_changed = memcmp(trace->context_before, trace->context_after, layout.bytes) != 0;
    }
    if (trace->caller_changed || trace->context_changed)
        trace->flags |= LI2_UW_CHANGED_MEMORY;
done:
    status.failure |= trace->flags;
    status.busy = 0;
}

LI2_UW_HIDDEN LI2_UW_NOINLINE void li2_uw_collect_original(void) { collect(NULL); }
LI2_UW_HIDDEN LI2_UW_NOINLINE void li2_uw_hook(void *context) { collect(context); }

LI2_UW_PUBLIC void li2_uw_consumer_addresses(uintptr_t output[5]) {
    output[0] = (uintptr_t)&_Unwind_Find_FDE;
    output[1] = (uintptr_t)&_Unwind_Backtrace;
    output[2] = (uintptr_t)&_Unwind_GetIPInfo;
    output[3] = (uintptr_t)&_Unwind_GetCFA;
    output[4] = (uintptr_t)&_Unwind_GetGR;
}
LI2_UW_PUBLIC const void *li2_uw_find_fde(uintptr_t pc) {
    struct Li2UwBases bases = {0};
    return _Unwind_Find_FDE((const void *)pc, &bases);
}
