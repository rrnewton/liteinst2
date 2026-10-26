#include "witness.h"
#include <cstring>
#include <unwind.h>

// Registration/lookup ABI must be bound to the actual consumer in root's
// qualification receipt. These declarations add no invented success result.
struct DwarfEhBases { void *text, *data, *function; };
extern "C" void __register_frame(const void *);
extern "C" const void *_Unwind_Find_FDE(const void *, DwarfEhBases *);

static CaptureConfig *active = nullptr;
static std::uint64_t registrations = 0;
static constexpr int callee_columns[] = {3, 6, 12, 13, 14, 15};

static _Unwind_Reason_Code step(_Unwind_Context *context, void *opaque) noexcept {
    auto *trace = static_cast<TraceRecord *>(opaque);
    if (trace->count == 32) {
        trace->overflow = 1;
        return _URC_NORMAL_STOP;
    }
    FrameRecord &frame = trace->frames[trace->count++];
    int before = -1;
    frame.ip = _Unwind_GetIPInfo(context, &before);
    frame.cfa = _Unwind_GetCFA(context);
    frame.before_instruction = before;
    const std::uint64_t lookup = frame.ip && !before ? frame.ip - 1 : frame.ip;
    frame.owned =
        (active->outer_begin <= lookup && lookup < active->outer_end) ||
        (active->source_begin <= lookup && lookup < active->source_end) ||
        (active->generated_begin <= lookup && lookup < active->generated_end);
    if (frame.owned) {
        for (std::size_t i = 0; i != 6; ++i)
            frame.callee[i] = _Unwind_GetGR(context, callee_columns[i]);
    }
    if (frame.ip == active->outer_return) {
        trace->reached_outer = 1;
        return _URC_NORMAL_STOP;
    }
    return _URC_NO_REASON;
}

__attribute__((noinline)) static void collect(void *context) noexcept {
    if (!active || active->count == active->capacity || active->capacity > 2 ||
        active->context_bytes > 256 || active->context_rbx_offset + 8 > active->context_bytes ||
        active->context_descriptor_offset + 32 != active->context_bytes) {
        if (active) active->failure = 1;
        return;
    }
    TraceRecord &trace = active->records[active->count++];
    std::memset(&trace, 0, sizeof trace);
    trace.context = reinterpret_cast<std::uintptr_t>(context);
    std::uint8_t before[256] = {};
    if (context) {
        std::memcpy(before, context, active->context_bytes);
        std::memcpy(&trace.context_pc, context, 8);
        std::memcpy(&trace.context_rsp, static_cast<std::uint8_t *>(context) + 8, 8);
        std::memcpy(&trace.context_rbx, static_cast<std::uint8_t *>(context) + active->context_rbx_offset, 8);
        std::memcpy(&trace.xstate_address, static_cast<std::uint8_t *>(context) + active->context_descriptor_offset, 8);
    }
    trace.result = _Unwind_Backtrace(step, &trace);
    if (context && std::memcmp(before, context, active->context_bytes) != 0)
        trace.context_changed = 1;
}

extern "C" void uw_capture_configure(CaptureConfig *config) noexcept { active = config; }
extern "C" __attribute__((noinline)) void uw_collect_original() noexcept { collect(nullptr); }
extern "C" __attribute__((noinline)) void uw_collect_hook(void *context) noexcept { collect(context); }
extern "C" void uw_register(const std::uint8_t *records) noexcept { ++registrations; __register_frame(records); }
extern "C" std::uint64_t uw_registration_count() noexcept { return registrations; }
extern "C" void uw_consumer_addresses(std::uintptr_t *output) noexcept {
    output[0] = reinterpret_cast<std::uintptr_t>(&__register_frame);
    output[1] = reinterpret_cast<std::uintptr_t>(&_Unwind_Find_FDE);
    output[2] = reinterpret_cast<std::uintptr_t>(&_Unwind_Backtrace);
    output[3] = reinterpret_cast<std::uintptr_t>(&_Unwind_GetIPInfo);
    output[4] = reinterpret_cast<std::uintptr_t>(&_Unwind_GetCFA);
    output[5] = reinterpret_cast<std::uintptr_t>(&_Unwind_GetGR);
}
extern "C" const std::uint8_t *uw_find_fde(std::uint64_t pc) noexcept {
    DwarfEhBases bases = {};
    return static_cast<const std::uint8_t *>(_Unwind_Find_FDE(reinterpret_cast<const void *>(pc), &bases));
}
