#pragma once
#include <cstddef>
#include <cstdint>

struct OuterInput {
    std::uint64_t callee[6]; // DWARF RBX,RBP,R12,R13,R14,R15
    std::uint64_t (*subject)();
};
struct OuterOutput {
    std::uint64_t call_rsp;
    std::uint64_t return_pc;
    std::uint64_t result;
    std::uint64_t callee[6];
};
static_assert(sizeof(OuterInput) == 56);
static_assert(offsetof(OuterInput, subject) == 48);
static_assert(sizeof(OuterOutput) == 72);
static_assert(offsetof(OuterOutput, callee) == 24);

struct FrameRecord {
    std::uint64_t ip, cfa, callee[6];
    std::int32_t before_instruction;
    std::uint32_t owned;
};
struct TraceRecord {
    FrameRecord frames[32];
    std::uint64_t context, context_rbx, context_pc, context_rsp, xstate_address;
    std::uint32_t count, reached_outer, overflow, context_changed;
    std::int32_t result;
    std::uint32_t reserved;
};
struct CaptureConfig {
    std::uint64_t outer_return, outer_begin, outer_end;
    std::uint64_t source_begin, source_end, generated_begin, generated_end;
    std::uint64_t context_bytes, context_rbx_offset, context_descriptor_offset;
    TraceRecord *records;
    std::uint32_t capacity, count, failure, reserved;
};
static_assert(sizeof(FrameRecord) == 72);
static_assert(sizeof(TraceRecord) == 2368);
static_assert(offsetof(TraceRecord, context) == 2304);
static_assert(offsetof(TraceRecord, count) == 2344);
static_assert(sizeof(CaptureConfig) == 104);
static_assert(offsetof(CaptureConfig, records) == 80);
extern "C" {
void uw_outer(const OuterInput *, OuterOutput *) noexcept;
std::uint64_t uw_frameless() noexcept;
std::uint64_t uw_frame_pointer() noexcept;
void uw_collect_original() noexcept;
void uw_collect_hook(void *) noexcept;
void uw_capture_configure(CaptureConfig *) noexcept;
void uw_register(const std::uint8_t *) noexcept;
std::uint64_t uw_registration_count() noexcept;
void uw_consumer_addresses(std::uintptr_t *) noexcept;
const std::uint8_t *uw_find_fde(std::uint64_t) noexcept;
extern const std::uint8_t uw_outer_begin[], uw_outer_end[], uw_outer_call[], uw_outer_return[];
extern const std::uint8_t uw_frameless_selected[], uw_frameless_call[], uw_frameless_after_call[], uw_frameless_end[];
extern const std::uint8_t uw_frame_pointer_selected[], uw_frame_pointer_call[], uw_frame_pointer_after_call[], uw_frame_pointer_end[];
}
