#ifndef LI2_INDEXED_DSO_WITNESS_H
#define LI2_INDEXED_DSO_WITNESS_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__GNUC__) || !defined(__x86_64__) || !defined(__linux__)
#error "This fixture requires GNU C on Linux x86-64"
#endif

#define LI2_UW_PUBLIC __attribute__((visibility("default")))
#define LI2_UW_HIDDEN __attribute__((visibility("hidden")))
#define LI2_UW_NOINLINE __attribute__((noinline, noclone, noipa))

enum {
    LI2_UW_MAX_FRAMES = 32,
    LI2_UW_MAX_CAPTURES = 2,
    LI2_UW_CONTEXT_BYTES = 176,
    LI2_UW_CALLER_BYTES = 256,
    LI2_UW_ORIGINAL = 1,
    LI2_UW_GENERATED = 2,
    LI2_UW_SOURCE_FRAME = 1,
    LI2_UW_REFERENCE_FRAME = 2,
    LI2_UW_GENERATED_FRAME = 4,
    LI2_UW_CALLER_FRAME = 8,
    LI2_UW_BAD_CONFIG = 1,
    LI2_UW_NOT_CONFIGURED = 2,
    LI2_UW_REENTRY = 4,
    LI2_UW_CAPTURE_OVERFLOW = 8,
    LI2_UW_BAD_CONTEXT = 16,
    LI2_UW_BAD_CALLER = 32,
    LI2_UW_CHANGED_MEMORY = 64,
    LI2_UW_BAD_FRAME = 128
};

struct Li2UwRange { uintptr_t begin, end; };

/* Exact HookContext v1, supplied independently by the driver and checked here.
 * Callee order is DWARF RBX, RBP, R12, R13, R14, R15. */
struct Li2UwLayout {
    uint32_t bytes, pc, rsp, callee[6], xstate;
};

struct Li2UwFrame {
    uint64_t ip, cfa, callee[6];
    int32_t before_instruction;
    uint32_t owned;
};

struct Li2UwTrace {
    struct Li2UwFrame frames[LI2_UW_MAX_FRAMES];
    uint8_t context_before[LI2_UW_CONTEXT_BYTES];
    uint8_t context_after[LI2_UW_CONTEXT_BYTES];
    uint8_t caller_before[LI2_UW_CALLER_BYTES];
    uint8_t caller_after[LI2_UW_CALLER_BYTES];
    uintptr_t context_address;
    uint64_t saved_pc, saved_rsp, saved_callee[6], saved_xstate[4];
    uintptr_t caller_address;
    uint64_t original_return_before, original_return_after;
    uint32_t frame_count, reached_caller, overflow, context_changed;
    uint32_t caller_changed, kind, flags;
    int32_t result;
};

/* The driver retains readable immutable stack mappings, writable record storage,
 * all code/CFI owners and the DSO handle. It proves actual permissions and that
 * records are separate from every input/output/config/code/CFI owner. Numeric
 * interval checks below do not establish mapping validity. No thread, handler,
 * concurrent writer, stack switch, unload or reentry is admitted. */
struct Li2UwConfig {
    struct Li2UwRange stack, source, reference, caller, generated;
    uintptr_t caller_memory;
    size_t caller_bytes;
    uintptr_t caller_return_slot, caller_return, selected;
    struct Li2UwLayout layout;
    struct Li2UwTrace *records;
    uint32_t capacity, reserved;
};

struct Li2UwStatus { uint32_t configured, count, failure, busy; };

_Static_assert(sizeof(uintptr_t) == 8, "64-bit pointers");
_Static_assert(sizeof(struct Li2UwLayout) == 40, "context layout ABI");
_Static_assert(sizeof(struct Li2UwFrame) == 72, "frame ABI");
_Static_assert(sizeof(struct Li2UwTrace) == 3328, "trace ABI");
_Static_assert(sizeof(struct Li2UwConfig) == 176, "configuration ABI");
_Static_assert(sizeof(struct Li2UwStatus) == 16, "status ABI");

LI2_UW_PUBLIC uint64_t li2_uw_work(const uint8_t *, size_t, uint64_t, uint64_t *);
LI2_UW_PUBLIC uint64_t li2_uw_reference(uint64_t);
LI2_UW_HIDDEN extern const uint8_t li2_uw_selected[], li2_uw_continuation[];
LI2_UW_HIDDEN void li2_uw_hook(void *);
LI2_UW_HIDDEN void li2_uw_collect_original(void);
LI2_UW_PUBLIC int li2_uw_configure(const struct Li2UwConfig *);
LI2_UW_PUBLIC struct Li2UwStatus li2_uw_capture_status(void);
LI2_UW_PUBLIC struct Li2UwStatus li2_uw_capture_end(void);
/* Find_FDE, Backtrace, GetIPInfo, GetCFA, GetGR, in that exact order. */
LI2_UW_PUBLIC void li2_uw_consumer_addresses(uintptr_t output[5]);
LI2_UW_PUBLIC const void *li2_uw_find_fde(uintptr_t);

#endif
