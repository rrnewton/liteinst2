#ifndef LI2_SELECTED_EFFECT_H
#define LI2_SELECTED_EFFECT_H
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include "decoder.h"

/* Additive, freestanding linked-provider ABI. None of these descriptive
   objects is a fetch, publication, mapping, syscall or frame-write permit.
   Existing provider.h / provider_callback.h interfaces remain unchanged. */
#define LI2_EFFECT_ABI 1U
#define LI2_EFFECT_PAGE UINT64_C(4096)
#define LI2_EFFECT_XSTATE_MAX 65536U
enum li2_effect_register {
    LI2_EFFECT_RAX, LI2_EFFECT_RCX, LI2_EFFECT_RDX, LI2_EFFECT_RBX,
    LI2_EFFECT_RSP, LI2_EFFECT_RBP, LI2_EFFECT_RSI, LI2_EFFECT_RDI,
    LI2_EFFECT_R8, LI2_EFFECT_R9, LI2_EFFECT_R10, LI2_EFFECT_R11,
    LI2_EFFECT_R12, LI2_EFFECT_R13, LI2_EFFECT_R14, LI2_EFFECT_R15
};
enum li2_effect_selector {
    LI2_EFFECT_CS, LI2_EFFECT_SS, LI2_EFFECT_DS,
    LI2_EFFECT_ES, LI2_EFFECT_FS, LI2_EFFECT_GS
};
struct li2_effect_source {
    /* object_id is the existing never-reused lifecycle index + 1, supplied by
       its authentic owner. offset is this page's backing-file offset. A
       provider may join object_id+offset to a trusted prebound ELF inventory;
       neither these scalars nor application paths confer source authority. */
    uint64_t page, object_id, allocation, generation, offset;
    /* Exact existing lifecycle backing kind: sealed=1 has nonzero object_id;
       anonymous=2 has zero object_id. Anonymous observation does not grant
       publication or acquire a fabricated module identity. */
    uint32_t backing, reserved;
};
/* Optional view of an immutable *copy*, never a live kernel frame. The caller
   has independently qualified the complete initialized layout and assigns its
   nonzero format identity. This leaf compares every supplied byte; it does not
   infer a hardware format from a length or an identity. NONE is all zero.
   Copies must remain valid/immutable throughout the transaction. */
struct li2_effect_xstate {
    const unsigned char *bytes;
    uint32_t length, reserved;
    uint64_t format;
};
struct li2_effect_state {
    /* Selectors are existing independently qualified runtime observations;
       DS/ES or segment bases must not be reconstructed from missing ucontext
       fields. No base value is supplied or invented by this interface. */
    uint64_t pc, gpr[16], logical_flags;
    uint16_t selectors[6];
    /* Bit i says selector i was actually qualified; every other value is zero.
       This does not weaken the caller's separate full-kernel-frame oracle. */
    uint16_t selectors_observed, reserved;
    struct li2_effect_xstate xstate;
};
struct li2_effect_input {
    uint32_t abi_version, source_count;
    uint64_t sequence;
    struct li2_decoded decoded;
    struct li2_effect_source source[2];
    struct li2_effect_state before;
};
/* Only the named class payload is used; every unused field must be zero.
   CPUID uses cpuid[EAX,EBX,ECX,EDX]; clocks use value and RDTSCP aux;
   random/ID use value and random carry; syscall uses raw RAX value. */
struct li2_effect_result {
    uint32_t kind, carry, aux, reserved;
    uint64_t value;
    uint32_t cpuid[4];
};
enum li2_effect_action {
    LI2_EFFECT_NATIVE = 1, LI2_EFFECT_SCRIPTED, LI2_EFFECT_UNCOMPLETED
};
enum li2_effect_fault_origin {
    LI2_EFFECT_REFUSAL = 1, LI2_EFFECT_PROVIDER_FAULT, LI2_EFFECT_NATIVE_FAULT
};
struct li2_effect_fault {
    uint32_t origin, code;
    int64_t detail;
    uint64_t address;
};
struct li2_effect_decision {
    uint32_t action, reserved;
    struct li2_effect_result result;
    struct li2_effect_fault fault;
};
typedef int (*li2_effect_callback)(const struct li2_effect_input *, void *,
                                  struct li2_effect_decision *);
typedef int (*li2_effect_post_callback)(const struct li2_effect_input *,
    const struct li2_effect_result *actual_native, void *, struct li2_effect_result *logical);
struct li2_effect_binding {
    uint32_t abi_version, reserved;
    li2_effect_callback callback;
    li2_effect_post_callback post_native;
    void *context;
};
extern const struct li2_effect_binding li2_effect_native_binding;

enum li2_effect_phase {
    LI2_EFFECT_EMPTY, LI2_EFFECT_CALLBACK_ENTERED, LI2_EFFECT_DECIDED,
    LI2_EFFECT_GUARDED, LI2_EFFECT_NATIVE_ENTERED, LI2_EFFECT_EXIT_ENTERED,
    LI2_EFFECT_NATIVE_RETURNED, LI2_EFFECT_POST_CALLBACK_ENTERED,
    LI2_EFFECT_OUTCOME, LI2_EFFECT_COMMITTED, LI2_EFFECT_REJECTED,
    LI2_EFFECT_FAILED
};
enum li2_effect_error {
    LI2_EFFECT_OK, LI2_EFFECT_ARGUMENT, LI2_EFFECT_STATE, LI2_EFFECT_RESULT,
    LI2_EFFECT_CALLBACK, LI2_EFFECT_COMMIT, LI2_EFFECT_NOT_COMPLETED,
    LI2_EFFECT_DECODE
};
struct li2_effect_owner {
    volatile sig_atomic_t phase;
    uint32_t first_error;
    volatile sig_atomic_t callback_entered, callback_returned;
    volatile sig_atomic_t native_entered, native_returned, exit_entered, committed;
    volatile sig_atomic_t post_guards_complete, post_callback_entered, post_callback_returned;
    int callback_status, post_callback_status;
    struct li2_effect_input input;
    struct li2_effect_binding binding;
    struct li2_effect_decision decision;
    struct li2_effect_result native_result, result;
    struct li2_effect_fault fault;
};

/* Runtime integration contract:
   - The caller is the existing exclusive selected-operation owner. It has
     authenticated the original source/decoder/fetch and genuine frame, and
     supplies logical flags from that owner, not a masked synthetic NX frame.
     The existing decoder is initialized and sealed before input validation;
     its exact re-decode checks descriptions, never live ownership.
   - begin copies input. Its XSTATE view names a separate immutable private
     copy. All arguments and callback context are valid, nonoverlapping owned
     objects, disjoint from the actual ucontext and its FP image.
   - Linked callbacks are trusted, nonreentrant, allocation/TLS/syscall-free.
     It may write only its decision and explicitly owned context statistics;
     no input/source/frame/permission mutation is allowed. Its context and
     function remain valid and immutable as bindings for this transaction.
   - guarded is called after shared lifecycle/rseq/dispatch guards. Backend
     entry guards precede native_enter, which marks entry into the real
     selected backend; for SYSCALL this can be the existing lifecycle
     dispatcher. It does NOT claim a raw kernel issue. Each raw issue-specific
     guard precedes the separate existing raw syscall entry marker; raw
     entry/return observations remain independently mandatory.
     native_return records the actual backend result immediately, BEFORE the
     post-effect guards. native_outcome is called only AFTER those guards;
     it invokes post_native with original input and immutable actual result.
     Null post_native preserves that result exactly. A post callback may change
     a SYSCALL result only for getpid/gettid; owner-dispatched mapping/rseq and
     every other syscall retain the actual result. Scripted never calls it.
     Commit follows successful outcome selection and actual frame application.
   - Reuse requires the runtime to retire all prior source/publication/frame
     ownership; this leaf only checks completed/refused state and increasing
     sequence. Failed/native-interrupted/exit transactions cannot be recycled.
   - commit's actual XSTATE view is an independently captured, disjoint copy;
     never pass expected()'s retained before-image as the actual observation.
   No function here executes an instruction/syscall, changes memory permission,
   writes an application frame, or authorizes application continuation. */
int li2_effect_validate_input(const struct li2_effect_input *);
int li2_effect_begin(struct li2_effect_owner *, const struct li2_effect_binding *,
                     const struct li2_effect_input *);
int li2_effect_guarded(struct li2_effect_owner *);
int li2_effect_native_enter(struct li2_effect_owner *);
int li2_effect_native_return(struct li2_effect_owner *, const struct li2_effect_result *);
int li2_effect_native_outcome(struct li2_effect_owner *);
int li2_effect_scripted_outcome(struct li2_effect_owner *);
int li2_effect_expected(const struct li2_effect_owner *, struct li2_effect_state *);
int li2_effect_commit(struct li2_effect_owner *, const struct li2_effect_state *);
int li2_effect_fail(struct li2_effect_owner *, unsigned);
/* Only the genuine native-fault dispatcher may supply NATIVE_FAULT, after an
   entered but unreturned attempt. Full original fault/frame custody stays with
   that dispatcher. Provider decisions cannot claim this origin. */
int li2_effect_native_fault(struct li2_effect_owner *, const struct li2_effect_fault *);

/* Finite adapter: at most 16 exact logical-PC/kind entries, immutable while
   linked. An unmatched operation uses Native. This is a convenience provider,
   not an instruction-location census or a source authority. */
#define LI2_EFFECT_SCRIPT_MAX 16U
struct li2_effect_script_entry {
    uint64_t pc;
    uint32_t kind, reserved;
    struct li2_effect_decision decision;
};
struct li2_effect_script {
    uint32_t abi_version, count;
    const struct li2_effect_script_entry *entries;
};
int li2_effect_script_callback(const struct li2_effect_input *, void *,
                               struct li2_effect_decision *);
_Static_assert(sizeof(struct li2_effect_source)==48,"effect source ABI");
_Static_assert(sizeof(struct li2_effect_xstate)==24,"effect copied XSTATE view ABI");
_Static_assert(sizeof(struct li2_effect_state)==184,"effect state ABI");
_Static_assert(sizeof(struct li2_effect_input)==368,"effect input ABI");
_Static_assert(sizeof(struct li2_effect_result)==40,"effect result ABI");
_Static_assert(sizeof(struct li2_effect_decision)==72,"effect decision ABI");
#endif
