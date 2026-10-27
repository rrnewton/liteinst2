#ifndef LI2_SELECTED_PROVIDER_H
#define LI2_SELECTED_PROVIDER_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/ucontext.h>
#include "decoder.h"
#if !defined(__x86_64__) || !defined(__linux__)
#error "selected provider requires Linux x86-64"
#endif

enum li2_selected_status {
    LI2_SELECTED_OK=0, LI2_SELECTED_ARGUMENT=1, LI2_SELECTED_FRAME=2,
    LI2_SELECTED_FLAGS=3, LI2_SELECTED_FACTS=4, LI2_SELECTED_DECODE=5,
    LI2_SELECTED_KIND=6, LI2_SELECTED_RSP=7, LI2_SELECTED_HARDWARE=8,
    LI2_SELECTED_SCRIPT=9, LI2_SELECTED_NATIVE_RESULT=10
};
enum li2_selected_origin { LI2_SELECTED_ORIGINAL_CONTEXT=1, LI2_SELECTED_NX_KNOWN_INPUT=2 };
enum li2_selected_mechanism { LI2_SELECTED_NATIVE=1, LI2_SELECTED_SCRIPTED=2 };
enum li2_selected_phase {
    LI2_SELECTED_REFUSED=0, LI2_SELECTED_VALIDATED=1,
    LI2_SELECTED_NATIVE_ENTERED=2, LI2_SELECTED_OUTCOME_RETAINED=3,
    LI2_SELECTED_COMPLETED=4
};
/* Actual CPUID observations made before arming/trapping, never the application's
   replacement CPUID policy. These are descriptive bytes, not execution permits. */
struct li2_selected_hardware { uint32_t abi_version,reserved,leaf0[4],leaf1[4],leaf7[4]; };
/* Caller retains a runtime-owned immutable source copy and actual decoded facts.
   Its separate authority binds live address/generation/alias/full fetch extent.
   logical_flags comes from an independent known-input boundary, never from
   clearing RF in a fetch-fault frame. This initial profile requires TF/RF clear. */
struct li2_selected_request {
    const struct li2_decoded *decoded;
    const unsigned char *source;
    size_t source_bytes;
    uint64_t logical_flags;
    enum li2_selected_origin origin;
    const siginfo_t *fault;
};
/* A typed deliberate replacement: random CF=0 requires value=0; CF=1 accepts
   exactly the operand-width value. RDPID requires width64/carry0/u32 value. */
struct li2_selected_script {
    uint32_t kind,width_bits,carry,reserved;
    uint64_t value;
};
/* Every refusal leaves the ucontext unchanged. A native hardware fault can
   occur after NATIVE_ENTERED; phase/native_attempts are volatile sig_atomic_t
   for that minimal interrupted prefix. Other fields are consumed only after
   the function returns. The caller must retain this prefix and fail-stop,
   never treat nested SIGILL/another signal as a scripted result or retry. */
struct li2_selected_completion {
    uint32_t abi_version,mechanism;
    volatile sig_atomic_t phase;
    uint32_t status;
    uint32_t kind,destination,width_bits,carry;
    volatile sig_atomic_t native_attempts;
    uint32_t reserved;
    uint64_t pc,next_pc,frame_flags,logical_flags,input_destination;
    uint64_t value,output_destination,output_flags;
};

/* Pre-arm singleton call only, with actual CPUID allowed. The caller prevents
   migration to unqualified hardware and retains these observations unchanged.
   Does not execute random instructions or grant any selected/gate authority. */
int li2_selected_observe_hardware(struct li2_selected_hardware *);
/* Both completion calls run on the owner's private runtime/signal stack, with
   decoder initialized+sealed and no concurrent/reentrant decoder/provider call.
   frame is an actual live kernel ucontext, exclusively borrowed; all request,
   source, hardware/script and output allocations are valid and mutually
   disjoint from frame and its FP state. No application stack is accessed.
   Source/current generation, signal ownership, singleton and complete fetch
   dependencies are checked by the caller before calling this data operation.
   It neither opens pages nor calls sigreturn. Only destination/RFLAGS/RIP in
   frame are written; its full fpregs pointer/header/payload remain untouched. */
int li2_selected_complete_native(ucontext_t *,const struct li2_selected_request *,
    const struct li2_selected_hardware *,struct li2_selected_completion *);
int li2_selected_complete_scripted(ucontext_t *,const struct li2_selected_request *,
    const struct li2_selected_script *,struct li2_selected_completion *);
#endif
