#ifndef LI2_UNROLLED_HASH_H
#define LI2_UNROLLED_HASH_H
#include "decoder.h"
#include <stddef.h>
#include <stdint.h>

#define LI2_UNROLLED_HASH_VERSION 1U
#define LI2_UNROLLED_HASH_SOURCE 39U
#define LI2_UNROLLED_HASH_BODY 24U
#define LI2_UNROLLED_HASH_COPIED 22U
#define LI2_UNROLLED_HASH_INSNS 8U
#define LI2_UNROLLED_HASH_COPIES 64U
#define LI2_UNROLLED_HASH_STRIDE 28U
#define LI2_UNROLLED_HASH_CODE 1797U
#define LI2_UNROLLED_HASH_MAX_ORIGINAL_STEPS 512U
#define LI2_UNROLLED_HASH_HEADS 513U
enum li2_unrolled_hash_status {
    LI2_UNROLLED_HASH_OK=0, LI2_UNROLLED_HASH_MISS=1,
    LI2_UNROLLED_HASH_ARGUMENT=2300, LI2_UNROLLED_HASH_DECODE,
    LI2_UNROLLED_HASH_SHAPE
};
enum li2_unrolled_hash_pc_kind {
    LI2_UNROLLED_HASH_COPIED_INSTRUCTION=1,
    LI2_UNROLLED_HASH_SUBSTITUTED_JZ=2,
    LI2_UNROLLED_HASH_FINAL_HEAD_JMP=3
};
struct li2_unrolled_hash_plan {
    uint32_t version,ready,decoder_calls,decoder_result;
    uintptr_t pc,stop,entry;
    unsigned char source[LI2_UNROLLED_HASH_SOURCE];
    unsigned char generated[LI2_UNROLLED_HASH_CODE];
    struct li2_decoded instructions[LI2_UNROLLED_HASH_INSNS],guard;
};
struct li2_unrolled_hash_pc {
    uint32_t version,ready,copy_index,source_offset,kind;
    uint32_t source_length,generated_length,reserved;
    uintptr_t original_pc,generated_pc;
};

/* Descriptions only: no publication, ownership, execution or data authority.
   All buffers are valid, aligned, complete, mutually disjoint owned storage;
   decoder is genuinely initialized/sealed. Source is exactly 39 bytes, with
   the fixed 24-byte original loop and a genuine 15-byte original guard window
   on one 4KiB page. All eight original instructions (including JNZ) and guard
   are actually decoded. The actual 89db MOV EBX,EBX guard (Code281, length2)
   is retained but never emitted or executed by this tactic.
   Each of 64 copies contains the exact first 22 bytes, then JZ rel32 to stop.
   A final JMP rel32 returns to pc on copy64's nonzero result. All 65 signed
   displacements and complete emitted bytes are checked; no absolute literal,
   indirect branch, call, return or memory store is emitted. Numeric window
   checks do not authenticate live page permissions, aliases or identities. */
int li2_unrolled_hash_plan_bytes(uintptr_t,const unsigned char *,size_t,
                                uintptr_t,struct li2_unrolled_hash_plan *);
/* Exact generated instruction heads only; interior/outside bytes return MISS.
   Every copied head maps to pc+source_offset in its copy. Each substituted JZ
   and the final head JMP map to the original JNZ at pc+22. The final JMP has
   copy_index=63. A PC association is not authority to resume or complete a
   fault. A malformed full plan is SHAPE, never a permissive partial map. */
int li2_unrolled_hash_map_pc(const struct li2_unrolled_hash_plan *,uintptr_t,
                           struct li2_unrolled_hash_pc *);

/* NEW DISTINCT RUNTIME CONTRACT -- not implemented by these pure APIs:
   Authenticate exact first-byte original NX, current source allocation and
   generation, all 39 source bytes/SEALED backing/stat/four seals/live VMA/
   aliases, old no-debug/no-CET/singleton/blocked-asynchronous/rseq-safe profile,
   all other owners closed, actual full saved frame/mask/bases/XSTATE/PKRU,
   logical TF=RF=0 and the existing RSP ingress bound before any owner RAW.
   A new typed source and rseq proof must not widen or forge old fetch15,
   register-run, WholeFunctionRequest or native-page execution permissions.
   Bind canonical overflow-free source/entry/exit ranges, disjoint original/
   generated/protected pages, actual immutable retained near-slot publication,
   all four seals, W^X, RX readback of all1797 bytes, no writable alias and
   sync-core. Source remains NX and unmodified. A plan alone supplies none of
   these proofs. Unsupported pre-entry states retain unchanged old routes.

   Entry changes only saved RIP; TF remains clear. The actual sigreturn must
   restore the application's complete XSTATE including PKRU before generated
   code. Only the application's CPU MOVZX reads bytes at successive RCX+1;
   neither handler nor planner pre-reads data, predicts a terminator, changes
   PKRU for access, or simulates the result using handler privileges. Original
   access rights, fault semantics and all existing no-write/private-range/
   rseq constraints still apply. No source byte is rewritten.

   Each completed copy preserves the eight original instruction effects:
   full64 entry RDX participates in the first ADD, later RDX is zero-extended
   from actual CPU byte reads. At first zero, JZ exits to original pc+24; after
   64 nonzero reads the final JMP exits to original pc. At most64 loads/512
   original instructions execute per entry. Both destinations are original NX
   events, never synthetic TRACE. This finite budget does NOT prove whole-loop
   termination; a later re-entry is separately owned and remains under the
   original process CPU/wall bounds. No new allowance is made for a timeout.

   Do not predict TEST's undefined AF or mask it from full native comparisons.
   Preserve all actual flags and unchanged GPR/FP/stack/data state; runtime
   may validate structural zero/nonzero exit facts without handler data reads.
   Native qualification owes full actual-state comparison to original code.
   Generated read faults and any unexpected/nested event are terminal within
   this scope: retain the actual fault prefix, full frame and exact original
   PC association; never fake completion or silently retry. Resumable original
   fault delivery is a separate unimplemented capability. Preserve first error
   and actual cleanup; retirement/synchronization/source-mutation guards and
   exact dispatch of either unexecuted original exit remain owner obligations.
   Old candidates, policies, cohorts, failed outcomes and caps are unchanged. */
_Static_assert(sizeof(uintptr_t)==8,"x86-64 unrolled hash description");
_Static_assert(LI2_UNROLLED_HASH_COPIES*LI2_UNROLLED_HASH_STRIDE+5==LI2_UNROLLED_HASH_CODE,"exact generated size");
_Static_assert(LI2_UNROLLED_HASH_COPIES*LI2_UNROLLED_HASH_INSNS==LI2_UNROLLED_HASH_MAX_ORIGINAL_STEPS,"original step bound");
#endif
