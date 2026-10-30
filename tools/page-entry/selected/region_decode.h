#ifndef LI2_REGION_DECODE_H
#define LI2_REGION_DECODE_H
#include "decoder.h"

/* Version 1 is a separate descriptive scalar profile, never an RX, data,
   legal-entry, rseq or generation lease. The old decoded/STEP facts are exact.
   API return uses li2_decoder_status. Any non-OK return leaves all 304 bytes
   zero. An OK return always has version=1 and a complete original decoded row;
   ready=1/refusal=0 is the ONLY supported result. Refusal leaves every field
   after decoded zero except version/refusal. No partial effect rows escape. */
enum li2_region_refusal {
    LI2_REGION_ACCEPT=0, LI2_REGION_UNSUPPORTED=1, LI2_REGION_INVALID=2,
    LI2_REGION_TRUNCATED=3, LI2_REGION_PREFIX=4, LI2_REGION_OPERANDS=5,
    LI2_REGION_EFFECTS=6, LI2_REGION_ADDRESS=7
};
enum li2_region_flow { LI2_REGION_NEXT=0, LI2_REGION_JCC=1, LI2_REGION_JMP=2 };
/* JCC condition is the architectural opcode nibble 0..15 (O,NO,B,AE,E,NE,
   BE,A,S,NS,P,NP,L,GE,LE,G). NEXT/JMP use NONE; target=0 for NEXT. */
enum { LI2_REGION_CONDITION_NONE=16, LI2_REGION_NO_REGISTER=16 };
enum li2_region_access {
    LI2_REGION_NO_ACCESS=0, LI2_REGION_READ=1,
    LI2_REGION_WRITE=2, LI2_REGION_READ_WRITE=3
};
enum li2_region_operand_kind {
    LI2_REGION_REGISTER=1, LI2_REGION_MEMORY=2,
    LI2_REGION_IMMEDIATE=3, LI2_REGION_BRANCH=4
};
enum li2_region_segment { LI2_REGION_DS=1, LI2_REGION_SS=2 };
struct li2_region_operand {
    uint64_t immediate;
    uint32_t kind, reg, width_bits, access, encoding_bits, reserved;
};
struct li2_region_register {
    uint32_t reg, width_bits, access, reserved;
};
struct li2_region_memory {
    uint64_t displacement;
    uint32_t base, index, scale, width_bytes, address_bits, segment, access, reserved;
};
struct li2_region_decoded {
    struct li2_decoded decoded;
    uint64_t target;
    struct li2_region_operand operands[2];
    struct li2_region_register registers[3];
    struct li2_region_memory memory;
    uint32_t version, ready, refusal, flow, condition;
    uint32_t operand_count, register_count, memory_count;
    uint32_t flags_read, flags_written, flags_set, flags_cleared, flags_undefined;
    uint32_t gpr_read, gpr_write, reserved[3];
};

/* Register numbers are physical 0=RAX,1=RCX,...,15=R15; width is separate.
   Exact info-factory register rows are retained (E32 read + R64 write is two
   rows). GPR masks conservatively union those rows. flags_* use ARCHITECTURAL
   RFLAGS bits, not iced RflagsBits. Undefined flags remain actual writes.
   Active unused operand fields and all inactive rows are zero. Memory uses
   NO_REGISTER for absent base/index, scale 1/2/4/8, 64-bit address arithmetic,
   and the actual sign-extended displacement as a u64. Immediate values are
   extended to operand width; encoding_bits records their original 8-bit size.
   Branch operand: width=64, encoding_bits=8/32, immediate=absolute target,
   access=READ; condition and target above independently join the bytes.
   No high8 registers, stores, RSP writes, RIP-relative memory or legacy prefixes.
   Canonical source/next/branch PCs use the finite 48-bit canonical profile.
   Same 1..15-byte owned/disjoint source, aligned output, immutable arena and
   serialized call contracts as li2_decoder_decode. No source bytes are read
   beyond available, and no application data is read. */
uint32_t li2_decoder_region_describe(uint64_t,const unsigned char *,size_t,
                                    struct li2_region_decoded *);

_Static_assert(sizeof(struct li2_region_operand)==32,"region operand ABI");
_Static_assert(sizeof(struct li2_region_register)==16,"region register ABI");
_Static_assert(sizeof(struct li2_region_memory)==40,"region memory ABI");
_Static_assert(sizeof(struct li2_region_decoded)==304,"region descriptor ABI");
_Static_assert(_Alignof(struct li2_region_decoded)==8,"region descriptor alignment");
_Static_assert(offsetof(struct li2_region_decoded,target)==72,"region target");
_Static_assert(offsetof(struct li2_region_decoded,operands)==80,"region operands");
_Static_assert(offsetof(struct li2_region_decoded,registers)==144,"region registers");
_Static_assert(offsetof(struct li2_region_decoded,memory)==192,"region memory");
_Static_assert(offsetof(struct li2_region_decoded,version)==232,"region version");
_Static_assert(offsetof(struct li2_region_decoded,flags_read)==264,"region flags");
_Static_assert(offsetof(struct li2_region_decoded,gpr_read)==284,"region GPR masks");
_Static_assert(offsetof(struct li2_region_decoded,reserved)==292,"region reserved");
#endif
