#ifndef LI2_WRITE_FOOTPRINT_H
#define LI2_WRITE_FOOTPRINT_H
#include <stddef.h>
#include <stdint.h>

enum li2_write_policy {
    LI2_WRITE_UNSUPPORTED=0, LI2_WRITE_NONE=1, LI2_WRITE_RANGE=2
};
/* Actual pre-instruction registers, in x86 encoding order:
   RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8,R9,R10,R11,R12,R13,R14,R15. */
struct li2_write_registers { uint64_t gpr[16],fs_base,gs_base; };
struct li2_write_footprint {
    uint64_t pc,next_pc,first,end;
    uint32_t abi_version,policy,code,length;
};
/* Descriptive only, under the existing 64-bit/no-CET TF profile. The owner
   authenticates bytes, pre-state, mapping generation and all four identity
   fields before using a result. RANGE overapproximates conditional writes;
   NONE has zero endpoints. UNSUPPORTED never permits execution. This query
   does not cover kernel writes, REP routes or application signal delivery.
   Source/registers/output are live, aligned where required, disjoint owned
   buffers, and obey the decoder's sealed-arena/single-caller contract. */
uint32_t li2_decoder_write_footprint(uint64_t,const unsigned char *,size_t,
    const struct li2_write_registers *,struct li2_write_footprint *);
#ifdef LI2_EVENT_PROFILE
#include "event_profile.h"
#define li2_decoder_write_footprint(...) LI2_EVENT_VALUE(LI2_EV_FOOTPRINT,(li2_decoder_write_footprint)(__VA_ARGS__))
#endif
_Static_assert(sizeof(struct li2_write_registers)==144,"write registers ABI");
_Static_assert(sizeof(struct li2_write_footprint)==48,"write footprint ABI");
#endif
