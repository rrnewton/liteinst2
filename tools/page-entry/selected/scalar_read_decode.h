#ifndef LI2_SCALAR_READ_DECODE_H
#define LI2_SCALAR_READ_DECODE_H
#include "region_decode.h"
#include "write_footprint.h"

/* Additive scalar-read feature, descriptor version 2, physical span ABI336.
   The old APIs still emit version1 with their exact original domain/refusals.
   Old supported rows differ here ONLY in version. New ready rows add:
     MOVSXD r64,r32 (no RSP destination, no memory source);
     CMP m8,imm8 (opcode80 /7; 64-bit DS/SS base/index or RIP address);
     TEST r8,r8 / CMP r8,r8 (opcode84/38; low-byte registers only);
     literal unprefixed 3/4/5/7/8-byte padding NOPs.
   Low-byte register numbers refer to physical bits7:0, never AH..BH.
   NOP has zero architectural operands/register/address/memory rows despite
   its encoded ModRM/SIB syntax. It neither reads data nor computes an address.
   CMP memory is a real one-byte CPU read; NONE means no write, NOT no fault.
   No operand data is read or supplied by this API. Undefined flags remain
   possible modifications, never guessed values. All inactive bytes are zero.

   Same immutable owned 1..15-byte source, aligned/disjoint output, initialized
   sealed arena and serialized caller contract as span_describe. Non-OK returns
   leave all output bytes zero. OK refusal retains only decoded/version/refusal.
   This is not a PF11/old planner descriptor; a future consumer must select
   version2 explicitly and independently reconstruct original/emitted facts,
   source/permission custody, data-fault recovery and current no-write evidence. */
enum { LI2_SCALAR_READ_VERSION = 2 };
uint32_t li2_decoder_scalar_read_describe(uint64_t,const unsigned char *,size_t,
                                       struct li2_span_decoded *);

/* Independent register-free no-write theorem plus unchanged TF admission.
   ABI1 footprint/zero endpoints; policy NONE only for an exact ready version2
   descriptor and separate instruction-semantic proof. Unsupported never grants
   execution. The actual write-footprint API remains an independent cold gate. */
uint32_t li2_decoder_scalar_read_none(uint64_t,const unsigned char *,size_t,
                                    struct li2_write_footprint *);
#endif
