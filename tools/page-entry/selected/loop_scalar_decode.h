#ifndef LI2_LOOP_SCALAR_DECODE_H
#define LI2_LOOP_SCALAR_DECODE_H
#include "scalar_read_decode.h"

/* Separate loop-effects feature. The old scalar APIs keep their exact output
   and refusal domains. This API lifts every ready scalar-read row only by
   changing version to3, and additionally admits canonical REX.W 0F AF /r
   register-only IMUL r64,r64. REX.X, RSP destination and every other prefix,
   width, implicit-product or memory form remain refused. The full physical
   descriptor is still336 bytes, with no repurposed or nonzero reserved fields.

   IMUL reads its destination and source and writes its64-bit destination.
   CF/OF are written; SF/ZF/AF/PF are undefined, not inferred or normalized.
   It has no memory, relocation, implicit register or FP effect. Copy its exact
   original bytes and retain actual flags at recovery boundaries. This is a
   descriptive API, not a plan, source, execution or recovery permit.

   The original owned/disjoint/immutable source, aligned output, sealed arena
   and serialized caller requirements apply. Non-OK leaves the whole output
   zero; an OK refusal retains only decoded/version/refusal. */
enum { LI2_LOOP_SCALAR_VERSION = 3, LI2_LOOP_IMUL_CODE = 2072 };
uint32_t li2_decoder_loop_scalar_describe(uint64_t,const unsigned char *,size_t,
                                        struct li2_span_decoded *);
/* Independent no-write theorem with the unchanged actual TF qualification. */
uint32_t li2_decoder_loop_scalar_none(uint64_t,const unsigned char *,size_t,
                                     struct li2_write_footprint *);
#endif
