#ifndef LI2_LOOP_EFFECTS_ENVELOPE_H
#define LI2_LOOP_EFFECTS_ENVELOPE_H
#include "loop_envelope.h"
#include "loop_scalar_decode.h"
#include "linked_byte_mov_guard.h"

/* Separate pure policy13 chooser. Same witness/geometry/discovery/ranking as
   policy12, but freshly decoded scalar-version3 and old-or-byte MOV nodes.
   This never selects a runtime fallback or grants an execution/cancel permit.
   The original held-source, host-alias and sealed-decoder contracts apply. */
#define LI2_LEE_VERSION 13U
int li2_lee_choose(const uintptr_t[2],const unsigned char[2][LI2_LE_PAGE],uintptr_t,
                   struct li2_le_witness *);
int li2_lee_validate(const uintptr_t[2],const unsigned char[2][LI2_LE_PAGE],uintptr_t,
                     const struct li2_le_witness *,struct li2_le_witness *);
#endif
