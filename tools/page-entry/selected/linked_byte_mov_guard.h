#ifndef LI2_LINKED_BYTE_MOV_GUARD_H
#define LI2_LINKED_BYTE_MOV_GUARD_H
#include "linked_mov_guard.h"

/* Two byte-store Codes only; old four-Code li2_decoder_mov_store/li2_mg_*
   domains, images, refusal outputs and recovery remain unchanged. These APIs
   use the SAME144-byte descriptor,6488-byte plan,24-byte boundary and152-byte
   recovered frame, with descriptor/plan version2 and table version1.

   Exact 88 /r or C6 /0 memory stores, one optional meaningful REX,64-bit DS/SS
   addressing with the old base/index/SIB/displacement/RIP forms. No address
   override, segment, LOCK/REP, REX.W, ignored extension or AH/CH/DH/BH source.
   A bare REX is accepted only for SPL/BPL/SIL/DIL. Source_kind1 names the low
   byte of full parent source_reg0..15; source_kind2 is immediate8, zero-extended
   in immediate with source_reg16. Width is exactly1. All inactive bytes zero.

   The exact old guard algorithm uses the entire [EA,EA+1) against the whole
   current exclusion table, computes EA before modifying operands, restores
   every scratch/flag before the actual copied store, and uses the same exact
   BEFORE/STORE/AFTER/REJECT boundary states. No data/source permissions or
   lifetime authority are implied. Existing rel32 reach refusals remain.
   Host storage/alias/source/arena and prevalidated-recovery obligations are
   identical to linked_mov_guard.h. Never pass a version2 plan to old APIs. */
#define LI2_BMG_VERSION 2U
enum { LI2_BMG_REGISTER_CODE = 279, LI2_BMG_IMMEDIATE_CODE = 401 };
uint32_t li2_decoder_byte_mov_store(uint64_t,const unsigned char *,size_t,struct li2_mg_store *);
int li2_bmg_interval_allowed(const struct li2_mg_table *,uint64_t,unsigned);
int li2_bmg_emit(uintptr_t,const unsigned char *,size_t,uintptr_t,uintptr_t,uintptr_t,
                 const struct li2_mg_table *,struct li2_mg_plan *);
int li2_bmg_validate(const struct li2_mg_plan *);
int li2_bmg_recover(const struct li2_mg_plan *,uintptr_t,const uint64_t[16],uint64_t,
                    const uint64_t[4],struct li2_mg_recovered *);
#endif
