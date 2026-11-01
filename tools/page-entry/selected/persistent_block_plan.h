#ifndef LI2_PERSISTENT_BLOCK_PLAN_H
#define LI2_PERSISTENT_BLOCK_PLAN_H
#include "persistent_group_compact.h"
#if !defined(LI2_PERSISTENT_BLOCK_PLAN) || LI2_PERSISTENT_BLOCK_PLAN != 1 || \
    !defined(LI2_PERSISTENT_DIRECT_FRONTIER) || LI2_PERSISTENT_DIRECT_FRONTIER != 1
#error "bounded blocks require their separate explicit direct-directory policy"
#endif
#define LI2_PB_VERSION 10U
_Static_assert(LI2_PG_VERSION!=LI2_PB_VERSION && LI2_PG_COMPACT_VERSION!=LI2_PB_VERSION,
    "separate block policy cannot alias the existing BFS version");
/* Same bounded storage geometry, distinct partition semantics and APIs.
   Old li2_pg_* validators reject this version. Only existing NONE-class
   straight-line instructions are copied. The first direct JMP/Jcc ends the
   block; every arm is a directory exit, including an in-pair/backward target.
   An unsupported non-root is a literal original-before exit. No CALL, RET,
   indirect-JMP or writer is admitted. No silent head-cap truncation occurs.
   Source bytes beyond the block remain retained but confer no head authority.
   All inputs are descriptive: an owner must separately prove immutable source,
   whole code/proof, directory membership and current entry/drain authority. */
int li2_pb_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *);
int li2_pb_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *);
/* Whole fresh reconstruction, including exact failure bytes and diagnosis.
   This does not turn a miss into an owner cancellation/entry capability. */
int li2_pb_miss_validate(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *);
int li2_pb_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pb_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pb_compact_direct(const struct li2_pg_compact *,unsigned,unsigned,struct li2_dd_plan *);
int li2_pb_compact_exit(const struct li2_pg_compact *,uintptr_t,uint64_t);
/* Exact emitted boundaries only, after whole immutable authentication.
   Full FP/siginfo/stack and actual fault handling remain the owner's job. */
int li2_pb_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_plan *,struct li2_pg_recovered *);
#endif
