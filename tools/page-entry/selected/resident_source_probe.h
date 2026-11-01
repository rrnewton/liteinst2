#ifndef LI2_RESIDENT_SOURCE_PROBE_H
#define LI2_RESIDENT_SOURCE_PROBE_H
#include "resident_source_lease.h"
#include "rseq_guard.h"
#if !defined(LI2_RESIDENT_SOURCE_PROBE) || LI2_RESIDENT_SOURCE_PROBE != 1
#error "distinct actual source-lease observation profile"
#endif
#define LI2_RSO_TARGET UINT64_C(0x4700000)
#define LI2_RSO_CONTROL (LI2_RSO_TARGET+4096)
void li2_rso_lease_bound(const struct li2_pg_token *,const struct li2_rsl_progress *);
void li2_rso_bound(const struct li2_pg_token *,uintptr_t,const struct li2_mg_table *);
void li2_rso_instruction(const struct li2_decoded *,const ucontext_t *);
void li2_rso_range(uintptr_t,size_t,int,const struct li2_rseq_state *);
void li2_rso_owner(uint64_t[16],struct li2_private_code_query[12]);
void li2_rso_raw(long,long,long,long,long,long,long,unsigned,long);
int li2_rso_backing(uintptr_t,uint64_t[20]);
#endif
