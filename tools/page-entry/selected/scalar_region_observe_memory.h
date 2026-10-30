#ifndef LI2_SCALAR_REGION_OBSERVE_MEMORY_H
#define LI2_SCALAR_REGION_OBSERVE_MEMORY_H
#include "region_source.h"
/* Qualification-only fixed fixture geometry, never production permissions. */
#define SRO_DATA_BASE UINT64_C(0x500000000000)
#define SRO_DATA_BYTES 8192U
#define SRO_STACK_BASE UINT64_C(0x500000100000)
#define SRO_STACK_EXTENT (128U*1024U)
#define SRO_STACK_RSP (SRO_STACK_BASE+4096+SRO_STACK_EXTENT-504)
#define SRO_STACK_FAULT (SRO_STACK_BASE+8192)
#define SRO_STACK_BYTES 224U /* old160 bytes plus both +50h/+58h operands */
enum { SRO_MEMORY_LIVE=0,SRO_MEMORY_TERMINAL=1,SRO_MEMORY_READBACK=2 };
struct li2_sro_map_row {
    uintptr_t first,end;
    uint64_t offset,major,minor,inode;
    unsigned prot,private;
};
struct li2_sro_maps {
    struct li2_fetch_map_progress maps;
    struct li2_maps_stats before,after;
    struct li2_sro_map_row rows[8],source,generated;
    unsigned rows_checked,source_checked,generated_checked;
};
struct li2_sro_memory {
    unsigned attempted,complete,stage,stack_kind,data_copied,stack_copied,stack_missing,stack_full;
    unsigned restore_started,restore_returned,restore_verified;
    int result;
    long detail,restore_result;
    uintptr_t rsp,data_first,stack_first,generated;
    struct li2_sro_maps initial,restored;
    unsigned char data[SRO_DATA_BYTES],stack[SRO_STACK_BYTES],stack_observed[SRO_STACK_BYTES];
};
/* READBACK is allowed only after the caller has retained an actual mapped
   generated load-fault frame, published first_error and completed generated
   revoke/synchronize/query. It rechecks actual source/generated R/NX before
   making the ONE fixed inaccessible stack page read-only, then never resumes.
   LIVE never changes permission: inaccessible bytes are explicitly absent,
   not fabricated zeros or authority. The strict reader must join all actual
   terminal bytes to the independent pre-protection native/app record. */
int li2_lifecycle_scalar_region_observe_memory(uintptr_t,unsigned,
    const struct li2_region_source_key *,uintptr_t,struct li2_sro_memory *);
#endif
