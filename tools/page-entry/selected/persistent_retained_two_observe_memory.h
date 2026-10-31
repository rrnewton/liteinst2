#ifndef LI2_PERSISTENT_RETAINED_TWO_OBSERVE_MEMORY_H
#define LI2_PERSISTENT_RETAINED_TWO_OBSERVE_MEMORY_H
#include "lifecycle_loader.h"
/* Qualification-only fixed fixture geometry, never production permissions. */
#define PTR2O_DATA_BASE UINT64_C(0x500000000000)
#define PTR2O_DATA_BYTES 8192U
#define PTR2O_STACK_BASE UINT64_C(0x500000100000)
#define PTR2O_STACK_EXTENT (128U*1024U)
#define PTR2O_STACK_RSP (PTR2O_STACK_BASE+4096+PTR2O_STACK_EXTENT-504)
#define PTR2O_STACK_BYTES 224U
struct li2_ptr2o_map_row {
    uintptr_t first,end;
    uint64_t offset,major,minor,inode;
    unsigned prot,private;
};
struct li2_ptr2o_memory {
    unsigned attempted,complete,after_abort,rows_checked,data_copied,stack_copied;
    int result;
    long detail;
    uintptr_t rsp,data_first,stack_first;
    struct li2_fetch_map_progress maps;
    struct li2_maps_stats before,after;
    struct li2_ptr2o_map_row rows[6];
    unsigned char data[PTR2O_DATA_BYTES],stack[PTR2O_STACK_BYTES];
};
/* Called only for the independently authenticated focal IMAGE_MAIN source.
   The fixed addresses and actual saved RSP are an observation restriction;
   they supply no authority to resume or to predict a scalar result. */
int li2_lifecycle_ptr2_observe_memory(uintptr_t,unsigned,struct li2_ptr2o_memory *);
#endif
