#ifndef LI2_LINKED_EPOCH_OBSERVE_MEMORY_H
#define LI2_LINKED_EPOCH_OBSERVE_MEMORY_H
#include "lifecycle_loader.h"
/* Qualification-only fixed fixture geometry, never production permissions. */
#define LETO_DATA_BASE UINT64_C(0x500000000000)
#define LETO_DATA_BYTES 8192U
#define LETO_STACK_BASE UINT64_C(0x500000100000)
#define LETO_STACK_EXTENT (128U*1024U)
#define LETO_STACK_RSP (LETO_STACK_BASE+4096+LETO_STACK_EXTENT-504)
#define LETO_STACK_BYTES 224U
struct li2_leto_map_row {
    uintptr_t first,end;
    uint64_t offset,major,minor,inode;
    unsigned prot,private;
};
struct li2_leto_memory {
    unsigned attempted,complete,after_abort,rows_checked,data_copied,stack_copied;
    int result;
    long detail;
    uintptr_t rsp,data_first,stack_first;
    struct li2_fetch_map_progress maps;
    struct li2_maps_stats before,after;
    struct li2_leto_map_row rows[6];
    unsigned char data[LETO_DATA_BYTES],stack[LETO_STACK_BYTES];
};
/* Called only for the independently authenticated focal IMAGE_MAIN source.
   The fixed addresses and actual saved RSP are an observation restriction;
   they supply no authority to resume or to predict a scalar result. */
int li2_lifecycle_link_observe_memory(uintptr_t,unsigned,struct li2_leto_memory *);
#endif
