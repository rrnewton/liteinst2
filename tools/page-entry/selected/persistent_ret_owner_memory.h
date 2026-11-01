#ifndef LI2_PERSISTENT_RET_OWNER_MEMORY_H
#define LI2_PERSISTENT_RET_OWNER_MEMORY_H
#include "lifecycle_loader.h"
#include "maps_call_stack.h"
#define PRTO_DATA_BASE UINT64_C(0x500000000000)
#define PRTO_DATA_BYTES 8192U
#define PRTO_STACK_BYTES 520U
struct li2_prto_map_row {
    uintptr_t first,end;
    uint64_t offset,major,minor,inode;
    unsigned prot,private;
};
struct li2_prto_memory {
    unsigned attempted,complete,rows_checked,pages_checked,site,reserved;
    unsigned source_copied,continuation_copied,data_copied,stack_copied;
    int result;
    long detail;
    uintptr_t rsp;
    struct li2_maps_call_stack stack_origin;
    struct li2_fetch_map_progress maps;
    struct li2_maps_stats before,after;
    struct li2_prto_map_row rows[6];
    struct li2_fetch_page pages[3];
    struct li2_fetch_backing backing[3];
    unsigned char source[8192],continuation[4096],data[PRTO_DATA_BYTES],stack[PRTO_STACK_BYTES];
};
/* Read-only capture of fixed authenticated ET_EXEC pages and the actual
   original-stack envelope. This issues no execution or write authority. */
int li2_lifecycle_prto_memory(uintptr_t,unsigned,struct li2_prto_memory *);
#endif
