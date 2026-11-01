#ifndef LI2_PERSISTENT_CALL_OWNER_MEMORY_H
#define LI2_PERSISTENT_CALL_OWNER_MEMORY_H
#include "lifecycle_loader.h"
#include "maps_call_stack.h"
#define PCLO_DATA_BASE UINT64_C(0x500000000000)
#define PCLO_DATA_BYTES 8192U
#define PCLO_STACK_BYTES 520U
struct li2_pclo_map_row {
    uintptr_t first,end;
    uint64_t offset,major,minor,inode;
    unsigned prot,private;
};
struct li2_pclo_memory {
    unsigned attempted,complete,rows_checked,pages_checked,site,reserved;
    unsigned source_copied,continuation_copied,data_copied,stack_copied;
    int result;
    long detail;
    uintptr_t rsp;
    struct li2_maps_call_stack stack_origin;
    struct li2_fetch_map_progress maps;
    struct li2_maps_stats before,after;
    struct li2_pclo_map_row rows[6];
    struct li2_fetch_page pages[3];
    struct li2_fetch_backing backing[3];
    unsigned char source[8192],continuation[4096],data[PCLO_DATA_BYTES],stack[PCLO_STACK_BYTES];
};
/* Read-only capture of fixed authenticated ET_EXEC pages and the actual
   original-stack envelope. This issues no execution or write authority. */
int li2_lifecycle_pclo_memory(uintptr_t,unsigned,struct li2_pclo_memory *);
#endif
