/* Included only by the explicit ABI3 owner, after pe and ped_count exist.
   No observer samples are published: each call is the original event site. */
#include "persistent_loop_counters.h"
_Static_assert(sizeof(struct plr_counts)==sizeof(struct li2_plc_counts),"whole protected/mirrored counts");
#define PLC_MATCH(n) _Static_assert(offsetof(struct plr_counts,n)==offsetof(struct li2_plc_counts,n),"same owner field " #n)
PLC_MATCH(chooser_attempts);PLC_MATCH(chooser_selected);PLC_MATCH(chooser_no_envelope);
PLC_MATCH(publications12);PLC_MATCH(hits12);PLC_MATCH(entries_with12);
PLC_MATCH(completed_with12);PLC_MATCH(historical_reconstructions);PLC_MATCH(actual_entries12);
#undef PLC_MATCH
static void plc_count(uint64_t *local,size_t offset) {
    struct li2_plc_record *record=(void *)li2_pgc_current;
    pe_need(offset<sizeof pe.loop.counts && offset%sizeof(uint64_t)==0 &&
        local==(void *)((unsigned char *)&pe.loop.counts+offset),PE_OVERFLOW,1);
    pe_need(record && __atomic_load_n(&record->base.header[15],__ATOMIC_ACQUIRE)==1 &&
        record->base.header[0]==LI2_PGC_MAGIC && record->base.header[1]==LI2_PLC_VERSION &&
        record->base.header[2]==LI2_PLC_BYTES && record->base.header[3]==LI2_PGC_PAGE &&
        record->base.header[10]==LI2_PGC_INITIAL_SEALS && record->base.header[11]==LI2_PGC_FINAL_SEALS &&
        record->base.header[12]==(uintptr_t)record && record->base.header[13]==1 &&
        record->base.header[14]==1,PE_OVERFLOW,2);
    uint64_t *mirror=(void *)((unsigned char *)&record->loop+offset);
    uint64_t value=__atomic_load_n(local,__ATOMIC_ACQUIRE);
    pe_need(value!=UINT64_MAX && __atomic_load_n(mirror,__ATOMIC_ACQUIRE)==value,PE_OVERFLOW,3);
    /* Keep the original protected update. A kill between these two atomic
       stores yields a per-cell prefix, never a completed-transaction claim. */
    ped_count(local);
    __atomic_store_n(mirror,value+1,__ATOMIC_RELEASE);
}
#define PLR_COUNT(n) plc_count(&pe.loop.counts.n,offsetof(struct plr_counts,n))
