/* Included only by the explicit ABI4 owner. Each mirror store follows the
   original protected counter update at its actual policy12/13 event site. */
#include "persistent_loop_effects_counters.h"
_Static_assert(sizeof(struct plr_counts)==sizeof(struct li2_plc_counts),"whole policy12 mirror");
_Static_assert(sizeof(struct ple_counts)==sizeof(struct li2_plec_counts),"whole policy13 mirror");
#define PLEC_MATCH(t,m,n) _Static_assert(offsetof(struct t,n)==offsetof(struct m,n),"same owner field " #n)
PLEC_MATCH(plr_counts,li2_plc_counts,chooser_attempts);PLEC_MATCH(plr_counts,li2_plc_counts,chooser_selected);
PLEC_MATCH(plr_counts,li2_plc_counts,chooser_no_envelope);PLEC_MATCH(plr_counts,li2_plc_counts,publications12);
PLEC_MATCH(plr_counts,li2_plc_counts,hits12);PLEC_MATCH(plr_counts,li2_plc_counts,entries_with12);
PLEC_MATCH(plr_counts,li2_plc_counts,completed_with12);PLEC_MATCH(plr_counts,li2_plc_counts,historical_reconstructions);
PLEC_MATCH(plr_counts,li2_plc_counts,actual_entries12);
PLEC_MATCH(ple_counts,li2_plec_counts,chooser_attempts);PLEC_MATCH(ple_counts,li2_plec_counts,chooser_selected);
PLEC_MATCH(ple_counts,li2_plec_counts,chooser_no_envelope);PLEC_MATCH(ple_counts,li2_plec_counts,publications13);
PLEC_MATCH(ple_counts,li2_plec_counts,hits13);PLEC_MATCH(ple_counts,li2_plec_counts,entries_with13);
PLEC_MATCH(ple_counts,li2_plec_counts,completed_with13);PLEC_MATCH(ple_counts,li2_plec_counts,historical_reconstructions);
PLEC_MATCH(ple_counts,li2_plec_counts,actual_entries13);
#undef PLEC_MATCH
static void plec_count(uint64_t *local,size_t offset,unsigned effects) {
    struct li2_plec_record *record=(void *)li2_pgc_current;
    pe_need(effects<=1 && offset<72 && offset%sizeof(uint64_t)==0 &&
        local==(void *)((unsigned char *)(effects?(void *)&pe.effects.counts:(void *)&pe.loop.counts)+offset),
        PE_OVERFLOW,1);
    pe_need(record && __atomic_load_n(&record->base.base.header[15],__ATOMIC_ACQUIRE)==1 &&
        record->base.base.header[0]==LI2_PGC_MAGIC && record->base.base.header[1]==LI2_PLEC_VERSION &&
        record->base.base.header[2]==LI2_PLEC_BYTES && record->base.base.header[3]==LI2_PGC_PAGE &&
        record->base.base.header[10]==LI2_PGC_INITIAL_SEALS && record->base.base.header[11]==LI2_PGC_FINAL_SEALS &&
        record->base.base.header[12]==(uintptr_t)record && record->base.base.header[13]==1 &&
        record->base.base.header[14]==1,PE_OVERFLOW,2);
    uint64_t *mirror=(void *)((unsigned char *)(effects?(void *)&record->effects:(void *)&record->base.loop)+offset);
    uint64_t value=__atomic_load_n(local,__ATOMIC_ACQUIRE);
    pe_need(value!=UINT64_MAX && __atomic_load_n(mirror,__ATOMIC_ACQUIRE)==value,PE_OVERFLOW,3);
    /* A kill between stores is a per-cell prefix, never a transaction. */
    ped_count(local);
    __atomic_store_n(mirror,value+1,__ATOMIC_RELEASE);
}
#define PLR_COUNT(n) plec_count(&pe.loop.counts.n,offsetof(struct plr_counts,n),0)
#define PLE_COUNT(n) plec_count(&pe.effects.counts.n,offsetof(struct ple_counts,n),1)
