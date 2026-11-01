#ifndef LI2_PERSISTENT_RET_RESUME_H
#define LI2_PERSISTENT_RET_RESUME_H
#include "maps_call_stack.h"
/* Private owner state; numeric rd_recovered values alone are not authority.
   The sole original-stack read has already completed before LOADED is issued.
   No entrypoint below reads the original stack word or replays its C3. */
enum prr_phase { PRR_IDLE=0,PRR_LOADED,PRR_DRAINED,PRR_ARMED,PRR_OBSERVED,PRR_CONSUMED };
struct prr_attempt {
    unsigned phase,event,terminal,consumed;
    uint64_t serial,completion_id;
    struct pda_ret_exit loaded;
    struct li2_rd_recovered interior,logical;
    int interior_result;
    struct le_frame after;
    struct li2_private_code_query before[2],observed[2];
    struct le_permission write,seal;
    struct li2_maps_call_stack stack;
};
static struct {
    uintptr_t allocation,code,cell;
    unsigned initialized,registered;
    uint64_t last_consumed,cell_value,cell_serial;
    struct le_permission initial_code,initial_cell;
    struct li2_private_code_query initial;
    struct prr_attempt run;
} prr;
static uintptr_t pcw_ret_miss(uintptr_t);
static void prr_initialize(void);
static void prr_reset(void);
static int prr_loaded_preentry(int,const siginfo_t *,const ucontext_t *);
static void prr_loaded_exit(int,siginfo_t *,ucontext_t *);
#endif
