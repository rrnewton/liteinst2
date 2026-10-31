/* Separate runtime policy: genuine pair NX routing, never an old owner with
   relaxed page counts. All fallback instruction owners keep their old gates. */
#ifdef LI2_LINKED_NATIVE_HINT
#include "linked_native_hint.h"
#endif
#ifdef LI2_LINKED_NATIVE_PROBE
#include "linked_native_probe.h"
#endif
static void selected_native_count(uintptr_t pc) {
    if(!first_target_pc)first_target_pc=pc;
    ++faults;if(pc==original_interpreter.entry)++first_interpreter;
    if(image_code(&original_main,pc))++main_faults;
    else if(image_code(&original_interpreter,pc))++interpreter_faults;
    else ++dependency_faults;
}
static int selected_native_fetch(int sig,siginfo_t *si,ucontext_t *uc) {
    if(selected_selftesting)return 0;
    checked(!selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
            !li2_lifecycle_fetch_interlock(),1432,0);
    uint64_t before=li2_lifecycle_pair_progress()->published;
    int result=li2_native_pair_nx(sig,si,uc,selected_flags_known,&selected_logical_flags);
#ifdef LI2_LINKED_NATIVE_PROBE
    int probe_result=li2_lifecycle_link_native_probe_outcome(result);
#endif
#ifdef LI2_LINKED_NATIVE_HINT
    int hint_result=li2_lifecycle_link_native_hint_outcome(result);
#endif
    checked(result==LI2_NP_FALLBACK || result==LI2_NP_RESUME || result==LI2_NP_REFAULT,
            (unsigned)result,li2_native_pair_progress()->first_detail);
#ifdef LI2_LINKED_NATIVE_HINT
    checked(!hint_result,(unsigned)hint_result,0);
#endif
#ifdef LI2_LINKED_NATIVE_PROBE
    checked(!probe_result,(unsigned)probe_result,0);
#endif
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    uint64_t after=li2_lifecycle_pair_progress()->published;
    checked(after>=before && after-before<=1,LI2_NP_STATE,70);
    if(after!=before && image_code(&original_main,pc)) {
        checked(native_main_admissions!=UINT64_MAX,1436,1);++native_main_admissions;
    }
    if(result==LI2_NP_RESUME || result==LI2_NP_REFAULT) {
        selected_flags_known=0;
        if(result==LI2_NP_REFAULT && image_code(&original_main,pc)) {
            checked(native_main_refaults!=UINT64_MAX,1436,0);++native_main_refaults;
        }
        selected_native_count(pc);return 1;
    }
    checked(li2_native_pair_quiet(),LI2_NP_STATE,71);selected_flags_known=1;
    /* A pair source/close observation deliberately ended the routing maps
       phase. Old owners get a fresh phase, never retained native rows. */
    struct li2_maps_stats maps;li2_maps_stats_read(&maps);
    if(!maps.active)checked(!li2_maps_phase_begin(),770,0);
    return 0;
}
