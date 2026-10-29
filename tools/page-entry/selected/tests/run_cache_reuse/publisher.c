/* Fixture-only gateway and supplied counter controls. No production setter. */
#define li2_step_raw li2_reuse_control_raw
#include "../../../register_run_publish.c"
void li2_reuse_supplied_counter(unsigned mode) {
    if(mode==20)cache.reuse.generation=UINT64_MAX;
    else if(mode==21)cache.diagnostic.attempts=UINT64_MAX;
    else if(mode==22) {
        cache.reuse.completions=UINT64_MAX;cache.reuse.history->completed_runs=UINT64_MAX;
    } else if(mode==23) {
        cache.reuse.copied_instructions=UINT64_MAX-1;
        cache.reuse.history->copied_instructions=UINT64_MAX-1;
    } else __builtin_trap();
}
