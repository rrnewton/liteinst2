/* Included after read_maps_checked inside the actual lifecycle TU. Bootstrap
   records the kernel-stack anchor before any guest instruction, then seeds
   this origin exactly once at maintained-view enable. No name from /proc/maps
   is used as provenance; later anonymous mappings cannot recreate this origin. */
#include "maps_call_stack.h"
static uintptr_t mcs_origin_first,mcs_origin_end;
static uint64_t mcs_origin_acquisition;
static int mcs_initialize(void) {
    if(mcs_origin_acquisition || !MV_LOAD(&mv.enabled) || MV_LOAD(&maps_stats.active) ||
       MV_LOAD(&mv.poisoned) || MV_LOAD(&maps_stats.poisoned) ||
       MV_LOAD(&mv_depth) || mv_stack_retired || !mv_stack_anchor)return LI2_FETCH_STATE;
    struct check_error e={0};struct li2_fetch_map_progress p;
    /* Actual fresh bootstrap observation, before any guest mapping operation. */
    int result=mv_fresh(&e,&p);if(result)return result;
    const struct map_row *r=mapping(mv_stack_anchor);
    if(mv_stack_retired || !MV_LOAD(&maps_stats.valid) || !r || !r->private ||
       r->prot!=(PROT_READ|PROT_WRITE) || r->inode || r->major || r->minor || r->offset ||
       mv_stack_first<PAGE || mv_stack_first>=mv_stack_end ||
       mv_stack_end>=(UINT64_C(1)<<47) || mv_stack_anchor<mv_stack_first ||
       mv_stack_anchor>=mv_stack_end || r->first>mv_stack_first || r->end<mv_stack_end ||
       !p.observation.acquisition_id || p.observation.io_performed!=1 ||
       p.observation.kind!=LI2_MAPS_DIRECT || p.observation.handler_id)
        return LI2_FETCH_STATE;
    mcs_origin_first=mv_stack_first;mcs_origin_end=mv_stack_end;
    mcs_origin_acquisition=p.observation.acquisition_id;return 0;
}
int li2_maps_call_stack_advisory(uintptr_t first,size_t bytes) {
    return active && !tx.guard && hooks.raw && hooks.protected_range &&
        MV_LOAD(&mv.enabled) && !MV_LOAD(&mv.poisoned) && !MV_LOAD(&maps_stats.poisoned) &&
        !MV_LOAD(&mv_depth) && !mv_stack_retired && mcs_origin_acquisition &&
        bytes && first>=PAGE && first<=UINTPTR_MAX-bytes &&
        first+bytes<(UINT64_C(1)<<47) && first>=mcs_origin_first &&
        first+bytes<=mcs_origin_end && !hooks.protected_range(first,bytes);
}
int li2_maps_call_stack_query(uintptr_t first,size_t bytes,struct li2_maps_call_stack *out) {
    if(!out || !bytes || first<PAGE || first>UINTPTR_MAX-bytes ||
       first+bytes>=(UINT64_C(1)<<47))return LI2_FETCH_ARGUMENT;
    /* The whole proposed envelope, including the extra upper word, is tested.
       No output/observer write precedes this real protected-range refusal. */
    if(!active || tx.guard || !hooks.raw || !hooks.protected_range ||
       !MV_LOAD(&mv.enabled) || MV_LOAD(&mv.poisoned) || MV_LOAD(&maps_stats.poisoned) ||
       MV_LOAD(&mv_depth) || mv_stack_retired || !mcs_origin_acquisition ||
       first<mcs_origin_first || first+bytes>mcs_origin_end ||
       hooks.protected_range(first,bytes))return LI2_FETCH_STATE;
    struct check_error e={0};struct li2_fetch_map_progress p;
    int result=read_maps_checked(&e,&p);if(result)return result;
    const struct map_row *r=mapping(first);
    if(mv_stack_retired || MV_LOAD(&mv_stack_pending) || !MV_LOAD(&maps_stats.valid) ||
       MV_LOAD(&mv.poisoned) || MV_LOAD(&maps_stats.poisoned) || MV_LOAD(&mv_depth) ||
       !r || !r->private || r->prot!=(PROT_READ|PROT_WRITE) ||
       r->inode || r->major || r->minor || r->offset || r->first>first || r->end<first+bytes ||
       first<mv_stack_first || first+bytes>mv_stack_end ||
       p.observation.acquisition_id<mcs_origin_acquisition ||
       p.observation.acquisition_id!=MV_LOAD(&maps_stats.acquisitions) ||
       p.observation.mutation_epoch!=MV_LOAD(&maps_stats.mutation_epoch))return LI2_FETCH_STATE;
    *out=(struct li2_maps_call_stack){.anchor=mv_stack_anchor,
        .origin_first=mcs_origin_first,.origin_end=mcs_origin_end,
        .first=first,.end=first+bytes,.origin_acquisition=mcs_origin_acquisition,
        .observation=p.observation};return 0;
}
