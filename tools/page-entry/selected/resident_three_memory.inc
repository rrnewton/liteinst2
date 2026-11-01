/* Included after read_maps_checked inside the actual lifecycle TU. Bootstrap
   records the kernel-stack anchor before any guest instruction, then seeds
   this origin exactly once at maintained-view enable. No name from /proc/maps
   is used as provenance; later anonymous mappings cannot recreate this origin. */
#include "resident_three_memory.h"
static uintptr_t r3s_origin_first,r3s_origin_end;
static uint64_t r3s_origin_acquisition;
static int r3s_initialize(void) {
    if(r3s_origin_acquisition || !MV_LOAD(&mv.enabled) || MV_LOAD(&maps_stats.active) ||
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
    r3s_origin_first=mv_stack_first;r3s_origin_end=mv_stack_end;
    r3s_origin_acquisition=p.observation.acquisition_id;return 0;
}
int li2_r3o_stack_advisory(uintptr_t first,size_t bytes) {
    return active && !tx.guard && hooks.raw && hooks.protected_range &&
        MV_LOAD(&mv.enabled) && !MV_LOAD(&mv.poisoned) && !MV_LOAD(&maps_stats.poisoned) &&
        !MV_LOAD(&mv_depth) && !mv_stack_retired && r3s_origin_acquisition &&
        bytes && first>=PAGE && first<=UINTPTR_MAX-bytes &&
        first+bytes<(UINT64_C(1)<<47) && first>=r3s_origin_first &&
        first+bytes<=r3s_origin_end && !hooks.protected_range(first,bytes);
}
int li2_r3o_stack_query(uintptr_t first,size_t bytes,struct li2_r3o_stack *out) {
    if(!out || !bytes || first<PAGE || first>UINTPTR_MAX-bytes ||
       first+bytes>=(UINT64_C(1)<<47))return LI2_FETCH_ARGUMENT;
    /* The whole proposed envelope, including the extra upper word, is tested.
       No output/observer write precedes this real protected-range refusal. */
    if(!active || tx.guard || !hooks.raw || !hooks.protected_range ||
       !MV_LOAD(&mv.enabled) || MV_LOAD(&mv.poisoned) || MV_LOAD(&maps_stats.poisoned) ||
       MV_LOAD(&mv_depth) || mv_stack_retired || !r3s_origin_acquisition ||
       first<r3s_origin_first || first+bytes>r3s_origin_end ||
       hooks.protected_range(first,bytes))return LI2_FETCH_STATE;
    struct check_error e={0};struct li2_fetch_map_progress p;
    int result=read_maps_checked(&e,&p);if(result)return result;
    const struct map_row *r=mapping(first);
    if(mv_stack_retired || MV_LOAD(&mv_stack_pending) || !MV_LOAD(&maps_stats.valid) ||
       MV_LOAD(&mv.poisoned) || MV_LOAD(&maps_stats.poisoned) || MV_LOAD(&mv_depth) ||
       !r || !r->private || r->prot!=(PROT_READ|PROT_WRITE) ||
       r->inode || r->major || r->minor || r->offset || r->first>first || r->end<first+bytes ||
       first<mv_stack_first || first+bytes>mv_stack_end ||
       p.observation.acquisition_id<r3s_origin_acquisition ||
       p.observation.acquisition_id!=MV_LOAD(&maps_stats.acquisitions) ||
       p.observation.mutation_epoch!=MV_LOAD(&maps_stats.mutation_epoch))return LI2_FETCH_STATE;
    *out=(struct li2_r3o_stack){.anchor=mv_stack_anchor,
        .origin_first=r3s_origin_first,.origin_end=r3s_origin_end,
        .first=first,.end=first+bytes,.origin_acquisition=r3s_origin_acquisition,
        .observation=p.observation};return 0;
}

/* Observation only: the complete retained original-stack query above precedes
   every read. It issues no source lease, owner token, generation or RX grant. */
int li2_lifecycle_r3o_memory(uintptr_t rsp,unsigned site,struct li2_r3o_memory *o) {
    if(!o || o->attempted || site>2 || rsp<PAGE+256 || rsp>=(UINT64_C(1)<<47)-264)
        return LI2_FETCH_ARGUMENT;
    o->attempted=1;o->rsp=rsp;o->site=site;
    li2_maps_stats_read(&o->before);
    li2_maps_view_require_fresh();
    int e=li2_r3o_stack_query(rsp-256,sizeof o->stack,&o->origin);
    li2_maps_stats_read(&o->after);
    if(e){o->result=e;return e;}
    if(o->before.poisoned || o->before.active>1 || o->after.poisoned || !o->after.valid ||
       o->after.active!=o->before.active || o->after.handler_id!=o->before.handler_id ||
       o->before.acquisitions==UINT64_MAX || o->before.fresh_calls==UINT64_MAX ||
       o->after.acquisitions!=o->before.acquisitions+1 ||
       o->after.fresh_calls!=o->before.fresh_calls+1 ||
       o->origin.observation.io_performed!=1 ||
       o->origin.observation.kind!=(o->before.active?LI2_MAPS_FRESH:LI2_MAPS_DIRECT) ||
       o->origin.observation.handler_id!=(o->before.active?o->before.handler_id:0))
        {o->result=LI2_FETCH_STATE;return o->result;}
    const volatile unsigned char *p=(void *)(rsp-256);
    for(size_t n=0;n<sizeof o->stack;n++){o->stack[n]=p[n];o->copied=(unsigned)n+1;}
    o->complete=1;return 0;
}
