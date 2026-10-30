/* Included after read_maps_checked(), while MV_LOAD/MV_STORE remain defined.
   The baseline hook is called only by a successful complete mv_fresh(), after
   canonicalization and before publication of maps_stats.valid. */
struct li2_maps_current_owner {
    uint64_t serial;
    unsigned busy,live;
    struct li2_maps_current_view view;
};
static struct li2_maps_current_owner maps_current;
static void mct_raw_boundary(void) { MV_STORE(&maps_current.live,0); }
static int mct_physical(const struct li2_fetch_map_progress *p) {
    return p->opened==1 && p->close_started==1 && p->closed==1 && p->fd>=0 &&
        !p->last_read && !p->close_result && p->bytes && p->rows &&
        p->observation.acquisition_id && p->observation.io_performed==1 &&
        (p->observation.kind==LI2_MAPS_FRESH || p->observation.kind==LI2_MAPS_DIRECT);
}
static int mct_state(void) {
    return active && hooks.raw && !tx.guard && MV_LOAD(&mv.enabled)==1 &&
        !MV_LOAD(&mv.poisoned) && !MV_LOAD(&maps_stats.poisoned) &&
        MV_LOAD(&maps_stats.active)==1 && MV_LOAD(&maps_stats.valid)==1 &&
        !MV_LOAD(&mv_depth) && !MV_LOAD(&mv_stack_pending) && !mv_stack_retired &&
        mv_stack_first>=PAGE && mv_stack_end>mv_stack_first &&
        mv_stack_anchor>=mv_stack_first && mv_stack_anchor<mv_stack_end &&
        row_count && row_count<=MAP_ROWS;
}
static int mct_query(const struct li2_fetch_map_progress *p) {
    unsigned k=p->observation.kind,io=p->observation.io_performed;
    return p->observation.acquisition_id==MV_LOAD(&maps_stats.acquisitions) &&
        p->observation.handler_id==MV_LOAD(&maps_stats.handler_id) &&
        p->observation.handler_id &&
        p->observation.mutation_epoch==MV_LOAD(&maps_stats.mutation_epoch) &&
        p->rows==row_count &&
        ((k==LI2_MAPS_FRESH && io==1) ||
         (k==LI2_MAPS_VERIFIED && io==1 && MV_LOAD(&mv.differential)==1) ||
         (k==LI2_MAPS_PROJECTED && !io && !MV_LOAD(&mv.differential)));
}
int li2_maps_current_validate(const struct li2_maps_current_ref *ref,
                              const struct li2_maps_current_view *v) {
    if(!ref || ref->owner!=&maps_current || !ref->serial ||
       ref->serial!=maps_current.serial || v!=&maps_current.view ||
       MV_LOAD(&maps_current.busy) || MV_LOAD(&maps_current.live)!=1 ||
       v->version!=1 || v->complete!=1 || v->result || v->detail ||
       v->serial!=ref->serial || !mct_state() ||
       v->query_serial!=MV_LOAD(&mv.queries) || v->table!=(uintptr_t)rows ||
       v->rows!=row_count || v->stack_first!=mv_stack_first || v->stack_end!=mv_stack_end ||
       !mct_query(&v->query) || !mct_physical(&v->physical) ||
       v->physical.observation.acquisition_id!=MV_LOAD(&mct_physical_id) ||
       v->physical.observation.acquisition_id!=v->query.observation.acquisition_id ||
       v->physical.observation.mutation_epoch>v->query.observation.mutation_epoch)
        return LI2_FETCH_STALE;
    return 0;
}
int li2_maps_current_acquire(struct li2_maps_current_ref *ref,
                             const struct li2_maps_current_view **out) {
    if(!ref || !out)return LI2_FETCH_ARGUMENT;
    *ref=(struct li2_maps_current_ref){0};*out=0;
    if(MV_LOAD(&maps_current.busy) || MV_LOAD(&maps_current.live))return LI2_FETCH_BUSY;
    if(MV_LOAD(&mv.poisoned) || MV_LOAD(&maps_stats.poisoned))return LI2_FETCH_STATE;
    if(!MV_LOAD(&mv.enabled) || mv_stack_retired)return LI2_MAPS_CURRENT_UNAVAILABLE;
    if(!active || !hooks.raw || tx.guard || MV_LOAD(&maps_stats.active)!=1 ||
       MV_LOAD(&mv_depth))return LI2_FETCH_STATE;
    if(maps_current.serial==UINT64_MAX){mv_poison();return LI2_FETCH_STATE;}
    MV_STORE(&maps_current.busy,1);
    maps_current.view=(struct li2_maps_current_view){.version=1};
    *out=&maps_current.view;
    struct check_error e={0};
    int error=read_maps_checked(&e,&maps_current.view.query);
    maps_current.view.physical=mct_physical_receipt;
    if(!error && mv_stack_retired)error=LI2_MAPS_CURRENT_UNAVAILABLE;
    if(!error && (!mct_state() || !mct_query(&maps_current.view.query) ||
       !mct_physical(&maps_current.view.physical) ||
       MV_LOAD(&mct_physical_id)!=maps_current.view.query.observation.acquisition_id))
        error=LI2_FETCH_STATE;
    if(error) {
        maps_current.view.result=error;maps_current.view.detail=e.detail;
        MV_STORE(&maps_current.busy,0);return error;
    }
    maps_current.view.serial=++maps_current.serial;
    maps_current.view.query_serial=MV_LOAD(&mv.queries);
    maps_current.view.table=(uintptr_t)rows;maps_current.view.rows=row_count;
    maps_current.view.stack_first=mv_stack_first;maps_current.view.stack_end=mv_stack_end;
    maps_current.view.complete=1;
    MV_STORE(&maps_current.live,1);MV_STORE(&maps_current.busy,0);
    *ref=(struct li2_maps_current_ref){&maps_current,maps_current.serial};
    error=li2_maps_current_validate(ref,*out);
    if(error) {
        MV_STORE(&maps_current.live,0);maps_current.view.complete=0;
        maps_current.view.result=error;*ref=(struct li2_maps_current_ref){0};
    }
    return error;
}
int li2_maps_current_release(const struct li2_maps_current_ref *ref) {
    int error=li2_maps_current_validate(ref,&maps_current.view);
    if(ref && ref->owner==&maps_current && ref->serial==maps_current.serial)
        MV_STORE(&maps_current.live,0);
    return error;
}
