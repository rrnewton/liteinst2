/* Actual three-resident source binding. Included inside the lifecycle owner;
   no caller-provided page list, compact pointer, generation or close flag is
   accepted. Storage publication and RX entry remain the separate r3 owner's
   responsibility. This first finite path retains complete authentication. */
enum rsl_resident_operation { RSL_R_BIND,RSL_R_SNAPSHOT,RSL_R_PLAN,RSL_R_VALIDATE };
static int rsl_resident_phase(unsigned phase) {
    return phase==LI2_R3_HELD || phase==LI2_R3_PLANNING ||
        phase==LI2_R3_PUBLISHING || phase==LI2_R3_BOUND || phase==LI2_R3_CLOSING;
}
int li2_rsl_resident_advisory(uintptr_t root) {
    if(rsl.owner.p.initialized!=1 || !rsl.owner.p.pages ||
       rsl.owner.p.pages>LI2_RSL_PAGES || root<PAGE ||
       root>=(UINT64_C(1)<<47)-2U*PAGE || (root&(PAGE-1))>PAGE-15)return 0;
    uintptr_t first=root&~(PAGE-1);unsigned found[2]={0};
    for(unsigned i=0;i<rsl.owner.p.pages;i++)for(unsigned j=0;j<2;j++)
        found[j]+=rsl.owner.page[i].original.address==first+j*PAGE;
    return found[0]==1 && found[1]==1;
}
static int rsl_resident_seed(const struct li2_r3_token *t,struct li2_r3_seed *seed) {
    if(!t || !seed || !rsl_resident_phase(li2_r3_owner_phase(t)) ||
       li2_r3_owner_seed(t,seed) || seed->complete!=1 || seed->reserved ||
       seed->serial!=t->serial || !seed->held.owner || !seed->held.sequence ||
       !seed->session || seed->pid<=0 || seed->pid!=seed->tid ||
       !li2_rsl_resident_advisory(seed->root))return LI2_FETCH_STATE;
    return 0;
}
static int rsl_resident_held(const struct li2_r3_seed *seed) {
    struct li2_span_fetch_observation actual={0};
    if(!seed || li2_lifecycle_span_fetch_snapshot(&actual) || actual.complete!=1 ||
       actual.progress.held!=1 || actual.progress.complete!=1 || actual.progress.first_error ||
       actual.ref.owner!=seed->held.owner || actual.ref.sequence!=seed->held.sequence ||
       actual.pc!=seed->root || actual.length!=15 || actual.page_count!=1 ||
       actual.pid!=seed->pid || actual.tid!=seed->tid)return LI2_FETCH_STALE;
    uintptr_t first=seed->root&~(PAGE-1);unsigned found=0;
    for(unsigned i=0;i<rsl.owner.p.pages;i++) {
        const struct rsl_page *page=&rsl.owner.page[i];
        if(page->original.address!=first)continue;
        if(!span_source_page_equal(&actual.pages[0],&page->identity) ||
           !span_source_backing_equal(&actual.backing[0],&page->backing) ||
           !equal(actual.bytes,page->bytes+(seed->root-first),sizeof actual.bytes))
            return LI2_FETCH_SOURCE;
        ++found;
    }
    return found==1?0:LI2_FETCH_SOURCE;
}
static int rsl_resident_token(const struct li2_r3_token *t) {
    const struct li2_rsl_resident_progress *r=&rsl.owner.resident;
    struct li2_r3_seed seed={0};
    return t && t->owner==r->bound.owner && t->serial && t->serial==r->bound.serial &&
        t->serial==r->last_serial && rsl.owner.p.initialized==1 && rsl.owner.p.valid==1 &&
        !rsl.owner.p.bound.owner && !rsl.owner.p.bound.serial &&
        r->epoch && r->epoch==rsl.owner.p.epoch && !rsl_resident_seed(t,&seed) &&
        equal(&seed,&r->seed,sizeof seed) && !rsl_resident_held(&seed);
}
/* Called only while the existing protected metadata interval is RW. Counts
   are observations, not authority; overflow is refusal before any update. */
static int rsl_resident_add(unsigned operation,unsigned authentications,unsigned extra_seal) {
    struct li2_rsl_resident_progress *r=&rsl.owner.resident;uint64_t *count=0;
    if(operation==RSL_R_BIND)count=&r->bindings;
    else if(operation==RSL_R_SNAPSHOT)count=&r->snapshots;
    else if(operation==RSL_R_PLAN)count=&r->plans;
    else if(operation==RSL_R_VALIDATE)count=&r->validations;
    else return LI2_FETCH_ARGUMENT;
    if(authentications>2 || extra_seal>1 || !rsl.owner.p.pages ||
       rsl.owner.p.pages>LI2_RSL_PAGES)return LI2_FETCH_ARGUMENT;
    uint64_t source=(uint64_t)authentications*rsl.owner.p.pages*PAGE;
    uint64_t plan=operation==RSL_R_PLAN?2U*PAGE:0;
    uint64_t guard=operation==RSL_R_PLAN?rsl.owner.p.pages:0;
    if(*count==UINT64_MAX || r->authentications>UINT64_MAX-authentications ||
       r->fresh_maps_passes>UINT64_MAX-authentications || r->source_bytes>UINT64_MAX-source ||
       r->plan_source_bytes>UINT64_MAX-plan || r->guard_pages>UINT64_MAX-guard ||
       r->observation_seals>UINT64_MAX-extra_seal)return LI2_FETCH_STATE;
    ++*count;r->authentications+=authentications;r->fresh_maps_passes+=authentications;
    r->source_bytes+=source;r->plan_source_bytes+=plan;r->guard_pages+=guard;
    r->observation_seals+=extra_seal;return 0;
}
static int rsl_resident_record(unsigned operation,unsigned authentications) {
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    return rsl_finish(rsl_resident_add(operation,authentications,1));
}
int li2_rsl_resident_bind(const struct li2_r3_token *t) {
    struct li2_r3_seed seed={0};
    if(!t || li2_r3_owner_phase(t)!=LI2_R3_HELD || rsl_resident_seed(t,&seed) ||
       rsl.owner.p.initialized!=1 || rsl.owner.p.bindings==UINT64_MAX ||
       t->serial<=rsl.owner.resident.last_serial)return LI2_FETCH_STATE;
    unsigned authentications=1;
    if(rsl.owner.p.valid) {
        int error=rsl_authenticate(0);if(error)return error;
        ++authentications;
    }
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    rsl.owner.p.valid=0;rsl.owner.p.bound=(struct li2_pg_token){0};rsl_resident_clear();
    int error=rsl_authenticate(1);
    if(!error)error=rsl_resident_held(&seed);
    if(!error)error=rsl_resident_add(RSL_R_BIND,authentications,0);
    if(!error) {
        rsl.owner.resident.bound=*t;rsl.owner.resident.seed=seed;
        rsl.owner.resident.epoch=rsl.owner.p.epoch;rsl.owner.resident.last_serial=t->serial;
        rsl.owner.p.valid=1;++rsl.owner.p.bindings;
    }
    return rsl_finish(error);
}
int li2_rsl_resident_validate(const struct li2_r3_token *t) {
    if(!rsl_resident_token(t))return LI2_FETCH_STALE;
    int error=rsl_authenticate(0);if(error)return error;
    if(!rsl_resident_token(t))return LI2_FETCH_STALE;
    return rsl_resident_record(RSL_R_VALIDATE,1);
}
int li2_rsl_resident_snapshot(const struct li2_r3_token *t,struct li2_rsl_ref *out,unsigned *pages) {
    if(!out || !pages || li2_r3_owner_phase(t)!=LI2_R3_HELD)return LI2_FETCH_ARGUMENT;
    int error=li2_rsl_resident_validate(t);if(error)return error;
    error=rsl_resident_record(RSL_R_SNAPSHOT,0);if(error)return error;
    *out=(struct li2_rsl_ref){&rsl.owner,rsl.owner.p.epoch};*pages=rsl.owner.p.pages;return 0;
}
int li2_rsl_resident_plan(const struct li2_r3_token *t,unsigned index) {
    if(!rsl_resident_token(t) || index>=LI2_R3_CERTIFICATES)return LI2_FETCH_STALE;
    const struct li2_pg_compact *plan=li2_r3_owner_plan(t,index);
    if(!plan)return LI2_FETCH_STATE;
    struct li2_rsl_ref ref={&rsl.owner,rsl.owner.p.epoch};
    int error=li2_rsl_covers(&ref,&plan->table);if(error)return error;
    for(unsigned i=0;i<2;i++) {
        unsigned found=0;
        for(unsigned j=0;j<rsl.owner.p.pages;j++)if(plan->page[i]==rsl.owner.page[j].original.address) {
            if(!equal(plan->source[i],rsl.owner.page[j].bytes,PAGE))return LI2_FETCH_SOURCE;
            ++found;
        }
        if(found!=1)return LI2_FETCH_SOURCE;
    }
    return rsl_resident_record(RSL_R_PLAN,0);
}
const struct li2_rsl_resident_progress *li2_rsl_resident_progress(void) {
    return &rsl.owner.resident;
}
