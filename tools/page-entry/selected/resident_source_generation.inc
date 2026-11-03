/* Included inside the actual lifecycle source owner. Its protected R state
   shares the existing source-owner permission interval and writer exclusion.
   Live source bytes, mappings, backing, aliases and rseq are never cached. */
static int rsl_generation_bound(const struct li2_r3_token *t) {
    struct li2_rsl_generation_progress *g=&rsl.owner.content;
    if(!rsl_resident_token(t) || li2_r3_owner_phase(t)!=LI2_R3_HELD || g->pending ||
       g->state>LI2_RSG_DIRTY)return LI2_FETCH_STATE;
    if(g->state==LI2_RSG_UNISSUED) {
        if(g->generation || g->publication_epoch || !rsl.owner.p.epoch)return LI2_FETCH_STATE;
        g->generation=1;g->publication_epoch=rsl.owner.p.epoch;g->state=LI2_RSG_LIVE;
    }
    return g->state==LI2_RSG_LIVE && g->generation && g->publication_epoch &&
        g->publication_epoch<=rsl.owner.p.epoch?0:LI2_FETCH_STALE;
}
/* No refresh of a DIRTY identity. A future retirement/republication owner
   would need a separate actual lifetime; address/protection ABA is not one. */
static int rsl_generation_dirty(void) {
    struct li2_rsl_generation_progress *g=&rsl.owner.content;
    if(g->state>LI2_RSG_DIRTY)return LI2_FETCH_STATE;
    if(g->state==LI2_RSG_LIVE || g->state==LI2_RSG_SUSPENDED) {
        if(g->generation==UINT64_MAX || g->invalidations==UINT64_MAX)return LI2_FETCH_STATE;
#ifdef LI2_RESIDENT_RX
        /* Revoke all resident code before dirtying this identity. A failed
           revoke never reaches the mutator or returns to guest execution. */
        int retire=li2_r3_rx_retire();if(retire)return retire;
#endif
        ++g->generation;++g->invalidations;g->state=LI2_RSG_DIRTY;
    }
    g->pending=0;g->pending_epoch=0;g->number=0;
    for(unsigned i=0;i<6;i++)g->args[i]=0;
    return 0;
}
static int rsl_generation_preservable(long number,const long args[6]) {
    /* First, small exact nonmapping set. All output extents still pass the
       original rsl_effect and rseq guards before RAW. FD topology, writes,
       mapping operations, deferred writers and every other form dirty. */
    if(number==SYS_getpid || number==SYS_gettid || number==SYS_getuid ||
       number==SYS_geteuid || number==SYS_getgid || number==SYS_getegid)return 1;
    if(li2_readonly_query(number,args,0))return 1;
    return number==SYS_arch_prctl && (args[0]==ARCH_GET_FS || args[0]==ARCH_GET_GS);
}
/* Called only in the existing trusted RW interval, after execution lease
   invalidation and before its seal and the original kernel-output guards. */
static int rsl_generation_before(long number,const long args[6]) {
    struct li2_rsl_generation_progress *g=&rsl.owner.content;
    if(!args || g->pending || g->state==LI2_RSG_SUSPENDED ||
       g->state>LI2_RSG_DIRTY || g->effects==UINT64_MAX)return LI2_FETCH_STATE;
    ++g->effects;g->result=0;
    if(g->state!=LI2_RSG_LIVE)return 0;
    if(!rsl_generation_preservable(number,args))return rsl_generation_dirty();
    g->state=LI2_RSG_SUSPENDED;g->pending=1;g->pending_epoch=rsl.owner.p.epoch;
    g->number=number;for(unsigned i=0;i<6;i++)g->args[i]=args[i];
#ifdef LI2_RESIDENT_RX
    return li2_r3_rx_suspend();
#else
    return 0;
#endif
}
int li2_rsl_generation_after_effect(long number,const long args[6],long result) {
    struct li2_rsl_generation_progress *g=&rsl.owner.content;
    if(!args || !rsl.owner.p.initialized || !rsl_identity())return LI2_FETCH_IDENTITY;
    if(g->state!=LI2_RSG_SUSPENDED)return g->pending?LI2_FETCH_STATE:0;
    if(g->pending!=1 || !g->generation || !g->publication_epoch ||
       g->pending_epoch!=rsl.owner.p.epoch || rsl.owner.p.valid ||
       rsl.owner.p.bound.owner || rsl.owner.p.bound.serial ||
       rsl.owner.resident.bound.owner || rsl.owner.resident.bound.serial ||
       g->number!=number || !equal(g->args,args,sizeof g->args) ||
       !rsl_generation_preservable(number,args))return LI2_FETCH_STATE;
    /* Identity getters have an independent real PID/TID join. Other getters
       return their actual native result; error always dirties this profile. */
    if(number==SYS_getpid && result!=RAW(SYS_getpid,0,0,0,0,0,0))return LI2_FETCH_IDENTITY;
    if(number==SYS_gettid && result!=RAW(SYS_gettid,0,0,0,0,0,0))return LI2_FETCH_IDENTITY;
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    g->result=result;
    int error=0;
    if(result<0)error=rsl_generation_dirty();
    else if(g->preserved==UINT64_MAX)error=LI2_FETCH_STATE;
    else {
        ++g->preserved;g->state=LI2_RSG_LIVE;g->pending=0;g->pending_epoch=0;g->number=0;
        for(unsigned i=0;i<6;i++)g->args[i]=0;
#ifdef LI2_RESIDENT_RX
        error=li2_r3_rx_resume();
#endif
    }
    return rsl_finish(error);
}
int li2_rsl_generation_not_native(void) {
    if(!rsl.owner.p.initialized || !rsl_identity())return LI2_FETCH_IDENTITY;
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    return rsl_finish(rsl_generation_dirty());
}
int li2_rsl_generation_source_mutation(void) {
    if(!rsl.owner.p.initialized || !rsl_identity() ||
       li2_lifecycle_fetch_interlock() || !li2_rsl_source_mutation_quiet() ||
       rsl.owner.p.epoch==UINT64_MAX || rsl.owner.p.invalidations==UINT64_MAX ||
       rsl.owner.content.source_mutations==UINT64_MAX)return LI2_FETCH_BUSY;
    if(rsl_permission(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    rsl.owner.p.valid=0;rsl.owner.p.bound=(struct li2_pg_token){0};rsl_resident_clear();
    ++rsl.owner.p.epoch;++rsl.owner.p.invalidations;++rsl.owner.content.source_mutations;
    return rsl_finish(rsl_generation_dirty());
}
int li2_rsl_resident_content(const struct li2_r3_token *t,struct li2_rsl_content_ref *out) {
    const struct li2_rsl_generation_progress *g=&rsl.owner.content;
    if(!out || !rsl_resident_token(t) || g->state!=LI2_RSG_LIVE || g->pending ||
       !g->generation || !g->publication_epoch || g->publication_epoch>rsl.owner.p.epoch)
        return LI2_FETCH_STALE;
    *out=(struct li2_rsl_content_ref){&rsl.owner,g->generation,g->publication_epoch};return 0;
}
int li2_rsl_resident_content_live(const struct li2_r3_token *t,const struct li2_rsl_content_ref *ref) {
    struct li2_rsl_content_ref actual={0};
    return !ref || li2_rsl_resident_content(t,&actual) || !equal(ref,&actual,sizeof actual)?
        LI2_FETCH_STALE:0;
}
const struct li2_rsl_generation_progress *li2_rsl_generation_progress(void) {
    return &rsl.owner.content;
}

#ifdef LI2_RESIDENT_RX
unsigned li2_rsl_resident_content_state(const struct li2_rsl_content_ref *ref) {
    const struct li2_rsl_generation_progress *g=&rsl.owner.content;
    if(!ref || ref->owner!=&rsl.owner || !rsl.owner.p.initialized ||
       !ref->generation || ref->generation!=g->generation ||
       !ref->publication_epoch || ref->publication_epoch!=g->publication_epoch ||
       g->publication_epoch>rsl.owner.p.epoch ||
       (g->state!=LI2_RSG_LIVE && g->state!=LI2_RSG_SUSPENDED) ||
       (g->state==LI2_RSG_LIVE && g->pending) ||
       (g->state==LI2_RSG_SUSPENDED && (g->pending!=1 ||
         g->pending_epoch!=rsl.owner.p.epoch)))return ~0U;
    return g->state;
}
#endif
