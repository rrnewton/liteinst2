/* Included after the complete protected sg_owner and original owner types.
   No mutable state or cached source result is hidden in a pure planner. */
#ifdef LI2_LOOP_CACHE8
_Static_assert(LI2_PTR_SLOTS==8 && PE_PROOF_BYTES==89U*PAGE,
    "eight retained certificates with the unchanged complete publication bytes");
#else
_Static_assert(LI2_PTR_SLOTS==2 && PE_PROOF_BYTES==89U*PAGE,
    "same two retained certificates and complete publication bytes");
#endif
_Static_assert(_Alignof(struct li2_ptr_slot)==PAGE &&
    offsetof(struct li2_ptr_slot,publication)%PAGE==0 &&
    sizeof(((struct li2_ptr_slot *)0)->publication_pages)==PE_PROOF_BYTES &&
    offsetof(struct li2_ptr_slot,registry_count)>=
        offsetof(struct li2_ptr_slot,publication)+PE_PROOF_BYTES,
    "no mutable owner field shares a publication-mirror page");
_Static_assert(_Alignof(struct li2_pg_epoch)==PAGE &&
    offsetof(struct li2_pg_epoch,retained)%PAGE==0,
    "every reserved mirror address is aligned in the real owner");

/* Observations carry no authority. The shared helper counts actual calls from
   initialization, byte-certificate checks and historical-capsule checks. */
static struct {
    uint64_t initialized,readonly_calls,query_attempts,requested_pages,query_errors;
    uint64_t mirror_opens,mirror_seals;
} lrc_observed;
static int lrc_readonly(uintptr_t first,size_t bytes) {
    if(lrc_observed.initialized!=1 || lrc_observed.readonly_calls==UINT64_MAX)return PE_STATE;
    ++lrc_observed.readonly_calls;
    if(!bytes || ((first|bytes)&(PAGE-1)) || first>UINTPTR_MAX-bytes ||
       selected_run_protect_contains(0,first,bytes)!=1)return PE_STATE;
    while(bytes) {
        size_t part=bytes>64U*PAGE?64U*PAGE:bytes;
        if(lrc_observed.query_attempts==UINT64_MAX ||
           lrc_observed.requested_pages>UINT64_MAX-part/PAGE ||
           lrc_observed.query_errors==UINT64_MAX)return PE_STATE;
        ++lrc_observed.query_attempts;lrc_observed.requested_pages+=part/PAGE;
        struct li2_private_code_query q={0};
        int error=li2_lifecycle_private_code_query(first,part,PROT_READ,&q);
        if(error || q.attempted!=1 || q.complete!=1 || q.result ||
           q.first!=first || q.end!=first+part || q.pages_checked!=part/PAGE ||
           q.expected_prot!=PROT_READ || q.actual_prot!=PROT_READ || q.sealed.kind) {
            ++lrc_observed.query_errors;
            return PE_PUBLICATION;
        }
        first+=part;bytes-=part;
    }
    return 0;
}
static int lrc_initialize(void) {
    if(!sg_owner.state.initialized || sg_owner.state.ro_initialized ||
       sg_owner.state.ro_writable_mask || pe.initialized || !pe_busy || pe_active ||
       pe.resuming || selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)!=1)
        return PE_STATE;
    if(lrc_observed.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&lrc_observed,sizeof lrc_observed))return PE_STATE;
    lrc_observed.initialized=1;
    for(unsigned slot=0;slot<LI2_PTR_SLOTS;slot++) {
        uintptr_t at=(uintptr_t)&pe.retained[slot].publication;
        /* The page-isolation assertions above make this replacement disjoint
           from every adjacent owner field. No guest has run in this owner. */
        long result=raw(SYS_mmap,at,PE_PROOF_BYTES,PROT_READ,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
        if((uintptr_t)result!=at || lrc_readonly(at,PE_PROOF_BYTES))return PE_PUBLICATION;
    }
    int error=lhc_initialize();if(error)return error;
#ifdef LI2_LOOP_RO_TEST
    error=lro_initialize();if(error)return error;
#endif
    sg_owner.state.ro_initialized=1;
    return 0; /* sg_initialize seals the complete root before returning. */
}
static int lrc_state(void) {
    if(sg_owner.state.ro_initialized!=1 || sg_owner.state.ro_writable_mask ||
       sg_owner.state.bytes.poisoned || pe.selected_slot>=LI2_PTR_SLOTS ||
       handling!=1 || !pe_busy || pe_failing || pe.resuming ||
       !pe_identity())return 0;
    return 1;
}
static int lrc_live(void) {
    return lrc_state() && !lrc_readonly((uintptr_t)&sg_owner,sizeof sg_owner) &&
        !lrc_readonly((uintptr_t)&PE_SLOT(publication),PE_PROOF_BYTES);
}
static int lrc_mirror_begin(void) {
    if(!lrc_live() || !sbc_unpublished() || pe.p.phase!=LI2_PG_PUBLISHING ||
       !pe.consumed || pe.warm || pe_active || PE_SLOT(generation).ready_generation ||
       lrc_observed.mirror_opens==UINT64_MAX)return PE_STATE;
    /* The existing replacement protocol already invalidated this slot's
       certificate and assigned the nonwrapping mirror epoch/writer serial. */
    if(sg_permission(PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    sg_owner.state.ro_writable_mask=1U<<pe.selected_slot;
    __asm__ volatile("":::"memory");
    if(sg_permission(PROT_READ))return PE_PUBLICATION;
    if(raw(SYS_mprotect,(long)&PE_SLOT(publication),PE_PROOF_BYTES,
        PROT_READ|PROT_WRITE,0,0,0))return PE_PUBLICATION;
    ++lrc_observed.mirror_opens;return 0;
}
static int lrc_mirror_end(void) {
    if(sg_owner.state.ro_initialized!=1 || pe.selected_slot>=LI2_PTR_SLOTS ||
       sg_owner.state.ro_writable_mask!=(1U<<pe.selected_slot) ||
       !sbc_unpublished() || handling!=1 || !pe_busy || pe_active || pe_failing ||
       pe.resuming || !pe_identity() || pe.p.phase!=LI2_PG_PUBLISHING ||
       lrc_observed.mirror_seals==UINT64_MAX)
        return PE_STATE;
    if(raw(SYS_mprotect,(long)&PE_SLOT(publication),PE_PROOF_BYTES,PROT_READ,0,0,0) ||
       lrc_readonly((uintptr_t)&PE_SLOT(publication),PE_PROOF_BYTES))return PE_PUBLICATION;
    ++lrc_observed.mirror_seals;
    if(sg_permission(PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    sg_owner.state.ro_writable_mask=0;
    __asm__ volatile("":::"memory");
    if(sg_permission(PROT_READ))return PE_PUBLICATION;
    return lrc_live()?0:PE_PUBLICATION;
}
static void lrc_abort(void) {
    /* The caller has poisoned/invalidate-all before this close. An error here
       remains terminal; no resumed guest or certificate reuse follows it. */
    lhc_abort();
    for(unsigned slot=0;slot<LI2_PTR_SLOTS;slot++)
        (void)raw(SYS_mprotect,(long)&pe.retained[slot].publication,
            PE_PROOF_BYTES,PROT_READ,0,0,0);
}
static void lrc_report(unsigned status,unsigned code) {
    struct writer w={.used=0};text(&w,"LI2_LOOP_RO_CERTIFICATE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"initialized\":",lrc_observed.initialized);
    field(&w,",\"readonly_calls\":",lrc_observed.readonly_calls);
    field(&w,",\"query_attempts\":",lrc_observed.query_attempts);
    field(&w,",\"requested_pages\":",lrc_observed.requested_pages);
    field(&w,",\"query_errors\":",lrc_observed.query_errors);
    field(&w,",\"mirror_opens\":",lrc_observed.mirror_opens);
    field(&w,",\"mirror_seals\":",lrc_observed.mirror_seals);
    text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    lhc_report(status,code);
#ifdef LI2_LOOP_RO_TEST
    lro_report(status,code);
#endif
}
