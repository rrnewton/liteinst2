/* Included only for LOOP, inside lifecycle_loader.c. No map query, decoder,
   source read, permission operation or observer mutation occurs on a hit. */
_Static_assert(PAGE==4096 && SEALED==1 && ANONYMOUS==2 && (PROT_READ|PROT_EXEC)==5,
    "negative hint uses the existing owned-page vocabulary");
static int pgs_hint_page(size_t index,struct li2_plnh_page *out) {
    if(used>RECORDS || index>=used || !out)return 0;
    const struct owned_page *p=&records[index];
    if(p->live!=1 || !p->allocation || !p->generation || p->admitted ||
       p->logical!=(PROT_READ|PROT_EXEC) ||
       (p->actual!=PROT_READ && p->actual!=(PROT_READ|PROT_EXEC)) ||
       !pgs_loop_owned_class(p))return 0;
    *out=(struct li2_plnh_page){.record=index+1,.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical};
    return 1;
}
int li2_pg_source_negative_decline(uintptr_t pc,const uintptr_t pages[2]) {
    if(!pg_source.p.initialized || pg_source.p.first_error || pg_source.p.aborted ||
       li2_pg_source_interlock() || !pages || !li2_plnh_cache_valid(&pg_negative_hint))return 0;
    for(unsigned i=0;i<pg_negative_hint.count;i++) {
        const struct li2_plnh_key *saved=&pg_negative_hint.key[i];
        if(saved->pc!=pc || saved->page[0].address!=pages[0] || saved->page[1].address!=pages[1] ||
           !li2_plnh_key_valid(saved))continue;
        struct li2_plnh_key actual={.pc=pc};unsigned j=0;
        for(;j<2;j++) {
            uint64_t record=saved->page[j].record;
            if(!record || record>used || !pgs_hint_page((size_t)record-1,&actual.page[j]))break;
        }
        if(j==2 && li2_plnh_key_equal(saved,&actual))return 1;
    }
    return 0;
}
void li2_pg_source_negative_remember(const struct li2_pg_token *t) {
    const struct li2_pg_source_progress *p=&pg_source.p;
    /* Caller is the one post-epoch_cancel site, after real TF resume. These
       source-side predicates independently bind that completed cancellation. */
    if(!pgs_token(t) || li2_pg_owner_phase(t)!=LI2_PG_CANCELLED ||
       p->phase!=LI2_PGS_CANCELLED || p->first_error || p->aborted ||
       p->source.complete!=1 || p->cancel_started!=1 || p->cancel_complete!=1 ||
       p->release_started!=1 || p->release_complete!=1 || !pgs_cancelled(p) ||
       p->cancelled_fetch.complete!=1 || p->cancelled_fetch.progress.held ||
       used>RECORDS)return;
    struct li2_plnh_key key={.pc=p->source.key.entry};
    for(unsigned j=0;j<2;j++) {
        const struct owned_page *old=&pg_source.original[j];
        const struct li2_fetch_page *source=&p->source.key.page[j].identity;
        if(old->live!=1 || old->admitted || old->actual!=PROT_READ ||
           source->address!=old->address || source->allocation!=old->allocation ||
           source->generation!=old->generation || source->offset!=old->offset ||
           source->initial_extent!=old->initial_extent || source->backing!=old->backing ||
           source->object!=old->object || source->logical!=old->logical ||
           source->closed_prot!=PROT_READ)return;
        size_t i=used;
        while(i && !(records[i-1].live && records[i-1].address==old->address))--i;
        if(!i || !pgs_hint_page(i-1,&key.page[j]))return;
        const struct li2_plnh_page expected={.record=i,.address=old->address,
            .allocation=old->allocation,.generation=old->generation,.offset=old->offset,
            .initial_extent=old->initial_extent,.backing=old->backing,
            .object=old->object,.logical=old->logical};
        if(!li2_plnh_page_equal(&expected,&key.page[j]))return;
    }
    li2_plnh_put(&pg_negative_hint,&key);
}
