/* Included only by the opt-in two-slot controller. All original semantic,
   physical query and full-byte checks remain at their original checkpoints. */
static int ptr_selected(void) {
    if(pe.selected_slot>=LI2_PTR_SLOTS)return 0;
    const struct li2_ptr_slot_ref *a=&pe.selection,*b=&pe.retained[pe.selected_slot].identity;
    return a->owner==&pe && b->owner==&pe && a->index==pe.selected_slot &&
        b->index==pe.selected_slot && !a->reserved && !b->reserved &&
        a->generation==b->generation;
}
static int ptr_storage(void) {
    if(!pe.initialized || !pe.registered || pe.selected_slot>=LI2_PTR_SLOTS ||
       pe.selected_bank>1 || protected_count>RANGES ||
       selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)!=1)return 0;
    uintptr_t first[3U*LI2_PTR_SLOTS],end[3U*LI2_PTR_SLOTS];unsigned used=0;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    if(pe.domain.allocated!=1 || pe.domain.registered!=1 || !pe.domain.directory ||
       (pe.domain.directory&(PAGE-1)) || pe.domain.directory>=(UINT64_C(1)<<47)-LI2_JD_DOMAIN_BYTES ||
       selected_run_protect_contains(0,pe.domain.directory,LI2_JD_DOMAIN_BYTES)!=1)return 0;
#endif
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *s=&pe.retained[i];
        if(s->identity.owner!=&pe || s->identity.index!=i || s->identity.reserved ||
           s->code_allocated!=2 || s->code_registered!=2 || s->proof_allocated!=1 ||
           s->proof_registered!=1 || !s->proof || (s->proof&(PAGE-1)) ||
           s->proof>=(UINT64_C(1)<<47)-PE_PROOF_BYTES || s->generation.proof!=s->proof ||
           selected_run_protect_contains(0,s->proof,PE_PROOF_BYTES)!=1)return 0;
        first[used]=s->proof;end[used++]=s->proof+PE_PROOF_BYTES;
        for(unsigned j=0;j<2;j++) {
            const struct ped_bank *b=&s->banks[j];
            const struct li2_pg_layout l=pg_layout(b->generated);
            if(b->allocated!=1 || b->registered!=1 || !b->generated ||
               (b->generated&(PAGE-1)) || b->generated>=(UINT64_C(1)<<47)-PE_ALLOC_BYTES ||
               (!j && b->generated>=(UINT64_C(1)<<31)-PE_ALLOC_BYTES) ||
               !pg_layout_equal(&b->layout,&l) || b->spill!=l.spill || b->virgin>1 ||
               (b->prot!=PROT_READ && b->prot!=(PROT_READ|PROT_WRITE) &&
                b->prot!=(PROT_READ|PROT_EXEC)) ||
               selected_run_protect_contains(0,b->generated,PE_ALLOC_BYTES)!=1)return 0;
            first[used]=b->generated;end[used++]=b->generated+PE_ALLOC_BYTES;
        }
    }
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<i;j++)
        if(pe.retained[i].identity.generation &&
           pe.retained[i].identity.generation==pe.retained[j].identity.generation)return 0;
    for(unsigned i=0;i<used;i++) {
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
        if(first[i]<pe.domain.directory+LI2_JD_DOMAIN_BYTES && pe.domain.directory<end[i])return 0;
#endif
        if(first[i]<(uintptr_t)&pe+sizeof pe && (uintptr_t)&pe<end[i])return 0;
        for(unsigned j=0;j<i;j++)if(first[i]<end[j] && first[j]<end[i])return 0;
    }
    return 1;
}
static int ptr_slots(unsigned index,unsigned linked) {
    if(index>=LI2_PTR_SLOTS || !ptr_storage())return 0;
    const struct li2_ptr_slot *s=&pe.retained[index];
    const struct li2_pg_generation *g=&s->generation;
    const struct li2_pg_compact *p=&((const struct pe_payload *)s->proof)->plan;
#ifdef LI2_PERSISTENT_DISPATCH
    if(linked>1 || g->linked!=linked || !p->exits || p->exits>LI2_PG_BOUNDARIES ||
       p->links>LI2_PG_BOUNDARIES || p->links+p->exits>LI2_PG_BOUNDARIES)return 0;
#else
    if(linked>1 || g->linked!=linked || !p->links || p->links+p->exits>LI2_PG_BOUNDARIES)return 0;
#endif
    const volatile unsigned char *b=(const void *)g->layout.slots;
    for(unsigned i=0;i<PAGE;i++) {
        unsigned j=i/8,k=i%8;uint64_t value=0;
        if(j<p->links)value=linked?p->edge[j].generated_target:p->edge[j].original_target;
        if(b[i]!=(unsigned char)(value>>(8*k)))return 0;
    }
    return 1;
}
static int ptr_stored(unsigned index) {
    if(index>=LI2_PTR_SLOTS)return 0;
    const struct li2_ptr_slot *s=&pe.retained[index];
    const struct li2_pg_generation *g=&s->generation;
    if(!pe_registered_storage() || g->installed!=1 || g->complete!=1 || g->proof_complete!=1 ||
       !g->generation || g->generation>pe.next_generation || g->generation!=s->identity.generation || g->ready_generation!=g->generation ||
       !g->build_serial || g->build_serial>pe.next_serial || !pg_closed(&g->layout,g->code_sealed) ||
       !pg_proof_permission_complete(&g->proof_sealed,g->proof,PROT_READ) ||
       g->code_copied!=PE_CODE_BYTES || g->code_verified!=PE_CODE_BYTES ||
       g->proof_zeroed!=PE_PROOF_BYTES || g->proof_copied!=sizeof(struct pe_payload) ||
       g->proof_verified!=PE_PROOF_BYTES || g->member_generation[0]!=2*g->generation ||
       g->member_generation[1]!=2*g->generation+1)return 0;
    unsigned found=0;
    for(unsigned i=0;i<2;i++)found+=g->generated==s->banks[i].generated &&
        g->spill==s->banks[i].spill && pg_layout_equal(&g->layout,&s->banks[i].layout);
    if(found!=1)return 0;
    const struct pe_payload *p=((const struct pe_payload *)s->proof);
    return equal(&p->header,&s->publication.header,sizeof p->header) &&
        equal(&p->source,&s->publication.source,sizeof p->source) &&
        p->header.version==1 && p->header.serial==g->build_serial &&
        p->header.generation==g->generation && p->header.registry==(uintptr_t)&pe &&
        p->header.generated==g->generated && p->header.spill==g->spill &&
        pg_layout_equal(&p->header.layout,&g->layout) &&
        equal(p->header.member_generation,g->member_generation,sizeof g->member_generation) &&
        p->header.table==g->proof+offsetof(struct pe_payload,plan.table) &&
        p->header.plan_proof==g->plan_proofs && g->plan_proofs==2 &&
        p->header.none_proof==g->none_proofs && g->none_proofs==1 &&
        equal(p->header.archive,pe_archive,32) && equal(p->header.policy,pe_policy,32) &&
        p->plan.version==LI2_PG_COMPACT_VERSION && p->plan.bytes==sizeof p->plan &&
        p->plan.ready==1 && !p->plan.result && pg_layout_equal(&p->plan.layout,&g->layout) &&
        p->plan.table.address==p->header.table && p->plan.entry==p->source.entry &&
#ifdef LI2_PERSISTENT_DISPATCH
        p->plan.heads && p->plan.heads<=LI2_PG_HEADS &&
        p->plan.member_heads[0]==(p->plan.heads<LI2_PE_HEADS?p->plan.heads:LI2_PE_HEADS) &&
        p->plan.member_heads[1]==(p->plan.heads>LI2_PE_HEADS?p->plan.heads-LI2_PE_HEADS:0) &&
        p->plan.exits && p->plan.exits<=LI2_PG_BOUNDARIES && p->plan.links<=LI2_PG_BOUNDARIES &&
        p->plan.links+p->plan.exits<=LI2_PG_BOUNDARIES &&
        (uintptr_t)p->plan.original==g->proof+offsetof(struct pe_payload,plan.original);
#else
        p->plan.heads>LI2_PE_HEADS && p->plan.heads<=LI2_PG_HEADS &&
        p->plan.member_heads[0]==LI2_PE_HEADS && p->plan.member_heads[1]==p->plan.heads-LI2_PE_HEADS &&
        p->plan.links && p->plan.exits && p->plan.links+p->plan.exits<=LI2_PG_BOUNDARIES;
#endif
}
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
static int ptr_permitted(unsigned index) { return pda_permitted(index); }
#else
static int ptr_permitted(unsigned index) {
    if(index>=LI2_PTR_SLOTS)return 0;
    const struct li2_ptr_slot *slot=&pe.retained[index];
    const struct ped_permit *p=&slot->permit;
    const struct li2_pg_generation *g=&slot->generation;
    const struct li2_pg_source_progress *s=&p->source;
    const struct li2_pg_rseq_progress *r=&p->rseq;
    if(!(p->valid==1 && p->serial && p->serial<=pe.next_serial &&
        slot->last_completed==p->serial && ptr_stored(index) &&
        p->generation==g->generation && p->generated==g->generated && p->proof==g->proof &&
        pg_layout_equal(&p->layout,&g->layout) &&
        equal(p->member_generation,g->member_generation,sizeof g->member_generation) &&
        !g->linked && !g->active_refs && !g->member_refs[0] && !g->member_refs[1] &&
        !g->incoming[0] && !g->incoming[1] && ptr_slots(index,0) &&
        pg_query_complete(&p->reset_slots,g->layout.slots,PAGE,PROT_READ) &&
        p->ref_sequence && p->fetch.sequence==p->ref_sequence && !p->fetch.held &&
        p->fetch.complete==1 && !p->fetch.first_error &&
        equal(p->close,g->close,sizeof p->close) && pg_closed(&g->layout,p->close) &&
        pg_proof_query_complete(&p->proof_query,g->proof,PROT_READ) &&
        s->serial==p->serial && s->phase==LI2_PGS_RELEASED && !s->first_error &&
        s->release_started==1 && s->release_complete==1 && s->source.complete==1 &&
        s->closed_extents==3 && s->closed_pages==17 &&
        pg_layout_equal(&s->layout,&g->layout) && s->source.anchor.sequence==p->ref_sequence &&
        equal(&p->generation_source,&slot->publication.source,sizeof p->generation_source) &&
        li2_pg_source_key_equal(&s->source.key,&p->generation_source) &&
        r->token.owner==&pe && r->token.serial==p->serial && !r->active && !r->first_error &&
        !r->unsafe_terminal && r->seed_complete==1 && r->entry_complete==1 && r->close_complete==1 &&
        !r->cancel_started && !r->cancel_complete &&
        r->registration_epoch==slot->publication.header.registered_epoch &&
        r->address==slot->publication.header.rseq_address && r->length==slot->publication.header.rseq_length &&
        r->signature==slot->publication.header.rseq_signature &&
        !r->word_before && !r->word_entry && !r->word_after))return 0;
    unsigned closed_bank=0;
    for(unsigned i=0;i<2;i++)closed_bank+=slot->banks[i].generated==g->generated &&
        !slot->banks[i].virgin && slot->banks[i].prot==PROT_READ;
    if(closed_bank!=1)return 0;
    for(unsigned i=0;i<3;i++)if(!pg_query_complete(&s->closed[i],pg_extent(&g->layout,i),
        pg_extent_bytes(i),PROT_READ))return 0;
#ifdef LI2_PERSISTENT_DISPATCH
    const struct pg_dispatch_cell_transition *cell=&g->cell[2];
    if(cell->started!=1 || cell->complete!=1 || cell->generation!=g->generation ||
       cell->serial!=p->serial || cell->after ||
       !pg_query_complete(&cell->mapping,g->spill,PAGE,PROT_READ|PROT_WRITE) ||
       *(const volatile uint64_t *)(g->spill+32))return 0;
#endif
    return 1;
}
#endif

/* Admission order is advisory. No certificate is claimed, reopened or
   relabelled here; a hit still needs fresh whole source/registration equality.
   Every candidate is either genuinely empty or has its real completed permit.
   Matching roots are unique; duplicate roots indicate corrupt owner state. */
static unsigned ptr_choose(uintptr_t pc) {
    pe_need(!pe_busy && !pe_active && !pe.resuming && ptr_selected() && ptr_storage() &&
        (pe.p.phase==LI2_PG_IDLE || pe.p.phase==LI2_PG_CLOSED || pe.p.phase==LI2_PG_CANCELLED) &&
        !pe.p.first_error,PE_STATE,42);
    unsigned match=LI2_PTR_SLOTS,empty=LI2_PTR_SLOTS,victim=LI2_PTR_SLOTS;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *s=&pe.retained[i];const struct li2_pg_generation *g=&s->generation;
        if(!g->installed) {
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
            pe_need(!s->claim.valid && !s->claim.id && !g->domain_refs,PE_STATE,73);
#endif
            pe_need(!s->identity.generation && !g->generation && !g->ready_generation &&
                !g->complete && !g->proof_complete && !g->build_serial &&
                !s->permit.valid && !s->permit.serial && !s->last_completed,
                PE_STATE,43+(long)i);
            if(empty==LI2_PTR_SLOTS)empty=i;
            continue;
        }
        pe_need(ptr_permitted(i),PE_RELEASE,40+(long)i);
        if(s->publication.source.entry==pc) {
            pe_need(match==LI2_PTR_SLOTS,PE_STATE,45);match=i;
        }
        if(victim==LI2_PTR_SLOTS || s->last_completed<pe.retained[victim].last_completed)victim=i;
    }
    unsigned chosen=match!=LI2_PTR_SLOTS?match:empty!=LI2_PTR_SLOTS?empty:victim;
    pe_need(chosen<LI2_PTR_SLOTS,PE_STATE,46);return chosen;
}
