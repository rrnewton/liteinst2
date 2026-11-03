/* A dormant node carries an immutable publication identity, never an old
   execution claim. The only claim issuer remains pda_complete. */
static int lta_node_bound(unsigned node) {
    for(unsigned slot=0;slot<LI2_PTR_SLOTS;slot++)
        if(ptr_node_index(slot)==node)return (int)slot;
    return -1;
}
static int lta_issued_value(unsigned node) {
    if(!ptr_node_storage(node))return 0;
    const struct lta_dormant *d=&lta_writer.value.dormant[node];
    const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
    const struct li2_pg_generation *g=&s->generation;
    return d->issued==1 && d->reserved==0 && d->bank<2 &&
        d->node_epoch && d->node_epoch==lta_writer.value.node[node] &&
        d->generation==g->generation && d->generation==s->identity.generation &&
        d->build_serial==g->build_serial && d->root==s->publication.source.entry &&
        d->page[0]==s->publication.source.page[0].identity.address &&
        d->page[1]==s->publication.source.page[1].identity.address &&
        g->installed==1 && g->complete==1 && g->proof_complete==1 &&
        g->ready_generation==g->generation && g->generated==s->banks[d->bank].generated &&
        pg_layout_equal(&g->layout,&s->banks[d->bank].layout) &&
        equal(&d->certificate,&sg_owner.state.bytes.certificate[node],sizeof d->certificate);
}
static int lta_closed_value(unsigned node) {
    if(!lta_issued_value(node))return 0;
    const struct lta_dormant *d=&lta_writer.value.dormant[node];
    const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
    const struct li2_pg_generation *g=&s->generation;
    return d->closed==1 && d->reusable==1 && d->retired_binding &&
        d->retired_binding<=pe.arena.next_binding && d->completion_id &&
        d->completion_id<=pe.domain.next_id && d->completion_serial==s->last_completed &&
        d->completion_serial && d->completion_serial<=pe.next_serial &&
        pda_zero(&s->claim,sizeof s->claim) && !s->permit.valid && !s->permit.serial &&
        !g->linked && !g->active_refs && !g->domain_refs &&
        !g->member_refs[0] && !g->member_refs[1] && !g->incoming[0] && !g->incoming[1] &&
        s->banks[d->bank].prot==PROT_READ && !s->banks[d->bank].virgin;
}
static int lta_available(unsigned slot) {
    unsigned node=ptr_node_index(slot);
    if(node>=PTR_NODE_COUNT)return 0;
    return PTR_NODE_AT(node).claim.valid?pda_permitted(slot):lta_closed_value(node);
}
/* Issued only after the original planner, byte publication, sealing and SBC
   issuer have all succeeded at these exact final addresses. */
static int lta_published(void) {
    unsigned node=ptr_node_index(pe.selected_slot);
    if(node>=PTR_NODE_COUNT || pe.warm || pe.p.phase!=LI2_PG_BOUND || !pe_busy || pe_active ||
       !ptr_stored(pe.selected_slot) || !sbc_match() || !pda_zero(&PE_SLOT(claim),sizeof PE_SLOT(claim)) ||
       !lta_topology_live())return PE_STATE;
    struct lta_dormant d={0};
    d.issued=1;d.node_epoch=lta_writer.value.node[node];
    d.generation=PE_SLOT(generation).generation;d.build_serial=PE_SLOT(generation).build_serial;
    d.root=PE_SLOT(publication).source.entry;d.bank=pe.selected_bank;
    for(unsigned i=0;i<2;i++)d.page[i]=PE_SLOT(publication).source.page[i].identity.address;
    d.certificate=sg_owner.state.bytes.certificate[node];
    lta_writer.value.dormant[node]=d;
    ped_count(&lta_writer.value.cold_nodes);
    return lta_issued_value(node)?0:PE_PUBLICATION;
}
/* Detach consumes the real previous completion exactly once. It cannot run
   until TRACE has closed, or while a current member is already admitted. */
static int lta_detach(unsigned slot) {
    unsigned node=ptr_node_index(slot);
    if(node>=PTR_NODE_COUNT || !pe_busy || pe_active || pe_closing || handling!=1 ||
       !pe.close_complete || pe.domain.work.bound)return PE_STATE;
    struct li2_ptr_slot *s=&PTR_NODE_AT(node);
    if(!s->generation.installed) return !s->identity.generation &&
        pda_zero(&s->claim,sizeof s->claim)?0:PE_STATE;
    if(lta_closed_value(node))return 0;
    if(!pda_permitted(slot) || !lta_issued_value(node))return PE_RELEASE;
    int error=lprx_revoke(LPRX_COLD);if(error)return error;
    unsigned bank=pda_bank(slot);
    if(bank>=2 || !pda_permitted(slot) || s->banks[bank].prot!=PROT_READ)return PE_RELEASE;
    struct lta_dormant *d=&lta_writer.value.dormant[node];
    const struct pda_completion *c=&pe.domain.completion[s->claim.cell];
    d->retired_binding=pe.arena.binding[slot].generation;
    d->completion_id=c->id;d->completion_serial=c->serial;
    pda_claim(slot);ped_count(PGC_REF(permit_claims));
    d->prepared_serial=d->prepared_binding=0;d->closed=d->reusable=1;
    pe.arena.rebind_mask&=~(1U<<slot);ped_count(&lta_writer.value.detached);
    return lta_closed_value(node)?0:PE_RELEASE;
}
static int lta_move(unsigned slot,unsigned node) {
    unsigned old=ptr_node_index(slot);
    if(old>=PTR_NODE_COUNT || node>=PTR_NODE_COUNT || !ptr_storage() ||
       lta_node_bound(node)>=0 || pe.arena.next_binding==UINT64_MAX)return PE_STATE;
    if(PTR_NODE_AT(node).generation.installed && !lta_closed_value(node))return PE_RELEASE;
    int error=lta_detach(slot);if(error)return error;
    PTR_NODE_AT(old).identity.index=LI2_PTR_SLOTS;
    ++lta_writer.value.next_binding;pe.arena.next_binding=lta_writer.value.next_binding;
    pe.arena.binding[slot]=(struct lta_binding){pe.arena.next_binding,node,0};
    PTR_NODE_AT(node).identity.index=slot;
    le_zero(&pe.rx.slot[slot],sizeof pe.rx.slot[slot]);
    if(pe.selected_slot==slot)pe.selection=PTR_NODE_AT(node).identity;
    return ptr_storage()?0:PE_STATE;
}
/* This is a new fresh-admission token. Current source/rseq/registry checks
   still precede domain entry; no saved completion is replayed as current. */
static int lta_prepare(unsigned slot) {
    unsigned node=ptr_node_index(slot);
    if(node>=PTR_NODE_COUNT || !lta_closed_value(node) || !pda_registry(slot) ||
       !pda_registration((const void *)PTR_NODE_AT(node).proof) ||
       !ptr_stored(slot) || !ptr_slots(slot,0))return PE_SOURCE;
    struct lta_dormant *d=&lta_writer.value.dormant[node];
    uint64_t epoch=lta_writer.value.node[node],binding=pe.arena.binding[slot].generation;
    const struct li2_pg_generation *g=&PTR_NODE_AT(node).generation;
    struct li2_private_code_query spill={0},slots={0};
    ped_count(&lta_writer.value.physical_checks);
    if(!sbc_node_identity(node,d->bank,&d->certificate) ||
       pe_query(g->spill,PAGE,PROT_READ|PROT_WRITE,&spill) ||
       pe_query(g->layout.slots,PAGE,PROT_READ,&slots) ||
       *(const volatile uint64_t *)(g->spill+32) || !ptr_slots(slot,0) ||
       epoch!=lta_writer.value.node[node] || binding!=pe.arena.binding[slot].generation ||
       !lta_closed_value(node))return PE_PUBLICATION;
    d->prepared_serial=pe.p.serial;d->prepared_binding=binding;
    pe.arena.rebind_mask|=1U<<slot;return 0;
}
static int lta_prepared(unsigned slot) {
    unsigned node=ptr_node_index(slot);
    if(node>=PTR_NODE_COUNT || !(pe.arena.rebind_mask&(1U<<slot)) || !lta_closed_value(node))return 0;
    const struct lta_dormant *d=&lta_writer.value.dormant[node];
    return d->prepared_serial==pe.p.serial && pe.p.serial &&
        d->prepared_binding==pe.arena.binding[slot].generation &&
        pda_registry(slot) && pda_registration((const void *)PTR_NODE_AT(node).proof);
}
static int lta_take(unsigned slot,unsigned peer) {
    if(peer>1 || !lta_prepared(slot) || !pe_busy || pe_active ||
       (pe.p.phase!=LI2_PG_CONSUMED && pe.p.phase!=LI2_PG_BOUND))return PE_STATE;
    struct lta_dormant *d=&lta_writer.value.dormant[ptr_node_index(slot)];
    d->closed=d->reusable=d->prepared_serial=d->prepared_binding=0;
    pe.arena.rebind_mask&=~(1U<<slot);
    ped_count(peer?&lta_writer.value.rebound_peers:&lta_writer.value.rebound);
    return 0;
}
static int lta_replace(unsigned slot) {
    unsigned node=ptr_node_index(slot);
    if(node>=PTR_NODE_COUNT || pe.warm || pe.p.phase!=LI2_PG_CONSUMED ||
       !lta_closed_value(node))return PE_STATE;
    struct lta_dormant *d=&lta_writer.value.dormant[node];
    d->closed=d->reusable=d->prepared_serial=d->prepared_binding=0;
    pe.arena.rebind_mask&=~(1U<<slot);ped_count(&lta_writer.value.evicted);
    return 0;
}
static int lc8_reachable(const struct li2_pgd_view *,const struct li2_pg_compact *);
/* A bounded proposal loop. An incompatible node is attempted only once in
   this activation; it receives neither a source lease nor a current claim. */
static unsigned lta_propose_peer(unsigned *tried) {
    const struct li2_pgd_view *v=&pe.domain.work.view;
    if(!tried || pe.p.phase!=LI2_PG_BOUND || pe.domain.work.bound)return LI2_PTR_SLOTS;
    for(unsigned node=0;node<PTR_NODE_COUNT;node++) {
        if((*tried&(1U<<node)) || lta_node_bound(node)>=0 || !PTR_NODE_AT(node).generation.installed)continue;
        pe_need(lta_closed_value(node),PE_RELEASE,9236);
        const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
        const struct pe_payload *p=(const void *)s->proof;
        if(s->registry_count!=protected_count ||
           !equal(s->registry,protected,protected_count*sizeof *protected) ||
           !pda_registration(p) || !lc8_reachable(v,&p->plan))continue;
        *tried|=1U<<node;
        unsigned victim=LI2_PTR_SLOTS;
        for(unsigned slot=0;slot<LI2_PTR_SLOTS;slot++) {
            unsigned included=0;
            for(unsigned i=0;i<v->count;i++)included|=v->member[i].identity.slot==slot;
            if(included)continue;
            if(victim==LI2_PTR_SLOTS || PTR_SLOT_AT(slot).last_completed<PTR_SLOT_AT(victim).last_completed)
                victim=slot;
        }
        if(victim==LI2_PTR_SLOTS)return victim;
        pe_need(!lta_move(victim,node),PE_RELEASE,9237);return victim;
    }
    return LI2_PTR_SLOTS;
}
