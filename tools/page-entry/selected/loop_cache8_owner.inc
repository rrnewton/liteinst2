/* Included only by the distinct cache8 owner after the unchanged registry,
   registration and pairwise-disjoint predicates. No planner/emitter is here. */
static int pda_member_live(const struct li2_pgd_member *);
static void pda_member(unsigned,unsigned);

static int lc8_members(const struct li2_pgd_view *v) {
    if(!v || !v->count || v->count>LI2_PGD_MEMBERS || v->reserved)return 0;
    unsigned heads=0,boundaries=0;
    for(unsigned i=0;i<v->count;i++) {
        const struct li2_pgd_member *m=&v->member[i];
        if(!pda_member_live(m) || !m->plan->heads ||
           m->plan->heads>LI2_JD_DOMAIN_HEADS-heads ||
           m->plan->exits>LI2_PG_BOUNDARIES-boundaries)return 0;
        heads+=m->plan->heads;boundaries+=m->plan->exits;
        if(m->plan->links>LI2_PG_BOUNDARIES-boundaries)return 0;
        boundaries+=m->plan->links;
        for(unsigned j=0;j<i;j++) {
            const struct li2_pgd_member *p=&v->member[j];
            if(m->identity.slot==p->identity.slot || m->identity.generation==p->identity.generation ||
               !pda_disjoint(m->plan,p->plan) || !li2_pgx_guard_union(m->plan,p->plan))return 0;
        }
    }
    for(unsigned i=v->count;i<LI2_PGD_MEMBERS;i++)
        if(!pda_zero(&v->member[i],sizeof v->member[i]))return 0;
    return heads && heads<=LI2_JD_DOMAIN_HEADS && boundaries<=LI2_PG_BOUNDARIES;
}
/* Advisory reachability only, from the already validated immutable DIRECT
   descriptor to an exact original head in the candidate publication. Source,
   generation, guard-table, claim and physical queries are separate below. */
static int lc8_reachable(const struct li2_pgd_view *v,const struct li2_pg_compact *candidate) {
    for(unsigned i=0;i<v->count;i++) {
        const struct li2_pg_compact *p=v->member[i].plan;
        for(unsigned h=0;h<p->heads;h++)if(p->head[h].kind==LI2_PG_DIRECT) {
            const struct li2_dd_descriptor *d=&p->instruction[h].direct;
            if(!p->head[h].successor_count || p->head[h].successor_count>2 ||
               d->external_mask&~3U)return 0;
            for(unsigned a=0;a<p->head[h].successor_count;a++)if(d->external_mask&(1U<<a))
                for(unsigned k=0;k<candidate->heads;k++)
                    if(d->target[a]==candidate->original[k].decoded.pc)return 1;
        }
    }
    return 0;
}
static const struct li2_pgd_view *lc8_offer(const struct li2_pg_token *t) {
    struct pda_work *w=&pe.domain.work;const struct li2_pgd_view *v=&w->view;
    const unsigned i=w->peer_member;
    if(!pe_token(t) || pe.p.phase!=LI2_PG_BOUND || !pe_busy || pe_active ||
       w->bound || w->peer>=LI2_PTR_SLOTS || w->primary>=LI2_PTR_SLOTS || w->peer==w->primary ||
       w->primary!=pe.selected_slot || w->primary_bank!=pe.selected_bank ||
       !i || i>=LI2_PGD_MEMBERS || v->count!=i || v->reserved ||
       !equal(&v->token,t,sizeof *t) || v->directory!=pe.domain.directory ||
       v->member[0].identity.slot!=w->primary || v->member[i].identity.slot!=w->peer ||
       !pg_layout_equal(&v->member[0].identity.layout,&pe.p.layout) ||
       !pda_permitted(w->peer))return 0;
    const struct li2_pgs_entry *entry=li2_pgs_owner_entry(t);
    if(!entry || !equal(entry,&v->entry,sizeof *entry))return 0;
    w->offer=*v;w->offer.count=i+1;
    return lc8_members(&w->offer) && lc8_reachable(v,v->member[i].plan)?&w->offer:0;
}
static int lc8_attach(void) {
    struct pda_work *w=&pe.domain.work;
    if(w->bound || w->view.count!=1 || w->peer!=LI2_PTR_SLOTS || w->peer_member ||
       !pda_zero(w->peer_claim,sizeof w->peer_claim) || !pda_zero(&w->offer,sizeof w->offer) ||
       !lc8_members(&w->view))return PE_STATE;
    while(w->view.count<LI2_PGD_MEMBERS) {
        unsigned peer=LI2_PTR_SLOTS,i=w->view.count;
        for(unsigned slot=0;slot<LI2_PTR_SLOTS;slot++) {
            unsigned included=0;
            for(unsigned j=0;j<i;j++)included|=w->view.member[j].identity.slot==slot;
            if(included || !pe.retained[slot].generation.installed)continue;
            /* Corrupt cached authority remains a failure, not a cache miss. */
            pe_need(pda_permitted(slot),PE_RELEASE,82);
            const struct pe_payload *p=(const void *)pe.retained[slot].proof;
            if(!pda_registry(slot) || !pda_registration(p) || !lc8_reachable(&w->view,&p->plan))continue;
            pda_member(i,slot);
            w->offer=w->view;w->offer.count=i+1;
            int compatible=lc8_members(&w->offer);
            le_zero(&w->offer,sizeof w->offer);
            if(compatible) {peer=slot;break;}
            le_zero(&w->view.member[i],sizeof w->view.member[i]);
        }
        if(peer==LI2_PTR_SLOTS)break;
        w->peer=peer;w->peer_member=i;ped_count(&pe.cache8.attach_attempts);
        if(!li2_pgd_source_pair_equal(w->view.member[0].key,w->view.member[i].key)) {
            unsigned accepted=0;int e=li2_pgx_source_prepare_member(&pe.token,i,&accepted);
            if(e)return e;
            if(!accepted) {
                ped_count(&pe.cache8.source_declines);
                /* This position is proposed once. Preserve the declined
                   source observation; do not overwrite it for another peer. */
                le_zero(&w->view.member[i],sizeof w->view.member[i]);
                le_zero(&w->offer,sizeof w->offer);
                w->peer=LI2_PTR_SLOTS;w->peer_member=0;break;
            }
        }
        pe_need(pda_permitted(peer),PE_RELEASE,83);
        pda_select(peer,pda_bank(peer));
        struct pda_claim_observation *claim=&w->peer_claim[i-1];
        int prot=lprx_slot_prot(peer);
        pe_need(prot>=0 && !pe_bytes() && !pg_queries(&PE_SLOT(generation).layout,prot,claim->code) &&
            !pg_proof_query(PE_SLOT(generation).proof,PROT_READ,&claim->proof) &&
            !pe_query(PE_SLOT(generation).spill,PAGE,PROT_READ|PROT_WRITE,&claim->spill) &&
            !pe_query(PE_SLOT(generation).layout.slots,PAGE,PROT_READ,&claim->slots),PE_RELEASE,84);
        pda_claim(peer);ped_count(PGC_REF(permit_claims));
        struct li2_pg_generation *g=&PE_SLOT(generation);
        le_zero(g->open,sizeof g->open);le_zero(g->close,sizeof g->close);le_zero(g->cleanup,sizeof g->cleanup);
        le_zero(&g->slots[1],2U*sizeof g->slots[1]);le_zero(&g->cell[1],2U*sizeof g->cell[1]);
        pda_member(i,peer);w->view.count=i+1;ped_count(&pe.cache8.accepted);
        pda_select(w->primary,w->primary_bank);
        le_zero(&w->offer,sizeof w->offer);w->peer=LI2_PTR_SLOTS;w->peer_member=0;
    }
    return lc8_members(&w->view)?0:PE_SOURCE;
}
