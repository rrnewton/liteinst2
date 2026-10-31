/* Only advisory selection is performed before real TRACE closure. The old
   selector still authenticates every retained claim and wins exact roots. */
struct pe_sub_choice { unsigned slot,bank,subentry;uintptr_t page[2]; };
static int pe_sub_choose(uintptr_t pc,struct pe_sub_choice *out) {
    if(!out)return 0;
    *out=(struct pe_sub_choice){0};
    unsigned slot=ptr_choose(pc);uintptr_t page=pc&~(PAGE-1);
    const struct li2_ptr_slot *chosen=&pe.retained[slot];
    if(chosen->generation.installed && chosen->publication.source.entry==pc) {
        if(!li2_pg_source_pair_advisory(pc))return 0;
        *out=(struct pe_sub_choice){slot,ped_bank_for(pc),0,{page,page+PAGE}};return 1;
    }
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *s=&pe.retained[i];if(!s->generation.installed)continue;
        const struct pe_payload *p=(const void *)s->proof;struct li2_pgs_target target;
        int found=li2_pgs_head_lookup(&p->plan,pc,&target);
        pe_need(found>=0,PE_PUBLICATION,110);
        if(!found || !li2_pgs_source_pair_advisory(pc,target.page))continue;
        unsigned bank=2;
        for(unsigned j=0;j<2;j++)if(s->generation.generated==s->banks[j].generated &&
            pg_layout_equal(&s->generation.layout,&s->banks[j].layout)) {
            pe_need(bank==2,PE_STATE,110);bank=j;
        }
        pe_need(bank<2 && target.root==p->source.entry && target.pc!=target.root,PE_STATE,111);
        *out=(struct pe_sub_choice){i,bank,1,{target.page[0],target.page[1]}};return 1;
    }
    if(!li2_pg_source_pair_advisory(pc))return 0;
    *out=(struct pe_sub_choice){slot,ped_bank_for(pc),0,{page,page+PAGE}};return 1;
}
static int pe_sub_candidate(const struct li2_pg_sources *s,const struct pe_payload *p) {
    if(s->key.entry==p->source.entry)return li2_pg_source_key_equal(&p->source,&s->key);
    if(!pe.subentry_selected || !li2_pgd_source_pair_equal(&p->source,&s->key))return 0;
    struct li2_pgs_target target;
    int found=li2_pgs_head_lookup(&p->plan,s->key.entry,&target);
    pe_need(found>=0,PE_PUBLICATION,111);
    return found==1 && target.root==p->source.entry && target.pc!=target.root;
}
static int pe_sub_fill(void) {
    const struct li2_pg_sources *s=li2_pg_source_view(&pe.token);
    const struct pe_payload *p=pe_payload();const struct li2_pg_generation *g=&PE_SLOT(generation);
    if(!s || !s->complete || pe.entry.complete || !ptr_selected() || !ptr_stored(pe.selected_slot) ||
       !pe.p.transfer_serial || pe.transfer.serial!=pe.p.transfer_serial ||
       !equal(&pe.ref,&s->anchor,sizeof pe.ref) || !pe_sub_candidate(s,p))return PE_SOURCE;
    struct li2_pgs_target target;
    if(li2_pgs_head_lookup(&p->plan,s->key.entry,&target)!=1)return PE_SOURCE;
    pe.entry=(struct li2_pgs_entry){.token=pe.token,.transfer_serial=pe.p.transfer_serial,
        .generation=g->generation,.build_serial=g->build_serial,.anchor=s->anchor,
        .slot=pe.selected_slot,.bank=pe.selected_bank,.target=target,
        .row=p->plan.head[target.head],.original=p->plan.original[target.head],.complete=1};
    return li2_pgs_entry_value(&pe.entry,&p->source,s,&g->layout)?0:PE_SOURCE;
}
const struct li2_pgs_entry *li2_pgs_owner_entry(const struct li2_pg_token *t) {
    const struct li2_pgs_entry *e=&pe.entry;
    if(!pe_token(t) || !ptr_selected() || !ptr_stored(pe.selected_slot) || e->token.owner!=t->owner || e->token.serial!=t->serial ||
       e->slot!=pe.selected_slot || e->bank!=pe.selected_bank ||
       e->transfer_serial!=pe.p.transfer_serial || pe.transfer.serial!=e->transfer_serial || e->target.pc!=pe.transfer.pc ||
       !equal(&e->anchor,&pe.ref,sizeof pe.ref))return 0;
    const struct li2_pg_sources *s=li2_pg_source_view(t);
    const struct pe_payload *p=pe_payload();const struct li2_pg_generation *g=&PE_SLOT(generation);
    if(!s || e->generation!=g->generation || e->build_serial!=g->build_serial ||
       !li2_pgs_entry_value(e,&p->source,s,&g->layout))return 0;
    struct li2_pgs_target target;
    if(li2_pgs_head_lookup(&p->plan,e->target.pc,&target)!=1 ||
       !equal(&target,&e->target,sizeof target) ||
       !equal(&p->plan.head[target.head],&e->row,sizeof e->row) ||
       !equal(&p->plan.original[target.head],&e->original,sizeof e->original))return 0;
    return e;
}
static int pe_sub_source_matches(const struct li2_pg_sources *s,const struct pe_payload *p) {
    const struct li2_pgs_entry *e=li2_pgs_owner_entry(&pe.token);
    return e && li2_pgs_entry_value(e,&p->source,s,&p->header.layout);
}
