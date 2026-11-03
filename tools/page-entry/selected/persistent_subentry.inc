#ifndef PTR_SLOT_AT
#define PTR_SLOT_AT(i) pe.retained[i]
#endif
/* The unchanged pure selector component includes this leaf directly. */
#ifndef LI2_REUSE_CENSUS
#ifndef RCC_SELECT_RESET
#define RCC_SELECT_RESET() ((void)0)
#endif
#ifndef RCC_SELECT_TEST
#define RCC_SELECT_TEST(bit,value) (value)
#endif
#endif
/* Only advisory selection is performed before real TRACE closure. The old
   selector still authenticates every retained claim and wins exact roots. */
struct pe_sub_choice { unsigned slot,bank,subentry;uintptr_t page[2]; };
static int pe_sub_choose(uintptr_t pc,struct pe_sub_choice *out) {
    if(!out)return 0;
    *out=(struct pe_sub_choice){0};
    RCC_SELECT_RESET();
    unsigned slot=ptr_choose(pc);uintptr_t page=pc&~(PAGE-1);
    const struct li2_ptr_slot *chosen=&PTR_SLOT_AT(slot);
    if(chosen->generation.installed && chosen->publication.source.entry==pc) {
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
        /* ptr_choose authenticated this whole immutable publication and its
           completed permit. Keep its actual pair, including a second-page
           root; current ownership is still only advisory until preparation. */
        if(page>(UINT64_C(1)<<47)-2*PAGE)return 0;
        const uintptr_t pages[2]={chosen->publication.source.page[0].identity.address,
            chosen->publication.source.page[1].identity.address};
        if(!RCC_SELECT_TEST(0,li2_pgs_source_pair_advisory(pc,pages)))return 0;
        *out=(struct pe_sub_choice){slot,ped_bank_for(pc),0,{pages[0],pages[1]}};return 1;
#else
        if(!RCC_SELECT_TEST(0,li2_pg_source_pair_advisory(pc)))return 0;
        *out=(struct pe_sub_choice){slot,ped_bank_for(pc),0,{page,page+PAGE}};return 1;
#endif
    }
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *s=&PTR_SLOT_AT(i);if(!s->generation.installed)continue;
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT
        if(lcx_cold_pending(ptr_node_index(i)) || lcx_cold_retired(ptr_node_index(i)))continue;
#endif
        const struct pe_payload *p=(const void *)s->proof;struct li2_pgs_target target;
        int found=RCC_SELECT_TEST(4+i,li2_pgs_head_lookup(&p->plan,pc,&target));
        pe_need(found>=0,PE_PUBLICATION,110);
        if(!found || !RCC_SELECT_TEST(1+i,li2_pgs_source_pair_advisory(pc,target.page)))continue;
        unsigned bank=2;
        for(unsigned j=0;j<2;j++)if(s->generation.generated==s->banks[j].generated &&
            pg_layout_equal(&s->generation.layout,&s->banks[j].layout)) {
            pe_need(bank==2,PE_STATE,110);bank=j;
        }
        pe_need(bank<2 && target.root==p->source.entry && target.pc!=target.root,PE_STATE,111);
        *out=(struct pe_sub_choice){i,bank,1,{target.page[0],target.page[1]}};return 1;
    }
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    if(!RCC_SELECT_TEST(3,li2_pg_source_pair_advisory(pc))) {
        /* Preserve the old forward pair first. A final executable page can
           instead use its real predecessor; no page is invented or opened. */
        if(page<2*PAGE || page>(UINT64_C(1)<<47)-2*PAGE)return 0;
        const uintptr_t pages[2]={page-PAGE,page};
        if(!li2_pgs_source_pair_advisory(pc,pages))return 0;
        *out=(struct pe_sub_choice){slot,ped_bank_for(pc),0,{pages[0],pages[1]}};return 1;
    }
#else
    if(!RCC_SELECT_TEST(3,li2_pg_source_pair_advisory(pc)))return 0;
#endif
    *out=(struct pe_sub_choice){slot,ped_bank_for(pc),0,{page,page+PAGE}};return 1;
}
#ifdef LI2_LOOP_TRANSLATION_ARENA
/* All choices are advisory. Only lta_move, after real TRACE closure, changes
   a binding; fresh source and physical admission follow that move. */
static int lta_choose(uintptr_t pc,struct pe_sub_choice *out,unsigned *node_out) {
    if(!node_out || !pe_sub_choose(pc,out))return 0;
    unsigned bound=ptr_node_index(out->slot);if(bound>=PTR_NODE_COUNT)return 0;
    *node_out=bound;
    if(out->subentry || (PTR_NODE_AT(bound).generation.installed &&
       PTR_NODE_AT(bound).publication.source.entry==pc))return 1;
    unsigned match=PTR_NODE_COUNT,bank=2,subentry=0;uintptr_t pages[2]={0};
    for(unsigned node=0;node<PTR_NODE_COUNT;node++) {
        const struct li2_ptr_slot *slot=&PTR_NODE_AT(node);
        if(lta_node_bound(node)>=0 || !slot->generation.installed)continue;
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT
        if(lcx_cold_retired(node))continue; /* May be a cold victim, never a cached head. */
#endif
        pe_need(lta_closed_value(node),PE_RELEASE,9232);
        const struct pe_payload *p=(const void *)slot->proof;
        struct li2_pgs_target target;
        int found=li2_pgs_head_lookup(&p->plan,pc,&target);
        pe_need(found>=0,PE_PUBLICATION,9233);
        if(!found || !li2_pgs_source_pair_advisory(pc,target.page))continue;
        unsigned candidate_bank=2,candidate_subentry=pc!=target.root;
        for(unsigned b=0;b<2;b++)if(slot->banks[b].generated==slot->generation.generated)candidate_bank=b;
        pe_need(candidate_bank<2 && target.root==p->source.entry,PE_STATE,9235);
        /* Distinct immutable plans may share a head. Preserve node order for
           subentries, prefer a unique exact root, and still check every node. */
        pe_need(match==PTR_NODE_COUNT || subentry || candidate_subentry,PE_STATE,9234);
        if(match==PTR_NODE_COUNT || (!candidate_subentry && subentry)) {
            match=node;bank=candidate_bank;subentry=candidate_subentry;
            pages[0]=target.page[0];pages[1]=target.page[1];
        }
    }
    if(match<PTR_NODE_COUNT) {
        *out=(struct pe_sub_choice){out->slot,bank,subentry,{pages[0],pages[1]}};
        *node_out=match;return 1;
    }
    /* Prefer unused immutable storage before replacing a live publication.
       The eight active bindings and every actual member bound stay fixed. */
    if(PTR_NODE_AT(bound).generation.installed)
        for(unsigned node=0;node<PTR_NODE_COUNT;node++)
            if(lta_node_bound(node)<0 && !PTR_NODE_AT(node).generation.installed) {
                *node_out=node;break;
            }
    /* A full arena must also replace older inactive publications; otherwise
       dormant startup nodes permanently reduce the reusable capacity. The
       preceding scan authenticated every installed inactive node. */
    if(*node_out==bound && PTR_NODE_AT(bound).generation.installed)
        for(unsigned node=0;node<PTR_NODE_COUNT;node++)
            if(lta_node_bound(node)<0 && PTR_NODE_AT(node).generation.installed &&
               PTR_NODE_AT(node).last_completed<PTR_NODE_AT(*node_out).last_completed)
                *node_out=node;
    return 1;
}
#endif
static int pe_sub_candidate(const struct li2_pg_sources *s,const struct pe_payload *p) {
#ifdef LI2_LOOP_CACHED_DIRECT_CONTEXT
    if(lcx_cold_pending(ptr_node_index(pe.selected_slot)) ||
       lcx_cold_retired(ptr_node_index(pe.selected_slot)))return 0;
#endif
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
