/* Explicit policy13 extension. The old chooser remains the first choice.
   These functions run only in the existing held-source decoder scopes. */
static int ple_no_envelope(const struct li2_pg_source_key *s) {
    const struct li2_le_witness *w=&pe.effects.choice;
    if(!plr_no_envelope(s) || w->version!=LI2_LPE_VERSION ||
       w->bytes!=sizeof *w || w->ready || w->result!=LI2_LE_NO_ENVELOPE ||
       w->entry!=s->entry || w->eligible)return 0;
    return li2_lee_validate(pe.loop.pages,pe.loop.source,s->entry,w,&pe.effects.check)==0;
}
static int ple_cold(const struct li2_pg_sources *s,const uintptr_t pages[2]) {
    pe_need(pe.loop.scope==PLR_COLD && pe_decoding && pe.loop.choice_complete==1 &&
        !pe.effects.choice_complete && plr_no_envelope(&s->key),PE_PLAN,245);
    PLE_COUNT(chooser_attempts);pe.loop.route=LI2_LPE_VERSION;
    int e=li2_lpe_plan_pages(pages,pe.candidate.plan.source,s->key.entry,&pe.p.layout,
        &pe.candidate.plan.table,&pe.cold,&pe.miss,&pe.effects.choice);
    if(e==LI2_LE_NO_ENVELOPE) {
        pe_need(!li2_lpe_miss_validate(&pe.cold,&pe.miss,e,&pe.rebuild,&pe.effects.check) &&
            ple_no_envelope(&s->key),PE_PLAN,246);
        pe.effects.choice_complete=1;PLE_COUNT(chooser_no_envelope);
        pe.loop.route=LI2_PF_VERSION;
        return li2_lpf_plan_pages(pages,pe.candidate.plan.source,s->key.entry,&pe.p.layout,
            &pe.candidate.plan.table,&pe.cold,&pe.miss);
    }
    if(!e) {
        pe_need(pe.effects.choice.ready==1 && !pe.effects.choice.result,PE_PLAN,247);
        plr_source(&s->key);pe.effects.choice_complete=1;PLE_COUNT(chooser_selected);
    } else if(li2_lpe_relocation_reason(&pe.cold,&pe.miss,e,&pe.rebuild,&pe.effects.check)) {
        pe_need(equal(&pe.effects.choice,&pe.effects.check,sizeof pe.effects.choice) &&
            pe.effects.choice.ready==1 && !pe.effects.choice.result,PE_PLAN,248);
        plr_source(&s->key);pe.effects.choice_complete=1;PLE_COUNT(chooser_selected);
    }
    return e;
}
static unsigned ple_miss_reason(const struct li2_pg_source_key *s) {
    if(!plr_no_envelope(s) || pe.effects.choice_complete!=1 ||
       pe.effects.choice.ready!=1 || pe.effects.choice.result)return 0;
    unsigned reason=li2_lpe_relocation_reason(&pe.cold,&pe.miss,pe.build_result,
        &pe.rebuild,&pe.effects.check);
    return reason && equal(&pe.effects.choice,&pe.effects.check,
        sizeof pe.effects.choice)?reason:0;
}
/* Called after the old saved-source NO_ENVELOPE reconstruction. No live
   retained plan or invented exclusion table supplies historical authority. */
static int ple_history_no_envelope(uintptr_t entry) {
    struct li2_le_witness *w=&pe.effects.historical;
    return li2_lee_choose(pe.loop.pages,pe.loop.source,entry,w)==LI2_LE_NO_ENVELOPE &&
        w->version==LI2_LPE_VERSION && w->bytes==sizeof *w && !w->ready &&
        w->result==LI2_LE_NO_ENVELOPE && w->entry==entry && !w->eligible &&
        !li2_lee_validate(pe.loop.pages,pe.loop.source,entry,w,&pe.effects.check);
}

/* Saved policy13 DIRECT uses its own source reconstruction and requires
   the independently reconstructed old-policy refusal before that choice. */
static int ple_direct_value(const struct pda_completion *c) {
    const struct pda_direct_exit *e=&c->direct_exit;
    if(e->complete!=1 || e->reserved || e->member>=c->count || c->count>LI2_PGD_MEMBERS ||
       e->head>=e->heads || !e->heads || e->heads>LI2_PG_HEADS || !e->exits ||
       e->exits>LI2_PG_BOUNDARIES || e->index>=e->exits || e->arm>1 ||
       (e->flags&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF)return 0;
    const struct pda_member_completion *m=&c->member[e->member];
    if(!li2_lpr_header(m->header.version,m->header.plan_policy,LI2_LPE_VERSION) ||
       !plr_scope_enter(PLR_HISTORY))return 0;
    int valid=0;plr_source(&m->source);
    struct li2_le_witness *old=&pe.loop.historical;
    if(li2_le_choose(pe.loop.pages,pe.loop.source,m->source.entry,old)!=LI2_LE_NO_ENVELOPE ||
       old->version!=LI2_LE_VERSION || old->bytes!=sizeof *old || old->ready ||
       old->result!=LI2_LE_NO_ENVELOPE || old->entry!=m->source.entry || old->eligible ||
       li2_le_validate(pe.loop.pages,pe.loop.source,m->source.entry,old,&pe.loop.check))goto done;
    struct li2_le_witness *w=&pe.effects.historical;
    if(li2_lee_choose(pe.loop.pages,pe.loop.source,m->source.entry,w) ||
       li2_lee_validate(pe.loop.pages,pe.loop.source,m->source.entry,w,&pe.effects.check))goto done;
    const struct li2_le_shape *s=&w->selected;
    if(w->ready!=1 || w->result || s->choice.heads!=e->heads || s->choice.exits!=e->exits ||
       s->head[0].pc!=m->source.entry || s->choice.links+s->choice.exits>LI2_PG_BOUNDARIES)goto done;
    const struct li2_le_head *h=&s->head[e->head];
    if(h->decoded>=w->decoded || h->decoded>=LI2_LE_HEADS || h->kind!=LI2_LE_NONE ||
       !h->external_mask || e->arm>=h->successors || !(h->external_mask&(1U<<e->arm)) ||
       h->token[e->arm]!=LI2_PG_HEADS+e->index || s->exit[e->index].head!=e->head ||
       s->exit[e->index].arm!=e->arm)goto done;
    unsigned char bytes[15]={0};size_t n=plr_window(h->pc,bytes);struct li2_lr_node node;
    if(li2_ler_bridge_node(h->pc,bytes,n,&w->node[h->decoded],&node) ||
       node.kind!=LI2_LE_NONE || !equal(&node.original,&e->original,sizeof e->original))goto done;
    struct li2_dd_descriptor direct;struct li2_jd_binding binding;uintptr_t internal[2]={0};
    if(li2_dd_span(&node.original,h->external_mask,&direct) ||
       !equal(&direct,&e->direct,sizeof direct) || li2_dd_arm(&direct,e->flags)!=(int)e->arm ||
       s->exit[e->index].target!=direct.target[e->arm] ||
       li2_pg_dispatch_binding(pe.loop.pages,&m->header.layout,m->header.table,e->heads,e->head,&binding))goto done;
    for(unsigned arm=0;arm<h->successors;arm++)if(!(h->external_mask&(1U<<arm))) {
        unsigned k=h->token[arm];if(k>=e->heads)goto done;
        if(k/64==e->head/64)internal[arm]=m->header.layout.generated[k/64]+(uintptr_t)(k%64)*LI2_PE_SLOT_BYTES;
        else {
            unsigned matches=0;
            for(unsigned j=0;j<s->choice.links;j++)if(s->link[j].head==e->head &&
                s->link[j].arm==arm && s->link[j].target==k) {
                ++matches;internal[arm]=m->header.layout.stubs+6U*j;
            }
            if(matches!=1)goto done;
        }
    }
    uintptr_t generated=m->header.layout.generated[e->head/64]+(uintptr_t)(e->head%64)*LI2_PE_SLOT_BYTES;
    if(li2_ld_emit(h->pc,bytes,n,h->external_mask,generated,m->header.spill,&binding,
        internal,&pe.loop.direct) || !equal(&pe.loop.direct.original,&direct,sizeof direct))goto done;
    struct li2_pe_head expected={0};unsigned page=2;
    for(unsigned i=0;i<2;i++)if(h->pc>=pe.loop.pages[i] && h->pc-pe.loop.pages[i]<LI2_REGION_PAGE)page=i;
    if(page>=2)goto done;
    expected.kind=LI2_PG_DIRECT;expected.source_page=page;expected.source_offset=(unsigned)(h->pc-pe.loop.pages[page]);
    expected.source_length=node.original.decoded.length;expected.generated_length=pe.loop.direct.record.image_bytes;
    expected.successor_count=h->successors;copy(expected.successors,h->token,sizeof expected.successors);
    if(!equal(&expected,&e->row,sizeof expected))goto done;
    PLE_COUNT(historical_reconstructions);valid=1;
 done:
    /* Private reconstruction output has no consumer beyond the row check. */
    le_zero(&pe.loop.direct,sizeof pe.loop.direct);
    plr_scope_leave(PLR_HISTORY);return valid;
}
