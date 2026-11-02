/* New profile only. Scratch is a member of the wholly registered/excluded pe.
   No operation here grants a source/entry lease or runs on an internal edge. */
enum plr_scope { PLR_COLD=1,PLR_CANCEL,PLR_HISTORY };
static int plr_scope_enter(unsigned scope) {
    if(scope<PLR_COLD || scope>PLR_HISTORY || pe.loop.scope || pe_decoding ||
       pe_failing || pe.domain.work.aborting || !pe.initialized || !pe.registered ||
       !pe_identity() || !ptr_storage() || pe.session.application_mask!=SELECTED_MASK ||
       selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)!=1)return 0;
    uint64_t mask=0;
    if(raw(SYS_rt_sigprocmask,SIG_SETMASK,0,(long)&mask,8,0,0) || mask!=SELECTED_MASK)return 0;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *s=&pe.retained[i];
        if(s->generation.linked || s->generation.active_refs || s->generation.domain_refs ||
           s->generation.member_refs[0] || s->generation.member_refs[1] ||
           s->generation.incoming[0] || s->generation.incoming[1])return 0;
        for(unsigned j=0;j<2;j++)if(s->banks[j].prot== (PROT_READ|PROT_EXEC))return 0;
    }
    if(scope==PLR_COLD || scope==PLR_CANCEL) {
        if(pe.p.phase!=LI2_PG_HELD || !pe_busy || pe_active || pe.consumed ||
           pe.redirected || pe.p.opened_pages)return 0;
    } else {
        switch(pe.p.phase) {
        case LI2_PG_IDLE:case LI2_PG_CLOSED:case LI2_PG_CANCELLED:
        case LI2_PG_HELD:case LI2_PG_CONSUMED:case LI2_PG_BOUND:break;
        default:return 0;
        }
        if(pe_active) {
            const struct li2_pg_source_progress *s=li2_pg_source_progress();
            const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
            if(!pe_busy || pe.p.phase!=LI2_PG_CLOSED || !pe.p.anchor_released ||
               !pe.p.registration_rechecked || !s || s->phase!=LI2_PGS_RELEASED ||
               s->first_error || s->release_complete!=1 || !r || r->active ||
               r->checking || r->first_error || r->close_complete!=1)return 0;
        }
    }
    pe.loop.scope=(sig_atomic_t)scope;pe_decoding=1;__asm__ volatile("":::"memory");
    selected_initialized();return 1;
}
static void plr_scope_leave(unsigned scope) {
    pe_need(pe.loop.scope==(sig_atomic_t)scope && pe_decoding==1,PE_REENTRY,241);
    selected_initialized();uint64_t mask=0;
    pe_need(!raw(SYS_rt_sigprocmask,SIG_SETMASK,0,(long)&mask,8,0,0) &&
        mask==SELECTED_MASK,PE_REENTRY,242);
    __asm__ volatile("":::"memory");pe_decoding=0;pe.loop.scope=0;
}
static void plr_source(const struct li2_pg_source_key *s) {
    for(unsigned i=0;i<2;i++) {
        pe.loop.pages[i]=s->page[i].identity.address;
        copy(pe.loop.source[i],s->page[i].bytes,LI2_REGION_PAGE);
    }
}
static int plr_no_envelope(const struct li2_pg_source_key *s) {
    const struct li2_le_witness *w=&pe.loop.choice;
    if(!s || !pe.loop.scope || !pe_decoding || w->version!=LI2_LE_VERSION ||
       w->bytes!=sizeof *w || w->ready || w->result!=LI2_LE_NO_ENVELOPE ||
       w->entry!=s->entry || w->eligible)return 0;
    plr_source(s);
    return li2_le_validate(pe.loop.pages,pe.loop.source,s->entry,w,&pe.loop.check)==0;
}
static int plr_cold(const struct li2_pg_sources *s,const uintptr_t pages[2]) {
    pe_need(pe.loop.scope==PLR_COLD && pe_decoding && !pe.loop.route &&
        !pe.loop.choice_complete && s && s->complete,PE_PLAN,240);
    PLR_COUNT(chooser_attempts);pe.loop.route=LI2_LP_VERSION;
    int e=li2_lp_plan_pages(pages,pe.candidate.plan.source,s->key.entry,&pe.p.layout,
        &pe.candidate.plan.table,&pe.cold,&pe.miss,&pe.loop.choice);
    if(e==LI2_LE_NO_ENVELOPE) {
        /* Numeric1 also means PG_MISS. Authenticate the entire distinct failed
           choice/plan before selecting the old policy; never branch on1 alone. */
        pe_need(!li2_lp_miss_validate(&pe.cold,&pe.miss,e,&pe.rebuild,&pe.loop.check) &&
            plr_no_envelope(&s->key),PE_PLAN,241);
        pe.loop.choice_complete=1;pe.loop.route=LI2_PF_VERSION;
        PLR_COUNT(chooser_no_envelope);
        return li2_lpf_plan_pages(pages,pe.candidate.plan.source,s->key.entry,&pe.p.layout,
            &pe.candidate.plan.table,&pe.cold,&pe.miss);
    }
    if(!e) {
        pe_need(pe.loop.choice.ready==1 && !pe.loop.choice.result,PE_PLAN,242);
        plr_source(&s->key);
        pe.loop.choice_complete=1;PLR_COUNT(chooser_selected);
    } else if(li2_lp_relocation_reason(&pe.cold,&pe.miss,e,&pe.rebuild,&pe.loop.check)) {
        pe_need(equal(&pe.loop.choice,&pe.loop.check,sizeof pe.loop.choice) &&
            pe.loop.choice.ready==1 && !pe.loop.choice.result,PE_PLAN,244);
        /* Cancellation reconstructs the same authenticated selected source. */
        plr_source(&s->key);
        pe.loop.choice_complete=1;PLR_COUNT(chooser_selected);
    }
    return e;
}
static unsigned plr_miss_reason(void) {
    const struct li2_pg_sources *s=li2_pg_source_view(&pe.token);
    if(pe.loop.choice_complete!=1 || !s || s->complete!=1 || pe.cold.entry!=s->key.entry)return 0;
    for(unsigned i=0;i<2;i++)if(pe.cold.page[i]!=s->key.page[i].identity.address ||
        !equal(pe.cold.source[i],s->key.page[i].bytes,LI2_REGION_PAGE))return 0;
    if(pe.loop.route==LI2_PF_VERSION) {
        if(!plr_no_envelope(&s->key))return 0;
        return li2_lpr_fallback_miss_valid(&pe.cold,&pe.miss,pe.build_result,&pe.rebuild)?pe.miss.reason:0;
    }
    if(pe.loop.route!=LI2_LP_VERSION || pe.loop.choice.ready!=1 || pe.loop.choice.result)return 0;
    unsigned reason=li2_lp_relocation_reason(&pe.cold,&pe.miss,pe.build_result,&pe.rebuild,&pe.loop.check);
    return reason && equal(&pe.loop.choice,&pe.loop.check,sizeof pe.loop.choice)?reason:0;
}
static int plr_miss_value(void) { return plr_miss_reason()!=0; }

static int plr_cancel_valid(void) {
    if(!plr_scope_enter(PLR_CANCEL))return 0;
    int valid=plr_miss_value();plr_scope_leave(PLR_CANCEL);return valid;
}
static size_t plr_window(uintptr_t pc,unsigned char b[15]) {
    size_t n=0;
    for(;n<15;n++) {
        unsigned i;for(i=0;i<2;i++)if(pc+n>=pe.loop.pages[i] &&
            pc+n-pe.loop.pages[i]<LI2_REGION_PAGE)break;
        if(i==2)break;
        b[n]=pe.loop.source[i][pc+n-pe.loop.pages[i]];
    }
    return n;
}
/* LOOP-domain policy11 keeps the original PF source graph. Reconstruct the
   complete NO_ENVELOPE, graph, cut ordinal and adapter from saved values;
   no live slot or fabricated exclusion table supplies historical authority.
   The caller subsequently retains every original PF directional predicate. */
static int plr_fallback_value(const struct pda_completion *c) {
    const struct pda_direct_exit *e=&c->direct_exit;
    if(e->complete!=1 || e->reserved || e->member>=c->count || c->count>LI2_PGD_MEMBERS ||
       e->head>=e->heads || !e->heads || e->heads>LI2_PG_HEADS || !e->exits ||
       e->exits>LI2_PG_BOUNDARIES || e->index>=e->exits || e->arm>1 ||
       (e->flags&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF)return 0;
    const struct pda_member_completion *m=&c->member[e->member];
    if(!li2_lpr_header(m->header.version,m->header.plan_policy,LI2_PF_VERSION) ||
       !plr_scope_enter(PLR_HISTORY))return 0;
    int valid=0;plr_source(&m->source);
    struct li2_le_witness *w=&pe.loop.historical;
    if(li2_le_choose(pe.loop.pages,pe.loop.source,m->source.entry,w)!=LI2_LE_NO_ENVELOPE ||
       w->version!=LI2_LE_VERSION || w->bytes!=sizeof *w || w->ready ||
       w->result!=LI2_LE_NO_ENVELOPE || w->entry!=m->source.entry || w->eligible ||
       li2_le_validate(pe.loop.pages,pe.loop.source,m->source.entry,w,&pe.loop.check))goto done;
    struct li2_pg_plan *g=&pe.rebuild;
    if(li2_lpf_graph_history(pe.loop.pages,pe.loop.source,m->source.entry,&m->header.layout,
        m->header.table,g) || g->ready || g->heads!=e->heads || g->exits!=e->exits ||
       g->links+g->exits>LI2_PG_BOUNDARIES)goto done;
    const struct li2_pe_head *h=&g->head[e->head];
    const struct li2_span_decoded *original=&g->original[e->head];
    const struct li2_dd_descriptor *direct=&g->instruction[e->head].direct;
    if(h->kind!=LI2_PG_DIRECT || e->arm>=h->successor_count ||
       !(direct->external_mask&(1U<<e->arm)) || h->successors[e->arm]!=LI2_PG_HEADS+e->index ||
       g->exit_pc[e->index]!=original->decoded.pc ||
       !equal(&g->frontier[e->index],original,sizeof *original) ||
       !equal(original,&e->original,sizeof *original) ||
       !equal(direct,&e->direct,sizeof *direct) || li2_dd_arm(direct,e->flags)!=(int)e->arm)goto done;
    struct li2_jd_binding binding;uintptr_t internal[2]={0};
    if(li2_pg_dispatch_binding(pe.loop.pages,&m->header.layout,m->header.table,g->heads,e->head,&binding))goto done;
    for(unsigned arm=0;arm<h->successor_count;arm++)if(!(direct->external_mask&(1U<<arm))) {
        unsigned k=h->successors[arm];if(k>=g->heads)goto done;
        if(k/64==e->head/64)internal[arm]=m->header.layout.generated[k/64]+(uintptr_t)(k%64)*LI2_PE_SLOT_BYTES;
        else {
            unsigned matches=0;
            for(unsigned j=0;j<g->links;j++)if(g->edge[j].kind==LI2_PG_CAPACITY_LINK &&
                g->edge[j].source_head==e->head && g->edge[j].successor==arm && g->edge[j].target_head==k) {
                ++matches;internal[arm]=m->header.layout.stubs+6U*j;
            }
            if(matches!=1)goto done;
        }
    }
    unsigned char bytes[15]={0};size_t n=plr_window(original->decoded.pc,bytes);
    uintptr_t generated=m->header.layout.generated[e->head/64]+(uintptr_t)(e->head%64)*LI2_PE_SLOT_BYTES;
    if(li2_ld_emit(original->decoded.pc,bytes,n,direct->external_mask,generated,m->header.spill,
        &binding,internal,&pe.loop.direct) || !equal(&pe.loop.direct.original,direct,sizeof *direct))goto done;
    struct li2_pe_head expected=*h;expected.generated_length=pe.loop.direct.record.image_bytes;
    if(!equal(&expected,&e->row,sizeof expected))goto done;
    PLR_COUNT(historical_reconstructions);valid=1;
 done:
    /* Both temporaries are dead after the exact saved-value comparison. */
    le_zero(&pe.rebuild,sizeof pe.rebuild);le_zero(&pe.loop.direct,sizeof pe.loop.direct);
    plr_scope_leave(PLR_HISTORY);return valid;
}
/* Called only after all decoder-free receipt/source/header/closed checks.
   Replaced members are described entirely by the saved source and header. */
static int plr_direct_value(const struct pda_completion *c) {
    const struct pda_direct_exit *e=&c->direct_exit;
    if(e->complete!=1 || e->reserved || e->member>=c->count || c->count>LI2_PGD_MEMBERS ||
       e->head>=e->heads || !e->heads || e->heads>LI2_PG_HEADS || !e->exits ||
       e->exits>LI2_PG_BOUNDARIES || e->index>=e->exits || e->arm>1 ||
       (e->flags&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF)return 0;
    const struct pda_member_completion *m=&c->member[e->member];
    if(!li2_lpr_header(m->header.version,m->header.plan_policy,LI2_LP_VERSION) ||
       !plr_scope_enter(PLR_HISTORY))return 0;
    int valid=0;plr_source(&m->source);
    struct li2_le_witness *w=&pe.loop.historical;
    if(li2_le_choose(pe.loop.pages,pe.loop.source,m->source.entry,w) ||
       li2_le_validate(pe.loop.pages,pe.loop.source,m->source.entry,w,&pe.loop.check))goto done;
    const struct li2_le_shape *s=&w->selected;
    if(w->ready!=1 || w->result || s->choice.heads!=e->heads || s->choice.exits!=e->exits ||
       s->head[0].pc!=m->source.entry || s->choice.links+s->choice.exits>LI2_PG_BOUNDARIES)goto done;
    const struct li2_le_head *h=&s->head[e->head];
    if(h->decoded>=w->decoded || h->decoded>=LI2_LE_HEADS || h->kind!=LI2_LE_NONE ||
       !h->external_mask || e->arm>=h->successors || !(h->external_mask&(1U<<e->arm)) ||
       h->token[e->arm]!=LI2_PG_HEADS+e->index || s->exit[e->index].head!=e->head ||
       s->exit[e->index].arm!=e->arm)goto done;
    unsigned char bytes[15]={0};size_t n=plr_window(h->pc,bytes);struct li2_lr_node node;
    if(li2_lr_bridge_node(h->pc,bytes,n,&w->node[h->decoded],&node) ||
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
    PLR_COUNT(historical_reconstructions);valid=1;
 done:
    /* Private reconstruction output has no consumer beyond the row check. */
    le_zero(&pe.loop.direct,sizeof pe.loop.direct);
    plr_scope_leave(PLR_HISTORY);return valid;
}
