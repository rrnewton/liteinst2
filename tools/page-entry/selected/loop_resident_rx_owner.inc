/* Explicit bounded lifetime: generated LOOP code and at most two actual
   authenticated original DIRECT branches may execute before the next offer.
   The second uses the unchanged complete TF chain close/prepare/arm path.
   No non-DIRECT TF, native-page, effect or source-writer route inherits RX. */
static int lprx_add(uint64_t *n,uint64_t amount) {
    if(*n>UINT64_MAX-amount)return PE_OVERFLOW;
    *n+=amount;return 0;
}
static int lprx_permission_count(uintptr_t address,size_t bytes,int prot,unsigned sync) {
    unsigned code=0;
    for(unsigned s=0;s<LI2_PTR_SLOTS;s++)for(unsigned b=0;b<2;b++) {
        const struct ped_bank *bank=&pe.retained[s].banks[b];
        if(!bank->allocated)continue;
        for(unsigned j=0;j<3;j++)code+=address==pg_extent(&bank->layout,j) &&
            bytes==pg_extent_bytes(j);
    }
    if(code>1 || sync>1)return PE_STATE;
    uint64_t *n=sync?(code?&pe.rx.code_syncs:&pe.rx.metadata_syncs):
        !code?&pe.rx.metadata_permissions:prot==(PROT_READ|PROT_EXEC)?&pe.rx.code_opens:
        prot==PROT_READ?&pe.rx.code_revokes:&pe.rx.code_writes;
    return lprx_add(n,1); /* Actual invocation, including a later failed syscall. */
}
static int lprx_slot_prot(unsigned slot) {
    if(slot>=LI2_PTR_SLOTS || !ptr_storage())return -1;
    const struct li2_ptr_slot *s=&pe.retained[slot];
    const struct li2_pg_generation *g=&s->generation;
    const struct lprx_slot *r=&pe.rx.slot[slot];
    unsigned bank=2;
    for(unsigned i=0;i<2;i++)if(s->banks[i].generated==g->generated) {
        if(bank!=2)return -1;
        bank=i;
    }
    if(bank>=2 || !g->installed || !ptr_stored(slot))return -1;
    if(s->banks[bank].prot==PROT_READ) {
        if(r->phase==LPRX_EMPTY)return pda_zero(r,sizeof *r)?PROT_READ:-1;
        return r->phase==LPRX_REVOKED && r->bank==bank &&
            r->generation==g->generation && r->serial && r->serial<=pe.next_serial &&
            pg_layout_equal(&r->layout,&g->layout) && pg_closed(&r->layout,r->revoke)?PROT_READ:-1;
    }
    return s->banks[bank].prot==(PROT_READ|PROT_EXEC) && r->phase==LPRX_RESIDENT &&
        r->bank==bank && r->generation==g->generation && r->serial && r->serial<=pe.next_serial &&
        pg_layout_equal(&r->layout,&g->layout) && pda_zero(r->revoke,sizeof r->revoke)?
        PROT_READ|PROT_EXEC:-1;
}
static int lprx_history_quiet(unsigned slot) {
    if(slot>=LI2_PTR_SLOTS)return 0;
    const struct li2_ptr_slot *s=&pe.retained[slot];
    for(unsigned b=0;b<2;b++)if(s->banks[b].prot==(PROT_READ|PROT_EXEC)) {
        if(lprx_slot_prot(slot)!=(PROT_READ|PROT_EXEC) || pe.rx.slot[slot].bank!=b ||
           s->generation.active_refs || s->generation.member_refs[0] || s->generation.member_refs[1] ||
           s->generation.incoming[0] || s->generation.incoming[1] || s->generation.linked ||
           s->generation.domain_refs)return 0;
        struct li2_private_code_query q[3]={0};
        if(pg_queries(&s->generation.layout,PROT_READ|PROT_EXEC,q))return 0;
    }
    return 1;
}
static int lprx_permitted(unsigned slot) {
    int prot=lprx_slot_prot(slot);if(prot<0)return 0;
    const struct li2_pg_generation *g=&pe.retained[slot].generation;
    if(g->linked || g->active_refs || g->domain_refs || g->member_refs[0] || g->member_refs[1] ||
       g->incoming[0] || g->incoming[1])return 0;
    struct li2_private_code_query q[3]={0};
    return !pg_queries(&g->layout,prot,q);
}
static int lprx_slots_prot(unsigned step) {
    int prot=lprx_slot_prot(pe.selected_slot);
    if(step>2 || prot<0 || !pe_busy || handling!=1 || pe_failing || pe_closing ||
       !pe_identity())return -1;
    if(prot==PROT_READ)return prot;
    /* Only private data changes. The guest is stopped at the exact existing
       fresh BOUND entry or authenticated recovered-exit checkpoint. The old
       linked/ref/slot transition and whole byte checks still surround it. */
    if(step==1) {
        if(pe.p.phase!=LI2_PG_OPENING || pe_active || pe.redirected ||
           !pe.consumed || !pe.domain.work.bound)return -1;
    } else if(step==2) {
        if(pe.p.phase!=LI2_PG_CLOSING || !pe_active || !pe.redirected ||
           !pe.exit_seen || !pe.recovery_complete ||
           selected_pending_route!=SELECTED_PERSISTENT_EPOCH || selected_step_pending!=1 ||
           pe.domain.work.exit_member>=pe.domain.work.view.count)return -1;
    } else return -1;
    return prot;
}
static int lprx_enter(unsigned member) {
    struct pda_work *w=&pe.domain.work;
    if(member>=w->view.count || member>=LI2_PGD_MEMBERS || pe.p.phase!=LI2_PG_OPENING ||
       !pe_busy || pe_active || handling!=1 || pe.rx.branch.phase)return PE_STATE;
    const struct li2_pgd_ref *v=&w->view.member[member].identity;
    if(v->slot!=pe.selected_slot || v->bank!=pe.selected_bank)return PE_STATE;
    struct li2_pg_generation *g=&PE_SLOT(generation);
    struct lprx_slot *r=&pe.rx.slot[v->slot];
    int prot=lprx_slot_prot(v->slot);if(prot<0)return PE_PUBLICATION;
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
    lrxo_member_begin(member,prot);
#endif
    if(prot==(PROT_READ|PROT_EXEC)) {
        if(!pda_zero(g->open,sizeof g->open) ||
           lprx_add(&pe.rx.retained_entries,1))return PE_STATE;
        w->rx_retained_mask|=1U<<member;
    } else {
        unsigned pages=0;
        int e=pg_permissions(&g->layout,PROT_READ|PROT_EXEC,g->open,&pages);if(e)return e;
        if(pages!=17)return PE_PUBLICATION;
        *r=(struct lprx_slot){.phase=LPRX_RESIDENT,.bank=v->bank,
            .generation=g->generation,.serial=pe.p.serial,.layout=g->layout};
        PE_SLOT(banks)[v->bank].prot=PROT_READ|PROT_EXEC;
        pe.p.opened_pages+=pages; /* Actual permission operations, not reuse. */
    }
    if(pg_queries(&g->layout,PROT_READ|PROT_EXEC,w->rx_open[member]) ||
       lprx_add(&pe.rx.entries,1))return PE_PUBLICATION;
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
    lrxo_member_end(member);
#endif
    return 0;
}
static int lprx_drain(void) {
    const struct pda_work *w=&pe.domain.work;
    if(!pe_busy || !pe_active || handling!=1 || pe.p.phase!=LI2_PG_CLOSING ||
       !pe.exit_seen || !pe.recovery_complete || !w->bound || !w->view.count ||
       w->view.count>LI2_PGD_MEMBERS || pe.p.closed_pages)return PE_STATE;
    for(unsigned i=0;i<w->view.count;i++) {
        unsigned slot=w->view.member[i].identity.slot;
        if(slot>=LI2_PTR_SLOTS || lprx_slot_prot(slot)!=(PROT_READ|PROT_EXEC) ||
           !pda_zero(pe.retained[slot].generation.close,sizeof pe.retained[slot].generation.close) ||
           pg_queries(&pe.retained[slot].generation.layout,PROT_READ|PROT_EXEC,
               pe.domain.work.rx_quiet[i]))return PE_PUBLICATION;
    }
    return lprx_add(&pe.rx.quiet_releases,1);
}
static int lprx_complete_value(const struct pda_completion *c) {
    if(!c || c->rx.version!=1 || c->rx.count!=c->count || c->rx.reserved ||
       !c->count || c->count>LI2_PGD_MEMBERS || c->rx.retained_mask&~((1U<<c->count)-1U) ||
       !li2_pgd_source_rx_value(&c->source,&c->domain_source,&c->rx.source) ||
       c->rx.source.token.owner!=&pe || c->rx.source.token.serial!=c->serial ||
       c->rx.source.released_fetch.pid!=c->rseq.pid ||
       c->rx.source.released_fetch.tid!=c->rseq.tid ||
       !equal(&c->rx.source.released_fetch.progress,&c->fetch,sizeof c->fetch))return 0;
    for(unsigned i=0;i<c->count;i++) {
        const struct pda_member_completion *m=&c->member[i];
        const struct li2_pg_generation *g=&m->generation;
        if(!equal(&c->rx.source.ref[i],&m->identity,sizeof m->identity))return 0;
        for(unsigned j=0;j<3;j++) {
            if(!pda_query(&c->domain_source.open[i][j],&g->layout,j,PROT_READ|PROT_EXEC) ||
               !pda_zero(&c->domain_source.close[i][j],sizeof c->domain_source.close[i][j]) ||
               !pda_query(&c->rx.open[i][j],&g->layout,j,PROT_READ|PROT_EXEC) ||
               !pda_query(&c->rx.code[i][j],&g->layout,j,PROT_READ|PROT_EXEC) ||
               !pda_query(&c->rx.source.query[i][j],&g->layout,j,PROT_READ|PROT_EXEC) ||
               !pda_query(&g->slots[2].code[j],&g->layout,j,PROT_READ|PROT_EXEC))return 0;
            const struct le_permission *o=&g->open[j];
            if(c->rx.retained_mask&(1U<<i)) {
                if(!pda_zero(o,sizeof *o) ||
                   !pda_query(&g->slots[1].code[j],&g->layout,j,PROT_READ|PROT_EXEC))return 0;
            } else if(o->started!=1 || o->returned!=1 || o->sync_started!=1 ||
                o->sync_returned!=1 || o->complete!=1 || o->prot!=(PROT_READ|PROT_EXEC) ||
                o->result || o->sync_result || !pda_query(&o->query,&g->layout,j,PROT_READ|PROT_EXEC) ||
                !pda_query(&g->slots[1].code[j],&g->layout,j,PROT_READ))return 0;
        }
    }
    for(unsigned i=c->count;i<LI2_PGD_MEMBERS;i++)
        if(!pda_zero(c->rx.open[i],sizeof c->rx.open[i]) ||
           !pda_zero(c->rx.code[i],sizeof c->rx.code[i]))return 0;
    return 1;
}
static int lprx_revoke(unsigned reason) {
    if(reason<1 || reason>=LPRX_REASON_COUNT)return PE_STATE;
    /* Clear the only non-LOOP execution ticket before the first permission
       operation. No failure can return an armed branch capability. */
    le_zero(&pe.rx.branch,sizeof pe.rx.branch);
    if(!pe.initialized)return 0;
    if(!ptr_storage() || pe_active || pe.resuming || pe_closing ||
       !pe_identity())return PE_STATE;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        struct lprx_slot *r=&pe.rx.slot[i];
        unsigned rx=0;
        for(unsigned b=0;b<2;b++)
            if(pe.retained[i].banks[b].prot==(PROT_READ|PROT_EXEC)) {
                if(r->phase!=LPRX_RESIDENT || r->bank!=b)return PE_STATE;
                ++rx;
            }
        if(r->phase!=LPRX_RESIDENT) {
            if(rx || (r->phase==LPRX_EMPTY?!pda_zero(r,sizeof *r):
                (r->phase!=LPRX_REVOKED || lprx_slot_prot(i)!=PROT_READ)))return PE_STATE;
            continue;
        }
        const struct li2_pg_generation *g=&pe.retained[i].generation;
        if(rx!=1 || lprx_slot_prot(i)!=(PROT_READ|PROT_EXEC) || g->linked || g->active_refs ||
           g->domain_refs || g->member_refs[0] || g->member_refs[1] ||
           g->incoming[0] || g->incoming[1])return PE_STATE;
        r->phase=LPRX_REVOKING;__asm__ volatile("":::"memory");
        unsigned pages=0;int e=pg_permissions(&r->layout,PROT_READ,r->revoke,&pages);
        if(e || pages!=17 || !pg_closed(&r->layout,r->revoke))return PE_PUBLICATION;
        pe.retained[i].banks[r->bank].prot=PROT_READ;
        if(lprx_add(&pe.rx.revocations[reason],1))return PE_OVERFLOW;
        __asm__ volatile("":::"memory");r->phase=LPRX_REVOKED;
    }
    return 0;
}
static void lprx_before_unsafe(unsigned reason) {
    int e=lprx_revoke(reason);if(e)selected_persistent_abort((unsigned)e,500+(long)reason);
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
    lrxo_unsafe(reason);
#endif
}
/* Stable source identity excludes only the real validation-progress counters;
   the actual arm/close still authenticates those counters and physical pages. */
static int lprx_source_same(const struct li2_chain_fetch *a,const struct li2_chain_fetch *b) {
    return equal(&a->ref,&b->ref,sizeof a->ref) && a->pc==b->pc && a->length==b->length &&
        a->page_count==b->page_count && a->pid==b->pid && a->tid==b->tid &&
        a->identity_observed==b->identity_observed && equal(a->bytes,b->bytes,sizeof a->bytes) &&
        equal(a->pages,b->pages,sizeof a->pages) && equal(a->backing,b->backing,sizeof a->backing);
}
static unsigned lprx_branch_phase(void) {return pe.rx.branch.phase;}
static int lprx_branch_value(void) {
    const struct lprx_branch *b=&pe.rx.branch;
    if(b->phase<1 || b->phase>2 || b->reserved || b->cell>=LI2_PGD_RECEIPTS ||
       b->slot>=2 || !b->id || !b->serial || b->transit_reserved ||
       !b->branches || b->branches>LPRX_DIRECT_LIMIT)return 0;
    const struct pda_completion *c=&pe.domain.completion[b->cell];
    const struct pda_direct_exit *d=&c->direct_exit;
    if(c->id!=b->id || c->serial!=b->serial || c->complete!=1 ||
       d->complete!=1 || d->member>=c->count || d->arm>=2 ||
       li2_dd_arm(&d->direct,d->flags)!=(int)d->arm ||
       d->flags!=(b->flags|SELECTED_RF) || (b->flags&(SELECTED_TF|SELECTED_RF)))return 0;
    if(b->branches==1)return d->direct.target[d->arm]==b->target &&
        pda_zero(&b->transit,sizeof b->transit);
    const struct lprx_transit *v=&b->transit;const struct li2_chain_fetch *f=&v->source;
    struct li2_dd_descriptor expected;
    if(v->previous_slot>=2 || v->previous_slot==b->slot || !v->previous_generation ||
       !v->previous_event || v->arm>1 || !f->ref.owner || !f->ref.sequence ||
       f->pc!=d->direct.target[d->arm] || !f->length || f->length>15 ||
       !f->page_count || f->page_count>2 || f->pid!=c->rseq.pid || f->tid!=c->rseq.tid ||
       f->identity_observed!=1 || f->progress.held!=1 || f->progress.complete!=1 ||
       f->progress.first_error || f->progress.sequence!=f->ref.sequence ||
       v->original.decoded.pc!=f->pc || v->original.decoded.available!=f->length ||
       !equal(v->original.decoded.bytes,f->bytes,f->length) ||
       li2_dd_span(&v->original,1,&expected) || !equal(&expected,&v->direct,sizeof expected) ||
       li2_dd_arm(&v->direct,b->flags)!=(int)v->arm ||
       v->direct.target[v->arm]!=b->target)return 0;
    return 1;
}
static const struct li2_decoded *lprx_branch_decoded(void) {
    const struct lprx_branch *b=&pe.rx.branch;
    return b->branches==1?&pe.domain.completion[b->cell].direct_exit.original.decoded:
        &b->transit.original.decoded;
}
/* Retention target only: current executable ownership is still mandatory.
   The shared range predicate excludes every strict private overlap while
   recognizing original executable mappings protected against guest writes. */
static int lprx_target_allowed(uintptr_t target) {
    return li2_lifecycle_known_code(target,1) &&
        !li2_initial_code_protection_intersects(protected,initial_code_range,
            protected_count,target,1,PROT_READ|PROT_EXEC);
}
static int lprx_direct_begin(const struct li2_lpr_replay *replay,
    const struct li2_span_decoded *original,const struct li2_dd_descriptor *direct,
    unsigned arm,uint64_t flags) {
    if(!replay || !original || !direct || pe.rx.branch.phase || pe_active || pe_busy ||
       handling!=1 || selected_step_pending || selected_pending_route!=SELECTED_NO_STEP ||
       pe.domain.work.receipt>=LI2_PGD_RECEIPTS)return 0;
    const struct pda_completion *c=&pe.domain.completion[pe.domain.work.receipt];
    const struct pda_direct_exit *d=&c->direct_exit;
    if(!pda_receipt(c) || c->id!=replay->id || c->serial!=replay->serial ||
       d->member!=replay->member || !d->complete || arm!=d->arm ||
       !equal(original,&d->original,sizeof *original) || !equal(direct,&d->direct,sizeof *direct) ||
       !li2_lpr_replay_value(original,direct,arm,d->flags,&selected_decoded,flags))return 0;
    uintptr_t target=direct->target[arm];
    /* Actual target membership is an additional retention condition only.
       A decline revokes RX and runs the unchanged original TF branch path. */
    if(!lprx_target_allowed(target))return 0;
    pe.rx.branch=(struct lprx_branch){.phase=1,.cell=pe.domain.work.receipt,
        .id=c->id,.serial=c->serial,.target=target,.flags=flags,.branches=1};
    if(lprx_add(&pe.rx.direct_offers,1))selected_persistent_abort(PE_OVERFLOW,520);
    return 1;
}
static int lprx_transit_ancestry(void) {
    const struct lprx_branch *b=&pe.rx.branch;
    if(b->branches!=2 || b->transit.previous_slot>=2)return 0;
    const struct li2_tf_chain_slot *p=&selected_chain.slots[b->transit.previous_slot];
    const struct pda_direct_exit *d=&pe.domain.completion[b->cell].direct_exit;
    return p->generation==b->transit.previous_generation && p->event_id==b->transit.previous_event &&
        p->phase==LI2_CHAIN_CLOSED && p->owner.step.phase==LI2_STEP_COMPLETE &&
        !p->owner.step.first_error && p->owner.continuation_complete==1 &&
        !p->owner.continuation_result && p->query.complete==1 && !p->query.result &&
        p->query.pc==b->transit.source.pc && p->release.complete==1 && !p->release.result &&
        p->fetch.progress.complete==1 && !p->fetch.progress.held &&
        p->owner.actual_post_pc==b->transit.source.pc &&
        (p->owner.actual_post_flags&~SELECTED_TF)==b->flags &&
        equal(&p->decoded,&d->original.decoded,sizeof p->decoded) &&
        equal(&p->owner.step.request.decoded,&p->decoded,sizeof p->decoded);
}
static int lprx_armed_value(void) {
    const struct lprx_branch *b=&pe.rx.branch;
    const struct li2_tf_chain *c=&selected_chain;
    if(b->phase!=2 || !lprx_branch_value() || c->active!=(int)b->slot ||
       c->pending!=1 || c->in_handler || c->first_error || c->event_id!=b->chain_event ||
       selected_pending_route!=SELECTED_GENERIC_TF || selected_step_pending!=1)return 0;
    const struct li2_tf_chain_slot *s=&c->slots[b->slot];
    const struct li2_decoded *decoded=lprx_branch_decoded();
    return s->generation==b->chain_generation && s->event_id==b->chain_event &&
        s->phase==LI2_CHAIN_EXECUTING && s->owner.step.phase==LI2_STEP_RUNNING &&
        !s->owner.step.in_handler && !s->owner.step.first_error &&
        s->owner.step.request.original_flags==b->flags &&
        equal(&s->decoded,decoded,sizeof s->decoded) &&
        equal(&s->owner.step.request.decoded,&s->decoded,sizeof s->decoded) &&
        s->owner.classification.flow==LI2_TF_NEAR_FLOW &&
        s->owner.classification.family==LI2_TF_BRANCH &&
        (b->branches==1 || (b->chain_event>b->transit.previous_event && lprx_transit_ancestry() &&
            equal(&b->transit.source,&s->fetch,sizeof s->fetch)));
}
static void lprx_direct_armed(void) {
    struct lprx_branch *b=&pe.rx.branch;
    const struct li2_tf_chain *c=&selected_chain;
    pe_need(b->phase==1 && lprx_branch_value() && c->active>=0 && c->active<2 &&
        c->pending==1 && !c->in_handler && !c->first_error &&
        selected_pending_route==SELECTED_GENERIC_TF && selected_step_pending==1,PE_STATE,521);
    const struct li2_tf_chain_slot *s=&c->slots[c->active];
    const struct li2_decoded *decoded=lprx_branch_decoded();
    pe_need(s->phase==LI2_CHAIN_EXECUTING && s->generation && s->event_id==c->event_id &&
        s->owner.step.phase==LI2_STEP_RUNNING && !s->owner.step.in_handler &&
        !s->owner.step.first_error && s->owner.step.request.original_flags==b->flags &&
        equal(&s->decoded,decoded,sizeof s->decoded) &&
        equal(&s->owner.step.request.decoded,&s->decoded,sizeof s->decoded) &&
        s->owner.classification.flow==LI2_TF_NEAR_FLOW &&
        s->owner.classification.family==LI2_TF_BRANCH,PE_STATE,522);
    if(b->branches==2) {
        pe_need(b->slot==(unsigned)c->active && c->event_id>b->transit.previous_event &&
            lprx_source_same(&b->transit.source,&s->fetch),PE_STATE,522);
        b->transit.source=s->fetch; /* Actual post-arm query/validation snapshot. */
    }
    b->slot=(unsigned)c->active;b->chain_generation=s->generation;b->chain_event=c->event_id;
    __asm__ volatile("":::"memory");b->phase=2;
    pe_need(lprx_armed_value(),PE_STATE,522);
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
    if(b->branches==2)lrxo_transit_armed();
    lrxo_armed();
#endif
}
static void lprx_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!pe.initialized)return;
    if(pe_active) {
        if(pe.rx.branch.phase)selected_persistent_abort(PE_EVENT,523);
        return; /* Original active-owner preentry follows. */
    }
    const struct lprx_branch *b=&pe.rx.branch;
    if(!b->phase) {
        for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++)
            if(pe.retained[i].banks[j].prot==(PROT_READ|PROT_EXEC))
                selected_persistent_abort(PE_EVENT,523);
        return;
    }
    if(handling || !lprx_armed_value() ||
       sig!=SIGTRAP || !si || !uc || si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE ||
       si->si_errno || (uintptr_t)si->si_addr!=b->target ||
       (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=b->target ||
       uc->uc_mcontext.gregs[REG_TRAPNO]!=1 || uc->uc_mcontext.gregs[REG_ERR] ||
       (uint64_t)uc->uc_mcontext.gregs[REG_EFL]!=(b->flags|SELECTED_TF))
        selected_persistent_abort(PE_EVENT,523);
    /* This does not consume the actual chain ticket. The unchanged real TRACE
       close/continuation and transfer still authenticate all registers/source. */
}
static void lprx_direct_closed(void) {
    if(!pe.rx.branch.phase)return;
    const struct lprx_branch *b=&pe.rx.branch;
    pe_need(b->phase==2 && lprx_branch_value(),PE_EVENT,524);
    const struct li2_tf_chain_slot *s=&selected_chain.slots[b->slot];
    pe_need(s->generation==b->chain_generation && s->phase==LI2_CHAIN_CLOSED &&
        s->owner.continuation_complete==1 && !s->owner.continuation_result &&
        s->query.complete==1 && !s->query.result && s->query.pc==b->target &&
        s->release.complete==1 && !s->release.result && !s->fetch.progress.held &&
        s->fetch.progress.complete==1 && pe.transfer.pc==b->target &&
        pe.transfer.flags==b->flags,PE_EVENT,524);
    pe_need(b->branches==1 || lprx_source_same(&b->transit.source,&s->fetch),PE_EVENT,524);
    pe_need(!lprx_add(b->branches==1?&pe.rx.direct_steps:&pe.rx.transit_steps,1),PE_OVERFLOW,524);
    le_zero(&pe.rx.branch,sizeof pe.rx.branch);
}
/* Called only by the real chain engine after full TRACE frame/identity,
   source revoke/query/release, and fresh read-only preparation/classification.
   It cannot bypass any chain arm, rseq, flags, byte or physical-source check. */
static void lprx_transit_prepared(const struct li2_tf_chain *chain,
    const struct li2_tf_chain_slot *previous,const struct li2_tf_chain_slot *next,
    const ucontext_t *uc) {
    struct lprx_branch saved=pe.rx.branch;
    pe_need(chain==&selected_chain && handling==1 && !pe_active && !pe_busy &&
        !pe_closing && !pe.resuming && saved.phase==2 && lprx_branch_value() &&
        selected_pending_route==SELECTED_GENERIC_TF && selected_step_pending==1 &&
        chain->in_handler==1 && !chain->first_error && chain->pending==1 &&
        chain->active>=0 && chain->active<2 && next==&chain->slots[chain->active] &&
        previous==&chain->slots[saved.slot] && previous!=next &&
        previous->generation==saved.chain_generation && previous->event_id==saved.chain_event &&
        chain->event_id>saved.chain_event && previous->phase==LI2_CHAIN_CLOSED &&
        previous->owner.step.phase==LI2_STEP_COMPLETE && !previous->owner.step.first_error &&
        previous->owner.continuation_complete==1 && !previous->owner.continuation_result &&
        previous->query.complete==1 && !previous->query.result && previous->query.pc==saved.target &&
        previous->release.complete==1 && !previous->release.result &&
        !previous->fetch.progress.held && previous->fetch.progress.complete==1 &&
        previous->owner.actual_post_pc==saved.target &&
        (previous->owner.actual_post_flags&~SELECTED_TF)==saved.flags && uc &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==saved.target &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==saved.flags &&
        (saved.branches==1 || lprx_source_same(&saved.transit.source,&previous->fetch)),
        PE_EVENT,526);
    pe_need(!lprx_add(saved.branches==1?&pe.rx.direct_steps:&pe.rx.transit_steps,1),PE_OVERFLOW,526);
    if(saved.branches==LPRX_DIRECT_LIMIT) {
        pe_need(!lprx_add(&pe.rx.transit_limit,1),PE_OVERFLOW,527);
        lprx_before_unsafe(LPRX_DECLINED);return;
    }
    const struct li2_chain_fetch *f=&next->fetch;
    struct li2_dd_descriptor direct={0};struct li2_span_decoded original={0};
    int arm=-1;
    if(next->phase!=LI2_CHAIN_PREPARING || next->event_id!=chain->event_id ||
       !next->generation || next->fallback || next->prepare_complete!=1 ||
       next->decode_complete!=1 || next->prepare_result || next->decode_result || next->classify_result ||
       next->descriptive_classification.flow!=LI2_TF_NEAR_FLOW ||
       next->descriptive_classification.family!=LI2_TF_BRANCH ||
       f->pc!=saved.target || f->identity_observed!=1 || f->pid!=chain->session->pid ||
       f->tid!=chain->session->tid || f->progress.held!=1 || f->progress.complete!=1 ||
       f->progress.first_error || f->progress.sequence!=f->ref.sequence ||
       li2_dd_describe(f->pc,f->bytes,f->length,1,&direct) ||
       li2_decoder_span_describe(f->pc,f->bytes,f->length,&original) ||
       !equal(&direct.decoded,&next->decoded,sizeof next->decoded) ||
       !equal(&original.decoded,&next->decoded,sizeof next->decoded) ||
       (arm=li2_dd_arm(&direct,saved.flags))<0 || !lprx_target_allowed(direct.target[arm])) {
        pe_need(!lprx_add(&pe.rx.transit_declined,1),PE_OVERFLOW,527);
        lprx_before_unsafe(LPRX_DECLINED);return;
    }
    pe_need(pda_receipt(&pe.domain.completion[saved.cell]),PE_RELEASE,527);
    struct lprx_branch issued={.phase=1,.cell=saved.cell,.slot=(unsigned)chain->active,
        .id=saved.id,.serial=saved.serial,.target=direct.target[arm],.flags=saved.flags,.branches=2,
        .transit={.original=original,.direct=direct,.source=*f,
            .previous_generation=saved.chain_generation,.previous_event=saved.chain_event,
            .previous_slot=saved.slot,.arm=(unsigned)arm}};
    pe.rx.branch=issued;
    pe_need(lprx_branch_value() && !lprx_add(&pe.rx.transit_offers,1),PE_EVENT,527);
}
static void lprx_handler_end(void) {
    if(pe_active && selected_pending_route==SELECTED_PERSISTENT_EPOCH && selected_step_pending==1) {
        pe_need(!pe.rx.branch.phase && pe.p.phase==LI2_PG_EXECUTING,PE_STATE,525);return;
    }
    if(lprx_armed_value())return;
    lprx_before_unsafe(LPRX_RETURN);
}
static void lprx_terminal(void) {
    if(!pe.initialized)return;
    if(lprx_add(&pe.rx.terminal_attempts,1))return;
    le_zero(&pe.rx.branch,sizeof pe.rx.branch);
    unsigned good=1;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned b=0;b<2;b++) {
        struct ped_bank *bank=&pe.retained[i].banks[b];
        if(bank->prot!=(PROT_READ|PROT_EXEC))continue;
        struct le_permission close[3]={0};unsigned pages=0;
        if(pg_permissions(&bank->layout,PROT_READ,close,&pages) || pages!=17 ||
           !pg_closed(&bank->layout,close))good=0;
        else bank->prot=PROT_READ;
    }
    if(good)(void)lprx_add(&pe.rx.terminal_closed,1);
}
static void lprx_report(unsigned status,unsigned code) {
    struct writer transit={0};text(&transit,"LI2_LOOP_RX_TRANSIT {\"version\":1");
    field(&transit,",\"status\":",status);field(&transit,",\"failure_code\":",code);
    field(&transit,",\"branch_limit\":",LPRX_DIRECT_LIMIT);
    field(&transit,",\"offers\":",pe.rx.transit_offers);
    field(&transit,",\"steps\":",pe.rx.transit_steps);
    field(&transit,",\"declined\":",pe.rx.transit_declined);
    field(&transit,",\"limit_revokes\":",pe.rx.transit_limit);
    text(&transit,"}\n");
    (void)raw(SYS_write,report_fd<0?2:report_fd,(long)transit.bytes,transit.used,0,0,0);
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
    lrxo_report(status,code);
#endif
    const struct pda_work *work=&pe.domain.work;
    const struct pda_completion *last=0;
    if(pe.p.phase==LI2_PG_CLOSED && work->bound==1 && work->completion==1 &&
       work->receipt<LI2_PGD_RECEIPTS) {
        const struct pda_completion *c=&pe.domain.completion[work->receipt];
        if(c->complete==1 && c->id==pe.domain.next_id && c->serial==pe.p.serial &&
           c->count==work->view.count && c->rx.version==1 && c->rx.count==c->count &&
           c->source.serial==c->serial && c->domain_source.token.owner==&pe &&
           c->domain_source.token.serial==c->serial && c->rx.source.token.owner==&pe &&
           c->rx.source.token.serial==c->serial &&
           equal(&c->domain_source.entry,&work->view.entry,sizeof work->view.entry))last=c;
    }
    struct writer w={0};text(&w,"LI2_LOOP_RESIDENT_RX {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
#define LPRX_FIELD(n) field(&w,",\"" #n "\":",pe.rx.n)
    LPRX_FIELD(entries);LPRX_FIELD(retained_entries);LPRX_FIELD(quiet_releases);
    LPRX_FIELD(direct_offers);LPRX_FIELD(direct_steps);
    LPRX_FIELD(code_opens);LPRX_FIELD(code_revokes);LPRX_FIELD(code_writes);LPRX_FIELD(code_syncs);
    LPRX_FIELD(metadata_permissions);LPRX_FIELD(metadata_syncs);
    LPRX_FIELD(terminal_attempts);LPRX_FIELD(terminal_closed);
#undef LPRX_FIELD
    field(&w,",\"last_complete\":",last!=0);
    field(&w,",\"last_id\":",last?last->id:0);
    field(&w,",\"last_serial\":",last?last->serial:0);
    field(&w,",\"last_count\":",last?last->count:0);
    field(&w,",\"last_retained_mask\":",last?last->rx.retained_mask:0);
    field(&w,",\"last_source_phase\":",last?last->source.phase:0);
    field(&w,",\"last_entry\":",last?last->source.source.key.entry:0);
    field(&w,",\"last_released_pc\":",last?last->rx.source.released_fetch.pc:0);
    field(&w,",\"last_root\":",last?last->domain_source.entry.target.root:0);
    field(&w,",\"last_head\":",last?last->domain_source.entry.target.head:0);
    field(&w,",\"last_slot\":",last?last->domain_source.entry.slot:0);
    field(&w,",\"last_bank\":",last?last->domain_source.entry.bank:0);
    field(&w,",\"last_generation\":",last?last->domain_source.entry.generation:0);
    field(&w,",\"revoke_cold\":",pe.rx.revocations[LPRX_COLD]);
    field(&w,",\"revoke_declined\":",pe.rx.revocations[LPRX_DECLINED]);
    field(&w,",\"revoke_fetch\":",pe.rx.revocations[LPRX_FETCH]);
    field(&w,",\"revoke_raw\":",pe.rx.revocations[LPRX_RAW]);
    field(&w,",\"revoke_native\":",pe.rx.revocations[LPRX_NATIVE]);
    field(&w,",\"revoke_return\":",pe.rx.revocations[LPRX_RETURN]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
