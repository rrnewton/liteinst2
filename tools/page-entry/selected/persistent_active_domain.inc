/* Distinct profile: each actual activation owns one/two retained certificates
   under one source/rseq lifetime. These helpers never run on an internal edge. */
static void pda_select(unsigned slot,unsigned bank) {
    pe_need(slot<LI2_PTR_SLOTS && bank<2,PE_STATE,80);
    pe.selected_slot=slot;pe.selection=pe.retained[slot].identity;pe.selected_bank=bank;
    pe_need(ptr_selected(),PE_STATE,81);
}
static unsigned pda_bank(unsigned slot) {
    if(slot>=LI2_PTR_SLOTS)return 2;
    const struct li2_ptr_slot *s=&pe.retained[slot];unsigned found=2;
    for(unsigned i=0;i<2;i++)if(s->generation.generated==s->banks[i].generated &&
        pg_layout_equal(&s->generation.layout,&s->banks[i].layout)) {
        if(found!=2)return 2;
        found=i;
    }
    return found;
}
static int pda_query(const struct li2_private_code_query *q,const struct li2_pg_layout *l,unsigned i,int prot) {
    return i<3 && pg_query_complete(q,pg_extent(l,i),pg_extent_bytes(i),prot);
}
/* Historical closure validation NEVER dereferences a saved member pointer.
   A consumed/replaced sibling is represented solely by these saved values. */
static int pda_zero(const void *value,size_t bytes) {
    const unsigned char *b=value;
    for(size_t i=0;i<bytes;i++)if(b[i])return 0;
    return 1;
}
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
static int pda_direct_exit_value(const struct pda_completion *c) {
    const struct pda_direct_exit *e=&c->direct_exit;
    if(!e->complete)return pda_zero(e,sizeof *e);
    if(e->complete!=1 || e->reserved || e->member>=c->count || e->member>=LI2_PGD_MEMBERS ||
       !e->heads || e->heads>LI2_PG_HEADS || e->head>=e->heads ||
       !e->exits || e->exits>LI2_PG_BOUNDARIES || e->index>=e->exits || e->arm>1 ||
       (e->flags&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF)return 0;
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    if(c->member[e->member].header.plan_policy==LI2_LPE_VERSION)return ple_direct_value(c);
#endif
    if(c->member[e->member].header.plan_policy==LI2_LP_VERSION)return plr_direct_value(c);
    if(c->member[e->member].header.plan_policy!=LI2_PF_VERSION ||
       !plr_fallback_value(c))return 0;
#endif
    const struct li2_pg_source_key *s=&c->member[e->member].source;
    if(s->page[0].identity.address>=s->page[1].identity.address)return 0;
    for(unsigned i=0;i<2;i++)if((s->page[i].identity.address&(PAGE-1)) ||
        s->page[i].identity.address>(UINT64_C(1)<<47)-PAGE)return 0;
    const struct li2_pe_head *h=&e->row;const struct li2_span_decoded *d=&e->original;
    const struct li2_dd_descriptor *a=&e->direct;struct li2_dd_descriptor expected;
    if(h->kind!=LI2_PG_DIRECT || h->source_page>=2 || h->source_offset>=PAGE ||
       !h->source_length || h->source_length>15 || d->decoded.length!=h->source_length ||
       d->decoded.pc!=s->page[h->source_page].identity.address+h->source_offset ||
       (e->head==0?d->decoded.pc!=s->entry:d->decoded.pc==s->entry) ||
       !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES ||
       li2_dd_span(d,a->external_mask,&expected) || !equal(a,&expected,sizeof *a) ||
       h->successor_count!=(a->flow==LI2_REGION_JCC?2U:1U) || e->arm>=h->successor_count ||
       (h->successor_count==1 && h->successors[1]) || li2_dd_arm(a,e->flags)!=(int)e->arm ||
       !(a->external_mask&(1U<<e->arm)) || h->successors[e->arm]!=LI2_PG_HEADS+e->index)return 0;
    unsigned external=0;
    for(unsigned arm=0;arm<h->successor_count;arm++) {
        unsigned in_pair=0;for(unsigned page=0;page<2;page++) {
            uintptr_t at=s->page[page].identity.address;
            if(a->target[arm]>=at && a->target[arm]-at<PAGE)++in_pair;
        }
        if(in_pair>1)return 0;
#ifdef LI2_PERSISTENT_FUSED_RUNTIME
        /* Version11 is a distinct direction policy. Reconstruct the cut
           from the saved source pair and original branch, independently of
           the cached descriptor's mask. No current plan pointer is read. */
        unsigned target_in_pair=0;
        for(unsigned page=0;page<2;page++) {
            uintptr_t at=s->page[page].identity.address;
            if(a->target[0]>=at && a->target[0]-at<PAGE)++target_in_pair;
        }
        if(target_in_pair>1)return 0;
        const unsigned backward=target_in_pair && a->target[0]<=d->decoded.pc;
        if((arm==0 && !backward) || (arm==1 && (backward || !in_pair)))external|=1U<<arm;
#else
#ifdef LI2_PERSISTENT_BLOCK_RUNTIME
        /* PB terminates at its first direct branch. Every arm is an exact
           directory exit, including in-pair/backward targets. This separate
           policy does not change the old outside-pair definition. */
        external|=1U<<arm;
#else
        if(!in_pair)external|=1U<<arm;
#endif
#endif
        unsigned k=h->successors[arm];
        if(k>=e->heads && (k<LI2_PG_HEADS || k-LI2_PG_HEADS>=e->exits))return 0;
        if((a->external_mask&(1U<<arm)) && k<LI2_PG_HEADS)return 0;
    }
    if(external!=a->external_mask || (external==3 && h->successors[0]==h->successors[1]))return 0;
#ifdef LI2_PERSISTENT_BLOCK_RUNTIME
    if(e->head+1!=e->heads || e->exits!=h->successor_count || e->index!=e->arm ||
       h->successors[0]!=LI2_PG_HEADS ||
       (h->successor_count==2 && h->successors[1]!=LI2_PG_HEADS+1U))return 0;
#endif
    unsigned n=0;
    for(;n<15;n++) {
        uintptr_t pc=d->decoded.pc+n;unsigned found=0;
        for(unsigned page=0;page<2;page++) {
            uintptr_t at=s->page[page].identity.address;
            if(pc>=at && pc-at<PAGE) {
                if(d->decoded.bytes[n]!=s->page[page].bytes[pc-at])return 0;
                ++found;
            }
        }
        if(found>1)return 0;
        if(!found)break;
    }
    return n==d->decoded.available;
}
#endif
#ifdef LI2_PERSISTENT_RET_DISPATCH
static int pda_ret_exit_value(const struct pda_completion *);
#endif
static int pda_receipt(const struct pda_completion *c) {
    if(!c || !c->id || c->id>pe.domain.next_id || !c->serial || c->serial>pe.next_serial ||
       c->complete!=1 || !c->count || c->count>LI2_PGD_MEMBERS)return 0;
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
#ifndef LI2_PERSISTENT_LOOP_RUNTIME
    if(!pda_direct_exit_value(c))return 0;
#endif
#endif
#ifdef LI2_PERSISTENT_RET_DISPATCH
    if(!pda_ret_exit_value(c))return 0;
#endif
    const struct li2_pg_source_progress *s=&c->source;
    const struct li2_pgd_source_progress *d=&c->domain_source;
    const struct li2_pg_rseq_progress *r=&c->rseq;
#ifdef LI2_LOOP_RESIDENT_RX
    if(!lprx_complete_value(c))return 0;
#endif
#ifdef LI2_LOOP_RESIDENT_RX
    if(s->serial!=c->serial || s->phase!=LI2_PGS_RX_RELEASED || s->first_error || s->first_detail || s->aborted ||
#else
    if(s->serial!=c->serial || s->phase!=LI2_PGS_RELEASED || s->first_error || s->first_detail || s->aborted ||
#endif
       s->source.complete!=1 || s->source.serial!=c->serial || s->release_started!=1 ||
       s->release_complete!=1 || s->opened_extents!=3 || s->opened_pages!=17 ||
#ifdef LI2_LOOP_RESIDENT_RX
       s->closed_extents || s->closed_pages || s->cancel_started || s->cancel_complete ||
#else
       s->closed_extents!=3 || s->closed_pages!=17 || s->cancel_started || s->cancel_complete ||
#endif
       !pg_layout_equal(&s->layout,&c->member[0].identity.layout) ||
#ifdef LI2_PERSISTENT_SUBENTRY
       !li2_pgs_entry_value(&d->entry,&c->member[0].source,&s->source,&c->member[0].identity.layout) ||
       d->entry.token.owner!=&pe || d->entry.slot!=c->member[0].identity.slot ||
       d->entry.bank!=c->member[0].identity.bank || d->entry.generation!=c->member[0].identity.generation ||
       d->entry.build_serial!=c->member[0].generation.build_serial ||
#else
       !li2_pg_source_key_equal(&s->source.key,&c->member[0].source) ||
#endif
       d->token.owner!=&pe || d->token.serial!=c->serial || d->count!=c->count ||
#ifdef LI2_LOOP_RESIDENT_RX
       d->bound!=1 || d->opened!=1 || d->closed || d->released!=1 || d->first_error || d->first_detail ||
#else
       d->bound!=1 || d->opened!=1 || d->closed!=1 || d->released!=1 || d->first_error || d->first_detail ||
#endif
       r->token.owner!=&pe || r->token.serial!=c->serial || r->active || r->checking ||
       r->first_error || r->first_detail || r->unsafe_terminal || r->seed_complete!=1 || r->entry_complete!=1 ||
       r->close_complete!=1 || r->cancel_started || r->cancel_complete ||
       r->domain_bound!=1 || r->domain_count!=c->count ||
       r->word_before || r->word_entry || r->word_after ||
       !c->fetch.sequence || c->fetch.sequence!=s->source.anchor.sequence ||
       c->fetch.held || c->fetch.complete!=1 || c->fetch.first_error ||
       !pg_query_complete(&c->directory_closed,pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ))return 0;
#ifdef LI2_PERSISTENT_UNREGISTERED
    if(!li2_pgu_progress_valid(r))return 0;
#endif
    for(unsigned i=0;i<c->count;i++) {
        const struct pda_member_completion *m=&c->member[i];
        const struct li2_pg_generation *g=&m->generation;
        const struct li2_pgd_ref *v=&m->identity;
        if(v->slot>=LI2_PTR_SLOTS || v->bank>1 || !v->generation || !v->root ||
           (i && (v->slot==c->member[0].identity.slot || v->generation==c->member[0].identity.generation)) ||
           v->generation!=g->generation || v->proof!=g->proof || v->root!=m->source.entry ||
           !pg_layout_equal(&v->layout,&g->layout) || v->layout.directory!=pe.domain.directory ||
           !equal(v,&d->ref[i],sizeof *v) || !equal(v,&r->domain_ref[i],sizeof *v) ||
#ifdef LI2_PERSISTENT_CROSS_PAIR
           ((!i || !d->peer.started)?!li2_pgd_source_pair_equal(&s->source.key,&m->source):
               (!li2_pgx_source_value(&d->peer,&s->source,&d->token,v,&m->source,LI2_PGX_CHECKS) ||
                d->peer.table[0].address!=c->member[0].header.table ||
                d->peer.table[1].address!=m->header.table)) ||
#else
           !li2_pgd_source_pair_equal(&s->source.key,&m->source) ||
#endif
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
           !li2_lpr_header(m->header.version,m->header.plan_policy,(unsigned)m->header.plan_policy) ||
           m->header.generation!=v->generation || m->header.serial!=g->build_serial ||
#else
           m->header.version!=1 || m->header.generation!=v->generation || m->header.serial!=g->build_serial ||
#endif
           m->header.registry!=(uintptr_t)&pe || m->header.generated!=g->generated ||
           m->header.spill!=g->spill || !pg_layout_equal(&m->header.layout,&g->layout) ||
#ifdef LI2_PERSISTENT_UNREGISTERED
           !pe_lifetime_matches(&m->header,r) ||
#endif
           m->header.registered_epoch!=r->registration_epoch || m->header.rseq_address!=r->address ||
           m->header.rseq_length!=r->length || m->header.rseq_signature!=r->signature ||
           !equal(m->header.archive,pe_archive,32) || !equal(m->header.policy,pe_policy,32) ||
           g->installed!=1 || g->complete!=1 || g->proof_complete!=1 ||
           g->ready_generation!=v->generation || g->linked || g->active_refs ||
           g->member_refs[0] || g->member_refs[1] || g->incoming[0] || g->incoming[1] || g->domain_refs ||
#ifdef LI2_LOOP_RESIDENT_RX
           !pda_zero(g->close,sizeof g->close) || !pg_proof_query_complete(&m->proof,g->proof,PROT_READ) ||
#else
           !pg_closed(&g->layout,g->close) || !pg_proof_query_complete(&m->proof,g->proof,PROT_READ) ||
#endif
           g->slots[2].started!=1 || g->slots[2].complete!=1 || g->slots[2].linked ||
           g->slots[2].copied!=PAGE || g->slots[2].verified!=PAGE ||
           !pg_query_complete(&g->slots[2].seal.query,g->layout.slots,PAGE,PROT_READ) ||
           g->cell[2].started!=1 || g->cell[2].complete!=1 || g->cell[2].after ||
           g->cell[2].generation!=g->generation || g->cell[2].serial!=c->serial ||
           !pg_query_complete(&g->cell[2].mapping,g->spill,PAGE,PROT_READ|PROT_WRITE))return 0;
        /* Independent source/controller queries retain distinct actual maps
           receipts; every exact interval/protection must close separately. */
#ifdef LI2_LOOP_RESIDENT_RX
        /* The complete RX query/open-transition checks are in the typed
           value validator, including zero unused/cold-vs-retained fields. */
#else
        for(unsigned j=0;j<3;j++)if(!pda_query(&d->open[i][j],&v->layout,j,PROT_READ|PROT_EXEC) ||
            !pda_query(&d->close[i][j],&v->layout,j,PROT_READ) ||
            !pda_query(&g->close[j].query,&v->layout,j,PROT_READ) ||
            g->open[j].started!=1 || g->open[j].returned!=1 ||
            g->open[j].sync_started!=1 || g->open[j].sync_returned!=1 ||
            g->open[j].complete!=1 || g->open[j].prot!=(PROT_READ|PROT_EXEC) ||
            g->open[j].result || g->open[j].sync_result ||
            !pda_query(&g->open[j].query,&v->layout,j,PROT_READ|PROT_EXEC))return 0;
#endif
    }
#ifdef LI2_PERSISTENT_CROSS_PAIR
    if(c->count==1 || li2_pgd_source_pair_equal(&c->member[0].source,&c->member[1].source)) {
        if(!pda_zero(&d->peer,sizeof d->peer))return 0;
    } else if(d->peer.started!=1)return 0;
#endif
    for(unsigned i=c->count;i<LI2_PGD_MEMBERS;i++)if(!pda_zero(&c->member[i],sizeof c->member[i]) ||
        !pda_zero(&d->ref[i],sizeof d->ref[i]) || !pda_zero(d->open[i],sizeof d->open[i]) ||
        !pda_zero(d->close[i],sizeof d->close[i]) || !pda_zero(&r->domain_ref[i],sizeof r->domain_ref[i]))return 0;
    for(unsigned j=0;j<3;j++)if(!pda_query(&s->opened[j],&s->layout,j,PROT_READ|PROT_EXEC) ||
#ifdef LI2_LOOP_RESIDENT_RX
        !pda_zero(&s->closed[j],sizeof s->closed[j]) ||
#else
        !pda_query(&s->closed[j],&s->layout,j,PROT_READ) ||
#endif
        !equal(&s->opened[j],&d->open[0][j],sizeof s->opened[j]) ||
        !equal(&s->closed[j],&d->close[0][j],sizeof s->closed[j]))return 0;
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
#ifdef LI2_LOOP_RO_CERTIFICATE
    if(!lhc_direct_value(c))return 0;
#else
    if(!pda_direct_exit_value(c))return 0;
#endif
#endif
    return 1;
}
#ifdef LI2_LOOP_RO_CERTIFICATE
#include "loop_history_certificate.inc"
#endif
static int pda_permitted(unsigned slot) {
    if(slot>=LI2_PTR_SLOTS || !ptr_storage())return 0;
    const struct li2_ptr_slot *s=&pe.retained[slot];const struct li2_pgd_claim *q=&s->claim;
    if(q->valid!=1 || q->reserved || q->cell>=LI2_PGD_RECEIPTS || q->member>=LI2_PGD_MEMBERS ||
       !q->id || s->permit.valid || !ptr_stored(slot))return 0;
    const struct pda_completion *c=&pe.domain.completion[q->cell];
    if(!pda_receipt(c) || q->id!=c->id || q->member>=c->count ||
       pe.domain.claimed[q->cell]&~((1U<<c->count)-1U) ||
       (pe.domain.claimed[q->cell]&(1U<<q->member)))return 0;
    const struct pda_member_completion *m=&c->member[q->member];
    if(m->identity.slot!=slot || m->identity.generation!=s->identity.generation ||
       m->identity.proof!=s->proof || s->last_completed!=c->serial ||
       !equal(&m->generation,&s->generation,sizeof s->generation) ||
       !equal(&m->header,&s->publication.header,sizeof m->header) ||
       !equal(&m->source,&s->publication.source,sizeof m->source) ||
       m->identity.bank!=pda_bank(slot) || s->banks[m->identity.bank].virgin ||
#ifdef LI2_LOOP_RESIDENT_RX
       !lprx_permitted(slot) || !ptr_slots(slot,0))return 0;
#else
       s->banks[m->identity.bank].prot!=PROT_READ || !ptr_slots(slot,0))return 0;
#endif
    return *(const volatile uint64_t *)(s->generation.spill+32)==0;
}
static void pda_claim(unsigned slot) {
    pe_need(pda_permitted(slot),PE_RELEASE,80);
    struct li2_pgd_claim *q=&pe.retained[slot].claim;
    pe.domain.claimed[q->cell]|=1U<<q->member;
    *q=(struct li2_pgd_claim){0};
}
static void pda_reset(void) {
#ifdef LI2_PERSISTENT_RET_DISPATCH
    pe_need(!prr_pending && !prr_busy,PE_STATE,171);
#endif
    pe_need(!pe_active && !pe_busy && !pe.domain.work.aborting,PE_STATE,82);
    le_zero(&pe.domain.work,sizeof pe.domain.work);
    pe.domain.work.peer=LI2_PTR_SLOTS;pe.domain.work.receipt=LI2_PGD_RECEIPTS;
    pe.domain.work.exit_member=pe.domain.work.recovery_member=LI2_PGD_MEMBERS;
}
static void pda_initialize(void) {
    pe_need(!pe.domain.allocated && !pe.domain.registered &&
        protected_count<=RANGES-3U*LI2_PTR_SLOTS-1U,PE_STATE,83);
    long v=raw(SYS_mmap,0,LI2_JD_DOMAIN_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    pe_need(v>0 && !((uintptr_t)v&(PAGE-1)) &&
        (uintptr_t)v<(UINT64_C(1)<<47)-LI2_JD_DOMAIN_BYTES,PE_PUBLICATION,v);
    pe.domain.directory=(uintptr_t)v;pe.domain.allocated=1;
    pe_need(!selected_run_protect_add(0,(uintptr_t)v,LI2_JD_DOMAIN_BYTES),PE_STATE,84);
    pe.domain.registered=1;
    pe_need(!pe_query((uintptr_t)v,LI2_JD_DOMAIN_BYTES,PROT_READ|PROT_WRITE,&pe.domain.initial) &&
        !pe_permission((uintptr_t)v,LI2_JD_DOMAIN_BYTES,PROT_READ,&pe.domain.initial_seal),PE_PUBLICATION,81);
    pe.domain.work.peer=LI2_PTR_SLOTS;pe.domain.work.receipt=LI2_PGD_RECEIPTS;
}
static int pda_registry(unsigned slot) {
    return slot<LI2_PTR_SLOTS && protected_count<=RANGES &&
        pe.retained[slot].registry_count==protected_count &&
        equal(pe.retained[slot].registry,protected,protected_count*sizeof *protected);
}
static int pda_registration(const struct pe_payload *p) {
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    return r && r->active && r->seed_complete && !r->first_error && !r->unsafe_terminal &&
#ifdef LI2_PERSISTENT_UNREGISTERED
        pe_lifetime_matches(&p->header,r) &&
#endif
        p->header.registered_epoch==r->registration_epoch && p->header.rseq_address==r->address &&
        p->header.rseq_length==r->length && p->header.rseq_signature==r->signature;
}
static int pda_disjoint(const struct li2_pg_compact *a,const struct li2_pg_compact *b) {
    if(a->exits+a->links+b->exits+b->links>LI2_PG_BOUNDARIES)return 0;
    for(unsigned i=0;i<a->heads;i++)for(unsigned j=0;j<b->heads;j++) {
        const struct li2_decoded *x=&a->original[i].decoded,*y=&b->original[j].decoded;
        if(!x->length || x->length>15 || !y->length || y->length>15 ||
           x->pc>UINTPTR_MAX-x->length || y->pc>UINTPTR_MAX-y->length ||
           (x->pc<y->pc+y->length && y->pc<x->pc+x->length))return 0;
    }
    for(unsigned i=0;i<a->exits;i++)for(unsigned j=0;j<b->exits;j++)if(a->exit_pc[i]==b->exit_pc[j])return 0;
    return 1;
}
static void pda_offer_peer(void) {
    pe_need(!pe.domain.work.bound && pe.domain.work.peer==LI2_PTR_SLOTS &&
        pe.p.phase==LI2_PG_HELD,PE_STATE,85);
    if(!pe.warm)return; /* A new cold certificate cannot expand its activation. */
    unsigned peer=1U-pe.selected_slot;
    const struct li2_ptr_slot *s=&pe.retained[peer];
    if(!s->generation.installed)return;
    pe_need(pda_permitted(peer),PE_RELEASE,82);
    const struct pe_payload *p=(const void *)s->proof;
    if(!pda_registry(peer) || !pda_registration(p) ||
#ifdef LI2_PERSISTENT_CROSS_PAIR
       !li2_pgx_guard_union(&pe_payload()->plan,&p->plan) ||
#else
       !li2_pgd_source_pair_equal(&p->source,&pe_payload()->source) ||
#endif
       !pda_disjoint(&pe_payload()->plan,&p->plan))return;
    pe.domain.work.peer=peer;
}
static int pda_member_live(const struct li2_pgd_member *m) {
    const struct li2_pgd_ref *v=&m->identity;
    if(v->slot>=LI2_PTR_SLOTS || v->bank>1 || !v->generation || !ptr_storage())return 0;
    const struct li2_ptr_slot *s=&pe.retained[v->slot];const struct li2_pg_generation *g=&s->generation;
    const struct pe_payload *p=(const void *)s->proof;
    return ptr_stored(v->slot) && v->generation==s->identity.generation && v->generation==g->generation &&
        v->proof==s->proof && v->root==p->source.entry && m->plan==&p->plan && m->key==&p->source &&
        pg_layout_equal(&v->layout,&g->layout) && pg_layout_equal(&v->layout,&s->banks[v->bank].layout) &&
        v->layout.directory==pe.domain.directory && pda_registry(v->slot) && pda_registration(p);
}
const struct li2_pgd_view *li2_pgd_owner_view(const struct li2_pg_token *t) {
    const struct pda_work *w=&pe.domain.work;const struct li2_pgd_view *v=&w->view;
    if(!t || t->owner!=&pe || !t->serial || t->serial!=pe.p.serial ||
       !w->bound || !v->count || v->count>LI2_PGD_MEMBERS || v->reserved ||
       !equal(t,&v->token,sizeof *t) || v->directory!=pe.domain.directory ||
       w->primary>=LI2_PTR_SLOTS || v->member[0].identity.slot!=w->primary ||
       !pg_layout_equal(&v->member[0].identity.layout,&pe.p.layout))return 0;
#ifdef LI2_PERSISTENT_SUBENTRY
    const struct li2_pgs_entry *entry=li2_pgs_owner_entry(t);
    if(!entry || !equal(entry,&v->entry,sizeof *entry))return 0;
#endif
    for(unsigned i=0;i<v->count;i++)if(!pda_member_live(&v->member[i]) ||
        (i && (v->member[i].identity.slot==v->member[0].identity.slot ||
               v->member[i].identity.generation==v->member[0].identity.generation)))return 0;
#ifdef LI2_PERSISTENT_CROSS_PAIR
    if(v->count==2 && !li2_pgx_guard_union(v->member[0].plan,v->member[1].plan))return 0;
#endif
    return v;
}
#ifdef LI2_PERSISTENT_CROSS_PAIR
const struct li2_pgd_view *li2_pgx_owner_offer(const struct li2_pg_token *t) {
    const struct pda_work *w=&pe.domain.work;const struct li2_pgd_view *v=&w->view;
    if(!pe_token(t) || pe.p.phase!=LI2_PG_BOUND || !pe_busy || pe_active || !pe.warm ||
       w->bound || w->peer>=LI2_PTR_SLOTS || w->primary>=LI2_PTR_SLOTS || w->peer==w->primary ||
       w->primary!=pe.selected_slot || w->primary_bank!=pe.selected_bank ||
       v->count!=1 || v->reserved || !equal(&v->token,t,sizeof *t) || v->directory!=pe.domain.directory ||
       v->member[0].identity.slot!=w->primary || v->member[1].identity.slot!=w->peer ||
       !pg_layout_equal(&v->member[0].identity.layout,&pe.p.layout) ||
       !pda_permitted(w->peer) || !pda_member_live(&v->member[0]) || !pda_member_live(&v->member[1]) ||
       !pda_disjoint(v->member[0].plan,v->member[1].plan) ||
       !li2_pgx_guard_union(v->member[0].plan,v->member[1].plan))return 0;
#ifdef LI2_PERSISTENT_SUBENTRY
    const struct li2_pgs_entry *entry=li2_pgs_owner_entry(t);
    if(!entry || !equal(entry,&v->entry,sizeof *entry))return 0;
#endif
    return v;
}
#endif
static void pda_member(unsigned at,unsigned slot) {
    struct pda_work *w=&pe.domain.work;unsigned bank=pda_bank(slot);
    pe_need(at<LI2_PGD_MEMBERS && slot<LI2_PTR_SLOTS && bank<2,PE_STATE,86);
    struct li2_ptr_slot *s=&pe.retained[slot];const struct pe_payload *p=(const void *)s->proof;
    w->view.member[at]=(struct li2_pgd_member){
        .identity={.generation=s->identity.generation,.slot=slot,.bank=bank,
            .proof=s->proof,.root=p->source.entry,.layout=s->generation.layout},
        .plan=&p->plan,.key=&p->source};
}
static int pda_directory_seal(void) {
    struct pda_work *w=&pe.domain.work;struct li2_jd_domain_directory *d=&w->directory;
    if(d->count || d->version || d->serial)return PE_STATE;
    d->version=LI2_JD_DOMAIN_VERSION;d->serial=pe.p.serial;
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_member *m=&w->view.member[i];const struct li2_pg_compact *p=m->plan;
        for(unsigned j=0;j<p->heads;j++) {
            if(d->count>=LI2_JD_DOMAIN_HEADS)return PE_PLAN;
            const uintptr_t pc=p->original[j].decoded.pc;
            for(size_t k=0;k<d->count;k++)if(d->row[k].pc==pc)return PE_PLAN;
            d->row[d->count++]=(struct li2_jd_domain_row){.pc=pc,
                .generated=p->layout.generated[j/64]+(uintptr_t)(j%64)*LI2_PE_SLOT_BYTES,
                .generation=m->identity.generation,.slot=m->identity.slot,.head=j};
        }
    }
    if(!d->count || d->count>LI2_JD_DOMAIN_HEADS)return PE_PLAN;
    int e=pe_permission(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ|PROT_WRITE,&w->directory_write);
    if(e)return e;
    volatile unsigned char *b=(void *)pe.domain.directory;const unsigned char *expected=(const void *)d;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)b[i]=i<sizeof *d?expected[i]:0;
    e=pe_permission(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&w->directory_seal);if(e)return e;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)if(b[i]!=(i<sizeof *d?expected[i]:0))return PE_PUBLICATION;
    return 0;
}
static int pda_directory_equal(void) {
    const struct pda_work *w=&pe.domain.work;
    if(w->directory_seal.complete!=1 || w->directory_seal.result || w->directory_seal.sync_result ||
       !pg_query_complete(&w->directory_seal.query,pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ))return 0;
    const volatile unsigned char *b=(const void *)pe.domain.directory;
    const unsigned char *expected=(const void *)&w->directory;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)if(b[i]!=(i<sizeof w->directory?expected[i]:0))return 0;
    return 1;
}
static int pda_bind(const ucontext_t *uc) {
    struct pda_work *w=&pe.domain.work;
#ifdef LI2_PERSISTENT_CALL_DISPATCH
    uint64_t call_stack_effect=0;
#ifdef LI2_PERSISTENT_RET_DISPATCH
    uint64_t ret_stack_effect=0;
#endif
#endif
    if(w->bound || pe.p.phase!=LI2_PG_BOUND || !pe_busy || pe_active || !pe_ready())return PE_STATE;
    w->primary=pe.selected_slot;w->primary_bank=pe.selected_bank;
    w->view.token=pe.token;w->view.directory=pe.domain.directory;w->view.count=1;
#ifdef LI2_PERSISTENT_SUBENTRY
    const struct li2_pgs_entry *entry=li2_pgs_owner_entry(&pe.token);if(!entry)return PE_SOURCE;
    w->view.entry=*entry;
#endif
    pda_member(0,w->primary);
#ifdef LI2_PERSISTENT_CROSS_PAIR
    if(pe.warm && w->peer<LI2_PTR_SLOTS) {
        pda_member(1,w->peer);
        if(!li2_pgd_source_pair_equal(w->view.member[0].key,w->view.member[1].key)) {
            unsigned accepted=0;int e=li2_pgx_source_prepare(&pe.token,&accepted);
            if(e)return e;
            if(!accepted) {w->peer=LI2_PTR_SLOTS;le_zero(&w->view.member[1],sizeof w->view.member[1]);}
        }
    }
#endif
    if(pe.warm && w->peer<LI2_PTR_SLOTS) {
        unsigned peer=w->peer;pe_need(peer!=w->primary && pda_permitted(peer),PE_RELEASE,83);
        pda_select(peer,pda_bank(peer));
#ifdef LI2_LOOP_RESIDENT_RX
        int peer_prot=lprx_slot_prot(peer);
        pe_need(peer_prot>=0 && !pe_bytes() && !pg_queries(&PE_SLOT(generation).layout,peer_prot,w->peer_claim.code) &&
#else
        pe_need(!pe_bytes() && !pg_queries(&PE_SLOT(generation).layout,PROT_READ,w->peer_claim.code) &&
#endif
            !pg_proof_query(PE_SLOT(generation).proof,PROT_READ,&w->peer_claim.proof) &&
            !pe_query(PE_SLOT(generation).spill,PAGE,PROT_READ|PROT_WRITE,&w->peer_claim.spill) &&
            !pe_query(PE_SLOT(generation).layout.slots,PAGE,PROT_READ,&w->peer_claim.slots),PE_RELEASE,84);
        pda_claim(peer);ped_count(PGC_REF(permit_claims));
        struct li2_pg_generation *g=&PE_SLOT(generation);
        le_zero(g->open,sizeof g->open);le_zero(g->close,sizeof g->close);le_zero(g->cleanup,sizeof g->cleanup);
        le_zero(&g->slots[1],2U*sizeof g->slots[1]);le_zero(&g->cell[1],2U*sizeof g->cell[1]);
        pda_member(1,peer);w->view.count=2;
        pda_select(w->primary,w->primary_bank);
    }
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {
        const struct pda_completion *c=&pe.domain.completion[i];
        if((pda_zero(c,sizeof *c) && !pe.domain.claimed[i]) ||
           (pda_receipt(c) && pe.domain.claimed[i]==(1U<<c->count)-1U)) {
            w->receipt=i;break;
        }
    }
    if(w->receipt>=LI2_PGD_RECEIPTS)return PE_RELEASE;
    w->bound=1;
    if(!li2_pgd_owner_view(&pe.token) || li2_pgd_source_bind(&pe.token) ||
       li2_pgd_rseq_bind(&pe.token,uc))return PE_SOURCE;
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_member *m=&w->view.member[i];
        struct li2_pg_generation *g=&pe.retained[m->identity.slot].generation;
        if(g->domain_refs || g->linked || g->active_refs)return PE_STATE;
        pda_select(m->identity.slot,m->identity.bank);
        if(pe_bytes())return PE_PUBLICATION;
        g->domain_refs=1;
        for(unsigned j=0;j<m->plan->heads;j++)if(m->plan->head[j].kind==LI2_PE_NONE
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
            || m->plan->head[j].kind==LI2_PG_DIRECT
#endif
        ) {
            const struct li2_span_decoded *d=&m->plan->original[j];
            pe.gpr_written|=d->gpr_write;
            pe.flags_written|=d->flags_written|d->flags_set|d->flags_cleared|d->flags_undefined;
#ifdef LI2_PERSISTENT_CALL_DISPATCH
        } else if(m->plan->head[j].kind==LI2_PG_CALL) {
            const struct li2_cd_descriptor *c=&m->plan->instruction[j].call;
#ifdef LI2_PERSISTENT_DIRECT_CALL
            uintptr_t target;
            if(c->version!=LI2_CD_VERSION || c->ready!=1 || c->refusal ||
               (c->target>=16 && (c->target!=LI2_CD_DIRECT_TARGET || li2_cd_direct_target(c,&target))))return PE_PLAN;
#else
            if(c->version!=LI2_CD_VERSION || c->ready!=1 || c->refusal || c->target>=16)return PE_PLAN;
#endif
            call_stack_effect|=UINT64_C(1)<<4;
#endif
#ifdef LI2_PERSISTENT_RET_DISPATCH
        } else if(m->plan->head[j].kind==LI2_PG_RET) {
            const struct li2_rd_descriptor *r=&m->plan->instruction[j].ret;
            if(r->version!=LI2_RD_VERSION || r->ready!=1 || r->refusal || r->reserved[0] ||
               r->reserved[1] || r->reserved[2] || r->reserved[3])return PE_PLAN;
            ret_stack_effect|=UINT64_C(1)<<4;
#endif
#ifdef LI2_ADD_GUARD
        } else if(m->plan->head[j].kind==LI2_PG_ADD) {
            const struct li2_ag_descriptor *a=&m->plan->instruction[j].add;
            if(a->version!=LI2_AG_VERSION || a->ready!=1 || a->refusal ||
               a->flags_written!=LI2_AG_STATUS || a->memory_access!=LI2_AG_READ_WRITE ||
               a->width_bytes!=8)return PE_PLAN;
            pe.flags_written|=a->flags_written;
#endif
        }
    }
    pda_select(w->primary,w->primary_bank);
    if((pe.gpr_written&~UINT64_C(0xffff)) || (pe.gpr_written&(UINT64_C(1)<<4)) ||
       (pe.flags_written&~UINT64_C(0x8d5)))return PE_PLAN;
#ifdef LI2_PERSISTENT_CALL_DISPATCH
    /* All old head kinds passed their unchanged no-RSP-write assertion above.
       Only the separately typed CALL branch contributes this stack effect. */
    pe.gpr_written|=call_stack_effect;
#ifdef LI2_PERSISTENT_RET_DISPATCH
    pe.gpr_written|=ret_stack_effect;
#endif
    int error=pda_directory_seal();if(error)return error;
    return pcw_bind(uc);
#else
    return pda_directory_seal();
#endif
}
static int pda_ready(unsigned linked) {
    const struct pda_work *w=&pe.domain.work;
    if(linked>1 || !li2_pgd_owner_view(&pe.token) || !pe_ready() || !pda_directory_equal())return 0;
#ifdef LI2_PERSISTENT_CALL_DISPATCH
    if(!pcw_equal())return 0;
#endif
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        const struct li2_pg_generation *g=&pe.retained[v->slot].generation;
        if(g->domain_refs!=1 || g->active_refs!=linked || g->member_refs[0]!=linked ||
           g->member_refs[1]!=linked || !ptr_slots(v->slot,linked))return 0;
        uint64_t incoming[2]={0,0};
        if(linked)for(unsigned j=0;j<w->view.member[i].plan->links;j++) {
            unsigned head=w->view.member[i].plan->edge[j].target_head;
            if(head>=w->view.member[i].plan->heads)return 0;
            ++incoming[head/64];
        }
        if(g->incoming[0]!=incoming[0] || g->incoming[1]!=incoming[1])return 0;
    }
    return 1;
}
static int pda_enter(const struct li2_pg_token *t,int sig,const siginfo_t *si,ucontext_t *uc) {
    struct pda_work *w=&pe.domain.work;
    if(!pe_token(t) || pe.p.phase!=LI2_PG_BOUND || !pe_busy || pe_active || !pda_ready(0) ||
       !le_unchanged(&pe.before,si,uc))return PE_STATE;
    pe.p.phase=LI2_PG_OPENING;pe.p.opened_pages=0;
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        pda_select(v->slot,v->bank);if(pe_bytes())return PE_PUBLICATION;
        int e=pg_link_data(1);if(e)return e;
    }
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        pda_select(v->slot,v->bank);struct li2_pg_generation *g=&PE_SLOT(generation);unsigned pages=0;
#ifdef LI2_LOOP_RESIDENT_RX
        (void)g;(void)pages;
        int e=lprx_enter(i);if(e)return e;
        if(!pg_refs(1) || !pg_slots(1))return PE_PUBLICATION;
#else
        int e=pg_permissions(&g->layout,PROT_READ|PROT_EXEC,g->open,&pages);if(e)return e;
        if(pages!=17 || !pg_refs(1) || !pg_slots(1))return PE_PUBLICATION;
        PE_SLOT(banks)[v->bank].prot=PROT_READ|PROT_EXEC;pe.p.opened_pages+=pages;
#endif
    }
    pda_select(w->primary,w->primary_bank);
#ifdef LI2_LOOP_RESIDENT_RX
    unsigned retained=(w->rx_retained_mask&1U)+((w->rx_retained_mask>>1)&1U);
    if(retained>w->view.count || pe.p.opened_pages!=17U*(w->view.count-retained) || li2_pgd_source_opened(t) ||
#else
    if(pe.p.opened_pages!=17U*w->view.count || li2_pgd_source_opened(t) ||
#endif
       li2_pg_rseq_live(t,uc,&pe.live[1]))return PE_SOURCE;
    pe_tls(&pe.before);
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        pda_select(v->slot,v->bank);if(pe_bytes())return PE_PUBLICATION;
    }
    pda_select(w->primary,w->primary_bank);
    if(!pe_identity() || !le_quiet(&pe.ref) || !pda_ready(1) ||
       !le_unchanged(&pe.before,si,uc) || sig!=SIGTRAP)return PE_FRAME;
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
    /* Count the actual authenticated redirect, not membership of a peer. */
    unsigned actual_loop_entry=0,entry_members=0;
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    unsigned actual_effects_entry=0;
#endif
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_member *m=&w->view.member[i];
        if(m->identity.slot!=w->view.entry.slot || m->identity.bank!=w->view.entry.bank ||
           m->identity.generation!=w->view.entry.generation)continue;
        struct li2_pgs_target target;
        if(li2_pgs_head_lookup(m->plan,w->view.entry.target.pc,&target)!=1 ||
           !equal(&target,&w->view.entry.target,sizeof target))return PE_FRAME;
        ++entry_members;actual_loop_entry=m->plan->version==LI2_LP_VERSION;
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
        actual_effects_entry=m->plan->version==LI2_LPE_VERSION;
#endif
    }
    if(entry_members!=1)return PE_FRAME;
#endif
    pe.p.phase=LI2_PG_EXECUTING;pe.redirected=1;ped_count(PGC_REF(entries));
    if(w->view.count==2)ped_count(&pe.domain.dual_entries);
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
    unsigned loop_entry=0;
    for(unsigned i=0;i<w->view.count;i++)loop_entry|=w->view.member[i].plan->version==LI2_LP_VERSION;
    if(loop_entry)PLR_COUNT(entries_with12);
    if(actual_loop_entry)PLR_COUNT(actual_entries12);
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    unsigned effects_entry=0;
    for(unsigned i=0;i<w->view.count;i++)effects_entry|=w->view.member[i].plan->version==LI2_LPE_VERSION;
    if(effects_entry)PLE_COUNT(entries_with13);
    if(actual_effects_entry)PLE_COUNT(actual_entries13);
#endif
#endif
    selected_step_pending=1;selected_pending_route=SELECTED_PERSISTENT_EPOCH;pe_active=1;
#ifdef LI2_PERSISTENT_SUBENTRY
    if(w->view.entry.target.pc!=w->view.entry.target.root)ped_count(&pe.subentry_entries);
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)w->view.entry.target.generated;
#else
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)w->view.member[0].plan->layout.generated[0];
#endif
    return 0;
}
static int pda_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    li2_pg_rseq_preentry();
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
    if(!pe_active && !pe_busy && !pe.loop.scope && selected_pending_route!=SELECTED_PERSISTENT_EPOCH)return 0;
#else
    if(!pe_active && !pe_busy && selected_pending_route!=SELECTED_PERSISTENT_EPOCH)return 0;
#endif
    if(pe_busy || pe_closing || pe_decoding || handling || !pe_active || !pe.redirected ||
       pe.p.phase!=LI2_PG_EXECUTING || selected_pending_route!=SELECTED_PERSISTENT_EPOCH ||
       selected_step_pending!=1 || pe.p.first_error || !pda_ready(1))return PE_REENTRY;
    struct pda_work *w=&pe.domain.work;
    pe_busy=1;pe.p.phase=LI2_PG_RECOVERING;pe.recovery_started=1;__asm__ volatile("":::"memory");
    if(le_capture(&pe.after,sig,si,uc))return PE_FRAME;
    const greg_t *g=pe.after.frame.greg;uintptr_t pc=(uintptr_t)g[REG_RIP];
#ifdef LI2_PERSISTENT_RET_DISPATCH
    int ret=prr_loaded_preentry(sig,si,uc);
    if(ret)return ret==1?0:ret;
#endif
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
    int exit=pe_exit_index(pc,(uint64_t)g[REG_EFL]);
    if(exit< -1)return PE_PUBLICATION;
    unsigned member=exit>=0?0:LI2_PGD_MEMBERS;
    for(unsigned i=1;i<w->view.count;i++) {
#ifdef LI2_PERSISTENT_FUSED_RUNTIME
        int candidate=PLR_EXIT(w->view.member[i].plan,pc,(uint64_t)g[REG_EFL]);
#else
#ifdef LI2_PERSISTENT_BLOCK_RUNTIME
        int candidate=li2_pb_compact_exit(w->view.member[i].plan,pc,(uint64_t)g[REG_EFL]);
#else
        int candidate=li2_pg_compact_exit(w->view.member[i].plan,pc,(uint64_t)g[REG_EFL]);
#endif
#endif
        if(candidate< -1)return PE_PUBLICATION;
        if(candidate>=0) {
            if(member!=LI2_PGD_MEMBERS)return PE_PUBLICATION;
            member=i;exit=candidate;
        }
    }
#else
    int exit=pe_exit_index(pc);unsigned member=exit>=0?0:LI2_PGD_MEMBERS;
    for(unsigned i=1;i<w->view.count;i++)for(unsigned j=0;j<w->view.member[i].plan->exits;j++)
        if(w->view.member[i].plan->exit_pc[j]==pc) {
            if(member!=LI2_PGD_MEMBERS)return PE_PUBLICATION;
            member=i;exit=(int)j;
        }
#endif
    if(member<w->view.count && sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR &&
       !si->si_errno && g[REG_TRAPNO]==14 && g[REG_ERR]==21 && (uintptr_t)si->si_addr==pc &&
       (uintptr_t)g[REG_CR2]==pc && ((uint64_t)g[REG_EFL]&(SELECTED_TF|SELECTED_RF))==SELECTED_RF &&
       ((uint64_t)g[REG_CSGSFS]&65535)==0x33 && (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47) &&
       pe.after.frame.mask==pe.session.application_mask) {
        pe.exit_seen=1;pe.exit_index=(unsigned)exit;w->exit_member=member;pe.recovery_complete=1;return 0;
    }
    ped_count(PGC_REF(unexpected));
    member=LI2_PGD_MEMBERS;
    for(unsigned i=0;i<w->view.count;i++)for(unsigned j=0;j<3;j++) {
        const struct li2_pg_layout *l=&w->view.member[i].identity.layout;
        if(pc>=pg_extent(l,j) && pc-pg_extent(l,j)<pg_extent_bytes(j)) {
            if(member!=LI2_PGD_MEMBERS)return PE_PUBLICATION;
            member=i;
        }
    }
    if(member==LI2_PGD_MEMBERS)return PE_EVENT;
    /* Only after savedPC selects the exact actual certificate may its
       initialized-boundary recovery consider that certificate's spill. */
    w->recovery_member=member;const struct li2_pgd_member *m=&w->view.member[member];
    uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=(uint64_t)g[pe_greg[i]];
#ifdef LI2_PERSISTENT_RET_DISPATCH
    for(unsigned i=0;i<m->plan->heads;i++)if(m->plan->head[i].kind==LI2_PG_RET &&
        pc>=m->identity.layout.generated[i/64]+(uintptr_t)(i%64)*LI2_PE_SLOT_BYTES &&
        pc-(m->identity.layout.generated[i/64]+(uintptr_t)(i%64)*LI2_PE_SLOT_BYTES)<LI2_PE_SLOT_BYTES) {
        prr.run.interior_result=li2_pg_compact_recover_ret(m->plan,i/64,i%64,pc,raw,
            (uint64_t)g[REG_EFL],(const uint64_t *)m->identity.layout.spill,&prr.run.interior);
        /* Keep the complete 176-byte target/phase value. A generated fault is
           terminal here; it cannot fall into the old 168-byte reconstruction. */
        return PE_EVENT;
    }
#endif
#ifdef LI2_PERSISTENT_FUSED_RUNTIME
    pe.recovery_result=PLR_RECOVER(m->plan,pc,raw,(uint64_t)g[REG_EFL],
        (const uint64_t *)m->identity.layout.spill,&pe.recovery_scratch,&pe.recovered);
#else
#ifdef LI2_PERSISTENT_BLOCK_RUNTIME
    pe.recovery_result=li2_pb_compact_recover(m->plan,pc,raw,(uint64_t)g[REG_EFL],
        (const uint64_t *)m->identity.layout.spill,&pe.recovery_scratch.direct,&pe.recovered);
#else
    pe.recovery_result=li2_pg_compact_recover(m->plan,pc,raw,(uint64_t)g[REG_EFL],
        (const uint64_t *)m->identity.layout.spill,&pe.recovery_scratch,&pe.recovered);
#endif
#endif
    if(!pe.recovery_result && pe.recovered.complete) {
        pe.recovery_complete=1;
        pe.guest_data_fault=sig==SIGSEGV && si->si_signo==SIGSEGV && !si->si_errno &&
            (si->si_code==SEGV_MAPERR || si->si_code==SEGV_ACCERR) && g[REG_TRAPNO]==14 &&
            !(g[REG_ERR]&16) && (uintptr_t)si->si_addr==(uintptr_t)g[REG_CR2] &&
            ((pe.recovered.kind==LI2_PG_GUARD && pe.recovered.phase==LI2_MG_STORE) ||
#ifdef LI2_ADD_GUARD
             (pe.recovered.kind==LI2_PG_ADD_GUARD && pe.recovered.phase==LI2_AG_RMW) ||
#endif
             (pe.recovered.kind==LI2_PG_COPIED && pe.recovered.phase==LI2_MG_BEFORE));
    }
    return PE_EVENT;
}
static int pda_drain(const struct li2_pg_token *t) {
    struct pda_work *w=&pe.domain.work;
    if(!pe_token(t) || !pe_active || !pe_busy || pe.p.phase!=LI2_PG_RECOVERING ||
       !pe.exit_seen || !pe.recovery_complete || w->exit_member>=w->view.count || !pda_ready(1))return PE_STATE;
    pe.p.phase=LI2_PG_CLOSING;pe.p.closed_pages=0;
#ifdef LI2_LOOP_RESIDENT_RX
    int quiet=lprx_drain();if(quiet)return quiet;
#else
    /* First close EVERY bank. No reset/ref release can precede the last NX. */
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        struct li2_pg_generation *g=&pe.retained[v->slot].generation;unsigned pages=0;
        int e=pg_permissions(&g->layout,PROT_READ,g->close,&pages);if(e)return e;
        if(pages!=17 || !pg_closed(&g->layout,g->close))return PE_PUBLICATION;
        pe.retained[v->slot].banks[v->bank].prot=PROT_READ;pe.p.closed_pages+=pages;
    }
    if(pe.p.closed_pages!=17U*w->view.count)return PE_PUBLICATION;
#endif
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        pda_select(v->slot,v->bank);int e=pg_link_data(2);if(e)return e;
        if(pe_bytes() || pg_proof_query(v->proof,PROT_READ,&w->proof_exit[i]))return PE_PUBLICATION;
    }
    pda_select(w->primary,w->primary_bank);pe.proof_exit=w->proof_exit[0];
    if(!pda_directory_equal() || pe_query(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&w->directory_closed))return PE_PUBLICATION;
    pe.p.phase=LI2_PG_RELEASING;
#ifdef LI2_LOOP_RESIDENT_RX
    pe.release_result=li2_pgd_source_release_rx(t);if(pe.release_result)return pe.release_result;
#else
    pe.release_result=li2_pgd_source_release(t);if(pe.release_result)return pe.release_result;
#endif
    pe.p.anchor_released=1;pe.final_fetch=*li2_lifecycle_fetch_progress();
    if(pe.final_fetch.held || pe.final_fetch.complete!=1 || pe.final_fetch.first_error ||
       pe.final_fetch.sequence!=pe.ref.sequence)return PE_RELEASE;
    if(li2_pg_rseq_close(t,&pe.after.uc))return PE_RSEQ;
    for(unsigned i=0;i<w->view.count;i++)pe.retained[w->view.member[i].identity.slot].generation.domain_refs=0;
    pe.p.registration_rechecked=1;pe.p.phase=LI2_PG_CLOSED;return 0;
}
static void pda_complete(void) {
    struct pda_work *w=&pe.domain.work;
    pe_need(w->bound && !w->completion && w->receipt<LI2_PGD_RECEIPTS &&
        pe.p.phase==LI2_PG_CLOSED && pe.domain.next_id!=UINT64_MAX,PE_RELEASE,85);
    struct pda_completion *c=&pe.domain.completion[w->receipt];
    pe_need((pda_zero(c,sizeof *c) && !pe.domain.claimed[w->receipt]) ||
        (pda_receipt(c) && pe.domain.claimed[w->receipt]==(1U<<c->count)-1U),PE_RELEASE,86);
#ifdef LI2_LOOP_RO_CERTIFICATE
    pe_need(!lhc_begin(c),PE_RELEASE,122);
#endif
    le_zero(c,sizeof *c);c->id=++pe.domain.next_id;c->serial=pe.p.serial;c->count=w->view.count;
    c->source=*li2_pg_source_progress();c->domain_source=*li2_pgd_source_progress();
    c->rseq=*li2_pg_rseq_progress();c->fetch=pe.final_fetch;c->directory_closed=w->directory_closed;
#ifdef LI2_LOOP_RESIDENT_RX
    c->rx.version=1;c->rx.count=c->count;c->rx.retained_mask=w->rx_retained_mask;
    c->rx.source=*li2_pgd_source_rx_progress();
    copy(c->rx.open,w->rx_open,sizeof c->rx.open);
    copy(c->rx.code,w->rx_quiet,sizeof c->rx.code);
#endif
    for(unsigned i=0;i<c->count;i++) {
        const struct li2_pgd_member *m=&w->view.member[i];struct li2_ptr_slot *s=&pe.retained[m->identity.slot];
        pe_need(!s->claim.valid && !s->claim.id && !s->permit.valid,PE_RELEASE,87);
        c->member[i]=(struct pda_member_completion){.identity=m->identity,.header=s->publication.header,
            .source=s->publication.source,.generation=s->generation,.proof=w->proof_exit[i]};
    }
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
    pe_need(pe.exit_seen && w->exit_member<w->view.count,PE_RELEASE,115);
    const struct li2_pg_compact *closed=w->view.member[w->exit_member].plan;
    const uintptr_t exit_pc=(uintptr_t)pe.after.frame.greg[REG_RIP];
    const uint64_t exit_flags=(uint64_t)pe.after.frame.greg[REG_EFL];
#ifdef LI2_PERSISTENT_FUSED_RUNTIME
    pe_need(PLR_EXIT(closed,exit_pc,exit_flags)==(int)pe.exit_index,PE_RELEASE,116);
#else
#ifdef LI2_PERSISTENT_BLOCK_RUNTIME
    pe_need(li2_pb_compact_exit(closed,exit_pc,exit_flags)==(int)pe.exit_index,PE_RELEASE,116);
#else
    pe_need(li2_pg_compact_exit(closed,exit_pc,exit_flags)==(int)pe.exit_index,PE_RELEASE,116);
#endif
#endif
    for(unsigned i=0;i<closed->heads;i++)if(closed->head[i].kind==LI2_PG_DIRECT &&
        closed->original[i].decoded.pc==exit_pc) {
        pe_need(!c->direct_exit.complete,PE_RELEASE,117);
        int arm=li2_dd_arm(&closed->instruction[i].direct,exit_flags);
        pe_need(arm>=0,PE_RELEASE,118);
        c->direct_exit=(struct pda_direct_exit){.complete=1,.member=w->exit_member,
            .heads=closed->heads,.head=i,.exits=closed->exits,.index=pe.exit_index,.arm=(unsigned)arm,
            .flags=exit_flags,.row=closed->head[i],.original=closed->original[i],.direct=closed->instruction[i].direct};
    }
#endif
    c->complete=1;pe.domain.claimed[w->receipt]=0;
    pe_need(pda_receipt(c),PE_RELEASE,88);
#ifdef LI2_LOOP_RO_CERTIFICATE
    pe_need(!lhc_issue(c),PE_RELEASE,123);
#endif
    for(unsigned i=0;i<c->count;i++) {
        struct li2_ptr_slot *s=&pe.retained[c->member[i].identity.slot];
        s->claim=(struct li2_pgd_claim){.id=c->id,.cell=w->receipt,.member=i,.valid=1};
        s->last_completed=c->serial;
        pe_need(pda_permitted(c->member[i].identity.slot),PE_RELEASE,89);
    }
    if(c->count==2)ped_count(&pe.domain.dual_completed);
#ifdef LI2_PERSISTENT_SUBENTRY
    if(w->view.entry.target.pc!=w->view.entry.target.root)ped_count(&pe.subentry_completed);
#endif
    w->completion=1;ped_count(PGC_REF(completed));pe.p.completion_permit=1;
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
    unsigned loop_completed=0;
    for(unsigned i=0;i<c->count;i++)loop_completed|=c->member[i].header.plan_policy==LI2_LP_VERSION;
    if(loop_completed)PLR_COUNT(completed_with12);
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    unsigned effects_completed=0;
    for(unsigned i=0;i<c->count;i++)effects_completed|=c->member[i].header.plan_policy==LI2_LPE_VERSION;
    if(effects_completed)PLE_COUNT(completed_with13);
#endif
#endif
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
    lrxo_complete(c);
#endif
}
static _Noreturn void pda_abort(unsigned code,long detail) {
    /* A corrupt directory/index cannot become an out-of-bounds cleanup read.
       No failed/partial path creates a joint record or releases shared source. */
    if(pe_failing || pe.selected_slot>=LI2_PTR_SLOTS || pe.domain.work.aborting) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    pe_failing=1;pe_busy=1;pe.domain.work.aborting=1;
    if(!pe.p.first_error){pe.p.first_error=code;pe.p.first_detail=detail;}
    pe.p.completion_permit=0;pe.p.phase=LI2_PG_FAILED;li2_maps_phase_fail();
    if(pe.initialized && ptr_storage()) {
        for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
            struct li2_ptr_slot *s=&pe.retained[i];
            if(s->generation.installed) {
                s->generation.ready_generation=0;unsigned ignored=0;
                (void)pg_permissions(&s->generation.layout,PROT_READ,s->generation.cleanup,&ignored);
            }
        }
    }
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE
    pdao_terminal(1);
#endif
#ifdef LI2_PERSISTENT_SUBENTRY_CAPTURE
    pso_terminal(1);
#endif
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE
    pdo_terminal(1);
#endif
#ifdef LI2_PERSISTENT_CROSS_PAIR_CAPTURE
    pxo_terminal(1);
#endif
    report(125,pe.p.first_error,pe.p.first_detail);
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
