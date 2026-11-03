/* Actual node identities and controls, using the shared complete frame,
   member, source, directory and FD custody observer. */
static void ltao_nodes(unsigned epoch,unsigned stage) {
    lc8o_need(epoch<14 && stage<2 && lta_topology_live(),300);
    for(unsigned node=0;node<PTR_NODE_COUNT;node++) {
        struct ltao_node *out=&lc8o.wire.arena.node[epoch][stage][node];
        const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
        const struct lta_dormant *d=&lta_writer.value.dormant[node];
        int slot=lta_node_bound(node);uint64_t *h=out->h;
        lc8o_need(!h[1] && !h[4],301);
        h[0]=s->generation.installed;h[1]=node;h[2]=slot<0?8U:(unsigned)slot;
        h[3]=slot<0?0:pe.arena.binding[slot].generation;
        h[4]=s->generation.generation;h[5]=s->generation.build_serial;
        h[6]=s->publication.source.entry;h[7]=s->proof;h[8]=s->generation.generated;
        h[9]=s->generation.spill;h[10]=(uintptr_t)&s->publication;
        h[11]=lta_writer.value.node[node];h[12]=d->issued;h[13]=d->closed;h[14]=d->reusable;
        h[15]=d->node_epoch;h[16]=d->retired_binding;h[17]=d->completion_id;
        h[18]=d->completion_serial;h[19]=d->prepared_serial;h[20]=d->prepared_binding;
        h[21]=s->claim.valid;h[22]=s->claim.id;h[23]=s->last_completed;
        out->issued=d->certificate;out->current=sg_owner.state.bytes.certificate[node];
    }
}
#if LI2_LOOP_CACHE8_CONTROL != 0
static void ltao_result(unsigned at,int refused,int restored) {
    lc8o_need(at==lc8o.arena_controls && at<20 && !refused && restored==1,302);
    uint64_t *row=lc8o.wire.arena.controls[at];
    row[0]=at;row[1]=0;row[2]=(unsigned)refused;row[3]=1;
    ++lc8o.arena_controls;++lc8o.arena_restorations;
}
static unsigned ltao_inactive_a0(void) {
    unsigned found=PTR_NODE_COUNT;
    for(unsigned node=0;node<PTR_NODE_COUNT;node++)
        if(PTR_NODE_AT(node).generation.installed &&
           PTR_NODE_AT(node).publication.source.entry==UINT64_C(0x410200)) {
            lc8o_need(found==PTR_NODE_COUNT,303);found=node;
        }
    lc8o_need(found<PTR_NODE_COUNT && lta_node_bound(found)<0 && lta_closed_value(found),304);
    return found;
}
static void ltao_dormant_controls(const struct pda_completion *c) {
    if(lc8o.epochs!=10)return;
    lc8o_need(!lc8o.arena_controls && lc8o.controls==24 && lc8o.restorations==24 &&
        c->count==5 && pda_receipt(c),305);
    unsigned node=ltao_inactive_a0();struct lta_dormant *d=&lta_writer.value.dormant[node];
    lc8o.busy=1;lc8o.arena_saved=*d;
    for(unsigned kind=0;kind<12;kind++) {
        switch(kind) {
        case 0:d->node_epoch^=1;break;
        case 1:d->generation^=1;break;
        case 2:d->build_serial^=1;break;
        case 3:d->root^=1;break;
        case 4:d->page[0]^=PAGE;break;
        case 5:d->page[1]^=PAGE;break;
        case 6:d->certificate.serial^=1;break;
        case 7:d->bank=2;break;
        case 8:d->retired_binding=0;break;
        case 9:d->completion_id=0;break;
        case 10:d->completion_serial^=1;break;
        default:d->reusable=0;break;
        }
        int refused=lta_closed_value(node);*d=lc8o.arena_saved;
        lc8o_need(equal(d,&lc8o.arena_saved,sizeof *d),306);
        ltao_result(kind,refused,lta_closed_value(node));
    }
    lc8o.busy=0;
}
#endif
static void ltao_binding_controls(void) {
#if LI2_LOOP_CACHE8_CONTROL == 1
    if(lc8o.epochs!=10)return;
    lc8o_need(lc8o.arena_controls==12 && pe.domain.work.view.count==5 && pda_ready(0),307);
    lc8o.busy=1;lc8o.saved_view=pe.domain.work.view;
    unsigned node=ptr_node_index(pe.selected_slot);
    uint64_t retired=lta_writer.value.dormant[node].retired_binding;
    lc8o_need(retired && retired!=pe.arena.binding[pe.selected_slot].generation,308);
    for(unsigned kind=0;kind<8;kind++) {
        struct li2_pgd_view *v=&pe.domain.work.view;
        switch(kind) {
        case 0:v->member[0].identity.node^=1;break;
        case 1:v->member[0].identity.binding_generation^=1;break;
        case 2:v->member[0].identity.node_reserved=1;break;
        case 3:v->member[2].identity.node=v->member[1].identity.node;break;
        case 4:v->member[2].identity.binding_generation=v->member[1].identity.binding_generation;break;
        case 5:v->member[0].identity.binding_generation=pe.arena.next_binding+1;break;
        case 6:v->member[0].identity.binding_generation=retired;break;
        default:v->member[0].identity.node=PTR_NODE_COUNT;break;
        }
        int refused=pda_ready(0);pe.domain.work.view=lc8o.saved_view;
        lc8o_need(equal(&pe.domain.work.view,&lc8o.saved_view,sizeof lc8o.saved_view),309);
        ltao_result(12+kind,refused,pda_ready(0));
    }
    lc8o.busy=0;
#endif
}
#if LI2_LOOP_CACHE8_CONTROL != 0
static void ltao_finished(const struct pda_completion *c) {
    ltao_dormant_controls(c);
#if LI2_LOOP_CACHE8_CONTROL == 2
    if(lc8o.epochs!=10)return;
    unsigned node=ltao_inactive_a0();struct li2_ptr_slot *s=&PTR_NODE_AT(node);
    struct ltao_raw *r=&lc8o.wire.arena.raw;uint64_t *h=r->h;
    lc8o_need(!h[0] && !lc8o.busy && lc8o.arena_controls==12,310);
    lc8o.busy=1;h[0]=1;h[1]=node;h[2]=(uintptr_t)&s->publication;h[3]=PAGE;
    h[4]=lta_writer.value.node[node];h[6]=lta_closed_value(node);h[15]=8;
    h[16]=pe.p.serial;h[17]=c->id;h[18]=sg_owner.state.bytes.certificate[node].valid;
    h[23]=lta_writer.value.dormant[node].reusable;
    uint64_t invalidations=lta_writer.value.epoch_invalidations;
    copy(r->epochs[0],lta_writer.value.node,sizeof r->epochs[0]);
    copy(r->before,&s->publication,PAGE);copy(lc8o.arena_page,&s->publication,PAGE);
    lc8o_need(!pe_query(h[2],PAGE,PROT_READ,&r->query[0]),311);
    h[7]=(uint64_t)raw(SYS_mprotect,(long)h[2],PAGE,PROT_READ|PROT_WRITE,0,0,0);
    lc8o_need(!h[7] && !pe_query(h[2],PAGE,PROT_READ|PROT_WRITE,&r->query[1]),312);
    h[8]=lta_closed_value(node);
    ((volatile unsigned char *)&s->publication)[0]^=1;
    copy(r->changed,&s->publication,PAGE);h[9]=lta_closed_value(node);
    copy(&s->publication,lc8o.arena_page,PAGE);
    h[10]=(uint64_t)raw(SYS_mprotect,(long)h[2],PAGE,PROT_READ,0,0,0);
    lc8o_need(!h[10] && !pe_query(h[2],PAGE,PROT_READ,&r->query[2]),313);
    copy(r->restored,&s->publication,PAGE);copy(r->epochs[1],lta_writer.value.node,sizeof r->epochs[1]);
    h[5]=lta_writer.value.node[node];h[11]=lta_closed_value(node);
    h[12]=equal(r->before,r->restored,PAGE);
    h[13]=equal(&lta_writer.value.dormant[node].certificate,
        &sg_owner.state.bytes.certificate[node],sizeof(struct sbc_certificate));
    for(unsigned i=0;i<PTR_NODE_COUNT;i++)if(i!=node && r->epochs[0][i]==r->epochs[1][i])h[19]|=UINT64_C(1)<<i;
    h[20]=3;h[21]=lta_writer.value.epoch_invalidations-invalidations;
    h[22]=lta_writer.value.poisoned;h[24]=lta_writer.value.dormant[node].reusable;
    lc8o_need(h[6]==1 && h[5]==h[4]+1 && !h[8] && !h[9] && !h[11] &&
        h[12]==1 && h[13]==1 && h[19]==((UINT64_C(1)<<PTR_NODE_COUNT)-1-(UINT64_C(1)<<node)) &&
        h[21]==1 && !h[22] && h[23]==1 && !h[24],314);
    lc8o.busy=0;h[25]=1;
#else
    if(lc8o.epochs==14)lc8o_need(lc8o.arena_controls==20 && lc8o.arena_restorations==20,315);
#endif
}
#endif
static void ltao_reentry(uintptr_t pc,int sig,const siginfo_t *si,const ucontext_t *uc) {
#if LI2_LOOP_CACHE8_CONTROL == 2
    struct ltao_wire *w=&lc8o.wire.arena;
    if(!w->raw.h[25])return;
    lc8o_need(pc==UINT64_C(0x410200) && lc8o.epochs==10 && !lc8o.active &&
        !lc8o.busy && !w->reentry.h[0],316);
    le_zero(&lc8o.scratch,sizeof lc8o.scratch);
    lc8o_need(!le_capture(&lc8o.scratch,sig,si,uc),317);
    lc8o_frame(&w->reentry,&lc8o.scratch,si,uc);lc8o_counts(w->reentry_counts);
    /* This is the genuine second DIRECT ticket before its TRACE is closed.
       Copy identity and pure value predicates; never consume the ticket. */
    const struct lprx_branch *b=&pe.rx.branch;
    lc8o_need(!w->pending[0] && b->slot<2 && b->transit.previous_slot<2 &&
        b->cell<LI2_PGD_RECEIPTS,318);
    const struct li2_tf_chain_slot *s=&selected_chain.slots[b->slot];
    const struct li2_tf_chain_slot *p=&selected_chain.slots[b->transit.previous_slot];
    uint64_t *h=w->pending;
    h[0]=1;h[1]=b->phase;h[2]=b->branches;h[3]=b->cell;h[4]=b->id;h[5]=b->serial;
    h[6]=b->slot;h[7]=b->chain_generation;h[8]=b->chain_event;h[9]=b->target;h[10]=b->flags;
    h[11]=lprx_branch_value();h[12]=lprx_armed_value();h[13]=lprx_transit_ancestry();
    h[14]=(uint64_t)selected_chain.active;h[15]=selected_chain.pending;
    h[16]=selected_chain.in_handler;h[17]=selected_chain.event_id;
    h[18]=s->generation;h[19]=s->event_id;h[20]=s->phase;h[21]=s->owner.step.phase;
    h[22]=b->transit.previous_slot;h[23]=b->transit.previous_generation;
    h[24]=b->transit.previous_event;
    h[25]=pe.rx.direct_offers;h[26]=pe.rx.direct_steps;
    h[27]=pe.rx.transit_offers;h[28]=pe.rx.transit_steps;
    h[29]=selected_pending_route;h[30]=selected_step_pending;
    h[31]=p->generation;h[32]=p->event_id;h[33]=p->phase;h[34]=p->owner.step.phase;
    h[35]=p->owner.continuation_complete;h[36]=p->query.complete;h[37]=p->release.complete;
    h[38]=p->owner.actual_post_pc;h[39]=p->owner.actual_post_flags;
    h[40]=s->decoded.pc;h[41]=s->decoded.code;h[42]=s->decoded.available;
    h[43]=b->transit.source.pc;h[44]=s->owner.step.request.original_flags;
    h[45]=pe.rx.transit_declined;h[46]=pe.rx.transit_limit;
#else
    (void)pc;(void)sig;(void)si;(void)uc;
#endif
}
static void ltao_report(unsigned status,unsigned code) {
    uint64_t *h=lc8o.wire.arena.h;
    h[0]=1;h[1]=PTR_NODE_COUNT;h[2]=LI2_PTR_SLOTS;h[3]=LI2_PGD_VERSION;
    h[4]=lc8o.arena_controls;h[5]=lc8o.arena_restorations;
    h[6]=status;h[7]=code;h[8]=lta_writer.value.poisoned;
    h[9]=lta_writer.value.detached;h[10]=lta_writer.value.rebound;
    h[11]=lta_writer.value.rebound_peers;h[12]=lta_writer.value.cold_nodes;
    h[13]=lta_writer.value.evicted;h[14]=lta_writer.value.epoch_invalidations;
    h[15]=lta_writer.value.physical_checks;h[16]=pe.arena.next_binding;
}
