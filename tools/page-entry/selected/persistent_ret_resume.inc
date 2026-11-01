/* Included after the unchanged ordinary pda owner. Every path is opt-in. */
static int prr_exact_range(uintptr_t address,size_t bytes) {
    unsigned found=0;
    if(!bytes || address>UINTPTR_MAX-bytes || protected_count>RANGES)return 0;
    for(size_t i=0;i<protected_count;i++)
        found+=protected[i].first==address && protected[i].end==address+bytes;
    return found==1;
}
static int prr_storage(void) {
    return prr.initialized==1 && prr.registered==1 && prr.allocation &&
        !(prr.allocation&(PAGE-1)) && prr.allocation<(UINT64_C(1)<<47)-2U*PAGE &&
        prr.code==prr.allocation+256 && prr.cell==prr.allocation+PAGE+256 &&
        prr_exact_range((uintptr_t)&prr,sizeof prr) &&
        prr_exact_range(prr.allocation,PAGE) && prr_exact_range(prr.allocation+PAGE,PAGE);
}
static int prr_bytes(uint64_t target) {
    if(!prr_storage())return 0;
    const volatile unsigned char *code=(const void *)prr.allocation;
    const volatile unsigned char *cell=(const void *)(prr.allocation+PAGE);
    for(size_t i=0;i<PAGE;i++) {
        if(code[i]!=(i==256?0xc3:0xcc))return 0;
        unsigned char wanted=i>=256 && i<264?(unsigned char)(target>>(8U*(i-256))):0;
        if(cell[i]!=wanted)return 0;
    }
    return 1;
}
static int prr_queries(struct li2_private_code_query q[2]) {
    if(!prr_storage())return PE_PUBLICATION;
    int e=pe_query(prr.allocation,PAGE,PROT_READ|PROT_EXEC,&q[0]);if(e)return e;
    return pe_query(prr.allocation+PAGE,PAGE,PROT_READ,&q[1]);
}
static void prr_initialize(void) {
    pe_need(!prr.initialized && !prr.registered && !prr.allocation && !prr_pending && !prr_busy &&
        selected_run_protect_contains(0,(uintptr_t)&prr,sizeof prr)==1 &&
        protected_count<=RANGES-3U*LI2_PTR_SLOTS-3U,PE_STATE,172);
    pe_need(!selected_run_protect_add(0,(uintptr_t)&prr,sizeof prr),PE_STATE,173);
    long value=raw(SYS_mmap,0,2U*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    pe_need(value>0 && !((uintptr_t)value&(PAGE-1)) &&
        (uintptr_t)value<(UINT64_C(1)<<47)-2U*PAGE,PE_PUBLICATION,value);
    prr.allocation=(uintptr_t)value;prr.code=prr.allocation+256;prr.cell=prr.allocation+PAGE+256;
    pe_need(!selected_run_protect_add(0,prr.allocation,PAGE) &&
        !selected_run_protect_add(0,prr.allocation+PAGE,PAGE),PE_STATE,174);
    prr.registered=1;
    pe_need(!pe_query(prr.allocation,2U*PAGE,PROT_READ|PROT_WRITE,&prr.initial),PE_PUBLICATION,171);
    unsigned char *code=(void *)prr.allocation;for(size_t i=0;i<PAGE;i++)code[i]=0xcc;
    code[256]=0xc3;le_zero((void *)(prr.allocation+PAGE),PAGE);
    pe_need(!pe_permission(prr.allocation,PAGE,PROT_READ|PROT_EXEC,&prr.initial_code) &&
        !pe_permission(prr.allocation+PAGE,PAGE,PROT_READ,&prr.initial_cell),PE_PUBLICATION,172);
    prr.initialized=1;pe_need(prr_bytes(0),PE_PUBLICATION,173);
}
static void prr_reset(void) {
    pe_need(!prr_pending && !prr_busy &&
        (prr.run.phase==PRR_IDLE || (prr.run.phase==PRR_CONSUMED && prr.run.consumed==1 &&
         prr.run.serial==prr.last_consumed)),PE_STATE,175);
    le_zero(&prr.run,sizeof prr.run);
}
static int pda_ret_exit_value(const struct pda_completion *c) {
    const struct pda_ret_exit *e=&c->ret_exit;
    if(!e->complete)return pda_zero(e,sizeof *e);
    if(e->complete!=1 || e->member>=c->count || e->member>=LI2_PGD_MEMBERS ||
       !e->heads || e->heads>LI2_PG_HEADS || e->head>=e->heads)return 0;
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
    if(c->direct_exit.complete)return 0;
#endif
    const struct pda_member_completion *m=&c->member[e->member];
    const struct li2_pg_source_key *s=&m->source;const struct li2_pe_head *h=&e->row;
    const struct li2_span_decoded *d=&e->original;const struct li2_rd_plan *p=&e->plan;
    const struct li2_rd_recovered *r=&e->recovered;
    const struct li2_rd_window *window=&e->window;
    const struct li2_maps_call_stack *stack=&e->stack;
    uintptr_t pages[2]={s->page[0].identity.address,s->page[1].identity.address};
    struct li2_rd_binding binding;struct li2_rd_descriptor descriptor;
    struct li2_span_decoded expected={.decoded=d->decoded,.version=1,.refusal=LI2_REGION_UNSUPPORTED};
    if(pages[0]>=pages[1] || (pages[0]&(PAGE-1)) || (pages[1]&(PAGE-1)) ||
       pages[0]<PAGE || pages[1]>(UINT64_C(1)<<47)-PAGE ||
       h->kind!=LI2_PG_RET || h->source_page>=2 || h->source_offset>=PAGE || h->source_length!=1 ||
       h->successor_count || h->successors[0] || h->successors[1] ||
       !equal(d,&expected,sizeof *d) || d->decoded.pc!=pages[h->source_page]+h->source_offset ||
       (e->head==0?d->decoded.pc!=s->entry:d->decoded.pc==s->entry) ||
       !d->decoded.available || d->decoded.available>15 ||
       li2_rd_describe(d->decoded.pc,d->decoded.bytes,d->decoded.available,&descriptor) ||
       !equal(&descriptor,&p->original,sizeof descriptor) ||
       !equal(&descriptor.decoded,&d->decoded,sizeof d->decoded) ||
       li2_pg_ret_binding(pages,&m->identity.layout,m->header.table,e->heads,e->head,&binding) ||
       !equal(&binding,&p->binding,sizeof binding) || p->spill!=m->identity.layout.spill ||
       p->generated!=m->identity.layout.generated[e->head/64]+(e->head%64)*LI2_PE_SLOT_BYTES ||
       h->generated_length!=p->record.image_bytes || e->landing!=binding.loaded_miss || li2_rd_validate(p) ||
       r->complete!=1 || r->target_valid!=1 || r->reserved || r->phase!=LI2_RD_LOADED_MISS ||
       r->original_pc!=d->decoded.pc || r->original_rsp!=r->gpr[4] ||
       r->original_rsp<PAGE || r->original_rsp>=(UINT64_C(1)<<47)-8 ||
       window->version!=LI2_RD_VERSION || window->owner!=(uintptr_t)&pe || window->serial!=c->serial ||
       window->first<PAGE || window->first>UINT64_MAX-512 || window->end!=window->first+512 ||
       window->end>=(UINT64_C(1)<<47)-8 || window->reserved[0] || window->reserved[1] || window->reserved[2] ||
       r->original_rsp<window->first || r->original_rsp>window->end ||
       stack->first!=window->first || stack->end!=window->end+8 ||
       stack->origin_first<PAGE || stack->origin_first>stack->first || stack->origin_end<stack->end ||
       stack->origin_end>=(UINT64_C(1)<<47) || stack->anchor<stack->origin_first || stack->anchor>=stack->origin_end ||
       !stack->origin_acquisition || stack->observation.acquisition_id<stack->origin_acquisition ||
       stack->observation.kind>LI2_MAPS_PROJECTED || stack->observation.io_performed>1 ||
       (r->flags&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF)return 0;
    for(unsigned i=0;i<d->decoded.available;i++) {
        unsigned found=0;uintptr_t at=d->decoded.pc+i;
        if(at<d->decoded.pc)return 0;
        for(unsigned j=0;j<2;j++)if(at>=pages[j] && at-pages[j]<PAGE) {
            if(d->decoded.bytes[i]!=s->page[j].bytes[at-pages[j]])return 0;
            ++found;
        }
        if(found!=1)return 0;
    }
    return 1;
}
static int prr_loaded_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct pda_work *w=&pe.domain.work;const greg_t *g=pe.after.frame.greg;
    uintptr_t pc=(uintptr_t)g[REG_RIP];unsigned member=LI2_PGD_MEMBERS,head=LI2_PG_HEADS;
    for(unsigned i=0;i<w->view.count;i++) {
        unsigned h=LI2_PG_HEADS;int found=li2_pg_compact_ret_loaded_miss(w->view.member[i].plan,pc,&h);
        if(found<0)return PE_PUBLICATION;
        if(found) {if(member!=LI2_PGD_MEMBERS)return PE_PUBLICATION;member=i;head=h;}
    }
    if(member==LI2_PGD_MEMBERS)return 0;
    if(prr_pending || prr_busy || prr.run.phase!=PRR_IDLE || !prr_storage() ||
       pe.p.serial<=prr.last_consumed ||
       sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 || (uintptr_t)si->si_addr!=pc || (uintptr_t)g[REG_CR2]!=pc ||
       ((uint64_t)g[REG_EFL]&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF ||
       ((uint64_t)g[REG_CSGSFS]&65535)!=0x33 || pe.after.frame.mask!=pe.session.application_mask ||
       !le_unchanged(&pe.after,si,uc) || !pda_ready(1) || !pcw_equal())return PE_EVENT;
    prr_busy=1;prr.run.serial=pe.p.serial;
    const struct li2_pgd_member *m=&w->view.member[member];struct pda_ret_exit *e=&prr.run.loaded;
    if(head>=m->plan->heads || li2_pg_compact_ret(m->plan,head/64,head%64,&e->plan))return PE_PLAN;
    uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=(uint64_t)g[pe_greg[i]];
    if(li2_rd_recover_loaded_miss(&e->plan,pc,raw,(uint64_t)g[REG_EFL],
       (const uint64_t *)m->identity.layout.spill,&e->recovered))return PE_FRAME;
    if(e->recovered.original_rsp<pcw.expected.first || e->recovered.original_rsp>pcw.expected.end ||
       e->recovered.original_rsp!=raw[4] || !equal(e->recovered.gpr,raw,sizeof raw) ||
       e->recovered.flags!=(uint64_t)g[REG_EFL])return PE_FRAME;
    e->member=member;e->heads=m->plan->heads;e->head=head;e->landing=pc;
    e->row=m->plan->head[head];e->original=m->plan->original[head];
    _Static_assert(sizeof e->window==sizeof pcw.expected,"same complete sealed window value");
    copy(&e->window,&pcw.expected,sizeof e->window);e->stack=pcw.bound_stack;e->complete=1;
    prr.run.phase=PRR_LOADED;pe.recovery_complete=1;
#ifdef LI2_PERSISTENT_RET_OWNER_CAPTURE
    prto_loaded();
#endif
    return 1;
}
static int prr_drain(const struct li2_pg_token *t) {
    struct pda_work *w=&pe.domain.work;
    if(!pe_token(t) || !pe_active || !pe_busy || pe.p.phase!=LI2_PG_RECOVERING ||
       pe.exit_seen || !pe.recovery_complete || w->exit_member!=LI2_PGD_MEMBERS ||
       prr_pending || !prr_busy || prr.run.phase!=PRR_LOADED || prr.run.serial!=t->serial ||
       prr.run.loaded.complete!=1 || prr.run.loaded.member>=w->view.count ||
       !pda_ready(1) || !pcw_equal())return PE_STATE;
    pe.p.phase=LI2_PG_CLOSING;pe.p.closed_pages=0;
    /* First close EVERY bank. No reset/ref release can precede the last NX. */
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        struct li2_pg_generation *g=&pe.retained[v->slot].generation;unsigned pages=0;
        int e=pg_permissions(&g->layout,PROT_READ,g->close,&pages);if(e)return e;
        if(pages!=17 || !pg_closed(&g->layout,g->close))return PE_PUBLICATION;
        pe.retained[v->slot].banks[v->bank].prot=PROT_READ;pe.p.closed_pages+=pages;
    }
    if(pe.p.closed_pages!=17U*w->view.count)return PE_PUBLICATION;
    for(unsigned i=0;i<w->view.count;i++) {
        const struct li2_pgd_ref *v=&w->view.member[i].identity;
        pda_select(v->slot,v->bank);int e=pg_link_data(2);if(e)return e;
        if(pe_bytes() || pg_proof_query(v->proof,PROT_READ,&w->proof_exit[i]))return PE_PUBLICATION;
    }
    pda_select(w->primary,w->primary_bank);pe.proof_exit=w->proof_exit[0];
    if(!pda_directory_equal() || pe_query(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&w->directory_closed))return PE_PUBLICATION;
    pe.p.phase=LI2_PG_RELEASING;
    pe.release_result=li2_pgd_source_release(t);if(pe.release_result)return pe.release_result;
    pe.p.anchor_released=1;pe.final_fetch=*li2_lifecycle_fetch_progress();
    if(pe.final_fetch.held || pe.final_fetch.complete!=1 || pe.final_fetch.first_error ||
       pe.final_fetch.sequence!=pe.ref.sequence)return PE_RELEASE;
    if(li2_pg_rseq_close(t,&pe.after.uc))return PE_RSEQ;
    for(unsigned i=0;i<w->view.count;i++)pe.retained[w->view.member[i].identity.slot].generation.domain_refs=0;
    pe.p.registration_rechecked=1;pe.p.phase=LI2_PG_CLOSED;return 0;
}
static void prr_complete(void) {
    struct pda_work *w=&pe.domain.work;
    pe_need(w->bound && !w->completion && w->receipt<LI2_PGD_RECEIPTS &&
        pe.p.phase==LI2_PG_CLOSED && pe.domain.next_id!=UINT64_MAX,PE_RELEASE,85);
    struct pda_completion *c=&pe.domain.completion[w->receipt];
    pe_need((pda_zero(c,sizeof *c) && !pe.domain.claimed[w->receipt]) ||
        (pda_receipt(c) && pe.domain.claimed[w->receipt]==(1U<<c->count)-1U),PE_RELEASE,86);
    le_zero(c,sizeof *c);c->id=++pe.domain.next_id;c->serial=pe.p.serial;c->count=w->view.count;
    c->source=*li2_pg_source_progress();c->domain_source=*li2_pgd_source_progress();
    c->rseq=*li2_pg_rseq_progress();c->fetch=pe.final_fetch;c->directory_closed=w->directory_closed;
    for(unsigned i=0;i<c->count;i++) {
        const struct li2_pgd_member *m=&w->view.member[i];struct li2_ptr_slot *s=&pe.retained[m->identity.slot];
        pe_need(!s->claim.valid && !s->claim.id && !s->permit.valid,PE_RELEASE,87);
        c->member[i]=(struct pda_member_completion){.identity=m->identity,.header=s->publication.header,
            .source=s->publication.source,.generation=s->generation,.proof=w->proof_exit[i]};
    }
    pe_need(!pe.exit_seen && w->exit_member==LI2_PGD_MEMBERS &&
        prr.run.phase==PRR_LOADED && prr.run.serial==c->serial &&
        prr.run.loaded.complete==1 && prr.run.loaded.member<c->count,PE_RELEASE,170);
    c->ret_exit=prr.run.loaded;

    c->complete=1;pe.domain.claimed[w->receipt]=0;
    pe_need(pda_receipt(c),PE_RELEASE,88);
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
    prr.run.completion_id=c->id;prr.run.phase=PRR_DRAINED;
#ifdef LI2_PERSISTENT_RET_OWNER_CAPTURE
    prto_drained();
#endif
}
static int prr_closed(void) {
    const struct pda_work *w=&pe.domain.work;
    if(!prr_storage() || !prr.run.serial || prr.run.serial<=prr.last_consumed ||
       prr.run.serial!=pe.token.serial || pe.token.owner!=&pe ||
       pe.p.serial!=prr.run.serial || pe.p.phase!=LI2_PG_CLOSED || !pe.p.completion_permit ||
       !w->bound || w->completion!=1 || w->receipt>=LI2_PGD_RECEIPTS ||
       !pe_identity() || !pe_registry() || !pcw_equal())return 0;
    const struct pda_completion *c=&pe.domain.completion[w->receipt];
    if(c->id!=prr.run.completion_id || c->serial!=prr.run.serial || !pda_receipt(c) ||
       !equal(&c->ret_exit,&prr.run.loaded,sizeof c->ret_exit) || pe.domain.claimed[w->receipt])return 0;
    for(unsigned i=0;i<c->count;i++) {
        const struct li2_ptr_slot *s=&pe.retained[c->member[i].identity.slot];
        if(s->claim.id!=c->id || s->claim.cell!=w->receipt || s->claim.member!=i ||
           !pda_permitted(c->member[i].identity.slot))return 0;
    }
    return 1;
}
static int prr_target_private(uint64_t target) {
    if(protected_count>RANGES)return 1;
    for(size_t i=0;i<protected_count;i++)if(target>=protected[i].first && target<protected[i].end) {
#ifdef LI2_INITIAL_CODE_PROTECTION
        /* Initial guest code is protected against writes, not private runtime
           storage. Authenticate both its exact range kind and executable
           image extent; any overlapping strict range still refuses. */
        if(initial_code_range[i]==1 &&
           (image_code(&original_main,target) || image_code(&original_interpreter,target)))continue;
#endif
        return 1;
    }
    return 0;
}
static void prr_arm(siginfo_t *si,ucontext_t *uc) {
    const struct li2_rd_recovered *r=&prr.run.loaded.recovered;
    pe_need(prr_busy && !prr_pending && prr.run.phase==PRR_DRAINED &&
        pe_active && pe_busy && !pe.resuming && prr_closed() && le_quiet(0) &&
        le_unchanged(&pe.after,si,uc) && !prr_target_private(r->target),PE_STATE,176);
    pe_need(!prr_queries(prr.run.before) && prr_bytes(prr.cell_value),PE_PUBLICATION,174);
    /* No owner can use the previous operand now. Code is never writable again. */
    pe_need(!pe_permission(prr.allocation+PAGE,PAGE,PROT_READ|PROT_WRITE,&prr.run.write),PE_PUBLICATION,175);
    le_zero((void *)(prr.allocation+PAGE),PAGE);
    *(volatile uint64_t *)prr.cell=r->target;prr.cell_value=r->target;prr.cell_serial=prr.run.serial;
    pe_need(!pe_permission(prr.allocation+PAGE,PAGE,PROT_READ,&prr.run.seal) &&
        prr_bytes(r->target) && le_unchanged(&pe.after,si,uc) && prr_closed(),PE_PUBLICATION,176);
    pe.resuming=1;prr.run.phase=PRR_ARMED;prr_pending=1;
    selected_step_pending=1;selected_pending_route=SELECTED_RET_RESUME;
#ifdef LI2_PERSISTENT_RET_OWNER_CAPTURE
    prto_armed();
#endif
    __asm__ volatile("":::"memory");
    for(unsigned i=0;i<16;i++)uc->uc_mcontext.gregs[pe_greg[i]]=(greg_t)r->gpr[i];
    uc->uc_mcontext.gregs[REG_RSP]=(greg_t)prr.cell;
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)prr.code;
    uc->uc_mcontext.gregs[REG_EFL]=(greg_t)((r->flags&~SELECTED_RF)|SELECTED_TF);
    pe_active=0;__asm__ volatile("":::"memory");pe_busy=0;prr_busy=0;
}
static void prr_loaded_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    pe_need(pe_active && pe_busy && prr_busy && !prr_pending && !pe.exit_seen &&
        pe.p.phase==LI2_PG_RECOVERING && prr.run.phase==PRR_LOADED &&
        selected_pending_route==SELECTED_PERSISTENT_EPOCH && selected_step_pending==1 &&
        pe.after.sig==sig && le_unchanged(&pe.after,si,uc),PE_STATE,177);
    pe_tls(&pe.after);pe_need(pe.before.fs==pe.after.fs && pe.before.gs==pe.after.gs,PE_TLS,170);
    pe_preserved();pe_need(pe_identity() && pe_ready() && le_quiet(&pe.ref) &&
        !li2_pg_rseq_live(&pe.token,uc,&pe.live[2]),PE_RSEQ,170);
    pe_need(!prr_drain(&pe.token) && le_unchanged(&pe.after,si,uc) &&
        le_quiet(0) && pe_registry(),PE_RELEASE,171);
    prr_complete();prr_arm(si,uc);
}
static int prr_frame_preserved(unsigned event) {
    const struct le_frame *a=&pe.after,*b=&prr.run.after;
    const struct li2_rd_recovered *r=&prr.run.loaded.recovered;
    const greg_t *g=b->frame.greg;
    if(event!=1 && event!=2)return 0;
    for(unsigned i=0;i<16;i++)if(i!=4 && (uint64_t)g[pe_greg[i]]!=r->gpr[i])return 0;
    if((uintptr_t)g[REG_RSP]!=(event==1?prr.cell+8:prr.cell) ||
       (uint64_t)g[REG_EFL]!=((r->flags&~SELECTED_RF)|SELECTED_TF|(event==2?SELECTED_RF:0)) ||
       g[REG_CSGSFS]!=a->frame.greg[REG_CSGSFS] || g[REG_OLDMASK]!=a->frame.greg[REG_OLDMASK] ||
       b->frame.mask!=a->frame.mask ||
       b->frame.mask!=pe.session.application_mask || b->frame.fp_bytes!=a->frame.fp_bytes ||
       !equal(b->frame.fp,a->frame.fp,LI2_STEP_FP_BYTES) ||
       b->fs!=a->fs || b->gs!=a->gs || b->tls_complete!=1 || a->tls_complete!=1)return 0;
    /* CR2 is retained literally in both frames. Intervening handler demand
       faults may change it; a TRACE or #GP supplies no cross-event CR2 equality.
       Keep every non-event ucontext byte. The 120-byte glibc mask tail aliases
       actual event siginfo; it is reconstructed, never ignored as padding. */
    const size_t info=offsetof(ucontext_t,uc_sigmask)+sizeof b->frame.mask;
    if(info+sizeof b->si>sizeof b->uc ||
       !equal((const unsigned char *)&a->uc+info,&a->si,sizeof a->si) ||
       !equal((const unsigned char *)&b->uc+info,&b->si,sizeof b->si))return 0;
    ucontext_t expected=a->uc;
    copy(expected.uc_mcontext.gregs,g,sizeof expected.uc_mcontext.gregs);
    expected.uc_mcontext.fpregs=b->uc.uc_mcontext.fpregs;
    copy((unsigned char *)&expected+info,&b->si,sizeof b->si);
    return equal(&expected,&b->uc,sizeof expected);
}
static _Noreturn void prr_unexpected(int sig,siginfo_t *si,ucontext_t *uc) {
    /* Preserve the actual rejected/nested frame under the old terminal guard. */
    if(pe_terminal_ingress){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_terminal_ingress=1;__asm__ volatile("":::"memory");
    if(!pe.unexpected_frame.started)(void)le_capture(&pe.unexpected_frame,sig,si,uc);
    selected_persistent_abort(PE_REENTRY,170);
}
static void selected_ret_resume_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!prr_pending && !prr_busy && selected_pending_route!=SELECTED_RET_RESUME)return;
    if(handling || prr_busy || prr_pending!=1 || prr.run.phase!=PRR_ARMED ||
       selected_pending_route!=SELECTED_RET_RESUME || selected_step_pending!=1 ||
       pe_active || pe_busy || !pe.resuming || !si || !uc ||
       prr.cell_value!=prr.run.loaded.recovered.target || prr.cell_serial!=prr.run.serial || !prr_closed())
        prr_unexpected(sig,si,uc);
    prr_busy=1;__asm__ volatile("":::"memory");
    pe_need(!le_capture(&prr.run.after,sig,si,uc),PE_FRAME,170);pe_tls(&prr.run.after);
    const greg_t *g=prr.run.after.frame.greg;unsigned event=0;
    const struct li2_rd_recovered *r=&prr.run.loaded.recovered;
    if(sig==SIGTRAP && si->si_signo==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
       g[REG_TRAPNO]==1 && !g[REG_ERR] && (uintptr_t)g[REG_RIP]==r->target &&
       (uintptr_t)si->si_addr==r->target)event=1;
    if(sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SI_KERNEL && !si->si_errno &&
       g[REG_TRAPNO]==13 && !g[REG_ERR] && (uintptr_t)g[REG_RIP]==prr.code && !si->si_addr)event=2;
    pe_need(event && prr_frame_preserved(event) && !prr_queries(prr.run.observed) &&
        prr_bytes(r->target) && !prr_target_private(r->target) &&
        !li2_maps_call_stack_query(pcw.seed.first,520,&prr.run.stack) &&
        prr.run.stack.anchor==pcw.bound_stack.anchor &&
        prr.run.stack.origin_first==pcw.bound_stack.origin_first &&
        prr.run.stack.origin_end==pcw.bound_stack.origin_end &&
        prr.run.stack.origin_acquisition==pcw.bound_stack.origin_acquisition &&
        prr.run.stack.first==pcw.bound_stack.first && prr.run.stack.end==pcw.bound_stack.end &&
        prr_closed(),PE_FRAME,171);
    prr.run.event=event;prr.run.logical=*r;
    /* Remove only the TF injected by this owner; preserve actual fault RF. */
    prr.run.logical.flags=(uint64_t)g[REG_EFL]&~SELECTED_TF;
    if(event==1) {
        prr.run.logical.gpr[4]=r->original_rsp+8;prr.run.logical.phase=LI2_RD_COMMITTED;
    }
    prr.run.phase=PRR_OBSERVED;
#ifdef LI2_PERSISTENT_RET_OWNER_CAPTURE
    prto_observed();
#endif
    if(event==2) {
        /* Keep the actual private-C3 #GP frame and its separate original-PC/SP
           mapping. The existing runtime policy terminates guest faults; this
           is not ordinary RET replay or synthetic signal delivery. */
        prr.run.terminal=1;prr.run.consumed=1;prr.last_consumed=prr.run.serial;
        prr.run.phase=PRR_CONSUMED;prr_pending=0;pe.resuming=0;
        selected_persistent_abort(PE_EVENT,173);
    }
}
static void selected_ret_resume_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    const struct li2_rd_recovered *r=&prr.run.loaded.recovered;
    pe_need(handling && prr_pending==1 && prr_busy && prr.run.phase==PRR_OBSERVED &&
        prr.run.event==1 && !prr.run.terminal && !prr.run.consumed &&
        selected_pending_route==SELECTED_RET_RESUME && selected_step_pending==1 &&
        !pe_busy && !pe_active && pe.resuming && sig==SIGTRAP &&
        le_unchanged(&prr.run.after,si,uc) && prr_closed() && le_quiet(0) && prr_bytes(r->target),PE_STATE,178);
    /* Consume before the only logical stack commit. The target has executed
       no instruction. A later real target fetch follows the ordinary route. */
    prr.run.consumed=1;prr.last_consumed=prr.run.serial;prr.run.phase=PRR_CONSUMED;
    prr_pending=0;__asm__ volatile("":::"memory");
    uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(r->original_rsp+8);
    uc->uc_mcontext.gregs[REG_EFL]=(greg_t)(r->flags&~SELECTED_RF);
    selected_logical_flags=r->flags&~SELECTED_RF;selected_flags_known=1;
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;pe.resuming=0;
    __asm__ volatile("":::"memory");prr_busy=0;
#ifdef LI2_PERSISTENT_RET_OWNER_CAPTURE
    prto_consumed(uc);
#endif
    /* Return through the existing handler epilogue, including maps/profile
       phase end. Never call selected_fetch with a fabricated NX event. */
}
