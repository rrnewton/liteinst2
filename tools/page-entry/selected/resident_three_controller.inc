/* The first resident execution is deliberately a single image-bound root and
   exactly three discovered direct-branch regions. No supplied graph, address
   list, larger old pgd view, or scripted completion grants execution. */
static _Noreturn void r3_fail(unsigned code,long detail) {
    /* Close actual code before terminal reporting, including a partial open.
       A failure never releases a successful completion or makes a pin free. */
    (void)r3_permission(PROT_READ|PROT_WRITE);
    if(!r3.first_error){r3.first_error=code;r3.first_detail=detail;}
    if(r3.active && r3.unexpected<UINT64_MAX)++r3.unexpected;
    for(unsigned i=0;i<LI2_R3_CERTIFICATES;i++)if(r3.certificate[i].identity.code_live)
        (void)raw(SYS_mprotect,r3.certificate[i].identity.code,R3_CODE_BYTES,PROT_READ,0,0,0);
    (void)raw(SYS_membarrier,32,0,0,0,0,0);
    r3.phase=LI2_R3_FAILED;(void)r3_permission(PROT_READ);
    selected_persistent_abort(code,detail);
}
static void r3_need(int condition,unsigned code,long detail) {if(!condition)r3_fail(code,detail);}
static void r3_tls(struct le_frame *frame) {
    frame->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&frame->fs,0,0,0,0);
    frame->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&frame->gs,0,0,0,0);
    r3_need(!frame->fs_result && !frame->gs_result,R3_FRAME,2);
    frame->tls_complete=1;
}
static int r3_source_pair(uintptr_t root,struct li2_pg_source_key *key) {
    uintptr_t first=root&~(PAGE-1);
    if(!key || first<PAGE || first>=(UINT64_C(1)<<47)-2U*PAGE || root-first>PAGE-15)
        return R3_SOURCE;
    unsigned found[2]={0};key->entry=root;
    for(unsigned i=0;i<r3.source_pages;i++) {
        if(li2_rsl_page_at(&r3.source,i,&r3_work.page))return R3_SOURCE;
        for(unsigned j=0;j<2;j++)if(r3_work.page.identity.address==first+j*PAGE) {
            if(found[j]++)return R3_SOURCE;
            key->page[j]=r3_work.page;
        }
    }
    return found[0]==1 && found[1]==1?0:R3_SOURCE;
}
static int r3_table(unsigned index) {
    size_t n=0;
    if(!r3_registry() || index>=r3.count)return R3_SOURCE;
    for(unsigned i=0;i<r3.registry_count;i++) {
        if(n==LI2_MG_RANGES)return R3_SOURCE;
        r3_work.range[n++]=(struct li2_mg_range){r3.registry[i].first,r3.registry[i].end};
    }
    for(unsigned i=0;i<r3.source_pages;i++) {
        if(n==LI2_MG_RANGES || li2_rsl_page_at(&r3.source,i,&r3_work.page))return R3_SOURCE;
        uintptr_t p=r3_work.page.identity.address;
        if(!p || p>UINTPTR_MAX-PAGE)return R3_SOURCE;
        r3_work.range[n++]=(struct li2_mg_range){p,p+PAGE};
    }
    const struct li2_r3_rseq_progress *r=li2_r3_rseq_progress();
    if(!r->active || r->registered>1 || !r->seed_complete)return R3_RSEQ;
    if(r->registered) {
        if(n==LI2_MG_RANGES || !r->address || r->address>UINTPTR_MAX-16)return R3_RSEQ;
        r3_work.range[n++]=(struct li2_mg_range){r->address+8,r->address+16};
    }
    uintptr_t at=r3.certificate[index].proof+offsetof(struct r3_payload,plan.table);
    return li2_mg_table_build(r3_work.range,n,at,&r3_work.table)?R3_SOURCE:0;
}
static int r3_root_known(uintptr_t root) {
    for(unsigned i=0;i<r3.count;i++)if(r3.certificate[i].root==root)return 1;
    return 0;
}
static int r3_discover(const struct li2_pg_compact *p) {
    for(unsigned i=0;i<p->heads;i++)if(p->head[i].kind==LI2_PG_DIRECT) {
        const struct li2_dd_descriptor *d=&p->instruction[i].direct;
        if(li2_pg_compact_direct(p,i/LI2_PE_HEADS,i%LI2_PE_HEADS,&r3_work.direct) ||
           li2_dd_validate(&r3_work.direct) ||
           !equal(d,&r3_work.direct.original,sizeof *d))return R3_SOURCE;
        for(unsigned arm=0;arm<(d->flow==LI2_REGION_JCC?2U:1U);arm++) {
            uintptr_t target=d->target[arm];
            if(!(d->external_mask&(1U<<arm)) || r3_root_known(target))continue;
            /* Only actual predeclared held-source pages may become another
               region. An absent page remains a real before-effect frontier. */
            if(!li2_rsl_resident_advisory(target))continue;
            uintptr_t page=target&~(PAGE-1);int overlaps=0;
            for(unsigned j=0;j<r3.count;j++) {
                uintptr_t old=r3.certificate[j].root&~(PAGE-1);
                overlaps|=page<old+2U*PAGE && old<page+2U*PAGE;
            }
            if(overlaps)continue;
            if(r3.count==LI2_R3_CERTIFICATES)return R3_SOURCE;
            r3.certificate[r3.count++].root=target;
        }
    }
    return 0;
}
static int r3_plans(const ucontext_t *uc) {
#ifdef LI2_RESIDENT_THREE_CAPTURE
    r3o_source_before_bind();
#endif
    if(r3.phase!=LI2_R3_HELD || !r3.busy || r3.active || r3.consumed ||
       !r3_registry() || li2_rsl_resident_bind(&r3.token) ||
       li2_rsl_resident_snapshot(&r3.token,&r3.source,&r3.source_pages) ||
       !r3.source_pages || r3.source_pages>LI2_RSL_PAGES)return R3_SOURCE;
    r3.phase=LI2_R3_PLANNING;
    if(!r3.publications) {
        r3.count=1;r3.certificate[0].root=r3.root;
        for(unsigned i=0;i<r3.count;i++) {
            struct r3_certificate *c=&r3.certificate[i];
            if(c->planned || c->installed || c->active_refs ||
               li2_pg_placement(c->root,&c->layout)!=1 || r3_source_pair(c->root,&c->mirror.source) ||
               r3_table(i))return R3_SOURCE;
            uintptr_t pages[2];
            for(unsigned j=0;j<2;j++) {
                pages[j]=c->mirror.source.page[j].identity.address;
                copy(c->mirror.plan.source[j],c->mirror.source.page[j].bytes,PAGE);
            }
            if(li2_pg_plan_pages(pages,c->mirror.plan.source,c->root,&c->layout,&r3_work.table,
                    &r3_work.cold,&r3_work.miss) || r3_work.cold.ready!=1 || r3_work.cold.result ||
               r3_work.miss.version!=LI2_PG_VERSION || r3_work.miss.status || r3_work.miss.reason ||
               r3_work.miss.site || r3_work.miss.pc || r3_work.miss.detail ||
               li2_pg_compact_build(&r3_work.cold,&r3_work.rebuild,&c->mirror.plan) ||
               li2_pg_compact_validate(&c->mirror.plan,&r3_work.rebuild,&r3_work.compact_rebuild))
                return R3_SOURCE;
            c->planned=1;++r3.planned;
            if(li2_r3_rseq_cold(&r3.token,i,uc) || li2_rsl_resident_plan(&r3.token,i) ||
               r3_discover(&c->mirror.plan))return R3_SOURCE;
        }
    } else if(r3.count!=LI2_R3_CERTIFICATES || r3.planned!=LI2_R3_CERTIFICATES ||
              r3.publications!=LI2_R3_CERTIFICATES || !r3_all_nx())return R3_PUBLICATION;
    if(r3.count!=LI2_R3_CERTIFICATES || r3.planned!=LI2_R3_CERTIFICATES)return R3_SOURCE;
    r3.gpr_written=0;r3.flags_written=0;
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];const struct li2_pg_compact *p=&c->mirror.plan;
        if(!p->heads || p->heads>LI2_PE_HEADS || p->links || p->stores || !p->exits ||
           p->exits>LI2_PG_BOUNDARIES || li2_rsl_resident_plan(&r3.token,i) ||
           li2_pg_compact_validate(p,&r3_work.rebuild,&r3_work.compact_rebuild))return R3_SOURCE;
        for(unsigned j=0;j<p->heads;j++) {
            if(p->head[j].kind!=LI2_PE_NONE && p->head[j].kind!=LI2_PG_DIRECT)return R3_SOURCE;
            const struct li2_span_decoded *d=&p->original[j];
            r3.gpr_written|=d->gpr_write;
            r3.flags_written|=d->flags_written|d->flags_set|d->flags_cleared|d->flags_undefined;
        }
    }
    return (r3.gpr_written&~UINT64_C(0xffff)) || (r3.gpr_written&(UINT64_C(1)<<4)) ||
        (r3.flags_written&~UINT64_C(0x8d5))?R3_SOURCE:0;
}
static int r3_current(const ucontext_t *uc) {
    if(!r3_registry() || !r3_identity() || !r3_token(&r3.token) ||
       li2_rsl_resident_validate(&r3.token))return R3_SOURCE;
    for(unsigned i=0;i<r3.count;i++) {
        le_zero(&r3.live[i],sizeof r3.live[i]);
        if(li2_rsl_resident_plan(&r3.token,i) ||
           li2_r3_rseq_live(&r3.token,uc,&r3.live[i]))return R3_RSEQ;
        if(r3.certificate[i].installed && r3_bytes(i))return R3_PUBLICATION;
    }
    return 0;
}
static int r3_open(void) {
    if(r3.phase!=LI2_R3_BOUND || !r3.busy || r3.active || !r3.consumed ||
       r3.count!=LI2_R3_CERTIFICATES || !r3_all_nx())return R3_STATE;
    r3.phase=LI2_R3_OPENING;
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];
        if(c->active_refs || !c->installed || !c->closed)return R3_STATE;
        c->active_refs=1;c->closed=0;
    }
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];
        if(raw(SYS_mprotect,c->identity.code,R3_CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0))
            return R3_PUBLICATION;
    }
    if(raw(SYS_membarrier,32,0,0,0,0,0))return R3_PUBLICATION;
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];
        le_zero(c->opened,sizeof c->opened);
        struct li2_sealed_code_query proof[2]={0};
        if(r3_code_query(i,PROT_READ|PROT_EXEC,c->opened) || r3_proof_query(i,proof) ||
           r3_data_query(i) || r3_bytes(i))return R3_PUBLICATION;
    }
    return r3_directory_query()?0:R3_PUBLICATION;
}
static int r3_preserved(void) {
    const greg_t *a=r3.before.frame.greg,*b=r3.after.frame.greg;
    for(unsigned i=0;i<16;i++)if(!(r3.gpr_written&(UINT64_C(1)<<i)) &&
        a[pe_greg[i]]!=b[pe_greg[i]])return R3_RESULT;
    for(unsigned i=0;i<NGREG;i++) {
        unsigned ordinary=0;for(unsigned j=0;j<16;j++)ordinary|=i==pe_greg[j];
        if(!ordinary && i!=REG_RIP && i!=REG_EFL && i!=REG_CR2 && i!=REG_TRAPNO && i!=REG_ERR &&
           a[i]!=b[i])return R3_RESULT;
    }
    return a[REG_TRAPNO]!=1 || a[REG_ERR] || b[REG_TRAPNO]!=14 || b[REG_ERR]!=21 ||
        ((uint64_t)b[REG_EFL]&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF ||
        ((uint64_t)b[REG_EFL]&~(r3.flags_written|SELECTED_RF))!=(r3.flags&~r3.flags_written) ||
        r3.before.frame.mask!=r3.after.frame.mask ||
        !equal(&r3.before.uc.uc_stack,&r3.after.uc.uc_stack,sizeof r3.before.uc.uc_stack) ||
        r3.before.uc.uc_flags!=r3.after.uc.uc_flags || r3.before.uc.uc_link!=r3.after.uc.uc_link ||
        r3.before.tls_complete!=1 || r3.after.tls_complete!=1 ||
        r3.before.fs_result || r3.before.gs_result || r3.after.fs_result || r3.after.gs_result ||
        r3.before.fs!=r3.after.fs || r3.before.gs!=r3.after.gs ||
        r3.before.frame.fp_bytes!=r3.after.frame.fp_bytes ||
        !equal(r3.before.frame.fp,r3.after.frame.fp,LI2_STEP_FP_BYTES)?R3_RESULT:0;
}
static int r3_drain(const ucontext_t *uc) {
    if(r3.phase!=LI2_R3_RECOVERING || !r3.busy || !r3.active || !r3.exit_seen ||
       r3.count!=LI2_R3_CERTIFICATES)return R3_STATE;
    r3.phase=LI2_R3_CLOSING;
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];
        if(c->active_refs!=1 || c->closed ||
           raw(SYS_mprotect,c->identity.code,R3_CODE_BYTES,PROT_READ,0,0,0))return R3_PUBLICATION;
    }
    if(raw(SYS_membarrier,32,0,0,0,0,0))return R3_PUBLICATION;
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];le_zero(c->drained,sizeof c->drained);
        if(r3_code_query(i,PROT_READ,c->drained) || r3_bytes(i))return R3_PUBLICATION;
        c->closed=1;
    }
    if(r3_current(uc) || !r3_directory_query())return R3_SOURCE;
    /* A reference becomes zero only after the actual complete all-three NX
       drain. No completion supplied by an observer can make it releasable. */
    for(unsigned i=0;i<r3.count;i++)r3.certificate[i].active_refs=0;
    r3.active=0;
    if(li2_lifecycle_fetch_release(&r3.held))return R3_SOURCE;
    r3.released=1;
    if(li2_r3_rseq_close(&r3.token,uc) || !r3_all_nx())return R3_RSEQ;
    return 0;
}
static int selected_resident_three_trace_try(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!r3.initialized || r3.first_error || r3.busy || r3.active ||
       (r3.phase!=LI2_R3_IDLE && r3.phase!=LI2_R3_DRAINED) ||
       (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=r3.root)return 0;
    unsigned route=0;
    if(!le_trace_coarse(sig,si,uc)) {
        if(pe_cross_page_trace_coarse(sig,si,uc))route=1;
        else if(pe_direct_trace_coarse(sig,si,uc))route=2;
        else return 0;
    }
    if(!li2_rsl_resident_advisory(r3.root))return 0;
    r3_need(!r3_permission(PROT_READ|PROT_WRITE),R3_PUBLICATION,10);
    r3_need(!pe_busy && !pe_active && !pe_decoding && !pe_closing &&
        !li2_pg_epoch_interlock() && !li2_pg_rseq_progress()->active &&
        r3.serial<UINT64_MAX && r3_registry_initial() && r3_identity() && r3_all_nx(),R3_STATE,11);
    r3.busy=1;r3.phase=LI2_R3_CLOSING_TRACE;++r3.serial;
    r3.token=(struct li2_r3_token){&r3,r3.serial};r3.consumed=0;r3.released=0;r3.exit_seen=0;
    le_zero(&r3.before,sizeof r3.before);le_zero(&r3.after,sizeof r3.after);
    int e=route==2?li2_tf_chain_span_close_direct(&selected_chain,sig,si,uc,&r3.ticket):
        route==1?li2_tf_chain_span_close_cross_page(&selected_chain,sig,si,uc,&r3.ticket):
        li2_tf_chain_span_close(&selected_chain,sig,si,uc,&r3.ticket);
    r3_need(!e && r3.ticket,R3_EVENT,e);r3.transfer=*li2_tf_chain_span_progress();
    r3_need(r3.transfer.phase==LI2_ST_CLOSED && r3.transfer.issued==1 &&
        r3.transfer.event==selected_chain.event_id && r3.transfer.pc==r3.root &&
        !li2_tf_chain_span_quiet(r3.ticket),R3_EVENT,12);
    r3_need(r3_registry_bind(),R3_STATE,12);
    r3.flags=r3.transfer.flags;selected_logical_flags=r3.flags;selected_flags_known=1;
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    r3_need(!le_capture(&r3.before,sig,si,uc) &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==r3.flags &&
        !(r3.flags&(SELECTED_TF|SELECTED_RF)) && le_quiet(0),R3_FRAME,13);
    r3_tls(&r3.before);
    le_zero(&selected_borrow,sizeof selected_borrow);le_zero(&selected_view,sizeof selected_view);
    e=li2_lifecycle_fetch_prepare(r3.root,15,&selected_borrow);
    r3_need(!e,R3_SOURCE,e);r3.held=selected_borrow;
    e=li2_lifecycle_fetch_view(&selected_borrow,&selected_view);
    r3_need(!e && selected_view.pc==r3.root && selected_view.length==15 && selected_view.page_count==1 &&
        selected_view.identity_observed && selected_view.pid==r3.session.pid &&
        selected_view.tid==r3.session.tid && !li2_lifecycle_span_fetch_snapshot(&r3.fetch),R3_SOURCE,14);
    r3.phase=LI2_R3_HELD;
    r3_need(!li2_r3_rseq_begin(&r3.token,uc) && !r3_plans(uc) &&
        !r3_current(uc) && le_quiet(&r3.held) && le_unchanged(&r3.before,si,uc),R3_SOURCE,15);
    e=li2_tf_chain_span_consume(r3.ticket,&selected_session,&r3.held,r3.root,sig,si,uc);
    r3.transfer=*li2_tf_chain_span_progress();
    r3_need(!e && r3.transfer.phase==LI2_ST_CONSUMED && r3.transfer.consumed==1,R3_EVENT,e);
    r3.consumed=1;
    if(!r3.publications) {
        r3.phase=LI2_R3_PUBLISHING;
        for(unsigned i=0;i<r3.count;i++)r3_need(!r3_publish(i),R3_PUBLICATION,20+i);
        r3_need(!r3_directory_build(),R3_PUBLICATION,23);
    }
    r3.phase=LI2_R3_BOUND;
    r3_need(!r3_current(uc) && !r3_open() && le_unchanged(&r3.before,si,uc) &&
        r3.entries<UINT64_MAX,R3_PUBLICATION,24);
    r3.phase=LI2_R3_ACTIVE;r3.active=1;++r3.entries;
    uintptr_t target=r3.certificate[0].layout.generated[0];
    r3_need(r3.expected_directory.count && r3.expected_directory.row[0].pc==r3.root &&
        r3.expected_directory.row[0].generated==target,R3_PUBLICATION,25);
    selected_pending_route=SELECTED_RESIDENT_THREE;selected_step_pending=1;
#ifdef LI2_RESIDENT_THREE_CAPTURE
    r3o_entered(si,uc);
#endif
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)target;
    selected_initialized();r3_need(!r3_permission(PROT_READ),R3_PUBLICATION,26);return 1;
}
static void selected_resident_three_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    li2_r3_rseq_preentry();
#ifdef LI2_RESIDENT_THREE_CAPTURE
    r3o_ingress(sig,si,uc);
#endif
    if(!r3.active)return;
    /* First action after rseq's nonreturning live-word guard: retain the real
       event frame before any TLS syscall or logical/context modification. */
    r3_need(!r3_permission(PROT_READ|PROT_WRITE),R3_PUBLICATION,30);
    r3_need(r3.ingresses<UINT64_MAX,R3_STATE,30);++r3.ingresses;
    r3_need(r3.busy && r3.phase==LI2_R3_ACTIVE && !r3.after.started &&
        selected_pending_route==SELECTED_RESIDENT_THREE && selected_step_pending==1 &&
        !le_capture(&r3.after,sig,si,uc),R3_FRAME,31);
    r3_tls(&r3.after);
}
static void selected_resident_three_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    r3_need(r3.active && r3.busy && r3.phase==LI2_R3_ACTIVE && r3.after.complete &&
        le_unchanged(&r3.after,si,uc) && r3_identity() && r3_registry(),R3_STATE,32);
    const greg_t *g=r3.after.frame.greg;uintptr_t pc=(uintptr_t)g[REG_RIP];unsigned found=0;
    r3_need(sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
        g[REG_TRAPNO]==14 && g[REG_ERR]==21 && (uintptr_t)si->si_addr==pc &&
        (uintptr_t)g[REG_CR2]==pc && ((uint64_t)g[REG_CSGSFS]&65535)==0x33 &&
        r3.after.frame.mask==r3.session.application_mask,R3_EVENT,33);
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];
        struct li2_sealed_code_query code[3]={0},proof[2]={0};
        r3_need(c->active_refs==1 && !c->closed && !r3_bytes(i) &&
            !r3_code_query(i,PROT_READ|PROT_EXEC,code) && !r3_proof_query(i,proof) &&
            !r3_data_query(i),R3_PUBLICATION,34);
        int exit=li2_pg_compact_exit(&c->mirror.plan,pc,(uint64_t)g[REG_EFL]);
        r3_need(exit!=-2,R3_EVENT,35);
        if(exit>=0){++found;r3.exit_member=i;r3.exit_index=(unsigned)exit;}
    }
    r3_need(found==1 && !r3_preserved(),R3_RESULT,36);r3.exit_seen=1;r3.phase=LI2_R3_RECOVERING;
    r3_need(!r3_drain(uc) && le_unchanged(&r3.after,si,uc) && r3.completed<UINT64_MAX,R3_SOURCE,37);
    ++r3.completed;r3.phase=LI2_R3_DRAINED;r3.busy=0;r3.ticket=0;
    selected_pending_route=SELECTED_NO_STEP;selected_step_pending=0;
    selected_logical_flags=(uint64_t)g[REG_EFL]&~SELECTED_RF;selected_flags_known=1;
    r3_need(r3.entries==r3.completed && li2_r3_owner_quiet(),R3_STATE,38);
    r3_need(!r3_permission(PROT_READ),R3_PUBLICATION,39);
#ifdef LI2_RESIDENT_THREE_CAPTURE
    r3o_terminal();
#endif
    /* Continue at the genuine original frontier. No target instruction has
       executed and no synthetic completion/frame is substituted. */
    selected_fetch(sig,si,uc);
}
