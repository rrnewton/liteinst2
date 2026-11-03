/* Cold values are rebuilt from the actual post-PGX view. Interior transfers
   only execute the shared DIRECT image; no owner callback runs on an edge. */
static int lcx_count(uint64_t *n) {
    if(*n==UINT64_MAX)return PE_OVERFLOW;
    ++*n;return 0;
}
static int lcx_storage(void) {
    const struct lcx_owner *o=&lcx_runtime.value;
    return o->initialized==1 && !o->poisoned && o->code && o->spill==o->code+PAGE &&
        !(o->code&(PAGE-1U)) && o->code<(UINT64_C(1)<<31)-2U*PAGE &&
        selected_run_protect_contains(0,(uintptr_t)&lcx_runtime,sizeof lcx_runtime)==1 &&
        selected_run_protect_contains(0,(uintptr_t)&lcx_live,sizeof lcx_live)==1 &&
        selected_run_protect_contains(0,(uintptr_t)lcx_cells,sizeof lcx_cells)==1 &&
        selected_run_protect_contains(0,o->code,2U*PAGE)==1;
}
static int lcx_overlap(uintptr_t a,uintptr_t z,uintptr_t b,size_t n) {
    return n && b<=UINTPTR_MAX-n && a<b+n && b<z;
}
static void lcx_advance(uint64_t *epoch) {
    if(*epoch==UINT64_MAX) {
        lcx_runtime.value.poisoned=1;
        selected_persistent_abort(PE_OVERFLOW,9420);
    }
    ++*epoch;
}
static void lcx_exposure(uintptr_t first,size_t bytes) {
    struct lcx_owner *o=&lcx_runtime.value;
    if(!bytes || first>=UINT64_C(0x800000000000) ||
       bytes>UINT64_C(0x800000000000)-first || first+bytes>UINTPTR_MAX-(PAGE-1U)) {
        o->poisoned=1;selected_persistent_abort(PE_PUBLICATION,9421);
    }
    uintptr_t end=(first+bytes+PAGE-1U)&~(uintptr_t)(PAGE-1U);
    first&=~(uintptr_t)(PAGE-1U);
    /* The live issuer and reconstruction scratch are permanently private RW.
       No restoring write or permission change may modify this authority. */
    if(lcx_overlap(first,end,(uintptr_t)&lcx_runtime,sizeof lcx_runtime)) {
        o->poisoned=1;selected_persistent_abort(PE_PUBLICATION,9422);
    }
    unsigned changed=0;
    if(lcx_overlap(first,end,o->code,2U*PAGE)){lcx_advance(&o->code_epoch);changed=1;}
    if(lcx_overlap(first,end,(uintptr_t)&lcx_live,sizeof lcx_live)){lcx_advance(&o->proof_epoch);changed=1;}
    if(lcx_overlap(first,end,pe.domain.directory,LI2_JD_DOMAIN_BYTES)){lcx_advance(&o->directory_epoch);changed=1;}
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++)
        if(lcx_overlap(first,end,(uintptr_t)&lcx_cells[i],sizeof lcx_cells[i])) {
            lcx_advance(&o->cell_epoch[i]);changed=1;
        }
    if(changed && lcx_count(&o->invalidations))selected_persistent_abort(PE_OVERFLOW,9423);
}
void li2_lcx_before_raw(long n,long a,long b,long c,long d,long e,long f) {
    (void)f;
    if(lcx_runtime.value.initialized!=1)return;
    if(n==SYS_mprotect
#ifdef SYS_pkey_mprotect
       || n==SYS_pkey_mprotect
#endif
    ) {
        if((unsigned long)c&(PROT_GROWSDOWN|PROT_GROWSUP)) {
            lcx_runtime.value.poisoned=1;selected_persistent_abort(PE_PUBLICATION,9424);
        }
        /* All permission transitions retire the prior tuple, including R.
           Only the explicit owner open/close protocol can issue its next one. */
        lcx_exposure((uintptr_t)a,(size_t)b);
    } else if(n==SYS_mmap) {
        if((unsigned long)d&MAP_FIXED)lcx_exposure((uintptr_t)a,(size_t)b);
    } else if(n==SYS_munmap || n==SYS_madvise)lcx_exposure((uintptr_t)a,(size_t)b);
    else if(n==SYS_mremap) {
        lcx_exposure((uintptr_t)a,(size_t)b>(size_t)c?(size_t)b:(size_t)c);
        if((unsigned long)d&MREMAP_FIXED)lcx_exposure((uintptr_t)e,(size_t)c);
    }
}
static int lcx_initialize(void) {
    struct lcx_owner *o=&lcx_runtime.value;
    if(pe.initialized || !pe_busy || pe_active || protected_count>RANGES-4U ||
       !pda_zero(&lcx_runtime,sizeof lcx_runtime) || !pda_zero(&lcx_live,sizeof lcx_live) ||
       !pda_zero(lcx_cells,sizeof lcx_cells))return PE_STATE;
    long code=raw(SYS_mmap,0,2U*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    if(code<=0 || ((uintptr_t)code&(PAGE-1U)) || (uintptr_t)code>=(UINT64_C(1)<<31)-2U*PAGE)return PE_PUBLICATION;
    /* As with the original LHC/descriptor roots, give every isolated owner
       extent an actual anonymous identity before any issuer is live. */
    if((uintptr_t)raw(SYS_mmap,(long)&lcx_runtime,sizeof lcx_runtime,PROT_READ|PROT_WRITE,
           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&lcx_runtime ||
       (uintptr_t)raw(SYS_mmap,(long)&lcx_live,sizeof lcx_live,PROT_READ,
           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&lcx_live ||
       (uintptr_t)raw(SYS_mmap,(long)lcx_cells,sizeof lcx_cells,PROT_READ,
           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)lcx_cells)return PE_PUBLICATION;
    o->code=(uintptr_t)code;o->spill=o->code+PAGE;
    if(selected_run_protect_add(0,(uintptr_t)&lcx_runtime,sizeof lcx_runtime) ||
       selected_run_protect_add(0,(uintptr_t)&lcx_live,sizeof lcx_live) ||
       selected_run_protect_add(0,(uintptr_t)lcx_cells,sizeof lcx_cells) ||
       selected_run_protect_add(0,o->code,2U*PAGE) ||
       raw(SYS_mprotect,o->code,PAGE,PROT_READ,0,0,0))return PE_PUBLICATION;
    struct li2_private_code_query q={0};
    if(pe_query(o->code,PAGE,PROT_READ,&q))return PE_PUBLICATION;
    le_zero(&q,sizeof q);if(pe_query(o->spill,PAGE,PROT_READ|PROT_WRITE,&q) ||
       lrc_readonly((uintptr_t)&lcx_live,sizeof lcx_live))return PE_PUBLICATION;
    for(size_t offset=0;offset<sizeof lcx_runtime;) {
        size_t bytes=sizeof lcx_runtime-offset;
        if(bytes>64U*PAGE)bytes=64U*PAGE;
        le_zero(&q,sizeof q);
        if(pe_query((uintptr_t)&lcx_runtime+offset,bytes,PROT_READ|PROT_WRITE,&q))return PE_PUBLICATION;
        offset+=bytes;
    }
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {
        if(lrc_readonly((uintptr_t)&lcx_cells[i],sizeof lcx_cells[i]))return PE_PUBLICATION;
        o->cell_epoch[i]=1;
    }
    o->code_epoch=o->proof_epoch=o->directory_epoch=1;
    __asm__ volatile("":::"memory");o->initialized=1;
    return lcx_storage()?0:PE_PUBLICATION;
}
static void lcx_reset(void) {
    pe_need(lcx_storage() && !pe_active && !pe_busy &&
        (!lcx_runtime.value.work.opened || lcx_runtime.value.work.closed),PE_STATE,9425);
    le_zero(&lcx_runtime.value.work,sizeof lcx_runtime.value.work);
}
static int lcx_reconstruct(struct lcx_bundle *out) {
    const struct li2_pgd_view *v=&pe.domain.work.view;
    le_zero(out,sizeof *out);
    out->version=1;out->serial=pe.p.serial;out->members=v->count;
    out->session=pe.session;copy(out->archive,pe_archive,32);copy(out->policy,pe_policy,32);
    for(unsigned i=0;i<v->count;i++) {out->ref[i]=v->member[i].identity;out->key[i]=*v->member[i].key;}
    for(unsigned from=0;from<v->count;from++) {
        const struct li2_pg_compact *p=v->member[from].plan;
        for(unsigned head=0;head<p->heads;head++) {
            if(p->head[head].kind!=LI2_PG_DIRECT)continue;
            const struct li2_dd_descriptor *d=&p->instruction[head].direct;
            for(unsigned arm=0;arm<2;arm++) {
                if(!(d->external_mask&(1U<<arm)))continue;
                unsigned found=LI2_PGD_MEMBERS;
                for(unsigned owner=0;owner<v->count;owner++) {
                    if(owner==from)continue;
                    struct li2_lcx_tail tail;
                    if(!li2_lcx_tail_value(v->member[owner].key,v->member[owner].plan,d->target[arm],&tail)) {
                        if(found!=LI2_PGD_MEMBERS)return PE_PLAN;
                        found=owner;
                    }
                }
                if(found==LI2_PGD_MEMBERS)continue;
                /* A single tail may be reached by only one recorded arm in
                   this initial bounded profile; never silently omit a route. */
                if(out->count>=LI2_DD_AUX_SLOTS)return PE_PLAN;
                unsigned i=out->count++;
                out->route[i]=(struct li2_lcx_route){from,head,arm,found};
                if(li2_lcx_image_value(&v->member[found],d->target[arm],lcx_runtime.value.code,
                       lcx_runtime.value.spill,i,&out->image[i]))return PE_PLAN;
            }
        }
    }
    if(!out->count) {le_zero(out,sizeof *out);return 0;}
    const struct li2_lcx_publication_layout publication={PE_PROOF_BYTES,
        offsetof(struct pe_payload,source),offsetof(struct pe_payload,plan)};
    return li2_lcx_lease_value(v,out->route,out->image,out->count,lcx_runtime.value.code,
        lcx_runtime.value.spill,&publication,&out->lease,&out->directory)?PE_PLAN:0;
}
const struct li2_lcx_image *li2_lcx_pending_images(const struct li2_pg_token *t) {
    const struct lcx_work *w=&lcx_runtime.value.work;
    return t && t->owner==&pe && t->serial==pe.p.serial && pe.p.phase==LI2_PG_BOUND &&
        pe_busy && !pe_active && pe_decoding && pe.loop.scope==PLR_HISTORY &&
        w->built==1 && w->candidate.count?w->candidate.image:0;
}
static int lcx_build(const ucontext_t *uc) {
    struct lcx_owner *o=&lcx_runtime.value;struct lcx_work *w=&o->work;
    if(!lcx_storage() || w->built || !pe_busy || pe_active || handling!=1 ||
       pe.p.phase!=LI2_PG_BOUND || pe.domain.work.bound!=1 ||
       !li2_pgd_owner_view(&pe.token))return PE_STATE;
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    const struct li2_pgd_source_progress *s=li2_pgd_source_progress();
    if(!r || !s || r->domain_bound!=1 || r->domain_count!=pe.domain.work.view.count ||
       r->first_error || r->active!=1 || s->bound!=1 || s->first_error ||
       s->count!=r->domain_count || !equal(r->domain_ref,s->ref,sizeof r->domain_ref))return PE_SOURCE;
    if(!plr_scope_enter(PLR_HISTORY))return PE_REENTRY;
    int result=lcx_reconstruct(&w->candidate);
    if(!result) {
        w->built=1;w->serial=pe.p.serial;
        if(w->candidate.count)result=li2_lcx_rseq_value(&pe.token,&w->candidate.lease,w->candidate.image,uc);
    }
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    if(!result && (lcx_reconstruct(&w->comparison) ||
       !equal(&w->comparison,&w->candidate,sizeof w->candidate)))result=PE_PLAN;
#endif
    plr_scope_leave(PLR_HISTORY);
    if(result)return result;
    return w->candidate.count?lcx_count(&o->builds):0;
}
static int lcx_code_equal(const struct lcx_bundle *b) {
    const volatile unsigned char *bytes=(const void *)lcx_runtime.value.code;
    for(unsigned i=0;i<PAGE;i++) {
        unsigned slot=i/LI2_DD_SLOT_BYTES,offset=i%LI2_DD_SLOT_BYTES;
        unsigned char expected=slot<b->count?b->image[slot].plan.value.image[offset]:0xcc;
        if(bytes[i]!=expected)return 0;
    }
    return 1;
}
static int lcx_current_value(unsigned preentry,int prot) {
    struct lcx_owner *o=&lcx_runtime.value;const struct lcx_work *w=&o->work;
    const struct lcx_bundle *b=&lcx_live.value;const struct li2_pgd_view *v=&pe.domain.work.view;
    if(preentry>2 || !lcx_storage() || w->built!=1 || w->published!=1 ||
       !w->candidate.count || w->serial!=pe.p.serial ||
       w->code_epoch!=o->code_epoch || w->proof_epoch!=o->proof_epoch ||
       w->directory_epoch!=o->directory_epoch || pe.domain.work.bound!=1 ||
       (preentry==1?!lgd_preentry_context():preentry==2?
         (handling || !pe_busy || !pe_active || pe.p.phase!=LI2_PG_RECOVERING ||
          !pe.recovery_started || !pe.redirected || pe_closing || pe_decoding ||
          selected_pending_route!=SELECTED_PERSISTENT_EPOCH || selected_step_pending!=1):handling!=1) ||
       lrc_readonly((uintptr_t)&lcx_live,sizeof lcx_live) ||
       !equal(b,&w->candidate,sizeof *b) || b->version!=1 || b->serial!=v->token.serial ||
       b->members!=v->count || !equal(&b->session,&pe.session,sizeof b->session) ||
       !equal(b->archive,pe_archive,32) || !equal(b->policy,pe_policy,32) ||
       !equal(&b->lease.token,&pe.token,sizeof pe.token))return 0;
    for(unsigned i=0;i<v->count;i++)
        if(!equal(&b->ref[i],&v->member[i].identity,sizeof b->ref[i]) ||
           !equal(&b->key[i],v->member[i].key,sizeof b->key[i]))return 0;
    struct li2_private_code_query code={0},spill={0},directory={0};
    if(pe_query(o->code,PAGE,prot,&code) || pe_query(o->spill,PAGE,PROT_READ|PROT_WRITE,&spill) ||
       pe_query(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&directory) || !lcx_code_equal(b))return 0;
    const volatile unsigned char *p=(const void *)pe.domain.directory;
    const unsigned char *expected=(const void *)&b->directory;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)if(p[i]!=(i<sizeof b->directory?expected[i]:0))return 0;
    return w->code_epoch==o->code_epoch && w->proof_epoch==o->proof_epoch &&
        w->directory_epoch==o->directory_epoch;
}
static int lcx_publish(void) {
    struct lcx_owner *o=&lcx_runtime.value;struct lcx_work *w=&o->work;
    if(!lcx_storage() || w->built!=1 || !w->candidate.count || w->published ||
       !pe_busy || pe_active || handling!=1 || pe.p.phase!=LI2_PG_BOUND ||
       w->serial!=pe.p.serial)return PE_STATE;
    int e=pe_permission(o->code,PAGE,PROT_READ|PROT_WRITE,&w->code_write);if(e)return e;
    if(pe_query(o->spill,PAGE,PROT_READ|PROT_WRITE,&w->spill_before))return PE_PUBLICATION;
    volatile unsigned char *code=(void *)o->code,*spill=(void *)o->spill;
    for(unsigned i=0;i<PAGE;i++) {
        unsigned slot=i/LI2_DD_SLOT_BYTES,offset=i%LI2_DD_SLOT_BYTES;
        code[i]=slot<w->candidate.count?w->candidate.image[slot].plan.value.image[offset]:0xcc;
        spill[i]=0;
    }
    e=pe_permission(o->code,PAGE,PROT_READ,&w->code_seal);if(e)return e;
    struct pda_work *d=&pe.domain.work;
    e=pe_permission(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ|PROT_WRITE,&d->directory_write);if(e)return e;
    volatile unsigned char *bytes=(void *)pe.domain.directory;
    const unsigned char *source=(const void *)&w->candidate.directory;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)bytes[i]=i<sizeof w->candidate.directory?source[i]:0;
    e=pe_permission(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&d->directory_seal);if(e)return e;
    e=pe_permission((uintptr_t)&lcx_live,sizeof lcx_live,PROT_READ|PROT_WRITE,&w->proof_write);if(e)return e;
    le_zero(&lcx_live,sizeof lcx_live);lcx_live.value=w->candidate;
    e=pe_permission((uintptr_t)&lcx_live,sizeof lcx_live,PROT_READ,&w->proof_seal);if(e)return e;
    w->code_epoch=o->code_epoch;w->proof_epoch=o->proof_epoch;w->directory_epoch=o->directory_epoch;
    w->published=1;
    return lcx_current_value(0,PROT_READ)?0:PE_PUBLICATION;
}
static int lcx_directory_equal(unsigned preentry) {
    const struct lcx_work *w=&lcx_runtime.value.work;
    return lcx_current_value(preentry,w->opened && !w->closed?PROT_READ|PROT_EXEC:PROT_READ);
}
static int lcx_directory_equal_preentry(void) {return lcx_directory_equal(1);}
static int lcx_open(void) {
    struct lcx_owner *o=&lcx_runtime.value;struct lcx_work *w=&o->work;
    if(!w->candidate.count)return w->built==1?0:PE_STATE;
    if(pe.p.phase!=LI2_PG_OPENING || !pe_busy || pe_active || handling!=1 ||
       w->opened || w->closed || !lcx_current_value(0,PROT_READ))return PE_STATE;
    int e=pe_permission(o->code,PAGE,PROT_READ|PROT_EXEC,&w->code_open);if(e)return e;
    w->code_epoch=o->code_epoch;w->opened=1;
    return lcx_current_value(0,PROT_READ|PROT_EXEC)?lcx_count(&o->opens):PE_PUBLICATION;
}
static int lcx_close(void) {
    struct lcx_owner *o=&lcx_runtime.value;struct lcx_work *w=&o->work;
    if(!w->candidate.count)return w->built==1?0:PE_STATE;
    if(pe.p.phase!=LI2_PG_CLOSING || !pe_busy || !pe_active || handling!=1 ||
       w->opened!=1 || w->closed || !lcx_current_value(0,PROT_READ|PROT_EXEC))return PE_STATE;
    int e=pe_permission(o->code,PAGE,PROT_READ,&w->code_close);if(e)return e;
    volatile unsigned char *spill=(void *)o->spill;for(unsigned i=0;i<PAGE;i++)spill[i]=0;
    if(pe_query(o->spill,PAGE,PROT_READ|PROT_WRITE,&w->spill_closed))return PE_PUBLICATION;
    w->code_epoch=o->code_epoch;w->closed=1;
    return lcx_current_value(0,PROT_READ)?lcx_count(&o->closes):PE_PUBLICATION;
}
static int lcx_recover(uintptr_t pc,const uint64_t raw[16],uint64_t flags) {
    struct lcx_owner *o=&lcx_runtime.value;struct lcx_work *w=&o->work;
    if(pc<o->code || pc-o->code>=PAGE)return 0;
    if(pe.p.phase!=LI2_PG_RECOVERING || !pe_busy || !pe_active ||
       w->recovery_owned || !lcx_current_value(2,PROT_READ|PROT_EXEC))return -1;
    unsigned slot=(unsigned)((pc-o->code)/LI2_DD_SLOT_BYTES);
    if(slot>=lcx_live.value.count)return -1;
    const struct li2_dd_aux_plan *p=&lcx_live.value.image[slot].plan;
    if(p->binding.slot!=slot || p->binding.code!=o->code || p->binding.spill!=o->spill ||
       p->value.generated!=o->code+(uintptr_t)slot*LI2_DD_SLOT_BYTES ||
       p->value.spill!=o->spill+(uintptr_t)slot*LI2_DD_AUX_SPILL_STRIDE)return -1;
    /* The complete sealed record and actual savedPC select the spill first.
       The shared boundary routine reads only initialized dirty spill words. */
    w->recovery_owned=1;
    w->recovery_result=(unsigned)li2_ld_aux_recover(p,pc,raw,flags,
        (const uint64_t *)p->value.spill,&w->recovered);
    if(lcx_count(&o->recoveries))return -1;
    return 1; /* All AUX signals remain terminal, even exact recovery success. */
}
static const struct lcx_bundle *lcx_current_bundle(void) {
    return lcx_runtime.value.work.published==1?&lcx_live.value:0;
}
static const struct lcx_side_value *lcx_completion_bundle(unsigned i) {
    return i<LI2_PGD_RECEIPTS && lcx_runtime.value.issued[i].auxiliary?&lcx_cells[i].value:0;
}
static unsigned lcx_cell(const struct pda_completion *c) {
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++)if(c==&pe.domain.completion[i])return i;
    return LI2_PGD_RECEIPTS;
}
static int lcx_issued_value(const struct pda_completion *c,unsigned i) {
    if(i>=LI2_PGD_RECEIPTS || !lcx_storage() || c!=&pe.domain.completion[i])return 0;
    const struct lcx_issuance *v=&lcx_runtime.value.issued[i];
    if(!c->id || c->complete!=1 || !c->count || c->count>LI2_PGD_MEMBERS ||
       v->id!=c->id || v->serial!=c->serial || v->members!=c->count ||
       v->auxiliary>LI2_DD_AUX_SLOTS || v->retired>1 || v->reserved)return 0;
    for(unsigned j=0;j<LI2_PGD_MEMBERS;j++) {
        if(j<c->count) {if(!equal(&v->ref[j],&c->member[j].identity,sizeof v->ref[j]))return 0;}
        else if(!pda_zero(&v->ref[j],sizeof v->ref[j]))return 0;
    }
    return 1;
}
static int lcx_receipt(const struct pda_completion *c) {
    unsigned i=lcx_cell(c);
    if(!lcx_issued_value(c,i))return 0;
    const struct lcx_owner *o=&lcx_runtime.value;
    const struct lcx_issuance *issued=&o->issued[i];
    if(!issued->auxiliary)return !issued->epoch && !issued->retired;
    if(issued->retired || !issued->epoch || issued->epoch!=o->cell_epoch[i] ||
       lrc_readonly((uintptr_t)&lcx_cells[i],sizeof lcx_cells[i]))return 0;
    const struct lcx_side_value *s=&lcx_cells[i].value;const struct lcx_bundle *b=&s->bundle;
    if(s->version!=1 || s->completion!=c || s->id!=c->id || s->serial!=c->serial ||
       s->epoch!=issued->epoch || b->version!=1 || b->serial!=c->serial ||
       b->members!=c->count || b->count!=issued->auxiliary ||
       b->reserved[0] || b->reserved[1] || !equal(&b->session,&pe.session,sizeof b->session) ||
       !equal(b->archive,pe_archive,32) || !equal(b->policy,pe_policy,32) ||
       b->lease.token.owner!=&pe || b->lease.token.serial!=c->serial ||
       b->lease.code!=o->code || b->lease.spill!=o->spill ||
       !pg_query_complete(&s->code_closed,o->code,PAGE,PROT_READ) ||
       !pg_query_complete(&s->spill_closed,o->spill,PAGE,PROT_READ|PROT_WRITE))return 0;
    for(unsigned j=0;j<c->count;j++)
        if(!equal(&b->ref[j],&c->member[j].identity,sizeof b->ref[j]) ||
           !equal(&b->key[j],&c->member[j].source,sizeof b->key[j]))return 0;
    return issued->epoch==o->cell_epoch[i];
}
static int lcx_complete(const struct pda_completion *c) {
    unsigned i=lcx_cell(c);struct lcx_owner *o=&lcx_runtime.value;struct lcx_work *w=&o->work;
    if(!lcx_storage() || i>=LI2_PGD_RECEIPTS || i!=pe.domain.work.receipt ||
       pe.p.phase!=LI2_PG_CLOSED || !pe_busy || !pe_active || handling!=1 ||
       c->complete!=1 || c->id!=pe.domain.next_id || c->serial!=pe.p.serial ||
       c->count!=pe.domain.work.view.count || w->built!=1 || w->serial!=c->serial)return PE_STATE;
    struct lcx_issuance issue={.id=c->id,.serial=c->serial,.members=c->count,
        .auxiliary=w->candidate.count};
    for(unsigned j=0;j<c->count;j++) {
        if(!equal(&c->member[j].identity,&pe.domain.work.view.member[j].identity,sizeof issue.ref[j]))return PE_STATE;
        issue.ref[j]=c->member[j].identity;
    }
    if(issue.auxiliary) {
        if(w->opened!=1 || w->closed!=1 || !lcx_current_value(0,PROT_READ) ||
           !pda_zero((const void *)o->spill,PAGE) || o->cell_epoch[i]>UINT64_MAX-2)return PE_PUBLICATION;
        struct le_permission write={0},seal={0};
        int e=pe_permission((uintptr_t)&lcx_cells[i],sizeof lcx_cells[i],PROT_READ|PROT_WRITE,&write);if(e)return e;
        le_zero(&lcx_cells[i],sizeof lcx_cells[i]);
        struct lcx_side_value *side=&lcx_cells[i].value;
        side->version=1;side->id=c->id;side->serial=c->serial;side->completion=c;
        side->epoch=o->cell_epoch[i]+1; /* Exact following R transition also retires the prior tuple. */
        side->code_closed=w->code_close.query;side->spill_closed=w->spill_closed;
        side->bundle=lcx_live.value;
        e=pe_permission((uintptr_t)&lcx_cells[i],sizeof lcx_cells[i],PROT_READ,&seal);if(e)return e;
        if(side->epoch!=o->cell_epoch[i] || !equal(&side->bundle,&w->candidate,sizeof side->bundle))return PE_PUBLICATION;
        issue.epoch=o->cell_epoch[i];
    }
    /* No candidate flag is an issuer. This write follows actual final drain,
       complete source/rseq release and the immutable side-proof readback. */
    o->issued[i]=issue;
    return lcx_receipt(c)?0:PE_PUBLICATION;
}
static void lcx_abort(void) {
    struct lcx_owner *o=&lcx_runtime.value;
    if(o->initialized!=1)return;
    o->poisoned=1;
    if(o->code && !(o->code&(PAGE-1U)) && o->code<(UINT64_C(1)<<31)-2U*PAGE) {
        (void)raw(SYS_mprotect,o->code,PAGE,PROT_READ,0,0,0);
        (void)raw(SYS_membarrier,32,0,0,0,0,0);
    }
}
/* Retirement is deliberately NOT lta_closed_value. It conveys no reusable
   publication or execution claim, only permission to overwrite this exact old
   node after the unchanged fresh cold planner and physical checks succeed. */
static int lcx_cold_retired(unsigned node) {
    if(node>=PTR_NODE_COUNT || !lcx_storage() || !ptr_node_storage(node))return 0;
    const struct lcx_retirement *r=&lcx_runtime.value.retired[node];
    const struct li2_pgd_ref *v=&r->ref;
    const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
    if(r->valid!=1 || r->reserved || r->cell>=LI2_PGD_RECEIPTS || r->member>=LI2_PGD_MEMBERS ||
       !r->id || r->id>pe.domain.next_id || !r->serial || r->serial>pe.next_serial ||
       v->node!=node || v->node_reserved || v->slot>=LI2_PTR_SLOTS || v->bank>=2 ||
       !v->binding_generation || v->binding_generation>pe.arena.next_binding || !v->generation ||
       v->generation!=s->generation.generation || v->generation!=s->identity.generation ||
       v->proof!=s->proof || v->root!=s->publication.source.entry ||
       !pg_layout_equal(&v->layout,&s->generation.layout) ||
       !pg_layout_equal(&v->layout,&s->banks[v->bank].layout) ||
       s->banks[v->bank].prot!=PROT_READ || s->banks[v->bank].virgin ||
       !s->generation.installed || !pda_zero(&s->claim,sizeof s->claim) || s->permit.valid || s->permit.serial ||
       s->generation.linked || s->generation.active_refs || s->generation.domain_refs ||
       s->generation.member_refs[0] || s->generation.member_refs[1] ||
       s->generation.incoming[0] || s->generation.incoming[1])return 0;
    /* The protected full ref was copied only while authenticating and
       consuming the original claim. It outlives reuse of that receipt cell;
       it still grants only a cold overwrite at this unchanged node. */
    return 1;
}
static int lcx_retirement_take(unsigned node) {
    if(!lcx_cold_retired(node) || pe.warm || pe.p.phase!=LI2_PG_CONSUMED ||
       !pe_busy || pe_active || pe.plan_proofs!=2 || pe.none_proofs!=1 ||
       pe.candidate.plan.ready!=1 || pe.candidate.plan.result)return PE_STATE;
    le_zero(&lcx_runtime.value.retired[node],sizeof lcx_runtime.value.retired[node]);
    return 0;
}
static int lcx_cold_pending(unsigned node) {
    if(node>=PTR_NODE_COUNT || !lcx_storage())return 0;
    const struct li2_ptr_slot *s=&PTR_NODE_AT(node);const struct li2_pgd_claim *q=&s->claim;
    if(q->valid!=1 || q->reserved || q->cell>=LI2_PGD_RECEIPTS || q->member>=LI2_PGD_MEMBERS)return 0;
    const struct lcx_owner *o=&lcx_runtime.value;const struct lcx_issuance *issued=&o->issued[q->cell];
    if(!issued->auxiliary || issued->retired || issued->epoch==o->cell_epoch[q->cell])return 0;
    const struct pda_completion *c=&pe.domain.completion[q->cell];
    if(!lcx_issued_value(c,q->cell) || !pda_receipt_base(c) || q->id!=c->id ||
       q->member>=c->count || (pe.domain.claimed[q->cell]&(1U<<q->member)))return 0;
    const struct li2_pgd_ref *r=&c->member[q->member].identity;
    return r->node==node && r->slot<LI2_PTR_SLOTS && ptr_node_index(r->slot)==node &&
        pe.arena.binding[r->slot].generation==r->binding_generation &&
        s->identity.generation==r->generation && s->generation.generation==r->generation &&
        equal(&s->generation,&c->member[q->member].generation,sizeof s->generation) &&
        !s->permit.valid && !s->generation.linked && !s->generation.active_refs &&
        !s->generation.domain_refs && lta_issued_value(node);
}
static int lcx_reclaimable(const struct pda_completion *c) {
    unsigned i=lcx_cell(c);
    if(i>=LI2_PGD_RECEIPTS || !lcx_issued_value(c,i) ||
       lcx_runtime.value.issued[i].retired!=1 || !pda_receipt_base(c) ||
       pe.domain.claimed[i]!=(1U<<c->count)-1U)return 0;
    return 1;
}
static int lcx_retire_invalid(void) {
    struct lcx_owner *o=&lcx_runtime.value;
    if(!lcx_storage() || !pe_busy || pe_active || pe.resuming || handling!=1 ||
       pe_closing || !pe.close_complete || pe.p.phase!=LI2_PG_IDLE ||
       pe.transfer.phase!=LI2_ST_CLOSED || pe.transfer.issued!=1 ||
       pe.domain.work.bound)return PE_STATE;
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {
        struct lcx_issuance *issued=&o->issued[i];
        if(!issued->auxiliary || issued->retired || issued->epoch==o->cell_epoch[i])continue;
        const struct pda_completion *c=&pe.domain.completion[i];
        /* Authenticate the original receipt and protected issuer, not the
           exposed side bytes. These checks only authorize discarding claims. */
        if(!lcx_issued_value(c,i) || !pda_receipt_base(c) ||
           (pe.domain.claimed[i]&~((1U<<c->count)-1U)))return PE_RELEASE;
        int e=lprx_revoke(LPRX_COLD);if(e)return e;
        for(unsigned j=0;j<c->count;j++) {
            if(pe.domain.claimed[i]&(1U<<j))continue;
            const struct li2_pgd_ref *ref=&c->member[j].identity;
            if(ref->slot>=LI2_PTR_SLOTS || ref->node>=PTR_NODE_COUNT ||
               ptr_node_index(ref->slot)!=ref->node)return PE_RELEASE;
            struct li2_ptr_slot *s=&PTR_NODE_AT(ref->node);
            const struct li2_pgd_claim expected={.id=c->id,.cell=i,.member=j,.valid=1};
            if(!equal(&s->claim,&expected,sizeof expected) || !ptr_stored(ref->slot) ||
               !lta_issued_value(ref->node) || !pda_zero(&o->retired[ref->node],sizeof o->retired[ref->node]) ||
               !equal(&s->generation,&c->member[j].generation,sizeof s->generation) ||
               s->generation.linked || s->generation.active_refs || s->generation.domain_refs ||
               s->banks[ref->bank].prot!=PROT_READ || !ptr_slots(ref->slot,0))return PE_RELEASE;
            o->retired[ref->node]=(struct lcx_retirement){.id=c->id,.serial=c->serial,
                .ref=*ref,.cell=i,.member=j,.valid=1};
            pe.domain.claimed[i]|=1U<<j;le_zero(&s->claim,sizeof s->claim);
            lta_writer.value.dormant[ref->node].reusable=0;
            if(lcx_count(&o->retirements))return PE_OVERFLOW;
        }
        issued->retired=1;
    }
    return 0;
}
