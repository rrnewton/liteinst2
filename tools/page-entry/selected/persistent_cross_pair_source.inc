/* Included inside the protected source owner after its original helpers.
   No new permission operation, fetch anchor, rseq word or mutable global. */
static int pgx_geometry(const struct li2_pg_source_key *key) {
    if(!key || !key->entry)return 0;
    unsigned root=0;
    for(unsigned i=0;i<2;i++) {
        uintptr_t page=key->page[i].identity.address;
        if(!page || (page&(PAGE-1)) || page>(UINT64_C(1)<<47)-PAGE ||
           (i && page<=key->page[0].identity.address))return 0;
        if(key->entry>=page && key->entry-page<PAGE)root=1;
    }
    return root;
}
static int pgx_table_page(const struct li2_mg_table *table,uintptr_t page) {
    if(!page || (page&(PAGE-1)) || page>(UINT64_C(1)<<47)-PAGE)return 0;
    /* Full containment, not the old interval_allowed intersection predicate.
       Validated tables have sorted, disjoint, maximally merged nodes. */
    for(unsigned i=0;i<table->count;i++)
        if(table->node[i].first<=page && page+PAGE<=table->node[i].end)return 1;
    return 0;
}
static int pgx_tables(const struct li2_mg_table table[2],const uintptr_t pages[2][2]) {
    for(unsigned t=0;t<2;t++) {
        if(li2_mg_table_validate(&table[t]))return 0;
        for(unsigned m=0;m<2;m++)for(unsigned p=0;p<2;p++)
            if(!pgx_table_page(&table[t],pages[m][p]))return 0;
    }
    return 1;
}
int li2_pgx_guard_union(const struct li2_pg_compact *a,const struct li2_pg_compact *b) {
    if(!a || !b)return 0;
    /* The immutable plans need not be adjacent or within a rel32 span: the
       existing directory dispatch loads an exact full-width generated PC. */
    const struct li2_mg_table *tables[2]={&a->table,&b->table};
    for(unsigned i=0;i<2;i++) {
        if(li2_mg_table_validate(tables[i]))return 0;
        for(unsigned j=0;j<2;j++)if(!pgx_table_page(tables[i],a->page[j]) ||
            !pgx_table_page(tables[i],b->page[j]))return 0;
    }
    return 1;
}
static int pgx_maps(const struct li2_fetch_map_progress *m) {
    return m->fd>=0 && m->opened==1 && m->close_started==1 && m->closed==1 &&
        !m->last_read && !m->close_result && m->bytes && m->rows;
}
int li2_pgx_source_value(const struct li2_pgx_source *x,const struct li2_pg_sources *primary,
    const struct li2_pg_token *token,const struct li2_pgd_ref *member,
    const struct li2_pg_source_key *key,unsigned checks) {
    if(!x || !primary || !token || !member || !key || !checks || checks>LI2_PGX_CHECKS ||
       !primary->complete || primary->reserved || !primary->anchor.owner || !primary->anchor.sequence ||
       !token->owner || !token->serial || primary->serial!=token->serial ||
       x->token.owner!=token->owner || x->token.serial!=token->serial ||
       x->started!=1 || x->complete!=1 || x->declined || x->decline_reason ||
       x->first_error || x->first_detail || x->checks!=checks ||
       !equal(&x->member,member,sizeof *member) || member->root!=key->entry ||
       !pgx_geometry(&primary->key) || !pgx_geometry(key) ||
       !li2_pg_source_key_equal(&x->key,key) || li2_pgd_source_pair_equal(&primary->key,key) ||
       x->allocation_epoch!=primary->allocation_epoch || x->generation_epoch!=primary->generation_epoch ||
       x->transactions_epoch!=primary->transactions_epoch || x->records_epoch!=primary->records_epoch)return 0;
    const uintptr_t pages[2][2]={{primary->key.page[0].identity.address,primary->key.page[1].identity.address},
        {key->page[0].identity.address,key->page[1].identity.address}};
    if(!pgx_tables(x->table,pages))return 0;
    for(unsigned k=0;k<LI2_PGX_CHECKS;k++) {
        const struct li2_pgx_check *c=&x->checkpoint[k];
        if(k>=checks) {if(!pgsd_zero(c,sizeof *c))return 0;continue;}
        if(c->started!=1 || c->complete!=1 || c->pages!=2 || !pgx_maps(&c->maps))return 0;
        for(unsigned i=0;i<2;i++)if(c->bytes[i]!=PAGE ||
            !span_source_page_equal(&c->page[i],&key->page[i].identity) ||
            !span_source_backing_equal(&c->backing[i],&key->page[i].backing))return 0;
    }
    return 1;
}
static int pgx_error(struct li2_pgx_source *x,unsigned code,long detail) {
    if(!x->first_error){x->first_error=code;x->first_detail=detail;}
    return pgsd_bad(code,detail);
}
static int pgx_decline(struct li2_pgx_source *x,unsigned reason) {
    x->declined=1;x->decline_reason=reason;return 0;
}
static int pgx_epochs(const struct li2_pg_token *t,const struct li2_pgx_source *x) {
    const struct li2_pg_sources *s=&pg_source.p.source;
    return pgs_token(t) && s->complete==1 && s->serial==t->serial &&
        x->token.owner==t->owner && x->token.serial==t->serial &&
        allocation_id==s->allocation_epoch && generation==s->generation_epoch &&
        counts.transactions==s->transactions_epoch && used==s->records_epoch &&
        x->allocation_epoch==s->allocation_epoch && x->generation_epoch==s->generation_epoch &&
        x->transactions_epoch==s->transactions_epoch && x->records_epoch==s->records_epoch;
}
static int pgx_check(const struct li2_pg_token *t,struct li2_pgx_source *x,
    const struct li2_pg_source_key *expected,unsigned stage) {
    if(stage>=LI2_PGX_CHECKS || !pgx_epochs(t,x) || !pgx_geometry(expected) ||
       x->first_error || x->declined || x->checks!=stage ||
       !pgsd_zero(&x->checkpoint[stage],sizeof x->checkpoint[stage]))
        return pgx_error(x,LI2_FETCH_STATE,110);
    struct li2_pgx_check *c=&x->checkpoint[stage];c->started=1;
    int e=li2_lifecycle_run_reuse_quiet(&pg_source.p.source.anchor);
    if(e)return pgx_error(x,(unsigned)e,111);
    if((e=li2_lifecycle_fetch_validate(&pg_source.p.source.anchor,0,PROT_READ)))
        return pgx_error(x,(unsigned)e,112);
    struct check_error check={0};
    if(read_maps_checked(&check,&c->maps))return pgx_error(x,check.code,check.detail);
    for(unsigned i=0;i<2;i++) {
        uintptr_t address=expected->page[i].identity.address;
        const struct owned_page *p=current(address);const struct map_row *r=mapping(address);
        if(!p || !p->live || !p->allocation || !p->generation || p->admitted ||
           p->backing!=SEALED || p->object>=object_count ||
           p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ) {
            if(!stage)return pgx_decline(x,1+i);
            return pgx_error(x,LI2_FETCH_STALE,113+i);
        }
        if(stage && !fetch_owned_equal(p,&pg_source.peer_original[i]))
            return pgx_error(x,LI2_FETCH_STALE,115+i);
        if(verify_page_checked(p,r,&check) || alias_check_checked(p->object,p->offset,PAGE,p->logical,
            p->address,p->address+PAGE,&check))return pgx_error(x,check.code,check.detail);
        if(!r || !r->private || r->prot!=PROT_READ || address<r->first ||
           address>=r->end || r->end-address<PAGE)return pgx_error(x,LI2_FETCH_PAGE,117+i);
        c->page[i]=(struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
            .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
            .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=p->actual,
            .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,.vma_minor=r->minor,
            .vma_inode=r->inode,.vma_offset=r->offset};
        ++c->pages;
        if(!stage) {pg_source.peer_original[i]=*p;x->key.page[i].identity=c->page[i];}
        if(!span_source_page_equal(&c->page[i],&expected->page[i].identity)) {
            if(!stage)return pgx_decline(x,3+i);
            return pgx_error(x,LI2_FETCH_STALE,119+i);
        }
        if((e=fetch_backing_check(p,&c->backing[i])))return pgx_error(x,(unsigned)e,121+i);
        if(!stage)x->key.page[i].backing=c->backing[i];
        if(!span_source_backing_equal(&c->backing[i],&expected->page[i].backing)) {
            if(!stage)return pgx_decline(x,5+i);
            return pgx_error(x,LI2_FETCH_BACKING,123+i);
        }
    }
    /* Authenticate BOTH complete mappings/backings before either full read. */
    for(unsigned i=0;i<2;i++) {
        const volatile unsigned char *b=(const void *)expected->page[i].identity.address;
        for(size_t j=0;j<PAGE;j++) {
            unsigned char value=b[j];if(!stage)x->key.page[i].bytes[j]=value;
            c->bytes[i]=(unsigned)j+1;
            if(value!=expected->page[i].bytes[j]) {
                if(!stage)return pgx_decline(x,7+i);
                return pgx_error(x,LI2_FETCH_SOURCE,(long)(i*PAGE+j));
            }
        }
    }
    if(!pgx_epochs(t,x))return pgx_error(x,LI2_FETCH_STALE,125);
    c->complete=1;++x->checks;return 0;
}
int li2_pgx_source_prepare(const struct li2_pg_token *t,unsigned *accepted) {
    struct li2_pgx_source *x=&pg_source.peer_candidate;
    const struct li2_pgd_view *offer=li2_pgx_owner_offer(t);
    const struct li2_pgd_member *m=offer?&offer->member[1]:0;
    const struct li2_pg_sources *s=&pg_source.p.source;
    if(!accepted || !m || li2_pg_owner_phase(t)!=LI2_PG_BOUND ||
       pg_source.p.phase!=LI2_PGS_HELD || pg_source.domain.bound ||
       !pgsd_zero(&pg_source.domain,sizeof pg_source.domain) || !pgsd_zero(x,sizeof *x) ||
       !pgx_geometry(m->key) || li2_pgd_source_pair_equal(m->key,&s->key))return pgsd_bad(LI2_FETCH_STATE,126);
    *accepted=0;x->started=1;x->token=*t;x->member=m->identity;x->key.entry=m->key->entry;
    x->allocation_epoch=s->allocation_epoch;x->generation_epoch=s->generation_epoch;
    x->transactions_epoch=s->transactions_epoch;x->records_epoch=s->records_epoch;
    /* The actual owner supplied these two exact validated immutable tables. */
    const struct li2_pg_compact *primary=offer->member[0].plan;
    if(!primary || !li2_pgx_guard_union(primary,m->plan))return pgx_error(x,LI2_FETCH_STATE,127);
    x->table[0]=primary->table;x->table[1]=m->plan->table;
    int e=pgs_live(t);if(e)return pgx_error(x,(unsigned)e,128);
    e=pgx_check(t,x,m->key,LI2_PGX_PREPARE);if(e || x->declined)return e;
    x->complete=1;
    if(!li2_pgx_source_value(x,s,t,&m->identity,m->key,1))return pgx_error(x,LI2_FETCH_SOURCE,129);
    *accepted=1;return 0;
}
static int pgx_bound(const struct li2_pgd_view *v,unsigned checks) {
    const struct li2_pgx_source *x=&pg_source.domain.peer;
    if(v->count==1 || li2_pgd_source_pair_equal(v->member[0].key,v->member[1].key))
        return pgsd_zero(x,sizeof *x);
    return v->count==2 && checks>=2 && checks<=LI2_PGX_CHECKS &&
        li2_pgx_source_value(x,&pg_source.p.source,&v->token,&v->member[1].identity,v->member[1].key,checks) &&
        equal(&x->table[0],&v->member[0].plan->table,sizeof x->table[0]) &&
        equal(&x->table[1],&v->member[1].plan->table,sizeof x->table[1]);
}
static int pgx_bind(const struct li2_pg_token *t,const struct li2_pgd_view *v) {
    struct li2_pgx_source *x=&pg_source.domain.peer;
    if(!pgsd_zero(x,sizeof *x))return pgsd_bad(LI2_FETCH_STATE,130);
    if(v->count==1 || li2_pgd_source_pair_equal(v->member[0].key,v->member[1].key))return 0;
    if(!li2_pgx_source_value(&pg_source.peer_candidate,&pg_source.p.source,t,
        &v->member[1].identity,v->member[1].key,1))return pgsd_bad(LI2_FETCH_SOURCE,131);
    *x=pg_source.peer_candidate;
    return pgx_check(t,x,v->member[1].key,LI2_PGX_BIND);
}
static int pgx_live(const struct li2_pg_token *t,const struct li2_pgd_view *v,unsigned stage) {
    if(v->count==1 || li2_pgd_source_pair_equal(v->member[0].key,v->member[1].key))
        return pgsd_zero(&pg_source.domain.peer,sizeof pg_source.domain.peer)?0:pgsd_bad(LI2_FETCH_STATE,132);
    return pgx_check(t,&pg_source.domain.peer,v->member[1].key,stage);
}
