/* Included by the existing protected source owner only in the new profile. */
int li2_pgs_head_lookup(const struct li2_pg_compact *p,uintptr_t pc,struct li2_pgs_target *out) {
    if(!out || !p || (uintptr_t)out%_Alignof(struct li2_pgs_target) ||
       (uintptr_t)p%_Alignof(struct li2_pg_compact))return -1;
    uintptr_t a=(uintptr_t)p,b=(uintptr_t)out;
    if(a>UINTPTR_MAX-sizeof *p || b>UINTPTR_MAX-sizeof *out ||
       (a<b+sizeof *out && b<a+sizeof *p))return -1;
    *out=(struct li2_pgs_target){0};
    if(p->version!=LI2_PG_COMPACT_VERSION || p->bytes!=sizeof *p || p->ready!=1 ||
       p->result || p->reserved || p->reserved2 || !p->heads || p->heads>LI2_PG_HEADS ||
       p->member_heads[0]!=(p->heads<64?p->heads:64) ||
       p->member_heads[1]!=(p->heads>64?p->heads-64:0) ||
       !p->entry || p->page[0]>=p->page[1] || (p->page[0]&(PAGE-1)) ||
       (p->page[1]&(PAGE-1)) || p->page[1]>(UINT64_C(1)<<47)-PAGE)return -1;
    unsigned found=LI2_PG_HEADS;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_pe_head *h=&p->head[i];const struct li2_decoded *d=&p->original[i].decoded;
        if(h->source_page>=2 || h->source_offset>=PAGE || !h->source_length || h->source_length>15 ||
           d->pc!=p->page[h->source_page]+h->source_offset || d->length!=h->source_length ||
           d->next_pc!=d->pc+d->length || !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES)
            return -1;
        if(d->pc==pc) {if(found!=LI2_PG_HEADS)return -1;found=i;}
    }
    if(p->original[0].decoded.pc!=p->entry)return -1;
    if(found==LI2_PG_HEADS)return 0;
    const struct li2_pe_head *h=&p->head[found];
    /* A certified internal straddle does not enlarge the real singleton
       fifteen-byte external fetch contract. */
    if(h->source_offset>PAGE-15)return 0;
    unsigned member=found/64,local=found%64;
    uintptr_t base=p->layout.generated[member];
    if(!base || (base&(PAGE-1)) || base>(UINT64_C(1)<<47)-LI2_PE_IMAGE_BYTES)return -1;
    *out=(struct li2_pgs_target){1,p->heads,found,member,local,h->source_page,
        p->entry,pc,base+(uintptr_t)local*LI2_PE_SLOT_BYTES,{p->page[0],p->page[1]}};
    return 1;
}
int li2_pgs_entry_source(const struct li2_pgs_entry *e,uintptr_t root,
    const struct li2_pg_sources *actual,const struct li2_pg_layout *layout) {
    if(!e || !root || !actual || !layout || e->complete!=1 || e->reserved ||
       !e->token.owner || !e->token.serial || e->token.serial!=actual->serial ||
       !e->transfer_serial || !e->generation || !e->build_serial || e->build_serial>e->token.serial ||
       e->slot>=2 || e->bank>1 || actual->complete!=1 || actual->reserved ||
       !e->anchor.owner || !e->anchor.sequence ||
       !equal(&e->anchor,&actual->anchor,sizeof e->anchor))return 0;
    const struct li2_pgs_target *t=&e->target;const struct li2_pe_head *h=&e->row;
    const struct li2_decoded *d=&e->original.decoded;
    if(t->version!=1 || !t->heads || t->heads>LI2_PG_HEADS || t->head>=t->heads ||
       t->member!=t->head/64 || t->local!=t->head%64 || t->source_page>=2 ||
       t->root!=root || t->pc!=actual->key.entry ||
       t->generated!=layout->generated[t->member]+(uintptr_t)t->local*LI2_PE_SLOT_BYTES ||
       (t->pc==t->root && t->head) ||
       (t->pc!=t->root && !t->head) || h->source_page!=t->source_page ||
       h->source_offset>PAGE-15 || !h->source_length || h->source_length>15 ||
       !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES ||
       d->abi_version!=1 || d->decode_status!=LI2_VALID || d->pc!=t->pc ||
       d->next_pc!=t->pc+h->source_length || d->length!=h->source_length || d->available!=15 ||
       t->pc!=t->page[t->source_page]+h->source_offset ||
       (h->kind!=LI2_PE_NONE && h->kind!=LI2_PE_MOV && h->kind!=LI2_PG_DISPATCH
#ifdef LI2_ADD_GUARD
        && h->kind!=LI2_PG_ADD
#endif
       ))return 0;
    for(unsigned i=0;i<2;i++)if(t->page[i]!=actual->key.page[i].identity.address)return 0;
    return equal(d->bytes,actual->key.page[t->source_page].bytes+h->source_offset,15);
}
int li2_pgs_entry_value(const struct li2_pgs_entry *e,const struct li2_pg_source_key *compiled,
    const struct li2_pg_sources *actual,const struct li2_pg_layout *layout) {
    return compiled && li2_pgs_entry_source(e,compiled->entry,actual,layout) &&
        li2_pgd_source_pair_equal(compiled,&actual->key) &&
        (e->target.pc!=e->target.root || li2_pg_source_key_equal(compiled,&actual->key));
}
int li2_pgs_source_pair_advisory(uintptr_t pc,const uintptr_t pages[2]) {
    if(!pages || pages[0]>=pages[1] || (pages[0]&(PAGE-1)) || (pages[1]&(PAGE-1)) ||
       pages[1]>(UINT64_C(1)<<47)-PAGE || !active || tx.guard || used>RECORDS || object_count>OBJECTS)
        return 0;
    unsigned found=0;
    for(unsigned j=0;j<2;j++) {
        if(pc>=pages[j] && pc-pages[j]<=PAGE-15)++found;
        const struct owned_page *p=0;
        for(size_t i=used;i;i--)if(records[i-1].live && records[i-1].address==pages[j]) {
            p=&records[i-1];break;
        }
        if(!p || !p->allocation || !p->generation || p->admitted || p->backing!=SEALED ||
           p->object>=object_count || p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ)return 0;
    }
    return found==1;
}
