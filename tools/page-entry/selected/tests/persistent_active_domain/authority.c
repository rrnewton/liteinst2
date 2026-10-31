/* Pure synthetic metadata inputs to the actual runtime predicates. These are
   not kernel permission receipts and grant no native/execution credit. */
static _Alignas(4096) unsigned char arena[2][PE_PROOF_BYTES+2U*PE_ALLOC_BYTES];
static _Alignas(4096) unsigned char directory[LI2_JD_DOMAIN_BYTES];
static struct li2_pg_epoch saved;
static unsigned positives,refusals,claims,reuse,bytes,blocked,permissions,directories,owners;
static void query(struct li2_private_code_query *q,uintptr_t a,size_t n,int prot) {
    *q=(struct li2_private_code_query){.attempted=1,.complete=1,.first=a,.end=a+n,
        .pages_checked=n/PAGE,.expected_prot=prot,.actual_prot=prot};
}
static void proof_query(struct pg_proof_query *q,uintptr_t a) {
    query(&q->part[0],a,PG_PROOF_FIRST_BYTES,PROT_READ);
    query(&q->part[1],a+PG_PROOF_FIRST_BYTES,PE_PROOF_BYTES-PG_PROOF_FIRST_BYTES,PROT_READ);
}
static void permission(struct le_permission *p,uintptr_t a,size_t n,int prot) {
    *p=(struct le_permission){.started=1,.returned=1,.sync_started=1,.sync_returned=1,.complete=1,.prot=prot};
    query(&p->query,a,n,prot);
}
/* Only this physical observation is stubbed. The actual controller directory
   construction, full-byte check and rejection predicates are extracted. */
static int pe_permission(uintptr_t a,size_t n,int prot,struct le_permission *p) {
    assert(a==(uintptr_t)directory && n==sizeof directory && !p->started);
    assert(prot==PROT_READ || prot==(PROT_READ|PROT_WRITE));
    permission(p,a,n,prot);++permissions;return 0;
}
static void stored(unsigned index,uint64_t generation) {
    struct li2_ptr_slot *s=&pe.retained[index];struct li2_pg_generation *g=&s->generation;
    struct pe_payload *v=&s->publication;
    s->identity.generation=generation;s->last_completed=40;
    s->banks[0].virgin=0;s->banks[0].prot=PROT_READ;
    g->installed=g->complete=g->proof_complete=1;g->generation=generation;g->ready_generation=generation;
    g->build_serial=10+index;g->plan_proofs=2;g->none_proofs=1;
    g->member_generation[0]=2*generation;g->member_generation[1]=2*generation+1;
    g->code_copied=g->code_verified=PE_CODE_BYTES;g->proof_zeroed=g->proof_verified=PE_PROOF_BYTES;
    g->proof_copied=sizeof *v;
    for(unsigned j=0;j<3;j++) {
        permission(&g->code_sealed[j],pg_extent(&g->layout,j),pg_extent_bytes(j),PROT_READ);
        g->close[j]=g->code_sealed[j];
        permission(&g->open[j],pg_extent(&g->layout,j),pg_extent_bytes(j),PROT_READ|PROT_EXEC);
    }
    g->proof_sealed=(struct pg_proof_permission){.started=1,.returned=1,.sync_started=1,
        .sync_returned=1,.complete=1,.prot=PROT_READ};proof_query(&g->proof_sealed.query,g->proof);
    v->header=(struct pe_header){.version=1,.serial=g->build_serial,.generation=generation,.registry=(uintptr_t)&pe,
        .generated=g->generated,.spill=g->spill,.table=g->proof+offsetof(struct pe_payload,plan.table),
        .layout=g->layout,.plan_proof=2,.none_proof=1,.registered_epoch=7,.rseq_address=0x700080,
        .rseq_length=32,.rseq_signature=0x53053053};
    memcpy(v->header.member_generation,g->member_generation,sizeof g->member_generation);
    memcpy(v->header.archive,pe_archive,32);memcpy(v->header.policy,pe_policy,32);
    v->source.entry=0x400200+0x200*index;
    for(unsigned j=0;j<2;j++) {
        v->source.page[j].identity=(struct li2_fetch_page){.address=0x400000+PAGE*j,.allocation=1,.generation=2,
            .offset=PAGE*j,.initial_extent=2*PAGE,.backing=1,.object=0,
            .logical=PROT_READ|PROT_EXEC,.closed_prot=PROT_READ};
        struct li2_fetch_backing *b=&v->source.page[j].backing;
        b->retained_fd=7;b->seals=SEALS;b->seals_observed=b->stat_observed=1;
        b->stat.st_dev=1;b->stat.st_ino=2;b->stat.st_size=2*PAGE;b->stat.st_mode=0100400;
        v->source.page[j].bytes[0]=0x90;
    }
    v->plan.version=LI2_PG_COMPACT_VERSION;v->plan.bytes=sizeof v->plan;v->plan.ready=1;
    v->plan.layout=g->layout;v->plan.table.address=v->header.table;v->plan.entry=v->source.entry;
    v->plan.heads=2;v->plan.member_heads[0]=2;v->plan.exits=1;
    for(unsigned j=0;j<2;j++){v->plan.page[j]=v->source.page[j].identity.address;memcpy(v->plan.source[j],v->source.page[j].bytes,PAGE);}
    memcpy((void *)g->proof,v,sizeof *v);
    g->slots[2].started=g->slots[2].complete=1;g->slots[2].copied=g->slots[2].verified=PAGE;
    permission(&g->slots[2].seal,g->layout.slots,PAGE,PROT_READ);
    g->cell[2]=(struct pg_dispatch_cell_transition){.generation=generation,.serial=40,.started=1,.complete=1};
    query(&g->cell[2].mapping,g->spill,PAGE,PROT_READ|PROT_WRITE);
    s->registry_count=protected_count;memcpy(s->registry,protected,protected_count*sizeof *protected);
}
static void initialize(void) {
    memset(&pe,0,sizeof pe);memset(arena,0,sizeof arena);memset(directory,0,sizeof directory);
    memset(protected,0,sizeof protected);pe.initialized=pe.registered=1;pe.next_serial=100;pe.next_generation=2;
    pe.p.phase=LI2_PG_CLOSED;pe.domain.directory=(uintptr_t)directory;pe.domain.allocated=pe.domain.registered=1;
    pe.domain.next_id=1;protected_count=0;
    protected[protected_count++]=(struct li2_fork_range){(uintptr_t)&pe,(uintptr_t)&pe+sizeof pe};
    protected[protected_count++]=(struct li2_fork_range){(uintptr_t)directory,(uintptr_t)directory+sizeof directory};
    for(unsigned i=0;i<2;i++) {
        struct li2_ptr_slot *s=&pe.retained[i];s->identity=(struct li2_ptr_slot_ref){.owner=&pe,.index=i};
        s->proof=(uintptr_t)arena[i];s->code_allocated=s->code_registered=2;s->proof_allocated=s->proof_registered=1;
        protected[protected_count++]=(struct li2_fork_range){s->proof,s->proof+PE_PROOF_BYTES};
        for(unsigned j=0;j<2;j++) {
            struct ped_bank *b=&s->banks[j];b->generated=s->proof+PE_PROOF_BYTES+j*PE_ALLOC_BYTES;
            b->layout=pg_layout(b->generated);b->spill=b->layout.spill;b->allocated=b->registered=b->virgin=1;
            b->prot=PROT_READ|PROT_WRITE;
            protected[protected_count++]=(struct li2_fork_range){b->generated,b->generated+PE_ALLOC_BYTES};
        }
        s->generation.proof=s->proof;s->generation.generated=s->banks[0].generated;
        s->generation.spill=s->banks[0].spill;s->generation.layout=s->banks[0].layout;
    }
    for(unsigned i=0;i<2;i++)stored(i,i+1);
    pe.selection=pe.retained[0].identity;assert(ptr_storage() && ptr_selected());
    struct pda_completion *c=&pe.domain.completion[0];c->id=1;c->serial=40;c->count=2;c->complete=1;
    c->source=(struct li2_pg_source_progress){.serial=40,.phase=LI2_PGS_RELEASED,
        .release_started=1,.release_complete=1,.opened_extents=3,.opened_pages=17,
        .closed_extents=3,.closed_pages=17,.layout=pe.retained[0].generation.layout};
    c->source.source.complete=1;c->source.source.serial=40;c->source.source.anchor.sequence=100;
    c->source.source.key=pe.retained[0].publication.source;c->fetch.sequence=100;c->fetch.complete=1;
    c->domain_source=(struct li2_pgd_source_progress){.token={&pe,40},.count=2,.bound=1,.opened=1,.closed=1,.released=1};
    c->rseq=(struct li2_pg_rseq_progress){.token={&pe,40},.seed_complete=1,.entry_complete=1,
        .close_complete=1,.domain_bound=1,.domain_count=2,.registration_epoch=7,.address=0x700080,
        .length=32,.signature=0x53053053};
    query(&c->directory_closed,pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ);
    for(unsigned i=0;i<2;i++) {
        struct li2_ptr_slot *s=&pe.retained[i];struct pda_member_completion *m=&c->member[i];
        m->identity=(struct li2_pgd_ref){.generation=i+1,.slot=i,.bank=0,.proof=s->proof,
            .root=s->publication.source.entry,.layout=s->generation.layout};
        m->header=s->publication.header;m->source=s->publication.source;m->generation=s->generation;
        proof_query(&m->proof,s->proof);c->domain_source.ref[i]=m->identity;c->rseq.domain_ref[i]=m->identity;
        for(unsigned j=0;j<3;j++) {
            c->domain_source.open[i][j]=s->generation.open[j].query;
            c->domain_source.close[i][j]=s->generation.close[j].query;
        }
        s->claim=(struct li2_pgd_claim){.id=1,.cell=0,.member=i,.valid=1};
    }
    memcpy(c->source.opened,c->domain_source.open[0],sizeof c->source.opened);
    memcpy(c->source.closed,c->domain_source.close[0],sizeof c->source.closed);
    assert(pda_receipt(c) && pda_permitted(0) && pda_permitted(1));saved=pe;
}
#define REFUSE(field,value,call) do { __auto_type old=(field);(field)=(value); \
    assert(!(call));++refusals;(field)=old;assert(call); } while(0)
static void blocked_claim(unsigned slot) {
    failure_code=0;failure_detail=0;
    if(!setjmp(failed)){pda_claim(slot);assert(!"bad claim accepted");}
    assert(failure_code==PE_RELEASE && failure_detail==80);++blocked;
}
int main(void) {
    initialize();positives+=3;
    struct pda_completion *c=&pe.domain.completion[0];struct li2_ptr_slot *s=&pe.retained[0];
    REFUSE(pe.selection.owner,0,ptr_selected());REFUSE(pe.selection.index,1,ptr_selected());
    REFUSE(pe.selection.generation,2,ptr_selected());REFUSE(pe.selected_slot,2,ptr_selected());
    REFUSE(s->claim.valid,0,pda_permitted(0));REFUSE(s->claim.id,2,pda_permitted(0));
    REFUSE(s->claim.cell,3,pda_permitted(0));REFUSE(s->claim.member,1,pda_permitted(0));
    REFUSE(s->claim.reserved,1,pda_permitted(0));REFUSE(pe.domain.claimed[0],1,pda_permitted(0));
    REFUSE(pe.domain.claimed[0],4,pda_permitted(0));REFUSE(c->complete,0,pda_receipt(c));
    REFUSE(c->count,3,pda_receipt(c));REFUSE(c->member[1].identity.slot,0,pda_receipt(c));
    REFUSE(c->domain_source.closed,0,pda_receipt(c));REFUSE(c->domain_source.released,0,pda_receipt(c));
    REFUSE(c->domain_source.close[1][2].complete,0,pda_receipt(c));
    REFUSE(c->member[1].generation.close[2].sync_returned,0,pda_receipt(c));
    REFUSE(c->member[1].generation.open[0].returned,0,pda_receipt(c));
    REFUSE(c->member[1].generation.domain_refs,1,pda_receipt(c));
    REFUSE(c->member[1].generation.cell[2].after,1,pda_receipt(c));
    REFUSE(c->member[1].proof.part[1].complete,0,pda_receipt(c));
    REFUSE(c->rseq.close_complete,0,pda_receipt(c));REFUSE(c->rseq.domain_ref[1].generation,1,pda_receipt(c));
    REFUSE(c->source.release_complete,0,pda_receipt(c));REFUSE(c->fetch.held,1,pda_receipt(c));
    REFUSE(c->directory_closed.actual_prot,PROT_READ|PROT_WRITE,pda_receipt(c));
    REFUSE(c->member[1].source.page[1].bytes[7],1,pda_receipt(c));
    assert(!pe_bytes());++positives;
    unsigned char *code=(void *)s->generation.generated;code[117]=1;assert(pe_bytes()==PE_PUBLICATION);++bytes;code[117]=0;
    unsigned char *proof=(void *)s->proof;proof[PE_PROOF_BYTES-1]=1;assert(pe_bytes()==PE_PUBLICATION);++bytes;proof[PE_PROOF_BYTES-1]=0;
    pe.domain.work.receipt=3;assert(!choose_receipt() && pe.domain.work.receipt==1);++reuse;
    pe.domain.completion[1].id=99;pe.domain.completion[2].id=99;
    pe.domain.work.receipt=3;assert(choose_receipt()==PE_RELEASE && pe.domain.work.receipt==3);++reuse;
    pe=saved;pda_claim(0);++claims;assert(pe.domain.claimed[0]==1 && pda_permitted(1));++positives;
    blocked_claim(0);assert(pe.domain.claimed[0]==1 && pda_permitted(1));
    /* Replace A's actual payload/generation. B claims the immutable saved A
       closure, never the retired A payload; this is the required causal case. */
    pe.next_generation=3;stored(0,3);pe.selection=pe.retained[0].identity;
    assert(pda_receipt(c) && pda_permitted(1) && !pda_permitted(0));positives+=2;
    pda_claim(1);++claims;assert(pe.domain.claimed[0]==3 && !pda_permitted(1));blocked_claim(1);
    pe.domain.work.receipt=3;assert(!choose_receipt() && pe.domain.work.receipt==0);++reuse;
    /* Coherent stale claim after reusing the cell still fails its identity. */
    pe.retained[1].claim=saved.retained[1].claim;c->id=2;pe.domain.next_id=2;pe.domain.claimed[0]=0;
    assert(!pda_permitted(1));++refusals;blocked_claim(1);
    pe=saved;
    for(unsigned i=0;i<2;i++)memcpy((void *)pe.retained[i].proof,&pe.retained[i].publication,sizeof(struct pe_payload));
    assert(ptr_choose(0x400200)==0 && ptr_choose(0x400400)==1);positives+=2;
    pe.p.serial=40;pe.domain.work.view.count=2;
    for(unsigned i=0;i<2;i++) {
        struct pe_payload *v=(void *)pe.retained[i].proof;
        for(unsigned j=0;j<2;j++)v->plan.original[j].decoded.pc=v->source.entry+4*j;
        pe.domain.work.view.member[i]=(struct li2_pgd_member){
            .identity=c->member[i].identity,.plan=&v->plan,.key=&v->source};
    }
    for(unsigned i=0;i<2;i++)for(unsigned j=0;j<3;j++) {
        uintptr_t a=pg_extent(&pe.domain.work.view.member[i].identity.layout,j);
        assert(recovery_member(a)==(int)i);++owners;
        assert(recovery_member(a+pg_extent_bytes(j)-1)==(int)i);++owners;
    }
    const uintptr_t excluded[]={pe.retained[0].generation.spill,pe.retained[1].generation.spill,
        pe.domain.directory,0x400200};
    for(unsigned i=0;i<4;i++){assert(recovery_member(excluded[i])==PE_EVENT);++owners;}
    struct li2_pg_layout actual=pe.domain.work.view.member[1].identity.layout;
    pe.domain.work.view.member[1].identity.layout=pe.domain.work.view.member[0].identity.layout;
    assert(recovery_member(pe.retained[0].generation.generated)==PE_PUBLICATION);++owners;
    pe.domain.work.view.member[1].identity.layout=actual;
    assert(!pda_directory_seal() && permissions==2 && pda_directory_equal());++directories;
    assert(pe.domain.work.directory.count==4 && pe.domain.work.directory.row[2].slot==1 &&
        pe.domain.work.directory.row[2].generated==pe.retained[1].generation.layout.generated[0]);
    directory[32+8]^=1;assert(!pda_directory_equal());++refusals;directory[32+8]^=1;
    assert(pda_directory_equal());
    memset(&pe.domain.work.directory,0,sizeof pe.domain.work.directory);
    memset(&pe.domain.work.directory_write,0,sizeof pe.domain.work.directory_write);
    memset(&pe.domain.work.directory_seal,0,sizeof pe.domain.work.directory_seal);
    ((struct pe_payload *)pe.retained[1].proof)->plan.original[0].decoded.pc=
        ((struct pe_payload *)pe.retained[0].proof)->plan.original[0].decoded.pc;
    assert(pda_directory_seal()==PE_PLAN && permissions==2);++directories;
    assert(positives==9 && refusals==30 && claims==2 && reuse==3 && bytes==2 && blocked==3 && directories==2 && owners==17);
    printf("active-domain-authority positives=%u refusals=%u claims=%u reuse=%u bytes=%u blocked=%u directories=%u owners=%u\n",
        positives,refusals,claims,reuse,bytes,blocked,directories,owners);
    return 0;
}
