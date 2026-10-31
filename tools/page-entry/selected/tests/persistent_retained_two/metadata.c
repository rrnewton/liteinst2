/* Pure metadata authority checks. The prepare script supplies exact live
   controller types, equality/query predicates and the real ptr_* include.
   Permission/source/rseq observations below are synthetic predicate inputs;
   this test performs no permission change, decoder call or guest execution. */
static _Alignas(4096) unsigned char arena[LI2_PTR_SLOTS][PE_PROOF_BYTES+2U*PE_ALLOC_BYTES];
static struct li2_ptr_slot saved_slots[LI2_PTR_SLOTS];
static unsigned positives,refusals,selections,blocked_selections,byte_refusals;
static void query(struct li2_private_code_query *q,uintptr_t address,size_t n,int prot) {
    *q=(struct li2_private_code_query){.attempted=1,.complete=1,.first=address,.end=address+n,
        .pages_checked=n/PAGE,.expected_prot=prot,.actual_prot=prot};
}
static void proof_query(struct pg_proof_query *q,uintptr_t address) {
    query(&q->part[0],address,PG_PROOF_FIRST_BYTES,PROT_READ);
    query(&q->part[1],address+PG_PROOF_FIRST_BYTES,PE_PROOF_BYTES-PG_PROOF_FIRST_BYTES,PROT_READ);
}
static void permission(struct le_permission *p,uintptr_t address,size_t n) {
    *p=(struct le_permission){.started=1,.returned=1,.sync_started=1,.sync_returned=1,.complete=1,.prot=PROT_READ};
    query(&p->query,address,n,PROT_READ);
}
static void complete_at(unsigned index,uint64_t serial) {
    struct li2_ptr_slot *s=&pe.retained[index];struct ped_permit *p=&s->permit;
    s->last_completed=serial;p->serial=serial;p->source.serial=serial;p->rseq.token.serial=serial;
    s->generation.cell[2].serial=serial;
}
static void make_stored(unsigned index) {
    struct li2_ptr_slot *s=&pe.retained[index];struct li2_pg_generation *g=&s->generation;
    struct ped_permit *p=&s->permit;struct pe_payload *v=&s->publication;
    if(pe.next_generation<index+1)pe.next_generation=index+1;
    s->identity.generation=index+1;s->banks[0].virgin=0;s->banks[0].prot=PROT_READ;
    g->installed=g->complete=g->proof_complete=1;g->generation=index+1;g->ready_generation=g->generation;
    g->build_serial=10+index;g->plan_proofs=2;g->none_proofs=1;
    g->member_generation[0]=2*g->generation;g->member_generation[1]=2*g->generation+1;
    g->code_copied=g->code_verified=PE_CODE_BYTES;g->proof_zeroed=g->proof_verified=PE_PROOF_BYTES;
    g->proof_copied=sizeof(struct pe_payload);
    for(unsigned i=0;i<3;i++) {
        permission(&g->code_sealed[i],pg_extent(&g->layout,i),pg_extent_bytes(i));
        g->close[i]=g->code_sealed[i];p->close[i]=g->close[i];
    }
    g->proof_sealed=(struct pg_proof_permission){.started=1,.returned=1,.sync_started=1,.sync_returned=1,
        .complete=1,.prot=PROT_READ};proof_query(&g->proof_sealed.query,g->proof);
    v->header=(struct pe_header){.version=1,.serial=g->build_serial,.generation=g->generation,.registry=(uintptr_t)&pe,
        .generated=g->generated,.spill=g->spill,.table=g->proof+offsetof(struct pe_payload,plan.table),
        .layout=g->layout,.plan_proof=2,.none_proof=1,.registered_epoch=7,.rseq_address=0x700080,
        .rseq_length=32,.rseq_signature=0x53053053};
    memcpy(v->header.member_generation,g->member_generation,sizeof g->member_generation);
    memcpy(v->header.archive,pe_archive,32);memcpy(v->header.policy,pe_policy,32);
    v->source.entry=0x400200+0x200*index;
    for(unsigned i=0;i<2;i++) {
        v->source.page[i].identity=(struct li2_fetch_page){.address=0x400000+PAGE*i,.allocation=1,.generation=2,
            .offset=PAGE*i,.initial_extent=2*PAGE,.backing=1,.object=0,.logical=PROT_READ|PROT_EXEC,.closed_prot=PROT_READ};
        struct li2_fetch_backing *b=&v->source.page[i].backing;
        b->retained_fd=7;b->seals=SEALS;b->seals_observed=b->stat_observed=1;
        b->stat.st_dev=1;b->stat.st_ino=2;b->stat.st_size=2*PAGE;b->stat.st_mode=0100400;
        v->source.page[i].bytes[0]=0x90;
    }
    v->plan.version=LI2_PG_COMPACT_VERSION;v->plan.bytes=sizeof v->plan;v->plan.ready=1;
    v->plan.layout=g->layout;v->plan.table.address=v->header.table;v->plan.entry=v->source.entry;
    v->plan.heads=2;v->plan.member_heads[0]=2;v->plan.exits=1;
    for(unsigned i=0;i<2;i++){v->plan.page[i]=v->source.page[i].identity.address;memcpy(v->plan.source[i],v->source.page[i].bytes,PAGE);}
    memcpy((void *)g->proof,v,sizeof *v);
    p->valid=1;p->generation=g->generation;p->generated=g->generated;p->proof=g->proof;
    p->layout=g->layout;memcpy(p->member_generation,g->member_generation,sizeof g->member_generation);
    p->ref_sequence=100+index;p->fetch.sequence=p->ref_sequence;p->fetch.complete=1;
    query(&p->reset_slots,g->layout.slots,PAGE,PROT_READ);proof_query(&p->proof_query,g->proof);
    p->generation_source=v->source;
    p->source.phase=LI2_PGS_RELEASED;p->source.release_started=p->source.release_complete=1;
    p->source.source.complete=1;p->source.source.anchor.sequence=p->ref_sequence;p->source.source.key=v->source;
    p->source.closed_extents=3;p->source.closed_pages=17;p->source.layout=g->layout;
    for(unsigned i=0;i<3;i++)p->source.closed[i]=g->close[i].query;
    p->rseq.token.owner=&pe;p->rseq.seed_complete=p->rseq.entry_complete=p->rseq.close_complete=1;
    p->rseq.registration_epoch=7;p->rseq.address=v->header.rseq_address;
    p->rseq.length=v->header.rseq_length;p->rseq.signature=v->header.rseq_signature;
    g->cell[2]=(struct pg_dispatch_cell_transition){.generation=g->generation,.started=1,.complete=1};
    query(&g->cell[2].mapping,g->spill,PAGE,PROT_READ|PROT_WRITE);
    s->registry_count=protected_count;memcpy(s->registry,protected,protected_count*sizeof *protected);
    complete_at(index,20+10*index);
}
static void initialize(void) {
    memset(&pe,0,sizeof pe);memset(arena,0,sizeof arena);memset(protected,0,sizeof protected);
    pe.initialized=pe.registered=1;pe.next_serial=50;pe.p.phase=LI2_PG_CLOSED;
    protected_count=1;protected[0]=(struct li2_fork_range){(uintptr_t)&pe,(uintptr_t)&pe+sizeof pe};
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        struct li2_ptr_slot *s=&pe.retained[i];
        s->identity=(struct li2_ptr_slot_ref){.owner=&pe,.index=i};s->proof=(uintptr_t)arena[i];
        s->code_allocated=s->code_registered=2;s->proof_allocated=s->proof_registered=1;
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
    pe.selection=pe.retained[0].identity;assert(ptr_storage() && ptr_selected());
}
static void choice(uintptr_t pc,unsigned expected) {
    memcpy(saved_slots,pe.retained,sizeof saved_slots);
    assert(ptr_choose(pc)==expected);assert(!memcmp(saved_slots,pe.retained,sizeof saved_slots));++selections;
}
#define REFUSE(field,value,call) do { \
    __auto_type saved=(field);(field)=(value);assert(!(call));++refusals;(field)=saved;assert(call); \
} while(0)
static void rejected_choice(unsigned code,long detail) {
    memcpy(saved_slots,pe.retained,sizeof saved_slots);failure_code=0;failure_detail=0;
    if(!setjmp(failed)){(void)ptr_choose(0x400800);assert(!"invalid replacement accepted");}
    assert(failure_code==code && failure_detail==detail);
    assert(!memcmp(saved_slots,pe.retained,sizeof saved_slots));++blocked_selections;
}
int main(void) {
    initialize();choice(0x400800,0);
    make_stored(0);pe.selection=pe.retained[0].identity;assert(ptr_permitted(0));++positives;
    choice(0x400800,1);choice(0x400200,0);
    make_stored(1);
    assert(ptr_permitted(0) && ptr_permitted(1) && ptr_selected());positives+=3;
    choice(0x400200,0);choice(0x400400,1);choice(0x400800,0);
    complete_at(1,15);choice(0x400800,1);
    complete_at(1,20);choice(0x400800,0);complete_at(1,30);
    struct li2_ptr_slot *s=&pe.retained[0];struct li2_pg_generation *g=&s->generation;struct ped_permit *p=&s->permit;
    REFUSE(pe.selection.owner,0,ptr_selected());REFUSE(pe.selection.index,1,ptr_selected());
    REFUSE(pe.selection.generation,2,ptr_selected());REFUSE(pe.selection.reserved,1,ptr_selected());
    REFUSE(pe.selected_slot,LI2_PTR_SLOTS,ptr_selected());
    REFUSE(s->identity.owner,0,ptr_stored(0));REFUSE(s->identity.index,1,ptr_stored(0));
    REFUSE(s->identity.generation,2,ptr_stored(0));REFUSE(s->identity.reserved,1,ptr_stored(0));
    REFUSE(s->proof,pe.retained[1].proof,ptr_stored(0));
    REFUSE(g->proof,pe.retained[1].proof,ptr_stored(0));REFUSE(g->generation,2,ptr_stored(0));
    REFUSE(g->ready_generation,0,ptr_stored(0));REFUSE(g->proof_verified,PE_PROOF_BYTES-1,ptr_stored(0));
    REFUSE(g->layout.generated[1],g->layout.generated[0],ptr_stored(0));
    REFUSE(protected_count,RANGES+1,ptr_stored(0));
    REFUSE(p->valid,0,ptr_permitted(0));REFUSE(p->generation,2,ptr_permitted(0));
    REFUSE(p->proof,pe.retained[1].proof,ptr_permitted(0));REFUSE(p->serial,pe.next_serial+1,ptr_permitted(0));
    REFUSE(s->last_completed,0,ptr_permitted(0));REFUSE(p->ref_sequence,0,ptr_permitted(0));
    REFUSE(p->fetch.held,1,ptr_permitted(0));REFUSE(p->fetch.complete,0,ptr_permitted(0));
    REFUSE(p->source.release_complete,0,ptr_permitted(0));REFUSE(p->source.closed_pages,16,ptr_permitted(0));
    REFUSE(p->rseq.active,1,ptr_permitted(0));REFUSE(p->rseq.close_complete,0,ptr_permitted(0));
    REFUSE(p->rseq.address,p->rseq.address+8,ptr_permitted(0));
    REFUSE(p->proof_query.part[1].complete,0,ptr_permitted(0));
    REFUSE(p->proof_query.part[0].end,p->proof_query.part[0].end-PAGE,ptr_permitted(0));
    REFUSE(g->active_refs,1,ptr_permitted(0));REFUSE(g->incoming[1],1,ptr_permitted(0));
    REFUSE(g->cell[2].after,1,ptr_permitted(0));REFUSE(g->cell[2].generation,2,ptr_permitted(0));
    REFUSE(*(uint64_t *)(g->spill+32),1,ptr_permitted(0));
    REFUSE(*(unsigned char *)g->layout.slots,1,ptr_permitted(0));
    REFUSE(p->source.source.key.page[1].bytes[7],1,ptr_permitted(0));
    struct ped_permit saved=*p;*p=pe.retained[1].permit;
    assert(!ptr_permitted(0));++refusals;*p=saved;assert(ptr_permitted(0));
    p->close[1].sync_returned=g->close[1].sync_returned=0;
    assert(!ptr_permitted(0));++refusals;rejected_choice(PE_RELEASE,40);
    p->close[1].sync_returned=g->close[1].sync_returned=1;assert(ptr_permitted(0));
    p->valid=0;rejected_choice(PE_RELEASE,40);p->valid=1;
    assert(!pe_bytes());++positives;
    unsigned char *code=(void *)g->generated;code[117]=1;assert(pe_bytes()==PE_PUBLICATION);++byte_refusals;code[117]=0;
    unsigned char *proof=(void *)g->proof;proof[PE_PROOF_BYTES-1]=1;
    assert(pe_bytes()==PE_PUBLICATION);++byte_refusals;proof[PE_PROOF_BYTES-1]=0;assert(!pe_bytes());
    assert(positives==5 && refusals==40 && selections==8 && blocked_selections==2 && byte_refusals==2);
    printf("retained-two positives=%u refusals=%u selections=%u blocked=%u bytes=%u\n",
           positives,refusals,selections,blocked_selections,byte_refusals);
    return 0;
}
