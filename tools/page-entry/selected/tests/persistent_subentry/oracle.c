/* Actual production predicates over synthetic owner/source/permission values.
   No physical query, decoder, generated instruction or guest runs here.
   The separate native all-head oracle qualifies emitted execution, not these
   scripted observations. No observation here is a publication capability. */
static _Alignas(4096) unsigned char arena[2][PE_PROOF_BYTES+2U*PE_ALLOC_BYTES];
static _Alignas(4096) unsigned char directory[LI2_JD_DOMAIN_BYTES];
static struct li2_pg_compact scratch_plan;
static unsigned checks[5];
static uintptr_t pair_base;
enum { LOOKUP,SELECT,ENTRY,LIFETIME,HISTORY };
#define CHECK(k,x) do {assert(x);++checks[k];} while(0)
#define REFUSE(k,field,value,call) do {__auto_type old=(field);(field)=(value); \
    CHECK(k,!(call));(field)=old;assert(call);} while(0)
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
static void head(struct li2_pg_compact *p,unsigned i,unsigned page,unsigned offset) {
    struct li2_pe_head *h=&p->head[i];struct li2_decoded *d=&p->original[i].decoded;
    *h=(struct li2_pe_head){.source_page=page,.source_offset=offset,.source_length=4,
        .generated_length=4,.kind=LI2_PE_NONE};
    *d=(struct li2_decoded){.abi_version=1,.decode_status=LI2_VALID,.available=15,
        .pc=p->page[page]+offset,.next_pc=p->page[page]+offset+4,.length=4,.code=1057};
    for(unsigned j=0;j<15;j++)d->bytes[j]=p->source[page][offset+j];
}
static void stored(unsigned index,uint64_t generation,uintptr_t root) {
    struct li2_ptr_slot *s=&pe.retained[index];struct li2_pg_generation *g=&s->generation;
    struct pe_payload *v=&s->publication;unsigned bank=ped_bank_for(root);
    memset(g,0,sizeof *g);memset(v,0,sizeof *v);
    g->proof=s->proof;g->generated=s->banks[bank].generated;g->spill=s->banks[bank].spill;g->layout=s->banks[bank].layout;
    s->identity.generation=generation;s->last_completed=40;
    s->banks[bank].virgin=0;s->banks[bank].prot=PROT_READ;
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
        .layout=g->layout,.plan_proof=2,.none_proof=1,.lifetime_version=1,.lifetime_mode=LI2_PGU_UNREGISTERED};
    memcpy(v->header.member_generation,g->member_generation,sizeof g->member_generation);
    memcpy(v->header.archive,pe_archive,32);memcpy(v->header.policy,pe_policy,32);v->source.entry=root;
    static const unsigned char nop[4]={0x0f,0x1f,0x40,0};
    for(unsigned j=0;j<2;j++) {
        v->source.page[j].identity=(struct li2_fetch_page){.address=pair_base+PAGE*j,.allocation=1,.generation=2,
            .offset=PAGE*j,.initial_extent=2*PAGE,.backing=SEALED,.object=0,
            .logical=PROT_READ|PROT_EXEC,.closed_prot=PROT_READ};
        struct li2_fetch_backing *b=&v->source.page[j].backing;
        b->retained_fd=7;b->seals=SEALS;b->seals_observed=b->stat_observed=1;
        b->stat.st_dev=1;b->stat.st_ino=2;b->stat.st_size=2*PAGE;b->stat.st_mode=0100400;
        for(unsigned k=0;k<PAGE;k++)v->source.page[j].bytes[k]=nop[k%4];
        v->plan.page[j]=v->source.page[j].identity.address;memcpy(v->plan.source[j],v->source.page[j].bytes,PAGE);
    }
    v->plan.version=LI2_PG_COMPACT_VERSION;v->plan.bytes=sizeof v->plan;v->plan.ready=1;
    v->plan.layout=g->layout;v->plan.table.address=v->header.table;v->plan.entry=root;
    v->plan.heads=68;v->plan.member_heads[0]=64;v->plan.member_heads[1]=4;v->plan.exits=1;
    v->plan.exit_pc[0]=pair_base+0xf00;
    for(unsigned i=0;i<68;i++)head(&v->plan,i,i/64,(unsigned)(root-pair_base)+4*(i%64));
    memcpy((void *)g->proof,v,sizeof *v);
    g->slots[2].started=g->slots[2].complete=1;g->slots[2].copied=g->slots[2].verified=PAGE;
    permission(&g->slots[2].seal,g->layout.slots,PAGE,PROT_READ);
    g->cell[2]=(struct pg_dispatch_cell_transition){.generation=generation,.serial=40,.started=1,.complete=1};
    query(&g->cell[2].mapping,g->spill,PAGE,PROT_READ|PROT_WRITE);
    s->registry_count=protected_count;memcpy(s->registry,protected,protected_count*sizeof *protected);
}
static struct li2_pg_rseq_progress unregistered(void) {
    return (struct li2_pg_rseq_progress){.token={&pe,40},.session=&pe.session,.pid=123,.tid=123,
        .seed_complete=1,.entry_complete=1,.close_complete=1,.domain_bound=1,
        .lifetime_mode=LI2_PGU_UNREGISTERED,.tls_complete=1,.fs=0x700000,.gs=0};
}
static struct li2_pgs_entry entry_value(unsigned slot,unsigned bank,unsigned at,
    const struct li2_pg_sources *s) {
    const struct li2_ptr_slot *v=&pe.retained[slot];struct li2_pgs_target target;
    assert(li2_pgs_head_lookup(&v->publication.plan,s->key.entry,&target)==1 && target.head==at);
    return (struct li2_pgs_entry){.token={&pe,s->serial},.transfer_serial=70,
        .generation=v->identity.generation,.build_serial=v->generation.build_serial,
        .anchor=s->anchor,.slot=slot,.bank=bank,.target=target,
        .row=v->publication.plan.head[at],.original=v->publication.plan.original[at],.complete=1};
}
static void completion(unsigned cell,unsigned count,unsigned first,unsigned second) {
    struct pda_completion *c=&pe.domain.completion[cell];memset(c,0,sizeof *c);
    c->id=cell+1;c->serial=40;c->count=count;c->complete=1;pe.domain.next_id=cell+1;
    const unsigned which[2]={first,second};
    c->source=(struct li2_pg_source_progress){.serial=40,.phase=LI2_PGS_RELEASED,
        .release_started=1,.release_complete=1,.opened_extents=3,.opened_pages=17,
        .closed_extents=3,.closed_pages=17,.layout=pe.retained[first].generation.layout};
    c->source.source=(struct li2_pg_sources){.complete=1,.serial=40,
        .anchor={.owner=(const void *)&pg_source,.sequence=100},.key=pe.retained[first].publication.source};
    c->fetch.sequence=100;c->fetch.complete=1;
    c->domain_source=(struct li2_pgd_source_progress){.token={&pe,40},.count=count,.bound=1,.opened=1,.closed=1,.released=1};
    c->domain_source.entry=entry_value(first,pda_bank(first),0,&c->source.source);
    c->rseq=unregistered();c->rseq.domain_count=count;
    query(&c->directory_closed,pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ);
    for(unsigned i=0;i<count;i++) {
        unsigned index=which[i];struct li2_ptr_slot *s=&pe.retained[index];struct pda_member_completion *m=&c->member[i];
        m->identity=(struct li2_pgd_ref){.generation=s->identity.generation,.slot=index,.bank=pda_bank(index),.proof=s->proof,
            .root=s->publication.source.entry,.layout=s->generation.layout};
        m->header=s->publication.header;m->source=s->publication.source;m->generation=s->generation;
        proof_query(&m->proof,s->proof);c->domain_source.ref[i]=m->identity;c->rseq.domain_ref[i]=m->identity;
        for(unsigned j=0;j<3;j++) {
            c->domain_source.open[i][j]=s->generation.open[j].query;
            c->domain_source.close[i][j]=s->generation.close[j].query;
        }
        s->claim=(struct li2_pgd_claim){.id=c->id,.cell=cell,.member=i,.valid=1};
    }
    memcpy(c->source.opened,c->domain_source.open[0],sizeof c->source.opened);
    memcpy(c->source.closed,c->domain_source.close[0],sizeof c->source.closed);
    assert(pda_receipt(c));
}
static void initialize_pair(uintptr_t base) {
    pair_base=base;
    memset(&pe,0,sizeof pe);memset(arena,0,sizeof arena);memset(directory,0,sizeof directory);
    memset(protected,0,sizeof protected);memset(&pg_source,0,sizeof pg_source);memset(&pg_rseq,0,sizeof pg_rseq);
    memset(records,0,sizeof records);memset(&tx,0,sizeof tx);pe_busy=pe_active=0;active=1;used=2;object_count=1;
    for(unsigned i=0;i<2;i++)records[i]=(struct owned_page){.address=pair_base+PAGE*i,.allocation=1,
        .generation=2,.offset=PAGE*i,.initial_extent=2*PAGE,.backing=SEALED,.object=0,
        .logical=PROT_READ|PROT_EXEC,.actual=PROT_READ,.live=1};
    pe.initialized=pe.registered=1;pe.next_serial=100;pe.next_generation=2;pe.p.phase=LI2_PG_CLOSED;
    pe.domain.directory=(uintptr_t)directory;pe.domain.allocated=pe.domain.registered=1;protected_count=0;
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
        s->generation.proof=s->proof;
    }
    stored(0,1,pair_base+0x200);stored(1,2,pair_base+0x800);pe.selection=pe.retained[0].identity;
    completion(0,1,0,0);completion(1,1,1,0);
    assert(ptr_storage() && ptr_selected() && pda_permitted(0) && pda_permitted(1));
}
static void initialize(void) {initialize_pair(0x400000);}
static void lookup_cases(void) {
    initialize();scratch_plan=pe.retained[0].publication.plan;
    struct li2_pg_compact *p=&scratch_plan;struct li2_pgs_target t;
    for(unsigned i=0;i<68;i++) {
        CHECK(LOOKUP,li2_pgs_head_lookup(p,p->original[i].decoded.pc,&t)==1 &&
            t.root==p->entry && t.head==i && t.member==i/64 && t.local==i%64 &&
            t.source_page==i/64 && t.generated==p->layout.generated[i/64]+512*(i%64) &&
            t.page[0]==0x400000 && t.page[1]==0x401000);
    }
    const uintptr_t absent[]={0,0x400201,0x400202,0x400203,0x400f00,0x402000,
        p->layout.generated[0],p->layout.stubs,p->layout.generated[1]+4*512};
    for(unsigned i=0;i<sizeof absent/sizeof *absent;i++)CHECK(LOOKUP,li2_pgs_head_lookup(p,absent[i],&t)==0);
#define BAD(field,value) do {__auto_type old=(field);(field)=(value); \
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x400200,&t)==-1);(field)=old;} while(0)
    BAD(p->version,0);BAD(p->bytes,0);BAD(p->ready,0);BAD(p->result,1);BAD(p->reserved,1);BAD(p->reserved2,1);
    BAD(p->heads,0);BAD(p->heads,129);BAD(p->member_heads[0],63);BAD(p->member_heads[1],3);
    BAD(p->entry,0x400204);BAD(p->page[0],0x401000);BAD(p->page[1],0x401001);BAD(p->page[1],UINT64_C(1)<<47);
    BAD(p->head[67].source_page,2);BAD(p->head[67].source_offset,4096);BAD(p->head[67].source_length,0);
    BAD(p->head[67].source_length,16);BAD(p->head[67].generated_length,0);BAD(p->head[67].generated_length,513);
    BAD(p->original[67].decoded.pc,0x401211);BAD(p->original[67].decoded.length,3);BAD(p->original[67].decoded.next_pc,0);
    BAD(p->layout.generated[0],0);BAD(p->layout.generated[0],1);
    BAD(p->layout.generated[0],(UINT64_C(1)<<47)-PAGE);
#undef BAD
    p->head[1]=p->head[0];p->original[1]=p->original[0];
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x400200,&t)==-1);
    *p=pe.retained[0].publication.plan;
    p->head[67].source_offset=4094;p->original[67].decoded.pc=0x401ffe;p->original[67].decoded.next_pc=0x402002;
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x401ffe,&t)==0); /* certified internal straddle is not an external fetch */
    *p=pe.retained[0].publication.plan;
    CHECK(LOOKUP,li2_pgs_head_lookup(0,0x400200,&t)==-1);
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x400200,0)==-1);
    unsigned char before[64];memcpy(before,p,sizeof before);
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x400200,(void *)p)==-1 && !memcmp(before,p,sizeof before));
    CHECK(LOOKUP,li2_pgs_head_lookup((void *)((uintptr_t)p+1),0x400200,&t)==-1);
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x400200,(void *)((uintptr_t)&t+1))==-1);
    CHECK(LOOKUP,li2_pgs_head_lookup((const void *)(UINTPTR_MAX-7),0x400200,&t)==-1);
    CHECK(LOOKUP,li2_pgs_head_lookup(p,0x400200,(void *)(UINTPTR_MAX-7))==-1);
}
static void blocked_choose(unsigned code,long detail) {
    struct pe_sub_choice choice;failure_code=0;failure_detail=0;
    if(!setjmp(failed)){(void)pe_sub_choose(0x400208,&choice);assert(!"invalid owner selected");}
    CHECK(SELECT,failure_code==code && failure_detail==detail);
}
static void selection_cases(void) {
    initialize();struct pe_sub_choice c;
    CHECK(SELECT,pe_sub_choose(0x400200,&c) && c.slot==0 && !c.subentry && !c.bank);
    CHECK(SELECT,pe_sub_choose(0x400800,&c) && c.slot==1 && !c.subentry && !c.bank);
    CHECK(SELECT,pe_sub_choose(0x400208,&c) && c.slot==0 && c.subentry && !c.bank);
    CHECK(SELECT,pe_sub_choose(0x401808,&c) && c.slot==1 && c.subentry && c.bank==0 &&
        c.page[0]==0x400000 && c.page[1]==0x401000 && !li2_pg_source_pair_advisory(0x401808));
    CHECK(SELECT,pe_sub_choose(0x400f00,&c) && !c.subentry); /* real frontier selects only the old cold attempt */
    CHECK(SELECT,pe_sub_choose(0x400201,&c) && !c.subentry); /* interior never a retained hit */
    CHECK(SELECT,!pe_sub_choose(0x402000,&c));CHECK(SELECT,!pe_sub_choose(0x401ffe,&c));
    /* Two separately completed certificates may overlap; lower slot wins
       unless the requested head is the other certificate's exact root. */
    stored(1,2,0x400208);completion(1,1,1,0);
    CHECK(SELECT,pe_sub_choose(0x400208,&c) && c.slot==1 && !c.subentry);
    stored(1,2,0x400800);head(&pe.retained[1].publication.plan,1,0,0x208);
    memcpy((void *)pe.retained[1].proof,&pe.retained[1].publication,sizeof(struct pe_payload));completion(1,1,1,0);
    CHECK(SELECT,pe_sub_choose(0x400208,&c) && c.slot==0 && c.subentry);
    CHECK(SELECT,pe_sub_choose(0x400208,&c) && c.slot==0 && c.subentry);
    pe.retained[1].claim.valid=0;blocked_choose(PE_RELEASE,41);pe.retained[1].claim.valid=1;
    pe.selection.owner=0;blocked_choose(PE_STATE,42);pe.selection.owner=&pe;
    pe.selected_slot=2;blocked_choose(PE_STATE,42);pe.selected_slot=0;
    struct pe_payload *v=(void *)pe.retained[0].proof;v->plan.head[2].generated_length=0;
    blocked_choose(PE_PUBLICATION,110);v->plan.head[2].generated_length=4;
    uintptr_t pages[2]={0x400000,0x401000};
    CHECK(SELECT,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,active,0,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,tx.guard,1,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,used,RECORDS+1,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,object_count,OBJECTS+1,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].live,0,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].generation,0,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].allocation,0,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].admitted,1,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].backing,ANONYMOUS,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].object,1,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].logical,PROT_READ,li2_pgs_source_pair_advisory(0x401208,pages));
    REFUSE(SELECT,records[1].actual,PROT_READ|PROT_EXEC,li2_pgs_source_pair_advisory(0x401208,pages));
    records[2]=records[1];records[2].admitted=1;used=3;
    CHECK(SELECT,!li2_pgs_source_pair_advisory(0x401208,pages));
    records[2].live=0;CHECK(SELECT,li2_pgs_source_pair_advisory(0x401208,pages));
    /* A root immediately below 2GiB is built in bank0. Its page2 head is
       above 2GiB: subentry must retain bank0 and the original pair, whereas
       the unchanged cold policy would choose bank1 and slide the pair. */
    initialize_pair(0x7ffff000);
    CHECK(SELECT,pe_sub_choose(0x80000208,&c) && c.slot==0 && c.subentry && c.bank==0 &&
        ped_bank_for(0x80000208)==1 && c.page[0]==0x7ffff000 && c.page[1]==0x80000000);
    CHECK(SELECT,!li2_pg_source_pair_advisory(0x80000208) &&
        li2_pgs_source_pair_advisory(0x80000208,c.page));
    initialize_pair(0x80000000);
    CHECK(SELECT,pe_sub_choose(0x80001808,&c) && c.slot==1 && c.subentry && c.bank==1);

}
static void activate(unsigned slot,unsigned at) {
    struct li2_ptr_slot *s=&pe.retained[slot];const struct pe_payload *p=(const void *)s->proof;
    pe.selected_slot=slot;pe.selection=s->identity;pe.selected_bank=pda_bank(slot);pe.subentry_selected=at!=0;
    pe.p.phase=LI2_PG_BOUND;pe.p.serial=100;pe.p.layout=s->generation.layout;
    pe.p.transfer_serial=70;pe.transfer.serial=70;pe.transfer.pc=p->plan.original[at].decoded.pc;
    pe.token=(struct li2_pg_token){&pe,100};pe.ref=(struct li2_fetch_ref){.owner=(const void *)&pg_source,.sequence=200};
    pg_source.token=pe.token;pg_source.p=(struct li2_pg_source_progress){.initialized=1,.serial=100,
        .phase=LI2_PGS_HELD,.layout=pe.p.layout};
    pg_source.p.source=(struct li2_pg_sources){.serial=100,.complete=1,.anchor=pe.ref,.key=p->source};
    pg_source.p.source.key.entry=pe.transfer.pc;pe.entry=(struct li2_pgs_entry){0};
    assert(!pe_sub_fill() && li2_pgs_owner_entry(&pe.token)==&pe.entry);
    pg_rseq=unregistered();pg_rseq.active=1;pg_rseq.close_complete=0;pg_rseq.token=pe.token;
}
static void entry_cases(void) {
    initialize();activate(1,66);struct li2_pgs_entry *e=&pe.entry;
    const struct pe_payload *p=pe_payload();struct li2_pg_sources *s=&pg_source.p.source;
    CHECK(ENTRY,e->slot==1 && e->bank==0 && e->target.head==66 && e->target.member==1 && e->target.local==2 &&
        e->target.root==0x400800 && e->target.pc==0x401808 && p->source.entry==0x400800);
    CHECK(ENTRY,!li2_pg_source_key_equal(&p->source,&s->key) && li2_pgd_source_pair_equal(&p->source,&s->key) &&
        pe_sub_source_matches(s,p));
    REFUSE(ENTRY,e->complete,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->reserved,1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->token.owner,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->token.serial,99,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.token.owner,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.token.serial,99,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->transfer_serial,69,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.p.transfer_serial,69,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.transfer.serial,69,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.transfer.pc,0x40180c,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->anchor.owner,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->anchor.sequence,199,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.ref.sequence,199,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->slot,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->bank,1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.selected_bank,1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->generation,1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->build_serial,10,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->target.root,0x400200,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->target.pc,0x401809,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->target.generated,e->target.generated+1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->target.head,65,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->target.heads,67,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->target.page[1],0x402000,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->row.source_page,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->row.source_offset,0x80c,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->row.kind,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->row.generated_length,5,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->original.decoded.code,1058,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,e->original.decoded.bytes[14],0xff,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->anchor.sequence,201,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->serial,99,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->complete,0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->key.entry,0x400800,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->key.page[0].bytes[4095],1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->key.page[1].bytes[0x816],1,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->key.page[1].identity.generation,3,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,s->key.page[1].backing.stat.st_ino,3,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pg_source.token.serial,99,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pg_source.p.layout.generated[0],0,li2_pgs_owner_entry(&pe.token));
    REFUSE(ENTRY,pe.selection.generation,1,li2_pgs_owner_entry(&pe.token));
    CHECK(ENTRY,pe_sub_fill()==PE_SOURCE); /* no second receipt over a completed one */
    pe.entry.complete=0;pe.subentry_selected=0;CHECK(ENTRY,pe_sub_fill()==PE_SOURCE);
    initialize();activate(0,0);p=pe_payload();s=&pg_source.p.source;
    CHECK(ENTRY,li2_pg_source_key_equal(&p->source,&s->key) && pe_sub_candidate(s,p));
    REFUSE(ENTRY,s->key.page[1].bytes[4095],1,pe_sub_candidate(s,p));
}
static void lifetime_cases(void) {
    initialize();activate(0,2);const struct pe_payload *p=pe_payload();
    CHECK(LIFETIME,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.active,0,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.seed_complete,0,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.first_error,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.unsafe_terminal,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.lifetime_mode,LI2_PGU_REGISTERED,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.word_observed,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.registration_epoch,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.address,0x700080,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.length,32,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.signature,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.tls_complete,0,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.fs_result,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.before.complete,1,pda_registration(p));
    REFUSE(LIFETIME,pg_rseq.current_observed.kind,1,pda_registration(p));
    /* Registered mode is distinct and still requires real descriptor receipts;
       these are explicitly scripted complete observations, not absent words. */
    struct pe_header h=p->header;h.lifetime_mode=LI2_PGU_REGISTERED;h.registered_epoch=7;
    h.rseq_address=0x700080;h.rseq_length=32;h.rseq_signature=0x53053053;
    struct li2_pg_rseq_progress r=pg_rseq;r.lifetime_mode=LI2_PGU_REGISTERED;r.word_observed=1;
    r.registration_epoch=7;r.address=h.rseq_address;r.page=0x700000;r.length=32;r.signature=h.rseq_signature;
    r.before.complete=r.observed.complete=1;r.registration_calls=1;
    CHECK(LIFETIME,pe_lifetime_matches(&h,&r));
    REFUSE(LIFETIME,r.word_observed,0,pe_lifetime_matches(&h,&r));
    REFUSE(LIFETIME,r.observed.complete,0,pe_lifetime_matches(&h,&r));
    REFUSE(LIFETIME,r.registration_epoch,8,pe_lifetime_matches(&h,&r));
}
static void history_cases(void) {
    initialize();memset(pe.domain.completion,0,sizeof pe.domain.completion);completion(0,2,0,1);
    struct pda_completion *c=&pe.domain.completion[0];
    /* Completion by value may name a genuine subentry, without changing the
       compiled root in either retained header/source certificate. */
    c->source.source.key.entry=0x401208;c->domain_source.entry=entry_value(0,0,66,&c->source.source);
    CHECK(HISTORY,pda_receipt(c) && pda_permitted(0) && pda_permitted(1));
    REFUSE(HISTORY,c->domain_source.entry.target.root,0x401208,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.token.owner,0,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.token.serial,39,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.slot,1,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.bank,1,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.generation,2,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.build_serial,11,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.entry.anchor.sequence,99,pda_receipt(c));
    REFUSE(HISTORY,c->source.source.key.page[1].bytes[4095],1,pda_receipt(c));
    REFUSE(HISTORY,c->member[0].source.entry,0x401208,pda_receipt(c));
    REFUSE(HISTORY,c->rseq.word_observed,1,pda_receipt(c));
    REFUSE(HISTORY,c->rseq.tls_complete,0,pda_receipt(c));
    REFUSE(HISTORY,c->domain_source.close[1][2].complete,0,pda_receipt(c));
    REFUSE(HISTORY,c->member[1].generation.close[2].sync_returned,0,pda_receipt(c));
    REFUSE(HISTORY,c->member[1].proof.part[1].complete,0,pda_receipt(c));
    REFUSE(HISTORY,c->rseq.domain_ref[1].generation,1,pda_receipt(c));
    REFUSE(HISTORY,c->source.release_complete,0,pda_receipt(c));
    REFUSE(HISTORY,c->fetch.held,1,pda_receipt(c));
    REFUSE(HISTORY,c->directory_closed.actual_prot,PROT_READ|PROT_WRITE,pda_receipt(c));
    pda_claim(0);CHECK(HISTORY,pe.domain.claimed[0]==1 && pda_permitted(1));
    pe.next_generation=3;stored(0,3,0x400a00);pe.selection=pe.retained[0].identity;
    CHECK(HISTORY,pda_receipt(c) && pda_permitted(1) && !pda_permitted(0));
    REFUSE(HISTORY,c->domain_source.entry.target.root,0x400a00,pda_receipt(c));
    REFUSE(HISTORY,pe.retained[1].claim.id,2,pda_permitted(1));
    pda_claim(1);CHECK(HISTORY,pe.domain.claimed[0]==3 && !pda_permitted(1));
}
int main(void) {
    lookup_cases();selection_cases();entry_cases();lifetime_cases();history_cases();
    assert(checks[LOOKUP]==112 && checks[SELECT]==33 && checks[ENTRY]==47 && checks[LIFETIME]==19 && checks[HISTORY]==25);
    printf("subentry-authority lookup=%u selection=%u entry=%u lifetime=%u history=%u synthetic_observations=1 native_credit=0\n",
        checks[LOOKUP],checks[SELECT],checks[ENTRY],checks[LIFETIME],checks[HISTORY]);
    return 0;
}
