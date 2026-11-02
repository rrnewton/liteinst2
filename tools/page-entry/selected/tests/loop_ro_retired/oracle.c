/* Actual observer and source comparator; supplied completed metadata only. */
static struct li2_pg_epoch before;
static unsigned char bank_before[4096];
static struct li2_pg_sources source,source_before;
static struct li2_pg_rseq_progress rseq,rseq_before;
static struct li2_lrx_counts want;
static unsigned checks,positives,negatives,wraps;
static void expect(int yes,unsigned line) {++checks;if(!yes){fprintf(stderr,"retired observer failure %u\n",line);exit(124);}}
#define CHECK(x) expect(!!(x),__LINE__)
static void snapshot(void) {memcpy(&before,&pe,sizeof pe);memcpy(bank_before,bank.page,4096);source_before=source;rseq_before=rseq;}
static void unchanged(void) {
    CHECK(!memcmp(&before,&pe,sizeof pe));CHECK(!memcmp(&source_before,&source,sizeof source));
    CHECK(!memcmp(&rseq_before,&rseq,sizeof rseq));CHECK(!memcmp(bank_before,bank.page,1696));
    CHECK(!memcmp(bank_before+2016,bank.page+2016,4096-2016));CHECK(!memcmp(&want,&bank.record.retired,sizeof want));
}
static void key(struct li2_pg_source_key *k,uintptr_t pc) {
    memset(k,0,sizeof *k);k->entry=pc;
    for(unsigned i=0;i<2;i++) {
        struct li2_fetch_page *p=&k->page[i].identity;
        p->address=0x400000+i*4096;p->allocation=7;p->generation=11;p->offset=i*4096;
        p->backing=ANONYMOUS;p->object=OBJECTS;p->logical=5;p->closed_prot=1;
        p->vma_first=0x400000;p->vma_end=0x402000;k->page[i].backing.retained_fd=-1;
        for(unsigned j=0;j<4096;j++)k->page[i].bytes[j]=(unsigned char)(j+i);
    }
}
static void setup(void) {
    memset(&pe,0xa5,sizeof pe);memset(&lrx_state,0,sizeof lrx_state);memset(&lrr_state,0,sizeof lrr_state);
    memset(bank.page,0,4096);memset(&source,0,sizeof source);memset(&rseq,0,sizeof rseq);memset(&want,0,sizeof want);
    li2_pgc_current=&bank.record.base.base.base.base;
    uint64_t *h=li2_pgc_current->header;h[0]=LI2_PGC_MAGIC;h[1]=6;h[2]=2016;h[3]=4096;h[15]=1;
    protected_count=1;protected[0]=(struct li2_fork_range){(uintptr_t)&lrx_state,(uintptr_t)&lrx_state+sizeof lrx_state};
    pe_busy=1;pe.selected_slot=0;pe.selected_bank=1;pe.warm=0;pe.p.serial=20;
    struct li2_ptr_slot *s=&pe.retained[0];struct li2_pg_generation *g=&s->generation;
    g->installed=g->complete=g->proof_complete=1;g->ready_generation=0;g->generation=5;g->build_serial=2;
    g->generated=0x900000;s->banks[0].generated=0x800000;s->banks[1].generated=0x900000;
    s->last_completed=3;s->registry_count=pe.candidate_registry_count=1;s->claim.valid=0;
    s->registry[0]=pe.candidate_registry[0]=(struct li2_fork_range){0x700000,0x701000};
    struct pe_header *v=&s->publication.header;v->generation=5;v->serial=2;
    v->lifetime_version=1;v->lifetime_mode=1;v->registered_epoch=9;v->rseq_address=0x600000;v->rseq_length=32;v->rseq_signature=0x53053053;
    key(&s->publication.source,0x400010);source.key=s->publication.source;source.complete=1;source.serial=20;
    rseq.active=rseq.seed_complete=1;rseq.lifetime_mode=1;rseq.registration_epoch=9;rseq.address=0x600000;rseq.length=32;rseq.signature=0x53053053;
    object_count=2;snapshot();lrx_initialize();CHECK(lrx_state.initialized==1);unchanged();
}
static void retire(void) {
    ++li2_pgc_current->group.retirements;++li2_pgc_current->group.offers;snapshot();lrx_retire();
    if(want.saves>=16)++want.overwrites;
    ++want.saves;unchanged();
    const struct lrx_retired *v=&lrx_state.ring[(lrx_state.next+15)%16];
    CHECK(v->valid==1 && v->retirement==want.saves && v->offer==PGC_VALUE(offers) && v->generation==5 &&
          v->build_serial==2 && v->completed_serial==3 && v->bank==1 && v->registry_count==1);
    CHECK(!memcmp(&v->source,&pe.retained[0].publication.source,sizeof v->source));
    CHECK(!memcmp(v->registry,pe.retained[0].registry,sizeof v->registry[0]));
}
static void query(unsigned category,unsigned rank,unsigned age,unsigned bank_change,unsigned registry_change,unsigned lifetime_change) {
    ++li2_pgc_current->group.offers;
    lrr_state.stage=2;lrr_state.failed=1;lrr_state.seen=31;lrr_state.passed=15;
    snapshot();lrx_source(&source,&rseq);unchanged();CHECK(lrx_test(4,0)==0);
    ++want.gate4;++want.search_done;
    if(category!=0)++want.root_seen;
    if(category>=2)++want.source_seen;
    if(category==3){++want.exact_seen;++want.retirement_rank[rank];++want.offer_age[age];}
    else if(category==0)++want.no_root;
    else if(category==1)++want.source_changed;
    else {++want.context_changed;want.bank_changed+=bank_change;want.registry_changed+=registry_change;want.lifetime_changed+=lifetime_change;}
    unchanged();
}
static void exact_and_mismatches(void) {
    setup();retire();query(3,0,0,0,0,0);++positives;
    for(unsigned n=0;n<13;n++) {
        setup();retire();unsigned category=1,bd=0,rd=0,ld=0;
        switch(n) {
        case 0:source.key.entry++;category=0;break;
        case 1:source.key.page[1].bytes[4095]^=1;break;
        case 2:source.key.page[0].identity.allocation++;break;
        case 3:source.key.page[1].identity.generation++;break;
        case 4:source.key.page[0].identity.vma_end+=4096;break;
        case 5:source.key.page[0].backing.stat_observed=1;break;
        case 6:pe.selected_bank=0;category=2;bd=1;break;
        case 7:pe.candidate_registry[0].end++;category=2;rd=1;break;
        case 8:pe.candidate_registry_count=0;category=2;rd=1;break;
        case 9:rseq.registration_epoch++;category=2;ld=1;break;
        case 10:rseq.address+=32;category=2;ld=1;break;
        case 11:rseq.lifetime_mode=2;category=2;ld=1;break;
        case 12:object_count=OBJECTS+1;break;
        }
        query(category,0,0,bd,rd,ld);++negatives;
    }
    setup();retire();rseq.length++;rseq.signature++;pe.selected_bank=0;pe.candidate_registry[0].first++;
    query(2,0,0,1,1,1);++negatives;
}
static void overwritten_history(void) {
    setup();
    for(unsigned i=0;i<17;i++){pe.retained[0].publication.source.entry=0x400010+i;retire();}
    source.key.entry=0x400010;query(0,0,0,0,0,0);++wraps;
    source.key.entry=0x400011;query(3,15,5,0,0,0);++wraps;
    source.key.entry=0x400020;query(3,0,2,0,0,0);++wraps;
    /* A newer same-source context mismatch cannot hide an older exact row. */
    setup();retire();pe.retained[0].registry[0].end++;retire();
    query(3,1,1,0,0,0);++wraps;
}
static void errors_and_returns(void) {
    setup();snapshot();lrx_test(4,0);want.gate4=1;want.error=4;unchanged();++negatives;
    CHECK(lrx_test(4,-7)==-7);CHECK(lrx_test(3,0)==0);unchanged();
    setup();bank.record.retired.gate4=want.gate4=UINT64_MAX;retire();
    lrr_state.stage=2;lrr_state.failed=1;lrr_state.seen=31;lrr_state.passed=15;
    ++li2_pgc_current->group.offers;snapshot();lrx_source(&source,&rseq);CHECK(lrx_test(4,0)==0);want.error=1;unchanged();++negatives;
    setup();pe.retained[0].generation.ready_generation=5;++li2_pgc_current->group.retirements;++li2_pgc_current->group.offers;
    snapshot();lrx_retire();want.error=7;unchanged();CHECK(lrx_state.count==0);++negatives;
    setup();retire();lrx_state.ring[0].valid=0;++li2_pgc_current->group.offers;
    lrr_state.stage=2;lrr_state.failed=1;lrr_state.seen=31;lrr_state.passed=15;
    snapshot();lrx_source(&source,&rseq);CHECK(lrx_test(4,0)==0);want.gate4=1;want.error=5;unchanged();++negatives;
    setup();snapshot();CHECK(lrx_test(4,-7)==-7 && lrx_test(4,9)==9 && lrx_test(3,0)==0);unchanged();++positives;
}
int main(void) {
    (void)pe_lifetime_matches;(void)pe_lifetime_stored;
    (void)lrr_begin;(void)lrr_evaluate;(void)lrr_test;(void)lrr_plan;(void)lrr_bound;(void)lrr_finish;
    exact_and_mismatches();overwritten_history();errors_and_returns();
    CHECK(positives==2 && negatives==18 && wraps==4);
    puts("{\"schema\":1,\"scope\":\"actual_retired_observer_supplied_metadata\",\"positives\":2,\"negative_cases\":18,\"ring_boundary_cases\":4,\"guest_executions\":0}");return 0;
}
