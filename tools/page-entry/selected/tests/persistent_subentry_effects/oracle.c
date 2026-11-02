/* Additional selector tests over the original complete scripted owner fixture.
   Every old assertion runs first. These observations grant no native execution
   or source-permission credit; actual source preparation is still required. */
enum { COLD_PAIR,SAVED_ROOT,SOURCE_REFUSAL,PERMIT_REFUSAL,MATCH_REFUSAL };
static unsigned pair_checks[5];
#define PAIR_CHECK(k,x) do {assert(x);++pair_checks[k];} while(0)
#define PAIR_REFUSE(k,field,value,call) do {__auto_type saved=(field);(field)=(value); \
    PAIR_CHECK(k,!(call));(field)=saved;assert(call);} while(0)

static int selected_pair(uintptr_t pc,uintptr_t first,uintptr_t second,unsigned slot) {
    struct effects_sub_choice c;
    return effects_sub_choose(pc,&c)==1 && c.slot==slot && !c.subentry &&
        c.bank==ped_bank_for(pc) && c.page[0]==first && c.page[1]==second;
}
static int effects_accepts(uintptr_t pc) {
    struct effects_sub_choice c;return effects_sub_choose(pc,&c);
}
static void third_page(void) {
    records[2]=records[1];records[2].address=pair_base+2*PAGE;
    records[2].allocation=records[2].generation=3;
    records[2].offset=0;records[2].initial_extent=PAGE;records[2].object=1;
    object_count=2;used=3;
}
static void saved_second_root(uintptr_t base) {
    initialize_pair(base);struct li2_ptr_slot *s=&pe.retained[0];
    struct pe_payload *v=&s->publication;
    v->source.entry=v->plan.entry=pair_base+PAGE+0x500;
    head(&v->plan,0,1,0x500);
    memcpy((void *)s->proof,v,sizeof *v);
    completion(0,1,0,0);pe.domain.next_id=2;
    assert(ptr_storage() && ptr_selected() && pda_permitted(0) && pda_permitted(1));
}
static void blocked_effects(uintptr_t pc,unsigned code,long detail) {
    struct effects_sub_choice c;failure_code=0;failure_detail=0;
    if(!setjmp(failed)) {
        (void)effects_sub_choose(pc,&c);assert(!"invalid completed permit selected");
    }
    PAIR_CHECK(PERMIT_REFUSAL,failure_code==code && failure_detail==detail);
}
static void cold_pair_cases(void) {
    initialize();struct pe_sub_choice old;
    PAIR_CHECK(COLD_PAIR,selected_pair(0x400f00,0x400000,0x401000,0));
    PAIR_CHECK(COLD_PAIR,!pe_sub_choose(0x401500,&old) &&
        selected_pair(0x401500,0x400000,0x401000,0));
    PAIR_CHECK(COLD_PAIR,selected_pair(0x401ff1,0x400000,0x401000,0));
    third_page();
    PAIR_CHECK(COLD_PAIR,pe_sub_choose(0x401500,&old) && old.page[0]==0x401000 &&
        old.page[1]==0x402000 && selected_pair(0x401500,0x401000,0x402000,0));
    initialize_pair(0x7ffff000);
    PAIR_CHECK(COLD_PAIR,selected_pair(0x80000500,0x7ffff000,0x80000000,0));
    initialize_pair(UINT64_C(0x500000200000));
    PAIR_CHECK(COLD_PAIR,selected_pair(UINT64_C(0x500000201500),
        UINT64_C(0x500000200000),UINT64_C(0x500000201000),0));
    initialize_pair((UINT64_C(1)<<47)-3*PAGE);
    PAIR_CHECK(COLD_PAIR,selected_pair((UINT64_C(1)<<47)-2*PAGE+0x500,
        (UINT64_C(1)<<47)-3*PAGE,(UINT64_C(1)<<47)-2*PAGE,0));
    initialize_pair((UINT64_C(1)<<47)-2*PAGE);
    const uintptr_t last_pair[2]={(UINT64_C(1)<<47)-2*PAGE,(UINT64_C(1)<<47)-PAGE};
    PAIR_CHECK(SOURCE_REFUSAL,effects_pair_advisory(last_pair[1]+0x500,last_pair) &&
        !effects_accepts(last_pair[1]+0x500));
    initialize();records[0].address=0;records[1].address=PAGE;
    const uintptr_t zero_pair[2]={0,PAGE};
    PAIR_CHECK(SOURCE_REFUSAL,effects_pair_advisory(PAGE+0x500,zero_pair) &&
        !effects_accepts(PAGE+0x500));
    initialize();
    for(unsigned i=0;i<2;i++) {
        records[i].backing=ANONYMOUS;records[i].object=OBJECTS;records[i].initial_extent=0;
    }
    PAIR_CHECK(COLD_PAIR,selected_pair(0x401500,0x400000,0x401000,0));
    for(unsigned i=0;i<2;i++) {
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].object,OBJECTS-1,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].initial_extent,1,effects_accepts(0x401500));
    }
}
static void source_refusal_cases(void) {
    initialize();struct effects_sub_choice c;
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(0x401ff2,&c));
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(0x402000,&c));
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(0,&c));
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(PAGE,&c));
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(UINT64_C(1)<<47,&c));
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(0x401500,0));
    PAIR_REFUSE(SOURCE_REFUSAL,active,0,effects_accepts(0x401500));
    PAIR_REFUSE(SOURCE_REFUSAL,tx.guard,1,effects_accepts(0x401500));
    PAIR_REFUSE(SOURCE_REFUSAL,used,RECORDS+1,effects_accepts(0x401500));
    PAIR_REFUSE(SOURCE_REFUSAL,object_count,OBJECTS+1,effects_accepts(0x401500));
    for(unsigned i=0;i<2;i++) {
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].live,0,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].address,0x410000,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].allocation,0,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].generation,0,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].admitted,1,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].backing,ANONYMOUS,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].object,object_count,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].logical,PROT_READ,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].actual,PROT_READ|PROT_EXEC,effects_accepts(0x401500));
    }
    records[2]=records[1];records[2].generation=0;used=3;
    PAIR_CHECK(SOURCE_REFUSAL,!effects_sub_choose(0x401500,&c));
    records[2].live=0;
    PAIR_CHECK(COLD_PAIR,selected_pair(0x401500,0x400000,0x401000,0));
}
static void saved_root_cases(void) {
    saved_second_root(0x400000);struct pe_sub_choice old;
    PAIR_CHECK(SAVED_ROOT,!pe_sub_choose(0x401500,&old) &&
        selected_pair(0x401500,0x400000,0x401000,0));
    third_page();
    PAIR_CHECK(SAVED_ROOT,effects_forward_advisory(0x401500) &&
        selected_pair(0x401500,0x400000,0x401000,0));
    for(unsigned i=0;i<2;i++) {
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].generation,0,effects_accepts(0x401500));
        PAIR_REFUSE(SOURCE_REFUSAL,records[i].actual,PROT_READ|PROT_EXEC,effects_accepts(0x401500));
    }
    saved_second_root(0x400000);
    pe.retained[0].claim.valid=0;blocked_effects(0x401500,PE_RELEASE,40);
    saved_second_root(0x400000);
    pe.retained[0].identity.generation=3;blocked_effects(0x401500,PE_STATE,42);
    saved_second_root(0x400000);
    pe.retained[0].publication.source.page[0].identity.address=0x3ff000;
    blocked_effects(0x401500,PE_RELEASE,40);
    saved_second_root(0x400000);
    pe.retained[0].publication.source.page[1].identity.generation=3;
    blocked_effects(0x401500,PE_RELEASE,40);
    saved_second_root(0x400000);
    pe.retained[0].generation.close[0].sync_returned=0;
    blocked_effects(0x401500,PE_RELEASE,40);
    saved_second_root((UINT64_C(1)<<47)-2*PAGE);
    const uintptr_t last_pair[2]={(UINT64_C(1)<<47)-2*PAGE,(UINT64_C(1)<<47)-PAGE};
    PAIR_CHECK(SOURCE_REFUSAL,effects_pair_advisory(last_pair[1]+0x500,last_pair) &&
        !effects_accepts(last_pair[1]+0x500));
}
static void matching_cases(void) {
    saved_second_root(0x400000);activate(0,0);
    struct li2_pg_sources *s=&pg_source.p.source;const struct pe_payload *p=pe_payload();
    PAIR_CHECK(SAVED_ROOT,pe_sub_candidate(s,p) && pe_sub_source_matches(s,p));
    for(unsigned i=0;i<2;i++) {
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.allocation,2,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.generation,3,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.address,0x410000,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.offset,PAGE*(i+1),pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.object,1,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.backing,ANONYMOUS,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.logical,PROT_READ,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].identity.closed_prot,PROT_READ|PROT_EXEC,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].backing.stat.st_ino,3,pe_sub_candidate(s,p));
        PAIR_REFUSE(MATCH_REFUSAL,s->key.page[i].bytes[4095],1,pe_sub_candidate(s,p));
    }
}
int main(void) {
    assert(original_subentry_main()==0);
    cold_pair_cases();source_refusal_cases();saved_root_cases();matching_cases();
    assert(pair_checks[COLD_PAIR]==9 && pair_checks[SAVED_ROOT]==3 &&
        pair_checks[SOURCE_REFUSAL]==40 && pair_checks[PERMIT_REFUSAL]==5 && pair_checks[MATCH_REFUSAL]==20);
    printf("effects-source-pair cold=%u saved_root=%u source_refusals=%u permit_refusals=%u matching_refusals=%u synthetic_observations=1 native_credit=0\n",
        pair_checks[COLD_PAIR],pair_checks[SAVED_ROOT],pair_checks[SOURCE_REFUSAL],
        pair_checks[PERMIT_REFUSAL],pair_checks[MATCH_REFUSAL]);
    return 0;
}
