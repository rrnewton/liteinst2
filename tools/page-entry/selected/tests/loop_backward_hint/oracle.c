/* Additive actual-loader component. The original oracle and its exact output
   run first. Controlled classification/key insertion is not evidence that an
   owner completed a cancellation; the production call site alone owns that. */
#define main loop_negative_hint_original_main
#include "tests/loop_negative_hint/oracle.c"
#undef main

static struct li2_pg_plan refusal_plan;
static struct li2_pg_miss refusal_miss;
static unsigned classifications;
static void refusal_fixture(void) {
    memset(&refusal_plan,0,sizeof refusal_plan);
    refusal_plan.version=LI2_PF_VERSION;refusal_plan.bytes=sizeof refusal_plan;
    refusal_plan.page[0]=hp[0];refusal_plan.page[1]=hp[1];
    refusal_plan.entry=root_pc;refusal_plan.result=LI2_PG_GRAPH;
    refusal_miss=(struct li2_pg_miss){.version=LI2_PF_VERSION,.status=LI2_PG_GRAPH,
        .reason=LI2_PFD_BACKWARD_UNSUPPORTED,.site=LI2_PGD_SOURCE,
        .pc=root_pc+16,.detail=root_pc-32};
}
static void classified(unsigned expected,const struct li2_pg_plan *plan,
    const struct li2_pg_miss *miss,int result,uintptr_t pc,const char *label) {
    need(li2_pg_source_negative_refusal(plan,miss,result,pc)==(int)expected,label);
    ++classifications;
}
#define CLASS(expected,label) classified(expected,&refusal_plan,&refusal_miss,LI2_PG_GRAPH,root_pc,label)
#define MISS(field,value) do { \
    const struct li2_pg_miss saved=refusal_miss;refusal_miss.field=(value); \
    CLASS(0,#field);refusal_miss=saved; \
} while(0)
#define PLAN(field,value) do { \
    const __typeof__(refusal_plan.field) saved=refusal_plan.field; \
    refusal_plan.field=(value);CLASS(0,#field);refusal_plan.field=saved; \
} while(0)
static void classification_cases(void) {
    refusal_fixture();CLASS(1,"explicit backward SOURCE/GRAPH with non-root miss PC");
    classified(0,0,&refusal_miss,LI2_PG_GRAPH,root_pc,"missing plan");
    classified(0,&refusal_plan,0,LI2_PG_GRAPH,root_pc,"missing miss");
    classified(0,&refusal_plan,&refusal_miss,LI2_PG_MISS,root_pc,"wrong result MISS");
    classified(0,&refusal_plan,&refusal_miss,LI2_PG_CORRUPT,root_pc,"corruption stays outside");
    classified(0,&refusal_plan,&refusal_miss,LI2_PG_GRAPH,root_pc+1,"wrong actual offer PC");
    MISS(version,LI2_LP_VERSION);
    MISS(status,LI2_PG_MISS);
    MISS(reason,LI2_PGD_NONE);
    MISS(reason,LI2_PGD_ROOT_UNSUPPORTED);
    MISS(reason,LI2_PGD_EXIT_LIMIT);
    MISS(reason,LI2_PFD_BACKWARD_UNSUPPORTED+1U);
    MISS(site,LI2_PGD_EMIT);
    MISS(site,LI2_PGD_NONE);
    MISS(pc,hp[1]+PAGE);
    MISS(detail,hp[1]+PAGE);
    MISS(detail,refusal_miss.pc+1);
    PLAN(entry,root_pc+1);
    PLAN(version,LI2_LP_VERSION);
    PLAN(ready,1);
    PLAN(result,0);
    /* The original ROOT branch retains its literal result/status/site/PC
       contract. A GRAPH root label cannot impersonate the new reason. */
    refusal_plan.result=LI2_PG_MISS;
    refusal_miss.status=LI2_PG_MISS;refusal_miss.reason=LI2_PGD_ROOT_UNSUPPORTED;
    refusal_miss.pc=root_pc;
    classified(1,&refusal_plan,&refusal_miss,LI2_PG_MISS,root_pc,"original root refusal");
    refusal_miss.pc=root_pc+1;
    classified(0,&refusal_plan,&refusal_miss,LI2_PG_MISS,root_pc,"root PC remains exact");
    refusal_miss.pc=root_pc;refusal_miss.site=LI2_PGD_EMIT;
    classified(0,&refusal_plan,&refusal_miss,LI2_PG_MISS,root_pc,"root site remains exact");
}
#undef CLASS
#undef MISS
#undef PLAN

static void controlled_put(void) {
    if(li2_pg_source_negative_refusal(&refusal_plan,&refusal_miss,LI2_PG_GRAPH,root_pc)) {
        struct li2_plnh_key k=key(0,1,root_pc);li2_plnh_put(&pg_negative_hint,&k);
    }
}
static void backward_identity_cases(unsigned backing) {
    fixture(backing);refusal_fixture();
    refusal_miss.reason=LI2_PGD_EXIT_LIMIT;controlled_put();
    expect(0,root_pc,hp,"different refusal class cannot seed a hint");
    refusal_miss.reason=LI2_PFD_BACKWARD_UNSUPPORTED;refusal_miss.site=LI2_PGD_EMIT;
    controlled_put();expect(0,root_pc,hp,"wrong site cannot seed a hint");
    refusal_miss.site=LI2_PGD_SOURCE;controlled_put();
    expect(1,root_pc,hp,"controlled backward refusal uses actual lifetime key");
    records[0].actual=PROT_READ|PROT_EXEC;records[1].actual=PROT_READ|PROT_EXEC;
    expect(1,root_pc,hp,"ordinary TF RX leaves source lifetime unchanged");
    records[0].actual=records[1].actual=PROT_READ;
    for(unsigned j=0;j<2;j++) {
        const struct owned_page saved=records[j];
        ++records[j].generation;expect(0,root_pc,hp,"each page generation invalidates");
        records[j]=saved;records[j].logical=PROT_READ|PROT_WRITE;
        expect(0,root_pc,hp,"each page logical permission invalidates");records[j]=saved;
    }
    retire(&records[0]);append(hp[0],1,0,backing,backing==SEALED?0:OBJECTS,
        PROT_READ|PROT_EXEC,PROT_READ);
    expect(0,root_pc,hp,"actual retire/append invalidates old backward key");
    struct li2_plnh_key k=key(2,1,root_pc);li2_plnh_put(&pg_negative_hint,&k);
    expect(1,root_pc,hp,"independently seeded new lifetime matches");
    retire(&records[1]);expect(0,root_pc,hp,"actual second-page retirement invalidates");
}
int main(void) {
    need(!loop_negative_hint_original_main(),"entire original actual-loader oracle");
    const unsigned original_hits=hits,original_misses=misses;
    classification_cases();backward_identity_cases(SEALED);backward_identity_cases(ANONYMOUS);
    need(classifications==24 && hits-original_hits==6 && misses-original_misses==16,
        "fixed additive refusal and lifetime populations");
    printf("loop_backward_hint classifications=%u lookup_hits=%u lookup_misses=%u entries=8 owner_entries=0\n",
        classifications,hits-original_hits,misses-original_misses);
    return 0;
}
