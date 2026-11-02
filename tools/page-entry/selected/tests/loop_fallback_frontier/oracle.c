/* Actual full plans/emitters versus the actual source-extracted saved helper.
   No generated instruction is executed. All old PF/LPF controls run first. */
static unsigned frontier_plans,prior_refusals,whole_adapters,frontier_controls,preserved_paths;
static struct li2_pg_plan history_graph,mutated_graph;
static struct li2_dd_plan reconstructed_direct;

static void frontier_emitted(unsigned head,unsigned frontier) {
    const struct li2_pe_head *h=&history_graph.head[head];
    const struct li2_dd_descriptor *a=&history_graph.instruction[head].direct;
    uintptr_t internal[2]={0},prior[2]={0};
    for(unsigned arm=0;arm<h->successor_count;arm++)if(!(a->external_mask&(1U<<arm))) {
        assert(plr_fallback_destination(&history_graph,head,arm,&internal[arm]));
        if(frontier) {
            assert(arm==1 && h->successors[arm]>=128 &&
                !prior_fallback_destination(&history_graph,head,arm,&prior[arm]));
            assert(internal[arm]==history_graph.original[head].decoded.next_pc &&
                internal[arm]==history_graph.exit_pc[h->successors[arm]-128]);++prior_refusals;
        } else {
            assert(prior_fallback_destination(&history_graph,head,arm,&prior[arm]) &&
                internal[arm]==prior[arm]);++preserved_paths;
        }
    }
    struct li2_jd_binding binding;
    assert(!li2_pg_dispatch_binding(history_graph.page,&history_graph.layout,history_graph.table.address,
        history_graph.heads,head,&binding));
    const struct li2_span_decoded *d=&history_graph.original[head];
    uintptr_t generated=history_graph.layout.generated[head/64]+(uintptr_t)(head%64)*512;
    assert(!li2_ld_emit(d->decoded.pc,d->decoded.bytes,d->decoded.available,a->external_mask,
        generated,history_graph.layout.spill,&binding,internal,&reconstructed_direct));
    assert(!memcmp(&reconstructed_direct,&full.guard[head].direct,sizeof reconstructed_direct) &&
        reconstructed_direct.record.image_bytes==full.head[head].generated_length &&
        !li2_ld_validate(&reconstructed_direct));++whole_adapters;
}
static void frontier_refusals(unsigned head) {
    const unsigned x=history_graph.head[head].successors[1]-128;
    for(unsigned control=0;control<14;control++) {
        mutated_graph=history_graph;
        struct li2_pe_head *h=&mutated_graph.head[head];
        struct li2_dd_descriptor *a=&mutated_graph.instruction[head].direct;
        switch(control) {
        case 0:h->successors[1]=mutated_graph.heads;break; /* malformed token gap */
        case 1:h->successors[1]=128+mutated_graph.exits;break;
        case 2:h->successors[1]=UINT32_MAX;break;
        case 3:++mutated_graph.exit_pc[x];break;
        case 4:++mutated_graph.frontier[x].decoded.pc;break;
        case 5:mutated_graph.frontier[x].ready=1;break;
        case 6:mutated_graph.frontier[x].refusal=0;break;
        case 7:++a->target[1];break;
        case 8:++mutated_graph.original[head].decoded.next_pc;break;
        case 9:h->kind=LI2_PE_NONE;break;
        case 10:h->successor_count=1;break;
        case 11:a->external_mask|=2;break;
        case 12:mutated_graph.original[head].flow=LI2_REGION_NEXT;break;
        case 13:mutated_graph.version=12;break;
        }
        uintptr_t result=UINTPTR_MAX;
        assert(memcmp(&mutated_graph,&history_graph,sizeof history_graph) &&
            !plr_fallback_destination(&mutated_graph,head,1,&result));++frontier_controls;
    }
    /* A nondirectional taken arm is not an unsupported fallthrough. */
    mutated_graph=history_graph;mutated_graph.head[head].successors[0]=128+x;
    mutated_graph.instruction[head].direct.external_mask=2;
    uintptr_t result=UINTPTR_MAX;
    assert(!plr_fallback_destination(&mutated_graph,head,0,&result));++frontier_controls;
}
static void frontier_cases(void) {
    static const unsigned char minimal[]={0x75,0x20,0xc6,0x00,0xcc};
    /* Actual failed startup pattern, independent literal bytes through JNE.
       Addresses are fixture data; no runtime path recognizes this specimen. */
    static const unsigned char startup[]={
        0x48,0xb8,0,0x10,0,0,0,0x50,0,0,
        0x41,0xc7,0x81,0,0x10,0,0,0x61,0x62,0x3d,0,
        0x49,0x89,0,0x49,0x89,0x40,0x18,0x48,0x2d,0,0x0e,0,0,
        0x49,0x89,0x40,0x30,0x48,0x83,0xc0,0x80,0x49,0x89,0x40,0x40,
        0x49,0xc7,0x40,0x48,0x1e,0,0,0,0x85,0xff,0x75,0x21,
        0x41,0xc6,0x81,0xf8,1,0,0,1};
    for(unsigned page=0;page<2;page++)for(unsigned shape=0;shape<2;shape++) {
        lpf_setup(0x402000,0x10000000);unsigned offset=page*4096+0x618;
        lpf_put(offset,shape?startup:minimal,shape?sizeof startup:sizeof minimal);
        struct li2_pg_miss miss;
        assert(!li2_lpf_plan_pages(lpf_pages,lpf_source,lpf_pages[0]+offset,
            &lpf_layout,&lpf_table,&full,&miss) && full.ready==1 && full.exits==2 &&
            full.heads==(shape?11U:1U) && !li2_lpf_plan_validate(&full,&scratch));
        assert(!li2_lpf_compact_build(&full,&scratch,&compact) &&
            !li2_lpf_compact_validate(&compact,&scratch,&rebuilt));
        assert(!li2_lpf_graph_history(lpf_pages,lpf_source,full.entry,&lpf_layout,
            lpf_table.address,&history_graph) && !history_graph.ready && !history_graph.result);
        unsigned head=full.heads-1;
        assert(history_graph.head[head].kind==LI2_PG_DIRECT &&
            history_graph.head[head].source_page==page &&
            history_graph.instruction[head].direct.external_mask==1 &&
            history_graph.head[head].successors[0]==128 && history_graph.head[head].successors[1]==129 &&
            !history_graph.frontier[1].ready && history_graph.frontier[1].refusal);
        frontier_emitted(head,1);frontier_refusals(head);++frontier_plans;
    }
    /* Existing same-bank and cross-bank internal destinations stay literal. */
    for(unsigned shape=3;shape<=5;shape+=2) {
        lpf_setup(0x402000,0x10000000);unsigned offset=lpf_shape(shape);struct li2_pg_miss miss;
        assert(!li2_lpf_plan_pages(lpf_pages,lpf_source,lpf_pages[0]+offset,
            &lpf_layout,&lpf_table,&full,&miss));
        assert(!li2_lpf_graph_history(lpf_pages,lpf_source,full.entry,&lpf_layout,
            lpf_table.address,&history_graph));
        for(unsigned head=0;head<history_graph.heads;head++)if(history_graph.head[head].kind==LI2_PG_DIRECT)
            frontier_emitted(head,0);
    }
}
int main(void) {
    assert(!original_lpf_main());struct li2_decoder_stats before,after;
    assert(!li2_decoder_stats(&before));frontier_cases();
    assert(frontier_plans==4 && prior_refusals==4 && whole_adapters==6 && frontier_controls==60 && preserved_paths==2);
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        before.allocation_calls==after.allocation_calls && before.deallocation_calls==after.deallocation_calls);
    printf("{\"profile\":\"loop-fallback-frontier-component-v1\",\"plans\":4,\"prior_refusals\":4,\"whole_adapters\":6,\"frontier_controls\":60,\"preserved_paths\":2,\"emitted_execution\":0,\"owner_credit\":0}\n");
    return 0;
}
