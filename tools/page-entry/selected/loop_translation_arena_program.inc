/* Actual terminal values only. No admission or lifetime path consumes them. */
#if !defined(LI2_LOOP_TRANSLATION_ARENA_PROGRAM) || LI2_LOOP_TRANSLATION_ARENA_PROGRAM != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_PROGRAM_BINDING_VERSION) || \
    LI2_PG_LOOP_TRANSLATION_ARENA_PROGRAM_BINDING_VERSION != 1
#error "exact distinct arena program observation binding required"
#endif
_Static_assert(PTR_NODE_COUNT==12 && LI2_PTR_SLOTS==8 && LI2_PGD_RECEIPTS==9,
    "all immutable nodes and unchanged active/completion bounds");
_Static_assert(55U*21U+1800U<=sizeof(((struct writer *)0)->bytes),
    "complete four-node terminal rows fit the original writer");
static void lta_program_report(unsigned status,unsigned code) {
    struct writer w={0};text(&w,"LI2_LOOP_ARENA_PROGRAM {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"nodes\":",PTR_NODE_COUNT);field(&w,",\"slots\":",LI2_PTR_SLOTS);
    field(&w,",\"initialized\":",lta_writer.value.initialized);
    field(&w,",\"poisoned\":",lta_writer.value.poisoned);
    field(&w,",\"topology_epoch\":",lta_writer.value.topology_epoch);
    field(&w,",\"next_binding\":",pe.arena.next_binding);
#define LTAP_VALUE(n) field(&w,",\"" #n "\":",lta_writer.value.n)
    LTAP_VALUE(detached);LTAP_VALUE(rebound);LTAP_VALUE(rebound_peers);LTAP_VALUE(cold_nodes);
    LTAP_VALUE(evicted);LTAP_VALUE(epoch_invalidations);LTAP_VALUE(stale_refusals);LTAP_VALUE(physical_checks);
#undef LTAP_VALUE
    field(&w,",\"writer_next_binding\":",lta_writer.value.next_binding);
    field(&w,",\"rebind_mask\":",pe.arena.rebind_mask);
#define LTAP_SLOT(n) \
    field(&w,",\"slot" #n "_node\":",pe.arena.binding[n].node); \
    field(&w,",\"slot" #n "_binding\":",pe.arena.binding[n].generation)
    LTAP_SLOT(0);LTAP_SLOT(1);LTAP_SLOT(2);LTAP_SLOT(3);
    LTAP_SLOT(4);LTAP_SLOT(5);LTAP_SLOT(6);LTAP_SLOT(7);
#undef LTAP_SLOT
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
    for(unsigned chunk=0;chunk<3;chunk++) {
        le_zero(&w,sizeof w);text(&w,"LI2_LOOP_ARENA_NODES");number(&w,chunk);
        text(&w," {\"version\":1");field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
        for(unsigned node=4U*chunk;node<4U*(chunk+1U);node++) {
            const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
            const struct lta_dormant *d=&lta_writer.value.dormant[node];
            int slot=lta_node_bound(node);
#define LTAP_NODE(name,value) do { \
    text(&w,",\"node");number(&w,node);field(&w,"_" name "\":",(uint64_t)(value)); \
} while(0)
            LTAP_NODE("generation",s->identity.generation);
            LTAP_NODE("claim",s->claim.valid);LTAP_NODE("completed_serial",s->last_completed);
            LTAP_NODE("active_slot",slot<0?LI2_PTR_SLOTS:(unsigned)slot);
            LTAP_NODE("root",s->publication.source.entry);LTAP_NODE("build_serial",s->generation.build_serial);
            LTAP_NODE("issued",d->issued);LTAP_NODE("closed",d->closed);LTAP_NODE("reusable",d->reusable);
            LTAP_NODE("node_epoch",lta_writer.value.node[node]);LTAP_NODE("issued_epoch",d->node_epoch);
            LTAP_NODE("prepared_serial",d->prepared_serial);LTAP_NODE("prepared_binding",d->prepared_binding);
#undef LTAP_NODE
        }
        text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
    }
}
