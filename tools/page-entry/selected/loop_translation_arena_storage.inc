/* Fixed final-address storage, separate from the eight execution bindings.
   This leaf issues no source lease, completion claim or execution permit. */
struct lta_range {
    uintptr_t first,end;
    size_t registry_index;
    struct li2_fork_range registered;
};
struct lta_topology {
    uint64_t version,complete;
    const struct li2_pg_epoch *owner;
    struct lta_range code[2],proof,owner_range,directory,root,writer;
};
static union {
    struct lta_topology value;
    unsigned char page[PAGE];
} lta_topology __attribute__((aligned(PAGE)));
struct lta_dormant {
    uint64_t issued,closed,reusable,node_epoch,generation,build_serial;
    uint64_t prepared_serial,prepared_binding;
    uint64_t retired_binding,completion_id,completion_serial;
    uintptr_t root,page[2];
    unsigned bank,reserved;
    struct sbc_certificate certificate;
};
struct lta_epochs {
    uint64_t initialized,poisoned,topology_epoch,next_binding;
    uint64_t node[LI2_LTA_NODES];
    struct lta_dormant dormant[LI2_LTA_NODES];
    uint64_t detached,rebound,rebound_peers,cold_nodes,evicted;
    uint64_t epoch_invalidations,stale_refusals,physical_checks;
};
static union {
    struct lta_epochs value;
    unsigned char pages[2U*PAGE];
} lta_writer __attribute__((aligned(PAGE)));
_Static_assert(sizeof lta_topology==PAGE && sizeof lta_writer==2U*PAGE &&
    sizeof(struct lta_epochs)<=2U*PAGE,"complete isolated arena metadata extents");

static unsigned ptr_node_index(unsigned slot) {
    if(slot>=LI2_PTR_SLOTS)return PTR_NODE_COUNT;
    const struct lta_binding *b=&pe.arena.binding[slot];
    return b->reserved || b->node>=PTR_NODE_COUNT || !b->generation ||
        b->generation>pe.arena.next_binding?PTR_NODE_COUNT:b->node;
}
static struct li2_ptr_slot *ptr_slot_address(unsigned slot) {
    unsigned node=ptr_node_index(slot);
    pe_need(node<PTR_NODE_COUNT,PE_STATE,9200);
    return &PTR_NODE_AT(node);
}
static int lta_range_live(const struct lta_range *r) {
    return r->first && r->end>r->first && r->registry_index<protected_count &&
        protected_count<=RANGES &&
        equal(&protected[r->registry_index],&r->registered,sizeof r->registered) &&
        r->registered.first<=r->first && r->end<=r->registered.end;
}
static int lta_topology_live(void) {
    const struct lta_topology *t=&lta_topology.value;
    return lta_writer.value.initialized==1 && !lta_writer.value.poisoned &&
        lta_writer.value.topology_epoch==1 &&
        lta_writer.value.next_binding==pe.arena.next_binding && t->version==LI2_LTA_VERSION &&
        t->complete==1 && t->owner==&pe &&
        lta_range_live(&t->code[0]) && lta_range_live(&t->code[1]) &&
        lta_range_live(&t->proof) && lta_range_live(&t->owner_range) &&
        lta_range_live(&t->directory) && lta_range_live(&t->root) &&
        lta_range_live(&t->writer) && t->owner_range.first==(uintptr_t)&pe &&
        t->owner_range.end==(uintptr_t)&pe+sizeof pe &&
        t->directory.first==pe.domain.directory &&
        t->directory.end==pe.domain.directory+LI2_JD_DOMAIN_BYTES &&
        t->root.first==(uintptr_t)&lta_topology &&
        t->root.end==(uintptr_t)&lta_topology+sizeof lta_topology &&
        t->writer.first==(uintptr_t)&lta_writer &&
        t->writer.end==(uintptr_t)&lta_writer+sizeof lta_writer;
}
/* No SG/SBC call is reachable here: the sealed backing code uses this
   address-topology theorem before dereferencing a selected or dormant node. */
static int ptr_node_storage(unsigned node) {
    if(node>=PTR_NODE_COUNT || !lta_topology_live())return 0;
    const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
    const struct lta_topology *t=&lta_topology.value;
    if(s->identity.owner!=&pe || s->identity.reserved ||
       s->identity.index>LI2_PTR_SLOTS || s->code_allocated!=2 || s->code_registered!=2 ||
       s->proof_allocated!=1 || s->proof_registered!=1 ||
       s->proof!=t->proof.first+node*PE_PROOF_BYTES || s->generation.proof!=s->proof)return 0;
    for(unsigned bank=0;bank<2;bank++) {
        const struct ped_bank *b=&s->banks[bank];
        struct li2_pg_layout layout=pg_layout(t->code[bank].first+node*PE_ALLOC_BYTES);
        if(b->allocated!=1 || b->registered!=1 || b->generated!=layout.generated[0] ||
           b->spill!=layout.spill || !pg_layout_equal(&b->layout,&layout) || b->virgin>1 ||
           (b->prot!=PROT_READ && b->prot!=(PROT_READ|PROT_WRITE) &&
            b->prot!=(PROT_READ|PROT_EXEC)))return 0;
    }
    return 1;
}
static int lta_storage(void) {
    if(!pe.initialized || !pe.registered || pe.arena.initialized!=1 ||
       pe.selected_slot>=LI2_PTR_SLOTS || pe.selected_bank>1 || !lta_topology_live())return 0;
    unsigned nodes=0;
    for(unsigned slot=0;slot<LI2_PTR_SLOTS;slot++) {
        unsigned node=ptr_node_index(slot);
        if(node>=PTR_NODE_COUNT || (nodes&(1U<<node)) || !ptr_node_storage(node))return 0;
        nodes|=1U<<node;
        const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
        if(s->identity.index!=slot)return 0;
        for(unsigned j=0;j<slot;j++) {
            const struct li2_ptr_slot *other=&PTR_SLOT_AT(j);
            if(pe.arena.binding[slot].generation==pe.arena.binding[j].generation ||
               (s->identity.generation && s->identity.generation==other->identity.generation))return 0;
        }
    }
    return 1;
}
static int lta_save_range(struct lta_range *r,uintptr_t first,size_t bytes) {
    if(!bytes || first>UINTPTR_MAX-bytes || protected_count>RANGES)return PE_STATE;
    for(size_t i=0;i<protected_count;i++)if(protected[i].first<=first && first+bytes<=protected[i].end) {
        *r=(struct lta_range){first,first+bytes,i,protected[i]};return 0;
    }
    return PE_STATE;
}
static int lta_allocate_storage(void) {
    if(pe.initialized || pe.arena.initialized || lta_writer.value.initialized ||
       lta_topology.value.complete || !pe_busy || pe_active || protected_count>RANGES-5U)return PE_STATE;
    if(selected_run_protect_add(0,(uintptr_t)&lta_topology,sizeof lta_topology) ||
       selected_run_protect_add(0,(uintptr_t)&lta_writer,sizeof lta_writer))return PE_STATE;
    if((uintptr_t)raw(SYS_mmap,(long)&lta_topology,sizeof lta_topology,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&lta_topology ||
       (uintptr_t)raw(SYS_mmap,(long)&lta_writer,sizeof lta_writer,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&lta_writer)return PE_PUBLICATION;
    struct lta_topology *t=&lta_topology.value;
    for(unsigned extent=0;extent<3;extent++) {
        size_t bytes=PTR_NODE_COUNT*(extent<2?PE_ALLOC_BYTES:PE_PROOF_BYTES);
        long address=raw(SYS_mmap,0,bytes,PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|(extent==0?MAP_32BIT:0),-1,0);
        if(address<=0 || ((uintptr_t)address&(PAGE-1U)) ||
           (uintptr_t)address>=(UINT64_C(1)<<47)-bytes ||
           (!extent && (uintptr_t)address>=(UINT64_C(1)<<31)-bytes) ||
           selected_run_protect_add(0,(uintptr_t)address,bytes))return PE_PUBLICATION;
        struct lta_range *range=extent<2?&t->code[extent]:&t->proof;
        if(lta_save_range(range,(uintptr_t)address,bytes))return PE_STATE;
    }
    for(unsigned node=0;node<PTR_NODE_COUNT;node++) {
        struct li2_ptr_slot *s=&PTR_NODE_AT(node);
        s->identity=(struct li2_ptr_slot_ref){.owner=&pe,.index=node<LI2_PTR_SLOTS?node:LI2_PTR_SLOTS};
        s->proof=t->proof.first+node*PE_PROOF_BYTES;s->generation.proof=s->proof;
        s->proof_allocated=s->proof_registered=1;
        for(unsigned bank=0;bank<2;bank++) {
            struct ped_bank *b=&s->banks[bank];
            b->generated=t->code[bank].first+node*PE_ALLOC_BYTES;
            b->layout=pg_layout(b->generated);b->spill=b->layout.spill;
            b->allocated=b->registered=b->virgin=1;b->prot=PROT_READ|PROT_WRITE;
            if(pg_queries(&b->layout,PROT_READ|PROT_WRITE,b->initial) ||
               pe_query(b->spill,PAGE,PROT_READ|PROT_WRITE,&b->initial_spill) ||
               pe_query(b->layout.slots,PAGE,PROT_READ|PROT_WRITE,&b->initial_slots))return PE_PUBLICATION;
        }
        s->code_allocated=s->code_registered=2;
        s->generation.generated=s->banks[0].generated;s->generation.spill=s->banks[0].spill;
        s->generation.layout=s->banks[0].layout;
        if(pg_proof_query(s->proof,PROT_READ|PROT_WRITE,&s->generation.proof_writable))return PE_PUBLICATION;
        lta_writer.value.node[node]=1;
        if(node<LI2_PTR_SLOTS)pe.arena.binding[node]=(struct lta_binding){node+1U,node,0};
    }
    lta_writer.value.next_binding=pe.arena.next_binding=LI2_PTR_SLOTS;pe.selected_slot=0;pe.selection=PTR_SLOT_AT(0).identity;
    return 0;
}
static int lta_seal_storage(void) {
    struct lta_topology *t=&lta_topology.value;
    if(pe.initialized || pe.arena.initialized || !pe_busy || pe_active ||
       lta_save_range(&t->owner_range,(uintptr_t)&pe,sizeof pe) ||
       lta_save_range(&t->directory,pe.domain.directory,LI2_JD_DOMAIN_BYTES) ||
       lta_save_range(&t->root,(uintptr_t)&lta_topology,sizeof lta_topology) ||
       lta_save_range(&t->writer,(uintptr_t)&lta_writer,sizeof lta_writer))return PE_STATE;
    const struct lta_range *ranges[7]={&t->code[0],&t->code[1],&t->proof,
        &t->owner_range,&t->directory,&t->root,&t->writer};
    for(unsigned i=0;i<7;i++)for(unsigned j=0;j<i;j++)
        if(ranges[i]->first<ranges[j]->end && ranges[j]->first<ranges[i]->end)return PE_STATE;
    t->version=LI2_LTA_VERSION;t->owner=&pe;t->complete=1;
    if(raw(SYS_mprotect,(long)&lta_topology,sizeof lta_topology,PROT_READ,0,0,0))return PE_PUBLICATION;
    struct li2_private_code_query query={0};
    if(pe_query((uintptr_t)&lta_topology,sizeof lta_topology,PROT_READ,&query))return PE_PUBLICATION;
    lta_writer.value.topology_epoch=lta_writer.value.initialized=1;pe.arena.initialized=1;
    return lta_topology_live()?0:PE_STATE;
}

/* Reuse is retired before the actual RAW gateway can expose a node. The
   issuer snapshot is in a different permanently private RW object. Shared
   SG metadata writes are not node-byte writes; dormant reuse independently
   compares its whole saved SBC identity around fresh physical queries. */
static int lta_overlap(uintptr_t first,uintptr_t end,uintptr_t at,size_t bytes) {
    return bytes && at<=UINTPTR_MAX-bytes && first<at+bytes && at<end;
}
static void lta_poison(void) {if(lta_writer.value.initialized)lta_writer.value.poisoned=1;}
static void lta_writer_range(uintptr_t first,size_t bytes) {
    if(!lta_writer.value.initialized || !bytes)return;
    if(first>UINTPTR_MAX-bytes || first+bytes>UINTPTR_MAX-(PAGE-1U)) {lta_poison();return;}
    uintptr_t end=(first+bytes+PAGE-1U)&~(uintptr_t)(PAGE-1U);first&=~(uintptr_t)(PAGE-1U);
    if(lta_overlap(first,end,(uintptr_t)&lta_writer,sizeof lta_writer) ||
       lta_overlap(first,end,(uintptr_t)&lta_topology,sizeof lta_topology)) {
        lta_poison();selected_persistent_abort(PE_PUBLICATION,9220);
    }
}
static void lta_exposure(uintptr_t first,size_t bytes) {
    if(!lta_writer.value.initialized || !bytes)return;
    if(first>UINTPTR_MAX-bytes || first+bytes>UINTPTR_MAX-(PAGE-1U)) {lta_poison();return;}
    uintptr_t end=(first+bytes+PAGE-1U)&~(uintptr_t)(PAGE-1U);first&=~(uintptr_t)(PAGE-1U);
    lta_writer_range(first,end-first);
    for(unsigned node=0;node<PTR_NODE_COUNT;node++) {
        const struct li2_ptr_slot *s=&PTR_NODE_AT(node);
        unsigned changed=lta_overlap(first,end,(uintptr_t)s,sizeof *s) ||
            lta_overlap(first,end,s->proof,PE_PROOF_BYTES);
        for(unsigned bank=0;bank<2;bank++)
            changed|=lta_overlap(first,end,s->banks[bank].generated,PE_CODE_BYTES);
        if(!changed)continue;
        lta_writer.value.dormant[node].reusable=0;
        if(lta_writer.value.node[node]==UINT64_MAX || lta_writer.value.epoch_invalidations==UINT64_MAX) {
            lta_poison();continue;
        }
        ++lta_writer.value.node[node];++lta_writer.value.epoch_invalidations;
    }
    /* Completion cells have their own page-isolated LHC/descriptor epochs.
       Their ordinary issue/recycle writes do not expose an arena binding or
       immutable node. Any write reaching the surrounding owner metadata does. */
    uintptr_t nodes=(uintptr_t)&pe.arena.node[0],after=nodes+sizeof pe.arena.node;
    uintptr_t cells=(uintptr_t)&pe.domain.completion[0];
    uintptr_t cells_end=cells+sizeof pe.domain.completion;
    if(lta_overlap(first,end,(uintptr_t)&pe,nodes-(uintptr_t)&pe) ||
       lta_overlap(first,end,after,cells-after) ||
       lta_overlap(first,end,cells_end,(uintptr_t)&pe+sizeof pe-cells_end))lta_poison();
    __asm__ volatile("":::"memory");
}
/* Poison retires reuse, not physical cleanup. Use the separately sealed
   allocation topology, including every inactive node, after any owner error. */
static int lta_terminal(void) {
    const struct lta_topology *t=&lta_topology.value;
    struct li2_private_code_query root={0};
    if(t->version!=LI2_LTA_VERSION || t->complete!=1 || t->owner!=&pe ||
       !lta_range_live(&t->root) || !lta_range_live(&t->code[0]) ||
       !lta_range_live(&t->code[1]) ||
       pe_query((uintptr_t)&lta_topology,sizeof lta_topology,PROT_READ,&root))return 0;
    unsigned good=1;
    for(unsigned node=0;node<PTR_NODE_COUNT;node++)for(unsigned bank=0;bank<2;bank++) {
        struct li2_pg_layout layout=pg_layout(t->code[bank].first+node*PE_ALLOC_BYTES);
        struct le_permission close[3]={0};unsigned pages=0;
        if(pg_permissions(&layout,PROT_READ,close,&pages) || pages!=17 ||
           !pg_closed(&layout,close))good=0;
        else PTR_NODE_AT(node).banks[bank].prot=PROT_READ;
    }
    return good;
}
