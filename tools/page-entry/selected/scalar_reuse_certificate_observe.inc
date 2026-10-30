/* Qualification-only actual observations. Entry hooks copy protected state
   and readable immutable bytes only. Terminal queries run after the original
   owner snapshot/cleanup and grant no execution or completion authority. */
static void srco_counts(uint64_t out[5]) {
    out[0]=srcg_store.publications;out[1]=srcg_store.retirements;
    out[2]=srcg_store.checks;out[3]=srcg_store.live_checks;
    out[4]=srcg_store.terminal_matches;
}
static int srco_registry(struct srco_registry *out) {
    if(out->complete || !protected_count || protected_count>RANGES)return 1;
    const struct image *b=bridge_runtime_image();
    if(!b || b->kind!=IMAGE_BRIDGE || !b->ph || !b->n || b->n>MAX_PHDR ||
       b->source || b->source_size || b->backing_fd!=-1)return 2;
    sro_copy(&out->bridge,b,sizeof(*b));sro_copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    sro_copy(out->ranges,protected,protected_count*sizeof(*protected));
#ifdef LI2_INITIAL_CODE_PROTECTION
    sro_copy(out->initial_code,initial_code_range,protected_count);
#endif
    out->address[0]=(uintptr_t)&srcg_store;out->bytes[0]=sizeof srcg_store;
    out->alignment[0]=__alignof__(srcg_store);
    out->address[1]=(uintptr_t)&sro_wire;out->bytes[1]=sizeof sro_wire;
    out->alignment[1]=__alignof__(sro_wire);
    out->address[2]=srcg_store.arena;out->bytes[2]=SRCG_TOTAL;out->alignment[2]=PAGE;
    for(size_t i=0;i<3;i++) {
        uintptr_t first=out->address[i];size_t bytes=out->bytes[i],a=out->alignment[i];
        if(!first || !bytes || first>UINTPTR_MAX-bytes || !a || (a&(a-1)) ||
           (first&(a-1)))return 3;
        unsigned count=0;
        for(size_t j=0;j<protected_count;j++)
            if(out->ranges[j].first==first && out->ranges[j].end==first+bytes && !out->initial_code[j]) {
                if(count++)return 4;
                out->range_index[i]=(unsigned)j;
            }
        if(count!=1)return 5;
        if(i==2)continue;
        count=0;
        for(size_t j=0;j<b->n;j++) {
            const Elf64_Phdr *p=&out->ph[j];
            if(p->p_type!=PT_LOAD || !p->p_memsz)continue;
            if(b->bias>UINTPTR_MAX-p->p_vaddr || p->p_memsz>UINTPTR_MAX-b->bias-p->p_vaddr)return 6;
            uintptr_t lo=b->bias+p->p_vaddr,hi=lo+p->p_memsz;
            if(first>=hi || lo>=first+bytes)continue;
            if(count++ || p->p_flags!=(PF_R|PF_W) || first<lo || first+bytes>hi)return 7;
            out->load_index[i]=(unsigned)j;
        }
        if(count!=1)return 8;
    }
    out->complete=1;return 0;
}
static void srco_initialize(void) {
    struct srco_wire *c=&sro_wire.certificate;
    sr_need(!c->h[0] && srcg_store.initialized==1 && srcg_protected(),SR_STATE,450);
    c->h[0]=UINT64_C(0x314347534c49324c);c->h[1]=1;c->h[2]=sizeof(*c);
    c->h[3]=sizeof srcg_store;c->h[4]=sizeof(struct li2_reuse_certificate);
    c->h[5]=SRCG_BYTES;c->h[6]=SR_PAGES;c->h[12]=(uintptr_t)&srcg_store;
    c->h[13]=srcg_store.arena;c->h[14]=sizeof c->payload;
    sr_need(!srco_registry(&c->initial_registry),SR_STATE,451);c->h[7]=1;
}
static void srco_source(size_t index) {
    sr_need(index<SRO_ROWS,SR_STATE,452);
    struct srco_focal *f=&sro_wire.certificate.focal[index];
    sr_need(!f->source_present && !f->slot_present,SR_STATE,453);
    srco_counts(f->before_counts);
    sro_copy(&f->source_rseq,li2_rseq_snapshot(),sizeof f->source_rseq);
    f->source_present=1;
}
static void srco_slot(size_t index) {
    sr_need(index<SRO_ROWS,SR_STATE,454);
    struct srco_focal *f=&sro_wire.certificate.focal[index];
    const struct sr_record *r=&selected_scalar_region.current;
    sr_need(f->source_present && !f->slot_present && r->slot_present && r->slot<SR_PAGES &&
        srcg_store.current.pending && srcg_store.current.committed &&
        srcg_store.current.slot==r->slot,SR_STATE,455);
    f->slot=r->slot;f->generation=srcg_store.current.generation;
    f->ready_generation=srcg_store.ready_generation[r->slot];f->address=srcg_address(r->slot);
    sr_need(f->address && f->generation && f->ready_generation==f->generation,SR_STATE,456);
    sro_copy(&f->current,&srcg_store.current,sizeof f->current);
    sro_copy(&f->publication,&srcg_store.slot[r->slot],sizeof f->publication);
    if(r->build_started && srcg_store.current.old_generation) {
        sr_need(srcg_store.retirement.new_generation==f->generation &&
            srcg_store.retirement.slot==f->slot,SR_STATE,457);
        sro_copy(&f->retirement,&srcg_store.retirement,sizeof f->retirement);
    }
    sro_copy(f->payload,(void *)f->address,SRCG_BYTES);f->copied=SRCG_BYTES;
    srco_counts(f->slot_counts);f->slot_present=1;
}
static void srco_complete(size_t index) {
    sr_need(index<SRO_ROWS,SR_STATE,458);
    struct srco_focal *f=&sro_wire.certificate.focal[index];
    sr_need(f->slot_present && !f->completed && selected_scalar_region.current.completed &&
        srcg_store.current.pending && srcg_store.current.generation==f->generation,SR_STATE,459);
    sro_copy(&f->completed_current,&srcg_store.current,sizeof f->completed_current);
    srco_counts(f->after_counts);f->completed=1;
}
static void srco_finish(void) {
    struct srco_wire *c=&sro_wire.certificate;
    if(!c->h[7] || c->h[8] || c->h[9])return;
    if(srcg_store.initialized!=1 || !srcg_protected()) {c->h[9]=1;return;}
    sro_copy(&c->store,&srcg_store,sizeof c->store);
    int e=srco_registry(&c->terminal_registry);
    if(e) {c->h[9]=(uint64_t)(10+e);return;}
    for(size_t i=0;i<SR_PAGES;i++) {
        uintptr_t address=srcg_address(i);
        /* Published extents stay R/NX. An unpublished abort with a stable
           current anchor also attempts R/NX cleanup. Never equate an unused
           anonymous RW/NX extent with a published certificate. */
        int touched=srcg_store.slot[i].started ||
            (srcg_store.current.pending && srcg_store.current.slot==i && srcg_store.current.cleanup.started);
        e=srcg_query(address,touched?PROT_READ:PROT_READ|PROT_WRITE,&c->terminal_mapping[i]);
        if(e) {c->h[9]=30;return;}
        sro_copy(c->payload[i],(void *)address,SRCG_BYTES);c->terminal_bytes[i]=SRCG_BYTES;++c->h[10];
    }
    if(srcg_store.current.pending) {
        if(srcg_store.current.slot>=SR_PAGES ||
           srcg_store.current.address!=srcg_address(srcg_store.current.slot)) {c->h[9]=31;return;}
        c->h[11]=SRCG_BYTES;
    }
    c->h[8]=1;
}
