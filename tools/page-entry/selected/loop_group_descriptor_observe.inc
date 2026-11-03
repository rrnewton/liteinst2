/* Included once after the original observer state and count helper. It does
   not replace production predicates or write any lifetime/claim authority. */
static void lgdo_preentry(unsigned epoch) {
    struct lgdo_preentry_observation *o=&lc8o.preentry;
    lc8o_need(epoch<5 && o->epochs==epoch && !o->serial[epoch] &&
        !o->refusal[epoch] && !o->restore[epoch],100);
    int incoming=pda_ready_preentry(),ordinary=pda_ready(1);
    lc8o_need(incoming==1 && ordinary==0,101);
    o->serial[epoch]=pe.p.serial;++o->epochs;++o->accepted;++o->ordinary_refusals;
#if LI2_LOOP_CACHE8_CONTROL != 0
    /* Each negative changes one actual live context field. No fake directory,
       claim, success callback or manufactured entry is supplied. All queries
       and differential work from both baseline calls remain counted. */
#define LGDO_PREENTRY_REFUSE(field,value,bit) do { \
    __typeof__(field) saved=(field); \
    lc8o_need(saved!=(value),102); \
    (field)=(value);__asm__ volatile("":::"memory"); \
    int refused=pda_ready_preentry()==0; \
    (field)=saved;__asm__ volatile("":::"memory"); \
    ++o->attempted; \
    if(refused){++o->refused;o->refusal[epoch]|=UINT64_C(1)<<(bit);} \
    lc8o_need(refused,103+(bit)); \
    int again=pda_ready_preentry(),old=pda_ready(1); \
    lc8o_need((field)==saved && again==1 && old==0,118+(bit)); \
    ++o->restorations;o->restore[epoch]|=UINT64_C(1)<<(bit); \
} while(0)
    LGDO_PREENTRY_REFUSE(handling,1,0);
    LGDO_PREENTRY_REFUSE(pe_active,0,1);
    LGDO_PREENTRY_REFUSE(pe_busy,1,2);
    LGDO_PREENTRY_REFUSE(pe_closing,1,3);
    LGDO_PREENTRY_REFUSE(pe_decoding,1,4);
    LGDO_PREENTRY_REFUSE(pe_failing,1,5);
    LGDO_PREENTRY_REFUSE(pe.resuming,1,6);
    LGDO_PREENTRY_REFUSE(pe.redirected,0,7);
    LGDO_PREENTRY_REFUSE(pe.p.phase,LI2_PG_BOUND,8);
    LGDO_PREENTRY_REFUSE(pe.p.first_error,PE_STATE,9);
    LGDO_PREENTRY_REFUSE(selected_pending_route,SELECTED_GENERIC_TF,10);
    LGDO_PREENTRY_REFUSE(selected_step_pending,0,11);
    LGDO_PREENTRY_REFUSE(pe.domain.work.bound,0,12);
    LGDO_PREENTRY_REFUSE(pe.domain.work.completion,1,13);
    LGDO_PREENTRY_REFUSE(pe.domain.work.aborting,1,14);
#undef LGDO_PREENTRY_REFUSE
#endif
}
static void lgdo_preentry_report(unsigned status,unsigned code) {
    const struct lgdo_preentry_observation *o=&lc8o.preentry;
    struct writer w={.used=0};text(&w,"LI2_LOOP_GROUP_DESCRIPTOR_PREENTRY {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"control\":",LI2_LOOP_CACHE8_CONTROL);
    field(&w,",\"epochs\":",o->epochs);field(&w,",\"accepted\":",o->accepted);
    field(&w,",\"ordinary_refusals\":",o->ordinary_refusals);
    field(&w,",\"attempted\":",o->attempted);field(&w,",\"refused\":",o->refused);
    field(&w,",\"restorations\":",o->restorations);
    field(&w,",\"serial0\":",o->serial[0]);field(&w,",\"serial1\":",o->serial[1]);
    field(&w,",\"serial2\":",o->serial[2]);field(&w,",\"serial3\":",o->serial[3]);
    field(&w,",\"serial4\":",o->serial[4]);
    field(&w,",\"refusal0\":",o->refusal[0]);field(&w,",\"refusal1\":",o->refusal[1]);
    field(&w,",\"refusal2\":",o->refusal[2]);field(&w,",\"refusal3\":",o->refusal[3]);
    field(&w,",\"refusal4\":",o->refusal[4]);
    field(&w,",\"restore0\":",o->restore[0]);field(&w,",\"restore1\":",o->restore[1]);
    field(&w,",\"restore2\":",o->restore[2]);field(&w,",\"restore3\":",o->restore[3]);
    field(&w,",\"restore4\":",o->restore[4]);text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
static void lgdo_snapshot(unsigned epoch,unsigned stage) {
    lc8o_need(epoch<5 && stage<4,70);
    struct lgdo_snapshot *o=&lc8o.wire.descriptor.snapshot[epoch][stage];
    const struct pda_work *w=&pe.domain.work;const struct lgd_manifest *g=&lgd_group.value;
    lc8o_need(!o->h[0],71);
    uint64_t *h=o->h;
    h[0]=1;h[1]=pe.p.serial;h[2]=pe.p.phase;h[3]=pe_active;h[4]=pe_busy;
    h[5]=w->view.count;h[6]=w->bound;h[7]=w->completion;h[8]=w->receipt;
    h[9]=w->descriptor_id;h[10]=w->descriptor_epoch;h[11]=g->id;h[12]=g->exposure;
    h[13]=lgd_writer.value.manifest;h[14]=lgd_writer.value.directory;h[15]=lgd_writer.value.root;
    h[16]=lgd_writer.value.next_id;h[17]=lgd_writer.value.poisoned;
    h[18]=PGC_VALUE(permit_claims);h[19]=pe.domain.next_id;h[20]=pe.next_serial;
    h[21]=pe.gpr_written;h[22]=pe.flags_written;h[23]=pe.domain.directory;
    h[24]=g->directory.serial;h[25]=g->directory.count;h[26]=g->count;
    const uint64_t d[]={lgd_counts.issues,lgd_counts.hits,lgd_counts.topology_hits,
        lgd_counts.topology_full,lgd_counts.topology_differential,lgd_counts.common_hits,
        lgd_counts.common_full,lgd_counts.common_differential,lgd_counts.history_fallbacks,
        lgd_counts.directory_writes,lgd_counts.directory_queries,lgd_counts.disagreements};
    copy(o->descriptor,d,sizeof d);
    const uint64_t history[]={lhc.counts.decisions,lhc.counts.hits,lhc.counts.misses,
        lhc.counts.full_calls,lhc.counts.differential_checks,lhc.counts.disagreements,
        lhc.counts.issues,lhc.counts.invalidations,lhc.counts.abort_invalidations,
        lhc.counts.errors,lhc.counts.restored_bytes};copy(o->history,history,sizeof history);
    for(unsigned i=0;i<8;i++) {
        const struct li2_ptr_slot *s=&pe.retained[i];const struct li2_pgd_claim *q=&s->claim;
        const uint64_t row[]={q->id,q->cell,q->member,q->valid,q->reserved,
            s->identity.generation,s->last_completed,s->generation.domain_refs};
        copy(o->claim[i],row,sizeof row);
    }
    for(unsigned i=0;i<9;i++) {
        const struct pda_completion *c=&pe.domain.completion[i];
        const uint64_t row[]={c->id,c->serial,c->count,pe.domain.claimed[i]};
        copy(o->cell[i],row,sizeof row);
    }
    o->directory_write=w->directory_write;o->directory_seal=w->directory_seal;
    o->directory_query=w->descriptor_query;
}
#if LI2_LOOP_CACHE8_CONTROL >= 1 && LI2_LOOP_CACHE8_CONTROL <= 5
static void lgdo_epoch(uint64_t out[4],unsigned i) {
    out[0]=lgd_root_epoch();out[1]=lgd_cell_epoch(i);out[2]=lgd_capsule_epoch(i);
    out[3]=lgd_writer.value.invalidations;
}
static void lgdo_counts(uint64_t out[32]) {
    const uint64_t v[]={lgd_counts.common_hits,lgd_counts.common_full,lgd_counts.common_differential,
        lgd_counts.history_fallbacks,lhc.counts.hits,lhc.counts.misses,lhc.counts.full_calls,
        lhc.counts.differential_checks,lhc.counts.disagreements,lgd_counts.topology_hits,
        lgd_counts.topology_full,lgd_counts.topology_differential,lgd_counts.directory_writes,
        lgd_writer.value.manifest,lgd_writer.value.directory,lgd_writer.value.root,
        lgd_writer.value.invalidations,lgd_writer.value.poisoned};copy(out,v,sizeof v);
}
static void lgdo_permission(struct lgdo_raw *r,unsigned at,uintptr_t first,size_t bytes,int prot) {
    lc8o_need(at<4 && !r->call[at][0],72);
    uint64_t *v=r->call[at];v[0]=SYS_mprotect;v[1]=first;v[2]=bytes;v[3]=(unsigned)prot;
    long result=raw(SYS_mprotect,first,bytes,prot,0,0,0);v[7]=(uint64_t)result;
    lc8o_need(!result,73);
}
/* Keep the original private query's 64-page limit. The larger completion
   has two independently observed contiguous pieces; no aggregate is fabricated. */
static int lgdo_queries(uintptr_t first,size_t bytes,struct li2_private_code_query out[2]) {
    if(!bytes || bytes>128U*PAGE)return PE_STATE;
    for(unsigned i=0;bytes && i<2;i++) {
        size_t part=bytes>64U*PAGE?64U*PAGE:bytes;
        int error=pe_query(first,part,PROT_READ,&out[i]);
        if(error)return error;
        first+=part;bytes-=part;
    }
    return bytes?PE_STATE:0;
}
/* Each action is a real pre-kernel invalidation followed by an actual memory
   edit and real R restoration. Success of full reconstruction is distinct from
   acceptance of stale cached witnesses. No epoch/certificate is reinstated. */
static void lgdo_raw_controls(const struct pda_completion *original) {
    unsigned cell=lhc_index(original);
    lc8o_need(cell<9 && original->count==4 && lhc_mask(original)==7 &&
        lhc.root.value.cell[cell].policy==LI2_PF_VERSION &&
        lhc_exposure_current(cell) && lhc_match(original,cell) && pda_receipt(original) &&
        lgd_view_match(&pe.domain.work.view) && lgd_directory_equal(),74);
    copy(&lc8o.saved_completion,original,sizeof lc8o.saved_completion);
    unsigned kind=LI2_LOOP_CACHE8_CONTROL-1U;lc8o_need(kind<5,89);
    {
        struct lgdo_raw *r=&lc8o.wire.descriptor.raw[0];uint64_t *h=r->h;
        struct pda_completion *c=(struct pda_completion *)original;
        uintptr_t first;size_t bytes;
        if(kind==0){first=(uintptr_t)c;bytes=sizeof *c;}
        else if(kind==1){first=(uintptr_t)&lhc.capsule[cell];bytes=sizeof lhc.capsule[cell];
            copy(&lc8o.descriptor_saved.capsule,&lhc.capsule[cell],bytes);}
        else if(kind==2){first=(uintptr_t)&lhc.root;bytes=sizeof lhc.root;
            copy(&lc8o.descriptor_saved.root,&lhc.root,bytes);}
        else if(kind==3){first=(uintptr_t)&lgd_group;bytes=sizeof lgd_group;
            copy(lc8o.descriptor_saved.manifest,&lgd_group,bytes);}
        else {first=pe.domain.directory;bytes=LI2_JD_DOMAIN_BYTES;
            copy(lc8o.descriptor_saved.directory,(const void *)first,bytes);}
        h[0]=1;h[1]=kind;h[2]=cell;h[3]=first;h[4]=bytes;
        h[12]=lhc_mask(original);h[13]=lhc.root.value.cell[cell].policy;
        lgdo_counts(r->counts[0]);lgdo_epoch(r->epoch[0],cell);
        lc8o_need(!lgdo_queries(first,bytes,r->query[0]),75);
        lgdo_permission(r,0,first,bytes,PROT_READ|PROT_WRITE);
        lgdo_epoch(r->epoch[1],cell);
        h[10]=(unsigned)(kind<3?pda_receipt(c):lgd_directory_equal());
        lc8o_need(!h[10],90);
        h[11]=(unsigned)(kind<3?lhc_exposure_current(cell):lgd_manifest_live());
        lc8o_need(!h[11],91);
        if(kind==0)c->complete=0;
        else if(kind==1)((unsigned char *)&lhc.capsule[cell])[0]^=1;
        else if(kind==2)lhc.root.value.cell[cell].id^=1;
        else if(kind==3)lgd_group.value.count=9;
        else ((struct li2_jd_domain_directory *)first)->row[0].generated^=1;
        lgdo_permission(r,1,first,bytes,PROT_READ);lgdo_epoch(r->epoch[2],cell);
        lc8o_need(!lgdo_queries(first,bytes,r->query[1]),76);
        int actual=kind<3?pda_receipt(c):lgd_directory_equal();h[5]=(unsigned)actual;
        /* Capsule bytes have no authority after exposure: the unchanged full
           graph reconstructor must succeed, with no cached witness restore. */
        lc8o_need(actual==(kind==1),77);lgdo_counts(r->counts[1]);
        lc8o_need(r->counts[1][0]==r->counts[0][0] && r->counts[1][4]==r->counts[0][4],78);
        if(kind==1)lc8o_need(r->counts[1][1]==r->counts[0][1]+2 &&
            r->counts[1][3]==r->counts[0][3]+1 && r->counts[1][6]==r->counts[0][6]+1,79);
        lgdo_permission(r,2,first,bytes,PROT_READ|PROT_WRITE);lgdo_epoch(r->epoch[3],cell);
        if(kind==0)copy(c,&lc8o.saved_completion,bytes);
        else if(kind==1)copy(&lhc.capsule[cell],&lc8o.descriptor_saved.capsule,bytes);
        else if(kind==2)copy(&lhc.root,&lc8o.descriptor_saved.root,bytes);
        else if(kind==3)copy(&lgd_group,lc8o.descriptor_saved.manifest,bytes);
        else copy((void *)first,lc8o.descriptor_saved.directory,bytes);
        lgdo_permission(r,3,first,bytes,PROT_READ);lgdo_epoch(r->epoch[4],cell);
        const void *saved=kind==0?(const void *)&lc8o.saved_completion:
            kind==1?(const void *)&lc8o.descriptor_saved.capsule:
            kind==2?(const void *)&lc8o.descriptor_saved.root:
            kind==3?(const void *)lc8o.descriptor_saved.manifest:(const void *)lc8o.descriptor_saved.directory;
        lc8o_need(equal((const void *)first,saved,bytes) &&
            !lgdo_queries(first,bytes,r->query[2]),80);
        h[6]=1;h[7]=(unsigned)pda_receipt(c);lc8o_need(h[7]==1,81);
        h[8]=(unsigned)lhc_exposure_current(cell);lc8o_need(h[8]==(kind>=3),82);
        if(kind>=3){h[9]=(unsigned)lgd_directory_equal();lc8o_need(!h[9],83);}
        lgdo_counts(r->counts[2]);
        lc8o_need(r->counts[2][0]==r->counts[0][0]+(kind>=3) &&
            r->counts[2][4]==r->counts[0][4]+(kind>=3),84);
        ++lc8o.wire.descriptor.h[4];
    }
}
#endif
static void lgdo_finished(const struct pda_completion *c) {
    if(lc8o.epochs!=5)return;
    uint64_t *h=lc8o.wire.descriptor.h;
    lc8o_need(!h[0],85);h[0]=1;h[1]=1;h[2]=sizeof lc8o.wire.descriptor;h[3]=LI2_LOOP_CACHE8_CONTROL;
#if LI2_LOOP_CACHE8_CONTROL >= 1 && LI2_LOOP_CACHE8_CONTROL <= 5
    lgdo_raw_controls(c);lc8o_need(h[4]==1,86);
#elif LI2_LOOP_CACHE8_CONTROL == 6
    lc8o_need(c && pda_receipt(c) && lgd_epochs_live(),87);
    h[5]=1;h[6]=(uintptr_t)&lgd_writer;h[7]=sizeof lgd_writer;h[10]=SYS_mprotect;h[11]=PROT_READ;
    /* The callback must terminate through real cleanup before this syscall
       or any subsequent instruction can return. No synthetic failure code. */
    h[8]=(uint64_t)raw(SYS_mprotect,(long)&lgd_writer,sizeof lgd_writer,PROT_READ,0,0,0);
    h[9]=1;lc8o_fail(88);
#else
    (void)c;
#endif
}
