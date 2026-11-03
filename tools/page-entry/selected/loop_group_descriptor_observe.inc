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
        lhc_cell(cell)->policy==LI2_PF_VERSION &&
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
        h[12]=lhc_mask(original);h[13]=lhc_cell(cell)->policy;
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
        else if(kind==2)lhc_cell(cell)->id^=1;
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
#if LI2_LOOP_CACHE8_CONTROL
/* These are cache-miss/issuance controls, not fabricated whole-owner failures.
   The complete common theorem still runs on every deliberately forced miss. */
static void lgdo_common_pair_record(const struct pda_completion *c,unsigned i,uint64_t *pairs) {
    uint64_t full=lgd_counts.common_full,hits=lgd_counts.common_hits,
        differential=lgd_counts.common_differential,lhc=lgd_counts.common_lhc_hits,
        renewed=lgd_counts.common_revalidated_hits;
    struct lgd_common_token actual;
    lc8o_need(!lhc_exposure_current(i) && lgd_common_value(c) &&
        lgd_counts.common_full==full+1 && lgd_counts.common_hits==hits &&
        lgd_counts.common_differential==differential &&
        lgd_common_snapshot(c,i,&actual) &&
        equal(&actual,&lgd_writer.value.common[i],sizeof actual),110);
    lc8o_need(lgd_common_value(c) && lgd_counts.common_full==full+1 &&
        lgd_counts.common_hits==hits+1 && lgd_counts.common_differential==differential+1 &&
        lgd_counts.common_lhc_hits==lhc && lgd_counts.common_revalidated_hits==renewed+1,111);
    ++*pairs;
}
static void lgdo_common_pair(const struct pda_completion *c,unsigned i) {
    lgdo_common_pair_record(c,i,&lc8o.common.quiet_pairs);
}
static void lgdo_common_unissued(const struct pda_completion *c,unsigned i) {
    struct lgd_common_token saved,unused;
    copy(&saved,&lgd_writer.value.common[i],sizeof saved);
    uint64_t full=lgd_counts.common_full,hits=lgd_counts.common_hits,
        differential=lgd_counts.common_differential;
    lc8o_need(!lgd_common_snapshot(c,i,&unused) && lgd_common_value(c) &&
        lgd_counts.common_full==full+1 && lgd_counts.common_hits==hits &&
        lgd_counts.common_differential==differential &&
        equal(&saved,&lgd_writer.value.common[i],sizeof saved),112);
}
static void lgdo_common_permission(uintptr_t first,size_t bytes,int prot) {
    lc8o_need(!raw(SYS_mprotect,(long)first,bytes,prot,0,0,0),113);
}
#endif
#if LI2_LOOP_CACHE8_CONTROL
/* Snapshot every certificate-related RAW epoch, not a hash or an authority. */
static void lgdo_isolation_epochs(uint64_t out[28]) {
    out[0]=lgd_root_epoch();
    for(unsigned i=0;i<9;i++) {
        out[1+i]=lgd_certificate_epoch(i);
        out[10+i]=lgd_cell_epoch(i);out[19+i]=lgd_capsule_epoch(i);
    }
}
static void lgdo_isolation_raw(struct pda_completion *c,const struct pda_completion *peer,
    unsigned i,unsigned j,unsigned bundle) {
    struct lgdo_isolation_observation *o=&lc8o.isolation;
    uint64_t *mask=bundle?&o->raw_bundle_mask:&o->raw_cell_mask;
    uintptr_t first=bundle?(uintptr_t)&lhc.root:lhc_certificate_address(i);
    size_t bytes=bundle?sizeof lhc.root:lhc_certificate_bytes();
    struct li2_private_code_query query={0};
    uint64_t before[28],after[28],invalidations=lgd_writer.value.invalidations;
    lc8o_need(!*mask && !lrc_readonly(first,bytes) && lhc_match_identity(c,i) &&
        lhc_match_identity(peer,j) && lhc_exposure_current(j) &&
        (bundle?!lhc_exposure_current(i):lhc_exposure_current(i)),143);
    copy(&lc8o.descriptor_saved.root,&lhc.root,sizeof lhc.root);
    lgdo_isolation_epochs(before);*mask=1;
    lgdo_common_permission(first,bytes,PROT_READ|PROT_WRITE);
    lc8o_need(!pe_query(first,bytes,PROT_READ|PROT_WRITE,&query),144);*mask|=2;
    lgdo_isolation_epochs(after);
    for(unsigned k=0;k<28;k++)
        lc8o_need(after[k]==before[k]+(bundle?k<10:k==1+i),145);
    lc8o_need(lgd_writer.value.invalidations==invalidations+1,146);*mask|=4;
    lc8o_need(!lhc_exposure_current(i) &&
        lhc_exposure_current(j)==(bundle?0:1),147);*mask|=8;
    lgdo_common_permission(first,bytes,PROT_READ);
    lc8o_need(!lrc_readonly(first,bytes),148);*mask|=16;
    lc8o_need(equal(&lc8o.descriptor_saved.root,&lhc.root,sizeof lhc.root),149);*mask|=32;
    lgdo_isolation_epochs(after);
    for(unsigned k=0;k<28;k++)
        lc8o_need(after[k]==before[k]+(bundle?k<10:k==1+i),150);
    lc8o_need(lgd_writer.value.invalidations==invalidations+1 &&
        !lhc_exposure_current(i) && lhc_exposure_current(j)==(bundle?0:1),151);*mask|=64;
    uint64_t fallback=lgd_counts.history_fallbacks,hits=lhc.counts.hits,
        common=lgd_counts.common_lhc_hits;
    lc8o_need(pda_receipt(c) && pda_receipt(peer) &&
        lgd_counts.history_fallbacks==fallback+(bundle?2:1) &&
        lhc.counts.hits==hits+(bundle?0:1) &&
        lgd_counts.common_lhc_hits==common+(bundle?0:1),152);*mask|=128;
    if(bundle)++o->raw_bundle;else ++o->raw_cell;
}
#endif
static void lgdo_isolation(const struct pda_completion *current) {
    if(lc8o.epochs>2)return;
    struct lgdo_isolation_observation *o=&lc8o.isolation;
    unsigned j=lhc_index(current);
    lc8o_need(current && current->complete==1 && current->serial==pe.p.serial &&
        j<9 && !lc8o.busy && !lhc_writer() && lhc_mask(current)==7 &&
        lhc_match(current,j) && lhc_exposure_current(j),153);
    if(lc8o.epochs==1) {
        lc8o_need(!o->epochs,154);o->epochs=1;o->cell=j;o->id=current->id;o->serial=current->serial;
        copy(&lc8o.isolation_certificate,lhc_cell(j),sizeof lc8o.isolation_certificate);
        lc8o.isolation_epoch[0]=lgd_root_epoch();
        lc8o.isolation_epoch[1]=lgd_certificate_epoch(j);
        lc8o.isolation_epoch[2]=lgd_cell_epoch(j);lc8o.isolation_epoch[3]=lgd_capsule_epoch(j);
        return;
    }
    unsigned i=(unsigned)o->cell;struct pda_completion *old=&pe.domain.completion[i];
    lc8o_need(lc8o.epochs==2 && o->epochs==1 && i<9 && j!=i &&
        old->id==o->id && old->serial==o->serial &&
        equal(&lc8o.isolation_certificate,lhc_cell(i),sizeof lc8o.isolation_certificate) &&
        lc8o.isolation_epoch[0]==lgd_root_epoch() &&
        lc8o.isolation_epoch[1]==lgd_certificate_epoch(i) &&
        lc8o.isolation_epoch[2]==lgd_cell_epoch(i) &&
        lc8o.isolation_epoch[3]==lgd_capsule_epoch(i) &&
        lhc_match(old,i) && lhc_exposure_current(i),155);
    o->epochs=2;o->peer=j;o->peer_id=current->id;o->peer_serial=current->serial;o->preserved=1;
    uint64_t common=lgd_counts.common_lhc_hits,history=lhc.counts.hits,
        renewed=lgd_counts.common_revalidated_hits;
    lc8o_need(pda_receipt(old) && lgd_counts.common_lhc_hits==common+1 &&
        lhc.counts.hits==history+1 && lgd_counts.common_revalidated_hits==renewed,156);
    o->common_hit=o->history_hit=1;
#if LI2_LOOP_CACHE8_CONTROL
    lc8o.busy=1;
    lgdo_isolation_raw(old,current,i,j,0);
    lgdo_isolation_raw(old,current,i,j,1);
    lc8o.busy=0;
#endif
    /* Restore the actual current completion's canonical historical scratch.
       The ordinary persistent exit independently validates it again. */
    lc8o_need(pda_receipt(current),157);
}
static void lgdo_isolation_report(unsigned status,unsigned code) {
    const struct lgdo_isolation_observation *o=&lc8o.isolation;
    struct writer w={.used=0};text(&w,"LI2_LOOP_HISTORY_ISOLATION {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"control\":",LI2_LOOP_CACHE8_CONTROL);
#define LGDO_ISOLATION_FIELD(n) field(&w,",\"" #n "\":",o->n)
    LGDO_ISOLATION_FIELD(epochs);LGDO_ISOLATION_FIELD(cell);LGDO_ISOLATION_FIELD(id);
    LGDO_ISOLATION_FIELD(serial);LGDO_ISOLATION_FIELD(peer);LGDO_ISOLATION_FIELD(peer_id);
    LGDO_ISOLATION_FIELD(peer_serial);LGDO_ISOLATION_FIELD(preserved);
    LGDO_ISOLATION_FIELD(common_hit);LGDO_ISOLATION_FIELD(history_hit);
    LGDO_ISOLATION_FIELD(raw_cell);LGDO_ISOLATION_FIELD(raw_cell_mask);
    LGDO_ISOLATION_FIELD(raw_bundle);LGDO_ISOLATION_FIELD(raw_bundle_mask);
    LGDO_ISOLATION_FIELD(stale_setup);LGDO_ISOLATION_FIELD(stale_setup_mask);
    LGDO_ISOLATION_FIELD(extra_misses);LGDO_ISOLATION_FIELD(extra_restorations);
    LGDO_ISOLATION_FIELD(extra_mask);
#undef LGDO_ISOLATION_FIELD
    text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
static void lgdo_common_controls(const struct pda_completion *current) {
#if LI2_LOOP_CACHE8_CONTROL
    if(lc8o.epochs!=4)return;
    struct lgdo_common_observation *o=&lc8o.common;
    lc8o_need(!o->epochs && !lc8o.busy && current && current->complete==1 &&
        current->serial==pe.p.serial && !lhc_writer() &&
        lgd_writer.value.initialized==1 && !lgd_writer.value.poisoned &&
        handling==1 && !pe_failing && !pe.resuming,114);
    struct pda_completion *c=0;unsigned i=LI2_PGD_RECEIPTS;
    for(unsigned at=0;at<LI2_PGD_RECEIPTS;at++) {
        struct pda_completion *old=&pe.domain.completion[at];
        if(old!=current && old->id && lhc_match_identity(old,at)) {
            c=old;i=at;break;
        }
    }
    lc8o_need(c && i<LI2_PGD_RECEIPTS,115);lc8o.busy=1;
    /* Per-cell issuance no longer makes unrelated completions stale. Establish
       the old suite's premise through an actual exposure, never epoch stores. */
    struct lgdo_isolation_observation *isolation=&lc8o.isolation;
    lc8o_need(!isolation->stale_setup && !lrc_readonly((uintptr_t)c,sizeof *c),140);
    isolation->stale_setup_mask=1;
    uint64_t before_root=lgd_root_epoch(),before_certificate=lgd_certificate_epoch(i),
        before_cell=lgd_cell_epoch(i),before_capsule=lgd_capsule_epoch(i);
    lgdo_common_permission((uintptr_t)c,sizeof *c,PROT_READ|PROT_WRITE);
    lgdo_common_permission((uintptr_t)c,sizeof *c,PROT_READ);
    isolation->stale_setup_mask|=2;
    lc8o_need(lgd_root_epoch()==before_root && lgd_certificate_epoch(i)==before_certificate &&
        lgd_cell_epoch(i)==before_cell+1 && lgd_capsule_epoch(i)==before_capsule,141);
    isolation->stale_setup_mask|=4;
    lc8o_need(!lrc_readonly((uintptr_t)c,sizeof *c) && lhc_match_identity(c,i) &&
        !lhc_exposure_current(i),142);
    isolation->stale_setup_mask|=8;isolation->stale_setup=1;
    o->epochs=1;o->serial=current->serial;o->cell=i;o->id=c->id;o->cell_serial=c->serial;
    struct lgd_common_token *t=&lgd_writer.value.common[i];
    le_zero(t,sizeof *t);lgdo_common_pair(c,i);
    for(unsigned kind=0;kind<31;kind++) {
        switch(kind) {
        case 0:t->valid^=1;break;case 1:t->index^=1;break;
        case 2:t->raw_root^=1;break;case 3:t->raw_cell^=1;break;
        case 4:t->raw_capsule^=1;break;case 5:t->source_context^=1;break;
        case 6:t->directory^=PAGE;break;case 7:t->certificate.valid^=1;break;
        case 8:t->certificate.policy^=1;break;case 9:t->certificate.mask^=1;break;
        case 10:t->certificate.reserved^=1;break;case 11:t->certificate.epoch^=1;break;
        case 12:t->certificate.id^=1;break;case 13:t->certificate.serial^=1;break;
        case 14:t->certificate.raw_root^=1;break;case 15:t->certificate.raw_cell^=1;break;
        case 16:t->certificate.raw_capsule^=1;break;case 17:t->certificate.source_context^=1;break;
        case 18:t->certificate.directory^=PAGE;break;case 19:t->certificate.owner=0;break;
        case 20:t->certificate.completion=0;break;case 21:t->certificate.capsule^=PAGE;break;
        case 22:t->certificate.session.pid^=1;break;case 23:t->certificate.session.tid^=1;break;
        case 24:t->certificate.session.sync_register^=1;break;
        case 25:t->certificate.session.sync_query^=1;break;
        case 26:t->certificate.session.application_mask^=1;break;
        case 27:t->certificate.session.initialized^=1;break;
        case 28:t->certificate.session.self_test_complete^=1;break;
        case 29:t->certificate.archive[0]^=1;break;
        default:t->certificate.policy_hash[0]^=1;break;
        }
        lgdo_common_pair(c,i);++o->token_misses;++o->token_restorations;
        o->token_mask|=UINT64_C(1)<<kind;
    }
    /* Supplied guard mutations are restored literally. Real RAW epochs are
       never restored; the writer control uses actual root permission calls. */
    for(unsigned kind=0;kind<6;kind++) {
        if(kind==0)lgd_writer.value.initialized=0;
        else if(kind==1)lgd_writer.value.poisoned=1;
        else if(kind==2)handling=0;
        else if(kind==3)pe_failing=1;
        else if(kind==4)pe.resuming=1;
        else {
            lgdo_common_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ|PROT_WRITE);
            lhc_set_writer(i+1);
            lgdo_common_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ);
        }
        lgdo_common_unissued(c,i);++o->guard_unissued;
        if(kind==0)lgd_writer.value.initialized=1;
        else if(kind==1)lgd_writer.value.poisoned=0;
        else if(kind==2)handling=1;
        else if(kind==3)pe_failing=0;
        else if(kind==4)pe.resuming=0;
        else {
            lgdo_common_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ|PROT_WRITE);
            lhc_set_writer(0);
            lgdo_common_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ);
        }
        le_zero(t,sizeof *t);lgdo_common_pair(c,i);++o->guard_restorations;
        o->guard_mask|=UINT64_C(1)<<kind;
    }
    for(unsigned kind=0;kind<3;kind++) {
        uintptr_t first=kind==0?(uintptr_t)c:kind==1?(uintptr_t)&lhc.capsule[i]:(uintptr_t)&lhc.root;
        size_t bytes=kind==0?sizeof *c:kind==1?sizeof lhc.capsule[i]:sizeof lhc.root;
        uint64_t root=lgd_root_epoch(),cell=lgd_cell_epoch(i),capsule=lgd_capsule_epoch(i);
        lc8o_need(!lrc_readonly(first,bytes),116);
        lgdo_common_permission(first,bytes,PROT_READ|PROT_WRITE);
        lgdo_common_unissued(c,i);++o->raw_unissued;
        lgdo_common_permission(first,bytes,PROT_READ);
        lc8o_need(!lrc_readonly(first,bytes) && lgd_root_epoch()==root+(kind==2) &&
            lgd_cell_epoch(i)==cell+(kind==0) && lgd_capsule_epoch(i)==capsule+(kind==1),117);
        lgdo_common_pair(c,i);++o->raw_restorations;o->raw_mask|=UINT64_C(1)<<kind;
    }
    struct lgd_common_token saved;copy(&saved,t,sizeof saved);
    lgdo_common_permission((uintptr_t)c,sizeof *c,PROT_READ|PROT_WRITE);c->complete=0;
    lgdo_common_permission((uintptr_t)c,sizeof *c,PROT_READ);
    uint64_t full=lgd_counts.common_full,hits=lgd_counts.common_hits,
        differential=lgd_counts.common_differential;
    lc8o_need(!lgd_common_value(c) && lgd_counts.common_full==full+1 &&
        lgd_counts.common_hits==hits && lgd_counts.common_differential==differential &&
        equal(&saved,t,sizeof saved),118);
    o->failed_full=1;o->failed_unissued=1;
    lgdo_common_permission((uintptr_t)c,sizeof *c,PROT_READ|PROT_WRITE);c->complete=1;
    lgdo_common_permission((uintptr_t)c,sizeof *c,PROT_READ);
    lgdo_common_pair(c,i);o->failed_restored=1;
    uint64_t history=lgd_counts.history_fallbacks;
    lc8o_need(!lhc_exposure_current(i) && pda_receipt(c) &&
        lgd_counts.history_fallbacks==history+1,119);
    o->history_fallback=1;lc8o_need(o->quiet_pairs==42,120);
    /* Two new certificate-epoch fields are additional to the unchanged31
       original mutations and42 original miss/hit pairs. */
    for(unsigned kind=0;kind<2;kind++) {
        if(kind==0)t->raw_certificate^=1;
        else t->certificate.raw_certificate^=1;
        lgdo_common_pair_record(c,i,&isolation->extra_restorations);
        ++isolation->extra_misses;isolation->extra_mask|=UINT64_C(1)<<kind;
    }
    lc8o.busy=0;
#else
    (void)current;
#endif
}
static void lgdo_common_report(unsigned status,unsigned code) {
    const struct lgdo_common_observation *o=&lc8o.common;
    struct writer w={.used=0};text(&w,"LI2_LOOP_COMMON_REVALIDATION {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"control\":",LI2_LOOP_CACHE8_CONTROL);
#define LGDO_COMMON_FIELD(n) field(&w,",\"" #n "\":",o->n)
    LGDO_COMMON_FIELD(epochs);LGDO_COMMON_FIELD(serial);LGDO_COMMON_FIELD(cell);
    LGDO_COMMON_FIELD(id);LGDO_COMMON_FIELD(cell_serial);LGDO_COMMON_FIELD(quiet_pairs);
    LGDO_COMMON_FIELD(token_misses);LGDO_COMMON_FIELD(token_restorations);LGDO_COMMON_FIELD(token_mask);
    LGDO_COMMON_FIELD(guard_unissued);LGDO_COMMON_FIELD(guard_restorations);LGDO_COMMON_FIELD(guard_mask);
    LGDO_COMMON_FIELD(raw_unissued);LGDO_COMMON_FIELD(raw_restorations);LGDO_COMMON_FIELD(raw_mask);
    LGDO_COMMON_FIELD(failed_full);LGDO_COMMON_FIELD(failed_unissued);LGDO_COMMON_FIELD(failed_restored);
    LGDO_COMMON_FIELD(history_fallback);
#undef LGDO_COMMON_FIELD
    text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
static void lgdo_finished(const struct pda_completion *c) {
    lgdo_isolation(c);
    lgdo_common_controls(c);
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
