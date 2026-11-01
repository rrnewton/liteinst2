/* Included after the whole unchanged certificate decision body, renamed
   sbc_decision only in this test profile. The old full comparator is intact. */
static int sbco_initialize(void) {
    if(sbco.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&sbco,sizeof sbco))return PE_STATE;
    sbco.initialized=1;return 0;
}
static int sbco_closed(void) {
    if(sbco.initialized!=1 || handling!=1 || !pe_busy || pe_active || pe.resuming ||
       pe_failing || pe_closing || !ptr_storage() ||
       selected_run_protect_contains(0,(uintptr_t)&sbco,sizeof sbco)!=1)return 0;
#ifdef LI2_PERSISTENT_RET_DISPATCH
    if(prr_pending || prr_busy)return 0;
#endif
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *s=&pe.retained[i];
        const struct li2_pg_generation *g=&s->generation;
        /* A bound but not opened member may hold one domain lease. It must
           still have no execution/incoming refs and every bank is NX. */
        if(g->active_refs || g->member_refs[0] || g->member_refs[1] ||
           g->incoming[0] || g->incoming[1] || g->domain_refs>1)return 0;
        for(unsigned j=0;j<2;j++) {
            const struct ped_bank *b=&s->banks[j];
            if(b->prot!=(b->virgin?(PROT_READ|PROT_WRITE):PROT_READ))return 0;
        }
    }
    return 1;
}
static int sbco_closed_queries(void) {
    if(!sbco_closed())return PE_STATE;
    /* Actual current permission queries, not a caller-provided NX flag. */
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++) {
        const struct ped_bank *b=&pe.retained[i].banks[j];
        struct li2_private_code_query q[3]={0};
        if(pg_queries(&b->layout,b->prot,q))return PE_PUBLICATION;
        for(unsigned k=0;k<3;k++)
            if(!pg_query_complete(&q[k],pg_extent(&b->layout,k),pg_extent_bytes(k),b->prot))
                return PE_PUBLICATION;
    }
    return 0;
}
static int sbco_claim(void) {
    if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL>=2 || pe.warm || sbco.stage)return 0;
    if(!sbc_live() || pe.p.phase!=LI2_PG_CONSUMED || !pe.consumed ||
       !pda_permitted(pe.selected_slot) || sbco_closed_queries())return PE_STATE;
    const struct sbc_owner *o=&sg_owner.state.bytes;
    const struct sbc_certificate *c=&o->certificate[pe.selected_slot];
    const struct li2_pg_generation *g=&PE_SLOT(generation);
    /* The replacement bank may already be selected. The completed victim
       is authenticated against its own actual bank, never the new bank. */
    if(c->valid!=1 || c->reserved || c->slot!=pe.selected_slot || c->bank>1 ||
       !c->serial || c->serial>o->next_serial || c->owner!=&pe ||
       c->mirror!=(uintptr_t)&PE_SLOT(publication) || c->mirror_bytes!=sizeof PE_SLOT(publication) ||
       !equal(&c->session,&pe.session,sizeof pe.session) ||
       c->mirror_epoch!=o->mirror_epoch[pe.selected_slot] || !c->mirror_epoch ||
       o->writer[pe.selected_slot] || c->generation!=g->generation ||
       c->build_serial!=g->build_serial || g->domain_refs ||
       !sbc_backing(g,&sg_owner.state.bank[c->slot][c->bank]) ||
       !equal(&c->backing,&sg_owner.state.bank[c->slot][c->bank],sizeof c->backing))return PE_STATE;
    const struct li2_pgd_claim *q=&PE_SLOT(claim);
    const struct pda_completion *done=&pe.domain.completion[q->cell];
    sbco.old=*c;sbco.claim_token=pe.p.serial;sbco.claim_id=q->id;
    sbco.claim_serial=done->serial;sbco.claim_cell=q->cell;sbco.claim_member=q->member;
    sbco.claimed_before=pe.domain.claimed[q->cell];sbco.stage=1;return 0;
}
static int sbco_invalidated(void) {
    if(sbco.stage!=1 || sbco.old.slot!=pe.selected_slot)return 0;
    const struct sbc_owner *o=&sg_owner.state.bytes;
    if(!sbco_closed() || pe.p.serial!=sbco.claim_token || !sbc_unpublished() ||
       PE_SLOT(claim).valid || PE_SLOT(claim).id || PE_SLOT(permit).valid ||
       o->mirror_epoch[pe.selected_slot]!=sbco.old.mirror_epoch+1 ||
       pe.domain.claimed[sbco.claim_cell]!=(sbco.claimed_before|(1U<<sbco.claim_member)) ||
       PE_SLOT(generation).generation!=sbco.old.generation)return PE_STATE;
    sbco.claimed_after=pe.domain.claimed[sbco.claim_cell];
    sbco.invalidated_epoch=o->mirror_epoch[pe.selected_slot];
    sbco.writer_token=o->writer[pe.selected_slot];sbco.stage=2;return 0;
}
static int sbco_mirror_write(void) {
    if(sbco.stage!=2 || sbco.old.slot!=pe.selected_slot)return 0;
    if(!sbco_closed() || pe.p.serial!=sbco.claim_token || pe.p.phase!=LI2_PG_PUBLISHING ||
       !sbc_unpublished() || sg_owner.state.bytes.mirror_epoch[pe.selected_slot]!=sbco.invalidated_epoch ||
       PE_SLOT(generation).generation<=sbco.old.generation)return PE_STATE;
    sbco.mirror_write_epoch=sg_owner.state.bytes.mirror_epoch[pe.selected_slot];
    sbco.stage=3;return 0;
}
static int sbco_issue(void) {
    if(sbco.stage!=3 || sbco.old.slot!=pe.selected_slot)return 0;
    const struct sbc_certificate *c=&sg_owner.state.bytes.certificate[pe.selected_slot];
    if(!sbco_closed() || pe.p.serial!=sbco.claim_token || pe.p.phase!=LI2_PG_PUBLISHING ||
       c->valid!=1 || c->serial<=sbco.old.serial || c->mirror_epoch!=sbco.invalidated_epoch ||
       c->generation<=sbco.old.generation || c->build_serial!=sbco.claim_token ||
       c->build_serial<=sbco.old.build_serial || c->mirror!=sbco.old.mirror ||
       c->mirror_bytes!=sbco.old.mirror_bytes || sg_owner.state.bytes.writer[pe.selected_slot])return PE_STATE;
    sbco.current=*c;sbco.issued_serial=c->serial;sbco.stage=4;return 0;
}
static int sbco_before(void) {
    if(!LI2_SEALED_BYTE_CERTIFICATE_CONTROL || sbco.fired)return 0;
    if((pe.p.phase!=LI2_PG_BOUND && pe.p.phase!=LI2_PG_OPENING) ||
       !sbco_closed() || !sbc_match())return 0;
    if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL==1 &&
       (sbco.stage!=4 || sbco.old.slot!=pe.selected_slot ||
        !equal(&sbco.current,&sg_owner.state.bytes.certificate[pe.selected_slot],sizeof sbco.current)))return 0;
    if(sbco_closed_queries() || sbc_queries(&PE_SLOT(generation),
       &sg_owner.state.bank[pe.selected_slot][pe.selected_bank]))return PE_PUBLICATION;
    sbco.token=pe.p.serial;sbco.phase=pe.p.phase;sbco.slot=pe.selected_slot;sbco.bank=pe.selected_bank;
    sbco.generation=PE_SLOT(generation).generation;sbco.domain_refs=PE_SLOT(generation).domain_refs;
    sbco.closed_before=1;sbco.candidate_before=1;
    sbco.current=sg_owner.state.bytes.certificate[pe.selected_slot];
    sbco.before=sbc_observed;sbco.fired=1;
    if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL==1) {
        if(sg_permission(PROT_READ|PROT_WRITE))return PE_PUBLICATION;
        /* Exact captured victim value; no new serial, epoch or permission. */
        sg_owner.state.bytes.certificate[pe.selected_slot]=sbco.old;
        __asm__ volatile("":::"memory");
        if(sg_permission(PROT_READ))return PE_PUBLICATION;
    } else if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL==2) {
        /* This byte is inside the wholly compared plan mirror, outside its
           header/source identity. The sealed proof remains untouched. */
        size_t at=offsetof(struct pe_payload,plan)+sizeof PE_SLOT(publication).plan-1;
        unsigned char *mirror=(void *)&PE_SLOT(publication);
        const volatile unsigned char *proof=(const void *)PE_SLOT(generation).proof;
        if(at>=sizeof PE_SLOT(publication) || mirror[at]!=proof[at])return PE_PUBLICATION;
        sbco.mirror_offset=at;sbco.mirror_before=mirror[at];mirror[at]^=1;
        __asm__ volatile("":::"memory");sbco.mirror_after=mirror[at];
    } else {
        sbco.close_attempted=1;
        sbco.close_result=raw(SYS_close,sbco.current.backing.fd,0,0,0,0,0);
        if(sbco.close_result)return PE_PUBLICATION;
    }
    sbco.candidate_after=(unsigned)sbc_match();return 0;
}
static void sbco_query(const struct li2_sealed_code_query *q,int error) {
    if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL!=3 || !sbco.fired || sbco.complete)return;
    pe_need(!sbco.query_calls,PE_STATE,197);
    sbco.query_calls=1;sbco.query_error=error;sbco.failed_query=*q;
}
static void sbco_after(int result) {
    if(!sbco.fired || sbco.complete)return;
    sbco.after=sbc_observed;sbco.decision_result=result;
    sbco.closed_after=(unsigned)sbco_closed();
    /* No permission-changing operation exists between the actual NX query
       and this decision. A deliberate refusal uses the ordinary abort path. */
    pe_need(sbco.closed_after && pe.p.serial==sbco.token &&
        pe.selected_slot==sbco.slot && pe.selected_bank==sbco.bank &&
        PE_SLOT(generation).generation==sbco.generation,PE_STATE,191);
    const struct sbc_counts *a=&sbco.after,*b=&sbco.before;
    pe_need(a->decisions==b->decisions+1 && a->full_scans==b->full_scans+1 &&
        a->issues==b->issues && a->invalidations==b->invalidations &&
        a->postseal_bytes==b->postseal_bytes && a->abort_invalidations==b->abort_invalidations,
        PE_STATE,192);
    if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL==1) {
        pe_need(!sbco.candidate_after && !result && a->last_failure==SBC_NONE && !a->last_full_result &&
            a->hits==b->hits && a->misses==b->misses+1 && a->full_scan_errors==b->full_scan_errors &&
            a->disagreements==b->disagreements && a->full_scan_bytes==b->full_scan_bytes+PE_CODE_BYTES+PE_PROOF_BYTES &&
            a->live_queries==b->live_queries && a->live_query_errors==b->live_query_errors,PE_STATE,193);
    } else if(LI2_SEALED_BYTE_CERTIFICATE_CONTROL==2) {
        pe_need(sbco.candidate_after==1 && result==PE_PUBLICATION &&
            a->last_failure==SBC_DISAGREEMENT && a->last_full_result==PE_PUBLICATION &&
            a->hits==b->hits+1 && a->misses==b->misses && a->full_scan_errors==b->full_scan_errors+1 &&
            a->disagreements==b->disagreements+1 && a->full_scan_bytes==b->full_scan_bytes &&
            a->live_queries==b->live_queries+3 && a->live_query_errors==b->live_query_errors,PE_STATE,194);
    } else {
        pe_need(sbco.candidate_after==1 && result==PE_PUBLICATION &&
            a->last_failure==SBC_LIVE_QUERY_ERROR && !a->last_full_result &&
            a->hits==b->hits && a->misses==b->misses+1 && a->full_scan_errors==b->full_scan_errors &&
            a->disagreements==b->disagreements && a->full_scan_bytes==b->full_scan_bytes+PE_CODE_BYTES+PE_PROOF_BYTES &&
            a->live_queries==b->live_queries+1 && a->live_query_errors==b->live_query_errors+1 &&
            sbco.query_calls==1 && sbco.query_error==LI2_FETCH_IDENTITY &&
            sbco.failed_query.result==LI2_FETCH_IDENTITY && sbco.failed_query.detail==1 &&
            sbco.failed_query.attempted==1 && !sbco.failed_query.complete &&
            sbco.failed_query.sealed.seals_result==-EBADF && sbco.failed_query.sealed.stat_result==-EBADF &&
            equal(&sbco.failed_query.sealed.identity,&sbco.current.backing,sizeof sbco.current.backing),
            PE_STATE,195);
    }
    sbco.complete=1;sbco.stopped=1;sbco.test_detail=192+LI2_SEALED_BYTE_CERTIFICATE_CONTROL;
    selected_persistent_abort(PE_PUBLICATION,(long)sbco.test_detail);
}
static int pe_bytes(void) {
    int error=sbco_before();pe_need(!error,PE_STATE,190);
    int result=sbc_decision();sbco_after(result);return result;
}
static void sbco_words(struct writer *w,const char *name,const void *value,size_t bytes) {
    const unsigned char *b=value;text(w,name);text(w,"[");
    for(size_t at=0;at<bytes;at+=8) {
        uint64_t word=0;for(unsigned j=0;j<8;j++)word|=(uint64_t)b[at+j]<<(8*j);
        if(at)text(w,",");
        number(w,word);
    }
    text(w,"]");
}
static void sbco_report(unsigned status,unsigned code) {
    struct writer w={.used=0};text(&w,"LI2_SEALED_BYTE_CERTIFICATE_TEST {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"control\":",LI2_SEALED_BYTE_CERTIFICATE_CONTROL);
    sbco_words(&w,",\"event\":",&sbco,offsetof(struct sbco_observation,old));
    sbco_words(&w,",\"old\":",&sbco.old,sizeof sbco.old);
    sbco_words(&w,",\"current\":",&sbco.current,sizeof sbco.current);
    sbco_words(&w,",\"before\":",&sbco.before,sizeof sbco.before);
    sbco_words(&w,",\"after\":",&sbco.after,sizeof sbco.after);
    sbco_words(&w,",\"failed_query\":",&sbco.failed_query,sizeof sbco.failed_query);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(sizeof(struct pe_header)==288 && sizeof(struct pe_payload)==362656 &&
    sizeof(struct li2_sealed_code_query)==296 &&
    sizeof(struct sbco_observation)%8==0 &&
    sizeof(struct sbco_observation)/8*21+256<=4096,"bounded complete observation row");
