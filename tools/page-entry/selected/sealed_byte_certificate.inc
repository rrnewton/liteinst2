/* Included immediately after the byte-exact original pe_bytes_full body.
   No source/mapping/permission/receipt/rseq predicate is memoized here. */
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
#include "sealed_byte_certificate_observe.h"
#endif
#ifdef LI2_LOOP_RO_CERTIFICATE
#include "loop_ro_certificate.inc"
#endif
static struct sbc_counts sbc_observed;
static int sbc_add(uint64_t *value,uint64_t amount) {
    if(*value>UINT64_MAX-amount)return PE_OVERFLOW;
    *value+=amount;return 0;
}
static int sbc_initialize(void) {
    if(!sg_owner.state.initialized || sbc_observed.initialized ||
       protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&sbc_observed,sizeof sbc_observed))return PE_STATE;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
    int error=sbco_initialize();if(error)return error;
#endif
#ifdef LI2_LOOP_RO_CERTIFICATE
    int mirror_error=lrc_initialize();if(mirror_error)return mirror_error;
#endif
    sbc_observed.initialized=1;return 0;
}
static int sbc_live(void) {
#ifdef LI2_LOOP_TRANSLATION_ARENA
    if(!sg_selected_node())return 0;
#endif
    if(!sg_owner.state.initialized || sg_owner.state.bytes.poisoned ||
       !sbc_observed.initialized || handling!=1 || !pe_busy || pe_failing || pe.resuming ||
       pe.p.first_error || pe.p.anchor_released || !ptr_selected() ||
       pe.selected_bank>1 || !pe_registered_storage() || !pe_identity() ||
       selected_run_protect_contains(0,(uintptr_t)&sg_owner,sizeof sg_owner)!=1 ||
       selected_run_protect_contains(0,(uintptr_t)&sbc_observed,sizeof sbc_observed)!=1)return 0;
    switch(pe.p.phase) {
    case LI2_PG_HELD:case LI2_PG_CONSUMED:case LI2_PG_PUBLISHING:
    case LI2_PG_BOUND:case LI2_PG_OPENING:case LI2_PG_CLOSING:break;
    default:return 0;
    }
#ifdef LI2_LOOP_RO_CERTIFICATE
    if(!lrc_state())return 0;
#else
    struct li2_rsl_ref ref={0};
    if(li2_rsl_current(&pe.token,&ref) || !li2_rsl_ref_live(&ref))return 0;
#endif
    const struct li2_pg_source_progress *s=li2_pg_source_progress();
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    return s && s->initialized==1 && s->serial==pe.token.serial &&
        !s->first_error && !s->aborted && !s->release_started && !s->release_complete &&
        (s->phase==LI2_PGS_HELD || s->phase==LI2_PGS_RX || s->phase==LI2_PGS_CLOSED) &&
        s->source.complete==1 && s->source.serial==pe.token.serial &&
        equal(&s->source.anchor,&pe.ref,sizeof pe.ref) && f && f->held==1 &&
        f->sequence==pe.ref.sequence && !f->first_error && r && r->active==1 &&
        !r->checking && !r->first_error && !r->unsafe_terminal && r->seed_complete==1 &&
        r->token.owner==&pe && r->token.serial==pe.token.serial;
}
static int sbc_unpublished(void) {
#ifdef LI2_LOOP_TRANSLATION_ARENA
    if(!sg_selected_node())return 0;
#endif
    if(!sg_owner.state.initialized || sg_owner.state.bytes.poisoned ||
       pe.selected_slot>=LI2_PTR_SLOTS || pe.selected_bank>1)return 0;
    const struct sbc_owner *o=&sg_owner.state.bytes;
    return !o->certificate[SBC_NODE_INDEX].valid && o->mirror_epoch[SBC_NODE_INDEX] &&
        o->writer[SBC_NODE_INDEX]==pe.p.serial && pe.p.serial;
}
static int sbc_replace_begin(void) {
    if(!sbc_live() || pe.p.phase!=LI2_PG_CONSUMED || pe_active || !pe.consumed ||
       pe.warm || PE_SLOT(claim).valid || PE_SLOT(claim).id || PE_SLOT(permit).valid)return PE_STATE;
    const struct li2_pg_generation *g=&PE_SLOT(generation);
    if(g->active_refs || g->member_refs[0] || g->member_refs[1] || g->incoming[0] ||
       g->incoming[1] || g->domain_refs || sg_owner.state.bytes.mirror_epoch[SBC_NODE_INDEX]==UINT64_MAX ||
       sbc_observed.invalidations==UINT64_MAX)return PE_STATE;
#ifdef LI2_LOOP_RO_CERTIFICATE
    if(!lrc_live())return PE_PUBLICATION;
#endif
    if(sg_permission(PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    struct sbc_owner *o=&sg_owner.state.bytes;
    o->certificate[SBC_NODE_INDEX].valid=0;
    ++o->mirror_epoch[SBC_NODE_INDEX];o->writer[SBC_NODE_INDEX]=pe.p.serial;
    __asm__ volatile("":::"memory");
    int error=sg_permission(PROT_READ);if(error)return error;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
    ++sbc_observed.invalidations;
    if((error=sbco_invalidated()))return error;
    return 0;
#else
    ++sbc_observed.invalidations;return 0;
#endif
}
static int sbc_backing(const struct li2_pg_generation *g,const struct li2_sealed_identity *id) {
    return id->fd>=0 && id->fd<=INT32_MAX && id->inode &&
        id->generation==g->generation && id->code==g->generated && id->proof==g->proof &&
        id->code_bytes==PE_CODE_BYTES && id->proof_bytes==PE_PROOF_BYTES &&
        id->bytes==PE_CODE_BYTES+PE_PROOF_BYTES && id->code_live==1 && id->proof_live==1 &&
        sg_find(g->generated,PE_CODE_BYTES)==id && sg_find(g->proof,PE_PROOF_BYTES)==id;
}
#ifdef LI2_LOOP_TRANSLATION_ARENA
static int sbc_queries_value(const struct li2_pg_generation *g,const struct li2_sealed_identity *id,int prot) {
#else
static int sbc_queries(const struct li2_pg_generation *g,const struct li2_sealed_identity *id) {
#endif
    /* Always fresh: actual maps, permissions, seals, fstat and complete alias
       census. The existing caller's retained query/transition records remain
       unchanged too. No successful old query is reused as current evidence. */
#ifndef LI2_LOOP_TRANSLATION_ARENA
#ifdef LI2_LOOP_RO_CERTIFICATE
    if(!lrc_live())return PE_PUBLICATION;
#endif
    int prot=PE_SLOT(banks)[pe.selected_bank].prot;
#endif
    if(prot!=PROT_READ && prot!=(PROT_READ|PROT_EXEC))return PE_PUBLICATION;
    for(unsigned extent=0;extent<2;extent++) {
        uintptr_t at=extent?g->proof:g->generated;
        size_t left=extent?PE_PROOF_BYTES:PE_CODE_BYTES;
        int expected=extent?PROT_READ:prot;
        while(left) {
            size_t bytes=left>64U*PAGE?64U*PAGE:left;
            struct li2_sealed_code_query q={0};
            int error=sbc_add(&sbc_observed.live_queries,1);if(error)return error;
            error=li2_lifecycle_sealed_code_query(id,at,bytes,expected,&q);
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
            sbco_query(&q,error);
#endif
            if(error || q.attempted!=1 || q.complete!=1 || q.result || q.first!=at ||
               q.end!=at+bytes || q.pages_checked!=bytes/PAGE || q.expected_prot!=expected ||
               q.actual_prot!=expected || q.sealed.kind!=LI2_SEALED_QUERY_KIND ||
               q.sealed.version!=LI2_SEALED_QUERY_VERSION || q.sealed.reserved ||
               q.sealed.seals_result!=LI2_SEALED_REQUIRED_SEALS || q.sealed.stat_result ||
               q.sealed.alias_complete!=1 || q.sealed.alias_pages!=(PE_CODE_BYTES+PE_PROOF_BYTES)/PAGE ||
               !q.sealed.alias_vmas || q.sealed.alias_vmas>q.sealed.alias_pages ||
               q.sealed.offset!=(extent?PE_CODE_BYTES+at-g->proof:at-g->generated) ||
               !equal(&q.sealed.identity,id,sizeof *id)) {
                error=sbc_add(&sbc_observed.live_query_errors,1);
                return error?error:PE_PUBLICATION;
            }
            at+=bytes;left-=bytes;
        }
    }
    return 0;
}
#ifdef LI2_LOOP_TRANSLATION_ARENA
static int sbc_queries(const struct li2_pg_generation *g,const struct li2_sealed_identity *id) {
    if(!lrc_live())return PE_PUBLICATION;
    return sbc_queries_value(g,id,PE_SLOT(banks)[pe.selected_bank].prot);
}
#endif
static int sbc_issue(void) {
    if(!sbc_live() || !sbc_unpublished() || pe.p.phase!=LI2_PG_PUBLISHING || pe_active ||
       !pe.consumed || pe.warm || sg_owner.state.bytes.next_serial==UINT64_MAX ||
       sbc_observed.issues==UINT64_MAX ||
       sbc_observed.postseal_bytes>UINT64_MAX-(PE_CODE_BYTES+PE_PROOF_BYTES))return PE_STATE;
    const struct li2_pg_generation *g=&PE_SLOT(generation);
    const struct li2_sealed_identity *id=&sg_owner.state.bank[SBC_NODE_INDEX][pe.selected_bank];
    if(g->installed!=1 || g->complete!=1 || g->proof_complete!=1 || !g->generation ||
       g->generation!=pe.next_generation || g->build_serial!=pe.p.serial || g->ready_generation ||
       g->code_copied!=PE_CODE_BYTES || g->code_verified!=PE_CODE_BYTES ||
       g->proof_zeroed!=PE_PROOF_BYTES || g->proof_copied!=sizeof(struct pe_payload) ||
       g->proof_verified!=PE_PROOF_BYTES || g->plan_proofs!=2 || g->none_proofs!=1 ||
       g->active_refs || g->member_refs[0] || g->member_refs[1] || g->incoming[0] ||
       g->incoming[1] || g->domain_refs || !pg_closed(&g->layout,g->code_sealed) ||
       !pg_proof_permission_complete(&g->proof_sealed,g->proof,PROT_READ) ||
       !sbc_backing(g,id))return PE_PUBLICATION;
    int error=sbc_queries(g,id);if(error)return error;
    if(sg_permission(PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    struct sbc_owner *o=&sg_owner.state.bytes;
    o->certificate[SBC_NODE_INDEX]=(struct sbc_certificate){
#ifdef LI2_LOOP_RO_CERTIFICATE
        .valid=0,
#else
        .valid=1,
#endif
        .slot=SBC_NODE_INDEX,.bank=pe.selected_bank,.serial=++o->next_serial,
        .mirror_epoch=o->mirror_epoch[SBC_NODE_INDEX],.generation=g->generation,
        .build_serial=g->build_serial,.owner=&pe,.mirror=(uintptr_t)&PE_SLOT(publication),
        .mirror_bytes=sizeof PE_SLOT(publication),.session=pe.session,.backing=*id};
    o->writer[SBC_NODE_INDEX]=0;__asm__ volatile("":::"memory");
#ifdef LI2_LOOP_RO_CERTIFICATE
    /* All identity fields and the R mirror precede validity. The R root is
       the publication boundary; no candidate may hit while it is writable. */
    o->certificate[SBC_NODE_INDEX].valid=1;__asm__ volatile("":::"memory");
#endif
    error=sg_permission(PROT_READ);if(error)return error;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
    ++sbc_observed.issues;sbc_observed.postseal_bytes+=PE_CODE_BYTES+PE_PROOF_BYTES;
    if((error=sbco_issue()))return error;
    return 0;
#else
    ++sbc_observed.issues;sbc_observed.postseal_bytes+=PE_CODE_BYTES+PE_PROOF_BYTES;return 0;
#endif
}
#ifdef LI2_LOOP_TRANSLATION_ARENA
#define SBC_MATCH_INDEX node
#define SBC_MATCH_BANK bank
#define SBC_MATCH_SLOT(field) slot->field
static int sbc_match_value(const struct li2_ptr_slot *slot,unsigned node,unsigned bank) {
    const struct sbc_owner *o=&sg_owner.state.bytes;
    const struct sbc_certificate *c=&o->certificate[node];
    const struct li2_pg_generation *g=&slot->generation;
    const struct li2_sealed_identity *id=&sg_owner.state.bank[node][bank];
#else
#define SBC_MATCH_INDEX SBC_NODE_INDEX
#define SBC_MATCH_BANK pe.selected_bank
#define SBC_MATCH_SLOT(field) PE_SLOT(field)
static int sbc_match(void) {
    if(!sbc_live())return 0;
    const struct sbc_owner *o=&sg_owner.state.bytes;
    const struct sbc_certificate *c=&o->certificate[SBC_NODE_INDEX];
    const struct li2_pg_generation *g=&PE_SLOT(generation);
    const struct li2_sealed_identity *id=&sg_owner.state.bank[SBC_NODE_INDEX][pe.selected_bank];
#endif
    return c->valid==1 && !c->reserved && c->serial && c->serial<=o->next_serial &&
        !o->writer[SBC_MATCH_INDEX] && c->mirror_epoch &&
        c->mirror_epoch==o->mirror_epoch[SBC_MATCH_INDEX] && c->slot==SBC_MATCH_INDEX &&
        c->bank==SBC_MATCH_BANK && c->owner==&pe && c->mirror==(uintptr_t)&SBC_MATCH_SLOT(publication) &&
        c->mirror_bytes==sizeof SBC_MATCH_SLOT(publication) && equal(&c->session,&pe.session,sizeof pe.session) &&
        c->generation==g->generation && c->build_serial==g->build_serial &&
        g->installed==1 && g->complete==1 && g->proof_complete==1 &&
        g->ready_generation==g->generation && g->generation &&
        g->generation==SBC_MATCH_SLOT(identity).generation && g->build_serial &&
        g->generation<=pe.next_generation && g->build_serial<=pe.next_serial &&
        g->code_verified==PE_CODE_BYTES && g->proof_verified==PE_PROOF_BYTES &&
        sbc_backing(g,id) && equal(&c->backing,id,sizeof *id);
}
#undef SBC_MATCH_INDEX
#undef SBC_MATCH_BANK
#undef SBC_MATCH_SLOT
#ifdef LI2_LOOP_TRANSLATION_ARENA
static int sbc_match(void) {
    if(!sbc_live())return 0;
    unsigned node=SBC_NODE_INDEX;
    return sbc_match_value(&PTR_NODE_AT(node),node,pe.selected_bank);
}
/* Physical/value evidence only. The arena owner supplies its protected whole
   issuance snapshot and separately authenticates the node's nonwrapping RAW
   epochs before and after this call, then obtains fresh source/rseq/registry
   and claim authority for the actual binding. A changed root certificate is
   not accepted, including a replacement with otherwise self-consistent fields. */
static int sbc_node_identity(unsigned node,unsigned bank,const struct sbc_certificate *issued) {
    if(node>=PTR_NODE_COUNT || bank>1 || !issued || !ptr_node_storage(node) ||
       !pe.initialized || !pe.registered || handling!=1 || !pe_busy || pe_active ||
       pe_failing || pe.resuming || pe.p.first_error || pe.p.anchor_released ||
       !pe_token(&pe.token) || !pe_identity() ||
       (pe.p.phase!=LI2_PG_HELD &&
        (pe.p.phase!=LI2_PG_BOUND || pe.domain.work.bound)) ||
       !sg_owner.state.initialized || sg_owner.state.bytes.poisoned ||
       sg_owner.state.ro_initialized!=1 || sg_owner.state.ro_writable_mask ||
       !sbc_observed.initialized ||
       selected_run_protect_contains(0,(uintptr_t)&sg_owner,sizeof sg_owner)!=1 ||
       selected_run_protect_contains(0,(uintptr_t)&sbc_observed,sizeof sbc_observed)!=1)return 0;
    const struct li2_ptr_slot *slot=&PTR_NODE_AT(node);
    const struct li2_pg_generation *g=&slot->generation;
    if(slot->banks[bank].prot!=PROT_READ || slot->banks[bank].virgin ||
       slot->banks[bank].generated!=g->generated ||
       !pg_layout_equal(&slot->banks[bank].layout,&g->layout) ||
       g->active_refs || g->member_refs[0] || g->member_refs[1] ||
       g->incoming[0] || g->incoming[1] || g->domain_refs || g->linked ||
       lrc_readonly((uintptr_t)&sg_owner,sizeof sg_owner) ||
       lrc_readonly((uintptr_t)&slot->publication,PE_PROOF_BYTES) ||
       !equal(issued,&sg_owner.state.bytes.certificate[node],sizeof *issued) ||
       !sbc_match_value(slot,node,bank))return 0;
    if(sbc_queries_value(g,&sg_owner.state.bank[node][bank],PROT_READ))return 0;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    if(ptr_node_bytes_full(node))return 0;
#endif
    return equal(issued,&sg_owner.state.bytes.certificate[node],sizeof *issued) &&
        sbc_match_value(slot,node,bank) && ptr_node_storage(node);
}
#endif
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
#define pe_bytes sbc_decision
#endif
static int pe_bytes(void) {
#ifdef LI2_LOOP_RO_TEST
    lro_byte_hook();
#endif
    int error=sbc_add(&sbc_observed.decisions,1);if(error)return error;
    sbc_observed.last_failure=SBC_NONE;sbc_observed.last_full_result=0;
    int candidate=sbc_match(),query=0;
    if(candidate)query=sbc_queries(&PE_SLOT(generation),
        &sg_owner.state.bank[SBC_NODE_INDEX][pe.selected_bank]);
#ifdef LI2_LOOP_RO_CERTIFICATE
    else if(!lrc_live())query=PE_PUBLICATION;
#endif
    int hit=candidate && !query;
    error=sbc_add(hit?&sbc_observed.hits:&sbc_observed.misses,1);if(error)return error;
    int scan=!hit;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    scan=1;
#endif
    if(scan) {
        error=sbc_add(&sbc_observed.full_scans,1);if(error)return error;
        int full=pe_bytes_full();sbc_observed.last_full_result=full;
        if(full) {
            error=sbc_add(&sbc_observed.full_scan_errors,1);if(error)return error;
            sbc_observed.last_failure=SBC_FULL_SCAN_ERROR;
            if(hit) {
                error=sbc_add(&sbc_observed.disagreements,1);if(error)return error;
                sbc_observed.last_failure=SBC_DISAGREEMENT;
            }
            return full;
        }
        error=sbc_add(&sbc_observed.full_scan_bytes,PE_CODE_BYTES+PE_PROOF_BYTES);
        if(error)return error;
    }
    if(query) {sbc_observed.last_failure=SBC_LIVE_QUERY_ERROR;return query;}
    return 0;
}
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
#undef pe_bytes
#include "sealed_byte_certificate_observe.inc"
#endif
static void sbc_abort(void) {
    /* Terminal paths never return to guest code. Poison before the old
       cleanup can mutate readiness or transition records; no cleanup path
       writes a publication mirror or issues a replacement certificate. */
    if(!sg_owner.state.initialized || sg_owner.state.bytes.poisoned)return;
    if(sg_permission(PROT_READ|PROT_WRITE))return;
    sg_owner.state.bytes.poisoned=1;
    for(unsigned i=0;i<SBC_NODE_COUNT;i++) {
        sg_owner.state.bytes.certificate[i].valid=0;
        sg_owner.state.bytes.writer[i]=0;
    }
    __asm__ volatile("":::"memory");
    (void)sg_permission(PROT_READ);
#ifdef LI2_LOOP_RO_CERTIFICATE
    lrc_abort();
#endif
    if(sbc_observed.abort_invalidations!=UINT64_MAX)++sbc_observed.abort_invalidations;
}
static void sbc_report(unsigned status,unsigned code) {
    struct writer w={.used=0};text(&w,"LI2_SEALED_BYTE_CERTIFICATE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    field(&w,",\"differential\":",1);
#else
    field(&w,",\"differential\":",0);
#endif
    field(&w,",\"bytes_per_complete_scan\":",PE_CODE_BYTES+PE_PROOF_BYTES);
    field(&w,",\"decisions\":",sbc_observed.decisions);field(&w,",\"hits\":",sbc_observed.hits);
    field(&w,",\"misses\":",sbc_observed.misses);field(&w,",\"full_scans\":",sbc_observed.full_scans);
    field(&w,",\"full_scan_errors\":",sbc_observed.full_scan_errors);
    field(&w,",\"disagreements\":",sbc_observed.disagreements);
    field(&w,",\"full_scan_bytes\":",sbc_observed.full_scan_bytes);
    field(&w,",\"postseal_bytes\":",sbc_observed.postseal_bytes);
    field(&w,",\"issues\":",sbc_observed.issues);field(&w,",\"invalidations\":",sbc_observed.invalidations);
    field(&w,",\"abort_invalidations\":",sbc_observed.abort_invalidations);
    field(&w,",\"live_queries\":",sbc_observed.live_queries);
    field(&w,",\"live_query_errors\":",sbc_observed.live_query_errors);
    field(&w,",\"last_failure\":",sbc_observed.last_failure);
    field(&w,",\"last_full_result\":",(unsigned)sbc_observed.last_full_result);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
#ifdef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE
    sbco_report(status,code);
#endif
#ifdef LI2_LOOP_RO_CERTIFICATE
    lrc_report(status,code);
#endif
}
