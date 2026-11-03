/* Observation only: no result participates in admission, cache or routing. */
#include "loop_rx_recurrence.h"
_Static_assert(LI2_PTR_SLOTS==2 && LI2_PG_HEADS==128 && RANGES==128,"literal observed dimensions");
static struct li2_lrc_row *lrc_row;
static void lrc_bad(unsigned code) {
    if(li2_lrc_bank && !li2_lrc_bank->header[16])
        __atomic_store_n(&li2_lrc_bank->header[16],code,__ATOMIC_RELEASE);
}
static int lrc_ready(void) {
    return li2_lrc_bank && li2_lrc_bank->header[15]==1 && !li2_lrc_bank->header[16];
}
static void lrc_commit(uint64_t phase) {
    __atomic_store_n(&lrc_row->words[127],phase,__ATOMIC_RELEASE);
}
static void lrc_counts(uint64_t *v) {
    v[0]=*PGC_EVENT_REF;for(unsigned i=0;i<5;i++)v[1+i]=*PGC_SIGNAL_REF(i);
    const uint64_t group[10]={PGC_VALUE(offers),PGC_VALUE(publications),PGC_VALUE(hits),
        PGC_VALUE(cold_attempts),PGC_VALUE(cancelled),PGC_VALUE(retirements),
        PGC_VALUE(permit_claims),PGC_VALUE(entries),PGC_VALUE(completed),PGC_VALUE(unexpected)};
    copy(v+6,group,sizeof group);
    const uint64_t rx[8]={pe.rx.code_opens,pe.rx.code_revokes,pe.rx.code_writes,pe.rx.code_syncs,
        pe.rx.metadata_permissions,pe.rx.metadata_syncs,pe.rx.entries,pe.rx.retained_entries};
    copy(v+16,rx,sizeof rx);
}
static void lrc_begin(const struct li2_pg_sources *s,const struct li2_pg_rseq_progress *r) {
    if(!lrc_ready())return;
    uint64_t n=li2_lrc_bank->header[17];
    if(lrc_row || n>=LI2_LRC_CAPACITY || li2_lrc_bank->header[18]!=n ||
       !s || !r || s->complete!=1 || s->reserved || pe.selected_slot>=2 ||
       pe.selected_bank>=2 || protected_count>128){lrc_bad(1);return;}
    /* Reserve before copying: a killed writer may leave this last row partial. */
    __atomic_store_n(&li2_lrc_bank->header[17],n+1,__ATOMIC_RELEASE);
    lrc_row=&li2_lrc_bank->row[n];uint64_t *v=lrc_row->words;
    const struct li2_ptr_slot *selected=&pe.retained[pe.selected_slot];
    v[0]=n+1;v[1]=s->key.entry;v[2]=pe.selected_slot;v[3]=pe.selected_bank;
    v[4]=pe.subentry_selected?2U:(selected->generation.installed && selected->publication.source.entry==s->key.entry)?1U:0U;
    v[5]=pe.p.serial;v[6]=protected_count;
    for(unsigned i=0;i<2;i++) {
        const struct li2_ptr_slot *slot=&pe.retained[i];const struct li2_pg_generation *g=&slot->generation;
        unsigned at=22+5*i;v[at]=g->generation;v[at+1]=slot->publication.source.entry;
        v[at+2]=slot->last_completed;v[at+3]=g->installed;
        v[at+4]=g->installed?(g->generated==slot->banks[1].generated):0;
        v[110+i]=pe.rx.slot[i].phase;
    }
    v[32]=s->allocation_epoch;v[33]=s->generation_epoch;
    v[34]=s->transactions_epoch;v[35]=s->records_epoch;
    v[36]=r->lifetime_mode;v[37]=r->registration_epoch;v[38]=r->address;
    v[39]=r->length;v[40]=r->signature;v[41]=r->fs;v[42]=r->gs;
    v[43]=r->fs_selector;v[44]=r->gs_selector;v[45]=r->registration_calls;
    v[46]=r->page;v[47]=r->token.serial;v[48]=s->complete;
    v[112]=s->anchor.sequence;v[113]=r->word_observed;v[114]=r->tls_complete;
    copy(&lrc_row->source,&s->key,sizeof s->key);
    for(size_t i=0;i<protected_count;i++) {
        lrc_row->registry[i].first=protected[i].first;lrc_row->registry[i].end=protected[i].end;
    }
    lrc_counts(v+60);lrc_commit(1);
}
static int lrc_test(unsigned bit,int value) {
    if(!lrc_ready())return value;
    if(!lrc_row || lrc_row->words[127]!=1 || bit>=10 ||
       lrc_row->words[7]!=((UINT64_C(1)<<bit)-1) ||
       lrc_row->words[8]!=lrc_row->words[7]){lrc_bad(2);return value;}
    lrc_row->words[7]|=UINT64_C(1)<<bit;
    if(value)lrc_row->words[8]|=UINT64_C(1)<<bit;
    return value;
}
static void lrc_plan(unsigned kind) {
    if(!lrc_ready())return;
    if(!lrc_row || lrc_row->words[127]!=1 || kind<1 || kind>4 ||
       (kind<=2?(lrc_row->words[7]!=1023 || lrc_row->words[8]!=1023):
                 lrc_row->words[7]==lrc_row->words[8])){lrc_bad(3);return;}
    uint64_t *v=lrc_row->words;v[9]=kind;v[10]=(uint64_t)(int64_t)pe.build_result;
    v[11]=pe.miss.reason;v[12]=pe.miss.site;v[13]=pe.miss.pc;v[14]=pe.miss.detail;
    v[15]=pe.loop.route;lrc_commit(3);
}
static void lrc_bound(void) {
    if(!lrc_ready())return;
    if(!lrc_row || lrc_row->words[127]!=3 || lrc_row->words[9]==3 ||
       pe.selected_slot!=lrc_row->words[2]){lrc_bad(4);return;}
    uint64_t *v=lrc_row->words;const struct li2_ptr_slot *s=&pe.retained[pe.selected_slot];
    const struct li2_pg_compact *p=&s->publication.plan;
    if(!p->heads || p->heads>128 || !s->generation.installed){lrc_bad(5);return;}
    v[16]=s->generation.generation;v[17]=s->generation.build_serial;
    v[18]=s->publication.source.entry;v[19]=p->heads;
    v[108]=s->generation.layout.generated[0];v[109]=s->generation.layout.generated[1];
    for(unsigned i=0;i<p->heads;i++) {
        if(p->head[i].source_page>=2 || p->head[i].source_offset>=4096){lrc_bad(6);return;}
        lrc_row->heads[i]=(uint16_t)(4096*p->head[i].source_page+p->head[i].source_offset);
    }
    lrc_commit(7);
}
static void lrc_finish(unsigned kind) {
    if(!lrc_ready())return;
    if(!lrc_row || (kind==1?lrc_row->words[127]!=3 || lrc_row->words[9]!=3:
        kind!=2 || lrc_row->words[127]!=7)){lrc_bad(7);return;}
    uint64_t *v=lrc_row->words;v[20]=kind;v[59]=pe.p.phase;
    if(kind==2) {
        const struct pda_work *w=&pe.domain.work;
        if(!w->completion || !w->view.count || w->view.count>2){lrc_bad(8);return;}
        v[21]=w->view.count;v[58]=w->rx_retained_mask;
        for(unsigned i=0;i<w->view.count;i++) {
            const struct li2_pgd_ref *m=&w->view.member[i].identity;
            if(m->slot>=2){lrc_bad(9);return;}
            v[50+4*i]=m->slot;v[51+4*i]=m->generation;
            v[52+4*i]=pe.retained[m->slot].generation.build_serial;v[53+4*i]=m->root;
        }
    }
    lrc_counts(v+84);lrc_commit(kind==1?11:15);lrc_row=0;
    uint64_t n=li2_lrc_bank->header[18]+1;
    __atomic_store_n(&li2_lrc_bank->header[18],n,__ATOMIC_RELEASE);
    if(n==LI2_LRC_CAPACITY) {
        __atomic_store_n(&li2_lrc_bank->header[19],LI2_LRC_STOP,__ATOMIC_RELEASE);
        /* Actual source/rseq drain and complete/cancel precede normal cleanup. */
        selected_persistent_abort(PE_PUBLICATION,LI2_LRC_STOP);
    }
}
