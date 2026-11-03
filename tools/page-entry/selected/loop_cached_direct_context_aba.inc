/* Distinct test-only live-proof ABA. No epoch or production predicate is
   repaired, and the unchanged entry path must produce the terminal refusal. */
#if LI2_LOOP_CACHED_DIRECT_CONTEXT_ABA != 1 || \
    !defined(LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_ABA_BINDING_VERSION) || \
    LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_ABA_BINDING_VERSION != 1
#error "cached DIRECT ABA requires its distinct complete binding"
#endif
#define LCXA_MAGIC UINT64_C(0x314142414132494c)
#define LCXA_FOOTER UINT64_C(0x314642414132494c)
struct lcxa_record {
    uint64_t h[40],counts[3][LCXO_COUNTS];
    struct li2_private_code_query query[3];
    unsigned char page[3][PAGE];
    struct le_frame before;
};
static struct lcxa_record lcxa;
_Static_assert(sizeof(struct lcxo_wire)+64+sizeof lcxa+64<4U*1024U*1024U,
    "original four-MiB capture bound including separate whole ABA evidence");
const uint64_t li2_lcxa_layout[] __attribute__((used,visibility("hidden")))={
    1,sizeof lcxa,offsetof(struct lcxa_record,counts),offsetof(struct lcxa_record,query),
    offsetof(struct lcxa_record,page),offsetof(struct lcxa_record,before),
    sizeof(struct li2_private_code_query),sizeof(struct le_frame),PAGE,40,3,LCXO_COUNTS
};
static void lcxa_bound(const struct lcxo_epoch *e) {
    if(lcxo.epochs!=1)return;
    struct lcx_owner *o=&lcx_runtime.value;const struct lcx_work *w=&o->work;
    uint64_t *h=lcxa.h;unsigned char *page=(unsigned char *)&lcx_live;
    lcxo_need(!h[0] && lcxo.active==2 && e->h[4]==UINT64_C(0x412200) &&
        e->h[6]==2 && e->h[17]==1 && w->built==1 && w->published==1 &&
        !w->opened && !w->closed && o->proof_epoch==w->proof_epoch &&
        pe.p.phase==LI2_PG_BOUND && pe_busy==1 && !pe_active && handling==1,60);
    h[0]=LCXA_MAGIC;h[1]=1;h[2]=sizeof lcxa;h[3]=1;h[5]=pe.p.serial;
    h[6]=lcxo.epochs;h[7]=(uintptr_t)page;h[8]=PAGE;h[38]=(uintptr_t)&lcxa;
    h[10]=page[0];h[11]=h[10]^1;h[16]=o->proof_epoch;h[19]=w->proof_epoch;
    h[21]=o->invalidations;h[25]=(uint64_t)pda_ready(0);lcxa.before=pe.before;
    lcxo_need(h[25]==1,66);
    lcxo_counts(lcxa.counts[0]);h[12]=lcxa.counts[0][10];h[14]=lcxa.counts[0][11];
    lcxo_need(!pe_query((uintptr_t)page,PAGE,PROT_READ,&lcxa.query[0]) &&
        pg_query_complete(&lcxa.query[0],(uintptr_t)page,PAGE,PROT_READ),61);
    copy(lcxa.page[0],page,PAGE);
    h[23]=(uint64_t)raw(SYS_mprotect,(long)page,PAGE,PROT_READ|PROT_WRITE,0,0,0);
    h[17]=o->proof_epoch;
    lcxo_need(!h[23] && h[17]==h[16]+1 && w->proof_epoch==h[19] &&
        !pe_query((uintptr_t)page,PAGE,PROT_READ|PROT_WRITE,&lcxa.query[1]) &&
        pg_query_complete(&lcxa.query[1],(uintptr_t)page,PAGE,PROT_READ|PROT_WRITE),62);
    page[0]=(unsigned char)h[11];copy(lcxa.page[1],page,PAGE);
    lcxo_need(lcxa.page[1][0]!=lcxa.page[0][0] &&
        equal(lcxa.page[1]+1,lcxa.page[0]+1,PAGE-1),63);
    copy(page,lcxa.page[0],PAGE);
    h[24]=(uint64_t)raw(SYS_mprotect,(long)page,PAGE,PROT_READ,0,0,0);
    h[18]=o->proof_epoch;h[20]=w->proof_epoch;h[22]=o->invalidations;
    lcxo_need(!h[24] && h[18]==h[16]+2 && h[20]==h[19] && h[18]!=h[20] &&
        h[22]==h[21]+2 && !pe_query((uintptr_t)page,PAGE,PROT_READ,&lcxa.query[2]) &&
        pg_query_complete(&lcxa.query[2],(uintptr_t)page,PAGE,PROT_READ),64);
    copy(lcxa.page[2],page,PAGE);
    h[26]=(uint64_t)pda_ready(0);h[27]=(uint64_t)lcx_current_value(0,PROT_READ);
    lcxo_counts(lcxa.counts[1]);
    lcxo_need(!h[26] && !h[27] && equal(lcxa.page[0],lcxa.page[2],PAGE) &&
        equal(&lcxa.before,&pe.before,sizeof pe.before) &&
        lcxa.counts[1][10]==h[12] && lcxa.counts[1][11]==h[14] &&
        pe.p.phase==LI2_PG_BOUND && pe_busy==1 && !pe_active && handling==1 &&
        w->serial==h[5] && w->built==1 && w->published==1 && !w->opened && !w->closed &&
        o->code_epoch==e->phase[0].h[10] && o->directory_epoch==e->phase[0].h[12],65);
    /* Observe real TLS only in the appendix after the whole production frame check. */
    pe_tls(&lcxa.before);
    h[4]=1;
    /* Return normally: no synthetic abort and no repaired issued epoch. */
}
static void lcxa_report(unsigned status,unsigned code) {
    uint64_t *h=lcxa.h;lcxo_counts(lcxa.counts[2]);
    h[13]=lcxa.counts[2][10];h[15]=lcxa.counts[2][11];
    h[28]=status;h[29]=code;h[30]=pe.p.first_error;h[31]=(uint64_t)pe.p.first_detail;
    h[32]=pe_active;h[33]=pe_busy;h[34]=pe.p.phase;h[35]=lcxo.failure;
    h[36]=lcx_runtime.value.proof_epoch;h[37]=lcx_runtime.value.work.proof_epoch;
    size_t at=0;uint64_t calls=0;long result=0;
    while(at<sizeof lcxa && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lcxa+at),sizeof lcxa-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lcxa-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lcxa)return;
    const uint64_t footer[]={LCXA_FOOTER,1,sizeof lcxa,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
