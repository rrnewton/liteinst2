/* Included only in a private copy of the existing observation-only fixture.
   The production guard is called exactly once by its unchanged caller. */
#define STORE_MAGIC UINT64_C(0x3152465453515256)
struct store_record {
    uint64_t h[40],before[23],after[23];
    unsigned char bytes[16];
    struct li2_write_footprint footprint;
    unsigned char page_before[4096],page_after[4096];
};
_Static_assert(sizeof(struct store_record)==8944,"complete separate store record");
static struct store_record store_record;
static int store_begin(const struct li2_decoded *d,const ucontext_t *uc) {
    const volatile uint64_t *c=(const volatile uint64_t *)(uintptr_t)APP_DATA;
    const struct li2_rseq_state *s=li2_rseq_snapshot();
    if(!d || !uc || c[0]!=APP_MAGIC || c[8]!=STORE_MAGIC || c[9]!=d->pc)return 0;
    ++store_record.h[4];
    if(store_record.h[4]!=1 || c[10]>2 || c[1]!=(c[10]==0?1:c[10]==1?6:5) ||
       c[11]!=1838 || c[12]!=6 || c[13]!=64 || c[14] || c[15] ||
       !s->registered || !s->held || s->phase!=LI2_RSEQ_ACTIVE ||
       !s->data.complete || s->data.address!=APP_AREA || s->data.page!=APP_PAGE)return 0;
    uint64_t *h=store_record.h;
    h[0]=STORE_MAGIC;h[1]=1;h[2]=sizeof(store_record);h[3]=c[1];
    h[7]=d->pc;h[8]=d->next_pc;h[9]=d->code;h[10]=d->length;h[11]=d->available;
    h[12]=(uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO];
    h[13]=(uint64_t)uc->uc_mcontext.gregs[REG_ERR];
    bytes_copy(&h[14],&uc->uc_sigmask,8);
    h[16]=raw_calls;h[18]=rx_calls;h[20]=s->registered;h[21]=s->held;h[22]=s->phase;
    h[23]=(uint64_t)s->pid;h[24]=(uint64_t)s->tid;
    h[25]=s->instruction_checks;h[27]=s->range_checks;h[29]=s->fs_base;h[30]=s->gs_base;
    h[36]=c[10];
    for(size_t i=0;i<23;i++)store_record.before[i]=(uint64_t)uc->uc_mcontext.gregs[i];
    bytes_copy(store_record.bytes,d->bytes,16);
    bytes_copy(store_record.page_before,(const void *)(uintptr_t)APP_PAGE,4096);h[37]=1;
    return 1;
}
static void store_after(const ucontext_t *uc,int result) {
    const struct li2_rseq_state *s=li2_rseq_snapshot();uint64_t *h=store_record.h;
    ++h[5];h[6]=(unsigned)result;bytes_copy(&h[15],&uc->uc_sigmask,8);
    h[17]=raw_calls;h[19]=rx_calls;h[26]=s->instruction_checks;h[28]=s->range_checks;
    h[31]=s->last_pc;h[32]=s->last_code;h[33]=s->last_policy;
    h[34]=s->last_first;h[35]=s->last_end;
    for(size_t i=0;i<23;i++)store_record.after[i]=(uint64_t)uc->uc_mcontext.gregs[i];
    bytes_copy(&store_record.footprint,&s->last_footprint,sizeof(store_record.footprint));
    bytes_copy(store_record.page_after,(const void *)(uintptr_t)APP_PAGE,4096);h[38]=1;
}
static void store_emit(void) {
    size_t at=0;
    while(at<sizeof(store_record)) {
        long n=application_underlying_raw(SYS_write,3,(long)((const unsigned char *)&store_record+at),sizeof(store_record)-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof(store_record)-at)return;
        at+=(size_t)n;
    }
}
