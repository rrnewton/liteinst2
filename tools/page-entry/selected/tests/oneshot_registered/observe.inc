/* Observation only, installed by prepare.py. No application/owner writes. */
struct orf_record {
    uint64_t h[64],rows[4][32];
    unsigned char source_before[8192],source_after[8192];
    unsigned char rseq_first[4096],rseq_last[4096],output[64];
};
_Static_assert(sizeof(struct orf_record)==26176,"complete bounded fallback record");
static struct orf_record orf_record;
static unsigned orf_used,orf_finished;
static void orf_copy(void *dst,const void *src,size_t n) {
    unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void orf_initialize(void) {
    volatile unsigned char *p=(void *)&orf_record;
    for(size_t i=0;i<sizeof orf_record;i++)p[i]=0;
    checked(original_main.entry==original_main.bias+4096 && !(original_main.entry&4095),1695,0);
    orf_record.h[0]=UINT64_C(0x31514553524f464f);orf_record.h[1]=1;
    orf_record.h[2]=sizeof orf_record;orf_record.h[9]=original_main.entry;
    orf_record.h[10]=original_main.bias;orf_record.h[27]=8192;
    orf_copy(orf_record.source_before,(const void *)original_main.entry,8192);
    orf_record.h[28]=1;orf_record.h[3]=1;
}
static void orf_fallback(const struct li2_rseq_state *rs,int sig,const siginfo_t *si,const ucontext_t *uc) {
    checked(orf_record.h[3] && !orf_finished && orf_used<4,1695,1);
    uint64_t *h=orf_record.rows[orf_used];
    h[0]=orf_used;h[1]=selected_decoded.pc;h[2]=selected_decoded.next_pc;
    h[3]=selected_decoded.kind;h[4]=selected_decoded.length;
    h[5]=rs->registered;h[6]=rs->held;h[7]=rs->phase;h[8]=rs->epoch;
    h[9]=rs->address;h[10]=rs->page;h[11]=rs->pid;h[12]=rs->tid;
    h[13]=*(const volatile uint64_t *)(rs->address+8);h[14]=rs->first_error;
    h[15]=selected_oneshot_used;h[16]=li2_lifecycle_fetch_interlock();h[17]=selected_view.length;
    h[18]=(unsigned)sig;h[19]=(unsigned)si->si_code;h[20]=(uintptr_t)si->si_addr;
    h[21]=(uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO];h[22]=(uint64_t)uc->uc_mcontext.gregs[REG_ERR];
    h[23]=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];h[24]=selected_logical_flags;
    h[25]=(uint64_t)uc->uc_mcontext.gregs[REG_CSGSFS]&UINT64_C(0xffff);
    if(!orf_used)orf_copy(orf_record.rseq_first,(const void *)rs->page,4096);
    ++orf_used;orf_record.h[4]=orf_used;
}
static void orf_terminal(unsigned status,unsigned code,long detail) {
    if(orf_finished || !orf_record.h[3])return;
    orf_finished=1;orf_record.h[5]=1;orf_record.h[6]=status;orf_record.h[7]=code;orf_record.h[8]=(uint64_t)detail;
    const struct li2_rseq_state *rs=li2_rseq_snapshot();
    orf_record.h[11]=rs->pid;orf_record.h[12]=rs->tid;
    orf_record.h[13]=rs->registered;orf_record.h[14]=rs->held;orf_record.h[15]=rs->phase;
    orf_record.h[16]=rs->epoch;orf_record.h[17]=rs->address;orf_record.h[18]=rs->page;
    orf_record.h[19]=rs->calls;orf_record.h[20]=rs->registrations;
    orf_record.h[21]=rs->unregistrations;orf_record.h[22]=rs->kernel_errors;orf_record.h[23]=rs->first_error;
    if(rs->registered && rs->held && rs->phase==LI2_RSEQ_ACTIVE && !rs->first_error) {
        orf_record.h[24]=*(const volatile uint64_t *)(rs->address+8);
        orf_copy(orf_record.rseq_last,(const void *)rs->page,4096);orf_record.h[29]=1;
    }
    orf_record.h[25]=selected_oneshot_used;
    for(unsigned i=0;i<selected_oneshot_used;i++)orf_record.h[26]+=selected_oneshot_owners[i].state.published==1;
    orf_record.h[30]=rs->signature;orf_record.h[31]=rs->length;orf_record.h[32]=rs->tls_complete;
    orf_copy(orf_record.source_after,(const void *)original_main.entry,8192);
    orf_copy(orf_record.output,(const void *)(original_main.bias+12288),64);
    checked(raw(SYS_write,3,(long)&orf_record,sizeof orf_record,0,0,0)==(long)sizeof orf_record,1695,2);
}
