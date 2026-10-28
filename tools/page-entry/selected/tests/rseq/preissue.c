/* One actual-memory component refusal, not registration or application
   execution qualification. Reuse the real sealed ELF, lifecycle, maps and raw
   helpers unchanged; none of the inherited injection flags is enabled. */
#define main inherited_fetch_main
#include "../fetch/fixture.c"
#undef main
#include "../../rseq_guard.h"

long raw(long n,long a,long b,long c,long d,long e,long f) {
    return hooked_raw(n,a,b,c,d,e,f);
}
_Noreturn void li2_decoder_abort(uint32_t reason) {
    fprintf(stderr,"UNEXPECTED_DECODER_ABORT %u\n",reason);exit(126);
}
struct preissue_record {
    uint64_t version,bytes,address,input,raw_rseq_calls,result,unchanged;
    struct li2_rseq_state owner;
    size_t raw_count;
    struct raw_record raw[MAX_LOG];
    unsigned char before[PAGE],after[PAGE];
};
static struct preissue_record record;
int main(int argc,char **argv) {
    (void)argv;need(argc==1,"exact nonzero pre-issue component case");
    case_name="nonzero_preissue";
    baseline_count=actual_maps(baseline,sizeof(baseline)/sizeof(baseline[0]));
    int fd=sealed_elf();
    const struct li2_lifecycle_hooks hooks={hooked_raw,fatal,protected_range};
    li2_lifecycle_initialize(&fd,1,&hooks);
    need(li2_lifecycle_enabled() && !li2_lifecycle_fetch_interlock(),"real lifecycle initialized");
    long mapped=dispatch(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(mapped>0,"real owned anonymous mapping");
    struct map m=observed((uintptr_t)mapped);
    need(m.first<=(uintptr_t)mapped && m.end-(uintptr_t)mapped>=PAGE &&
         m.prot==(PROT_READ|PROT_WRITE) && m.private && !m.inode && !m.major && !m.minor,
         "independent actual RW/NX anonymous mapping");
    uintptr_t address=(uintptr_t)mapped+64;
    *(volatile uint64_t *)(address+8)=UINT64_C(0x0000000000000001);
    memcpy(record.before,(const void *)(uintptr_t)mapped,PAGE);
    need(!li2_rseq_initialize(protected_range),"actual singleton initialized");
    long args[6]={(long)address,32,0,0x53053053,0,0},original_result=731;
    int result=li2_rseq_dispatch(args,&original_result);
    const struct li2_rseq_state *s=li2_rseq_snapshot();
    need(result==LI2_RSEQ_WORD && s->first_error==LI2_RSEQ_WORD && s->first_detail==2,
         "precise nonzero-word refusal");
    need(s->phase==LI2_RSEQ_PREPARING && s->held==1 && !s->registered &&
         s->transaction.before.attempted==1 && s->transaction.before.complete==1 &&
         !s->transaction.before.error && s->transaction.before.address==address &&
         s->transaction.before.allocation && s->transaction.before.generation,
         "actual page custody before refused issue");
    need(s->transaction.input_word_observed==1 && s->transaction.input_word==1 &&
         s->transaction.attempted==1 && !s->transaction.issued && !s->transaction.returned &&
         !s->transaction.after.attempted && !s->registrations && !s->kernel_errors &&
         original_result==731,"no raw result or registration fabricated");
    for(size_t i=0;i<raw_count;i++)if(raw_log[i].n==SYS_rseq)++record.raw_rseq_calls;
    need(!record.raw_rseq_calls,"zero actual raw rseq calls");
    memcpy(record.after,(const void *)(uintptr_t)mapped,PAGE);
    need(!memcmp(record.before,record.after,PAGE),"complete data page unchanged");
    record.version=1;record.bytes=sizeof(record);record.address=address;record.input=1;
    record.result=(unsigned)result;record.unchanged=1;record.owner=*s;record.raw_count=raw_count;
    memcpy(record.raw,raw_log,raw_count*sizeof(raw_log[0]));
    size_t done=0;while(done<sizeof(record)) {
        long n=K(SYS_write,1,(const unsigned char *)&record+done,sizeof(record)-done,0,0,0);
        need(n>0,"complete pre-issue record write");done+=(size_t)n;
    }
    fprintf(stderr,"RSEQ_PREISSUE status=125 error=1209 detail=2 raw_rseq=0 unchanged=1\n");
    return 125;
}
