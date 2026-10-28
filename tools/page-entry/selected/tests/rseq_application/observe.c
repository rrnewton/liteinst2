/* Fixture-only observation. Calls the unchanged real guards/raw wrapper once;
   returns their exact results. No observer branch grants application execution. */
#define _GNU_SOURCE
#include "observe.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#define APP_DATA UINT64_C(0x405000)
#define APP_PAGE UINT64_C(0x600000)
#define APP_AREA (APP_PAGE+64)
#define APP_WORD (APP_AREA+8)
#define APP_MAGIC UINT64_C(0x3150504151455352)
#define OBS_MAGIC UINT64_C(0x3153424f51455352)
extern long application_underlying_raw(long,long,long,long,long,long,long);
extern int application_real_instruction(const struct li2_decoded *,const ucontext_t *);
extern int application_real_before_syscall(long,const long[6]);
struct application_record { uint64_t h[128]; unsigned char before[4096],after[4096],terminal[4096]; };
_Static_assert(sizeof(struct application_record)==13312,"fixed observed record");
static struct application_record record;
static const ucontext_t *dispatch_frame;
static uint64_t raw_calls,rx_calls,watched_calls;
static unsigned watching,finished;
static long watched_number=-1;
static void bytes_copy(void *dst,const void *src,size_t n) {
    unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static int watched(long n,long a,long b) {
    if(!watching || n!=watched_number)return 0;
    if(n==SYS_read)return (uintptr_t)b==APP_WORD;
    if(n==SYS_getrandom)return (uintptr_t)a==APP_WORD;
    if(n==SYS_mprotect || n==SYS_munmap)return (uintptr_t)a==APP_PAGE;
    return 1;
}
long raw(long n,long a,long b,long c,long d,long e,long f) {
    ++raw_calls;
    if(n==SYS_mprotect && (c&PROT_EXEC))++rx_calls;
    if(watched(n,a,b))++watched_calls;
    return application_underlying_raw(n,a,b,c,d,e,f);
}
void application_dispatch_frame(const ucontext_t *uc) { dispatch_frame=uc; }
static int begin(unsigned kind,uint64_t pc,const ucontext_t *uc,const struct li2_decoded *d,long n) {
    const struct li2_rseq_state *s=li2_rseq_snapshot();
    /* Only the literal fixture's authenticated initial ELF data page is read.
       Register/page identity must match before any anonymous-page observation. */
    const volatile uint64_t *config=(const volatile uint64_t *)(uintptr_t)APP_DATA;
    if(finished || watching || !uc || config[0]!=APP_MAGIC || config[2]!=pc)return 0;
    if(config[1]>=17 || config[4]!=APP_AREA || config[5]!=APP_PAGE || config[6]!=APP_WORD ||
       (s->registered && (!s->data.complete || s->data.address!=APP_AREA || s->data.page!=APP_PAGE)))return 0;
    record.h[3]=config[1];record.h[7]=kind;record.h[8]=1;record.h[10]=pc;
    record.h[11]=(uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO];
    record.h[12]=(uint64_t)uc->uc_mcontext.gregs[REG_ERR];
    record.h[13]=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    record.h[17]=raw_calls;record.h[20]=rx_calls;
    watched_number=n;watching=1;record.h[23]=watched_calls;record.h[26]=(uint64_t)n;
    bytes_copy(record.before,(const void *)(uintptr_t)APP_PAGE,4096);
    bytes_copy(&record.h[14],record.before+72,8);record.h[30]=1;
    for(size_t i=0;i<23;i++)record.h[40+i]=(uint64_t)uc->uc_mcontext.gregs[i];
    bytes_copy(&record.h[86],&uc->uc_sigmask,8);
    if(d){bytes_copy(&record.h[88],d->bytes,16);record.h[90]=d->length;record.h[101]=d->code;}
    record.h[102]=s->registered;record.h[103]=s->held;record.h[104]=s->phase;
    return 1;
}
static void after(const ucontext_t *uc,int result) {
    record.h[9]=(unsigned)result;record.h[18]=raw_calls;record.h[21]=rx_calls;record.h[24]=watched_calls;
    bytes_copy(record.after,(const void *)(uintptr_t)APP_PAGE,4096);
    bytes_copy(&record.h[15],record.after+72,8);record.h[31]=1;
    for(size_t i=0;i<23;i++)record.h[63+i]=(uint64_t)uc->uc_mcontext.gregs[i];
    bytes_copy(&record.h[87],&uc->uc_sigmask,8);
}
int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *uc) {
    int observed=begin(1,d?d->pc:0,uc,d,-1);
    int result=application_real_instruction(d,uc);
    if(observed)after(uc,result);
    return result;
}
int li2_rseq_before_syscall(long n,const long a[6]) {
    const ucontext_t *uc=dispatch_frame;
    uint64_t pc=uc?(uint64_t)uc->uc_mcontext.gregs[REG_RIP]-2:0;
    int observed=begin(2,pc,uc,0,n);
    int result=application_real_before_syscall(n,a);
    if(observed)after(uc,result);
    return result;
}
void application_terminal(unsigned status,unsigned code,long detail,unsigned route,unsigned pending,const struct li2_tf_chain *chain) {
    if(finished)return;
    finished=1;
    const struct li2_rseq_state *s=li2_rseq_snapshot();
    const volatile uint64_t *config=(const volatile uint64_t *)(uintptr_t)APP_DATA;
    record.h[0]=OBS_MAGIC;record.h[1]=1;record.h[2]=sizeof(record);
    record.h[3]=config[1];record.h[4]=status;record.h[5]=code;record.h[6]=(uint64_t)detail;
    record.h[19]=raw_calls;record.h[22]=rx_calls;record.h[25]=watched_calls;
    if(s->address==APP_AREA && s->page==APP_PAGE && (s->data.complete || s->transaction.before.complete)) {
        bytes_copy(record.terminal,(const void *)(uintptr_t)APP_PAGE,4096);
        bytes_copy(&record.h[16],record.terminal+72,8);record.h[32]=1;
    }
    record.h[91]=route;record.h[92]=pending;
    if(chain && chain->initialized && (unsigned)chain->active<2) {
        const struct li2_tf_chain_slot *slot=&chain->slots[chain->active];
        record.h[93]=chain->pending;record.h[94]=slot->phase;
        record.h[95]=slot->owner.step.phase;record.h[96]=slot->owner.step.trace_seen;
        record.h[97]=slot->owner.step.open_started[0]|(slot->owner.step.open_started[1]<<1);
        record.h[98]=slot->owner.step.opened[0]|(slot->owner.step.opened[1]<<1);
        record.h[99]=slot->release.started;record.h[100]=slot->release.complete;
    }
    record.h[105]=s->registered;record.h[106]=s->held;record.h[107]=s->phase;
    record.h[108]=s->first_error;record.h[109]=(uint64_t)s->first_detail;
    record.h[110]=s->transaction.attempted;record.h[111]=s->transaction.issued;record.h[112]=s->transaction.returned;
    record.h[113]=(uint64_t)s->transaction.result;record.h[114]=s->calls;record.h[115]=s->registrations;
    record.h[116]=s->unregistrations;record.h[117]=s->kernel_errors;
    size_t at=0;while(at<sizeof(record)) {
        long n=application_underlying_raw(SYS_write,3,(long)((const unsigned char *)&record+at),sizeof(record)-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof(record)-at)return;
        at+=(size_t)n;
    }
}
