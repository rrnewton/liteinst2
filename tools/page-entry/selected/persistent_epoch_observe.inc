/* Finite diagnostic capture only. Actual runtime ownership, source validation,
   registration pin, recovery and close calls are unchanged. No injected event. */
#include "persistent_epoch_observe_memory.h"
#if LI2_PERSISTENT_EPOCH_CAPTURE != 1 || LI2_PERSISTENT_EPOCH != 1
#error "actual persistent primitive capture profile"
#endif
#define PEO_MAGIC UINT64_C(0x314f455049324c)
#define PEO_FOOTER UINT64_C(0x3146455049324c)
struct peo_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
};
struct peo_wire {
    uint64_t h[64],raw_ingress[6];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct peo_registry startup_registry,initial_registry,terminal_registry;
    struct li2_tf_chain predecessor,closed_chain;
    struct le_frame returned,terminal_frame;
    struct li2_pe_progress entered_progress;
    struct li2_pe_source_progress entered_source;
    struct li2_pe_rseq_progress entered_rseq;
    struct li2_rseq_state entered_state;
    struct li2_fetch_progress entered_fetch;
    struct li2_peo_memory before_memory;
    struct li2_pe_epoch owner;
    struct li2_pe_source_progress terminal_source;
    struct li2_pe_rseq_progress terminal_rseq;
    struct li2_rseq_state terminal_state;
    struct li2_peo_memory after_memory;
    struct pe_payload initial_payload,terminal_payload;
    unsigned char initial_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char terminal_tail[PE_PROOF_BYTES-sizeof(struct pe_payload)];
    unsigned char initial_code[PE_CODE_BYTES],terminal_code[PE_CODE_BYTES];
};
static struct peo_wire peo_wire;
static unsigned peo_ready,peo_finished,peo_capturing;
static const uint64_t peo_step_frame_fp_alignment __attribute__((used))=__alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct peo_wire)+64<4U*1024U*1024U,"one generation, full actual state below original16MiB cap");
static void peo_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void peo_registry(struct peo_registry *out) {
    pe_need(!out->complete && protected_count && protected_count<=RANGES,PE_STATE,100);
    const struct image *b=bridge_runtime_image();
    pe_need(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
        !b->source && !b->source_size && b->backing_fd==-1,PE_STATE,101);
    peo_copy(&out->bridge,b,sizeof *b);peo_copy(out->ph,b->ph,b->n*sizeof *b->ph);
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    peo_copy(out->ranges,protected,protected_count*sizeof *protected);
    peo_copy(out->initial_code,initial_code_range,protected_count);out->complete=1;
}
static void peo_initialize(void) {
    __asm__ volatile(""::"r"(&peo_step_frame_fp_alignment):"memory");
    pe_need(!peo_ready && !peo_finished && !pe.p.serial,PE_STATE,102);
    uint64_t *h=peo_wire.h;
    h[0]=PEO_MAGIC;h[1]=2;h[2]=sizeof peo_wire;h[3]=sizeof pe;
    h[4]=sizeof(struct pe_payload);h[5]=PE_PROOF_BYTES;h[6]=PE_CODE_BYTES;
    h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);h[9]=(uintptr_t)li2_raw6;
    h[10]=(uintptr_t)li2_gateway_start;h[11]=(uintptr_t)li2_gateway_end;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    pe_need(!selected_run_protect_add(0,(uintptr_t)&peo_wire,sizeof peo_wire),PE_STATE,103);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&peo_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    pe_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(peo_wire.sink_initial.st_mode) && (peo_wire.sink_initial.st_mode&07777)==0600 &&
        peo_wire.sink_initial.st_nlink==1 && !peo_wire.sink_initial.st_size,PE_STATE,104);h[18]=1;
    const char *mode=fork_env("LI2_PERSISTENT_EPOCH_APP_MODE");
    pe_need(mode && mode[0]>='0' && mode[0]<='2' && !mode[1],PE_STATE,105);h[19]=(unsigned)(mode[0]-'0');
    peo_copy(&peo_wire.main,&original_main,sizeof original_main);
    peo_copy(&peo_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    peo_copy(&peo_wire.hardware,&selected_hardware,sizeof selected_hardware);
    peo_copy(&peo_wire.session,&selected_session,sizeof selected_session);
    h[20]=(uintptr_t)&pe;h[21]=(uintptr_t)&peo_wire;h[22]=(uintptr_t)li2_pe_source_progress();
    h[23]=(uintptr_t)li2_pe_rseq_progress();h[24]=(uintptr_t)&selected_chain;
    h[25]=(uintptr_t)li2_tf_chain_span_progress();h[26]=pe.generation.generated;
    h[27]=pe.generation.proof;h[28]=pe.generation.spill;
    peo_registry(&peo_wire.startup_registry);peo_ready=1;
}
static void peo_ingress(int sig) {
    if(!peo_ready)return;
    if(peo_wire.raw_ingress[0]==UINT64_MAX || peo_capturing) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++peo_wire.raw_ingress[0];
    unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    if(peo_wire.raw_ingress[i]==UINT64_MAX) {
        (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++peo_wire.raw_ingress[i];
}
static void peo_begin(void) {
    pe_need(peo_ready && !peo_wire.h[29] && !peo_capturing,PE_STATE,106);
    /* Lazy protected landing pages may be registered during guest startup.
       The immutable epoch begins here, before closing its real predecessor. */
    peo_registry(&peo_wire.initial_registry);
    peo_wire.h[29]=1;peo_wire.h[30]=peo_wire.raw_ingress[0];
    peo_copy(&peo_wire.predecessor,&selected_chain,sizeof selected_chain);
}
static void peo_closed(void) {
    pe_need(peo_wire.h[29] && !peo_wire.h[31],PE_STATE,107);
    peo_copy(&peo_wire.closed_chain,&selected_chain,sizeof selected_chain);peo_wire.h[31]=1;
}
static void peo_publication(unsigned terminal) {
    const struct pe_payload *p=pe_payload();
    peo_copy(terminal?&peo_wire.terminal_payload:&peo_wire.initial_payload,p,sizeof *p);
    peo_copy(terminal?peo_wire.terminal_tail:peo_wire.initial_tail,
        (const unsigned char *)p+sizeof *p,PE_PROOF_BYTES-sizeof *p);
    peo_copy(terminal?peo_wire.terminal_code:peo_wire.initial_code,
        (const void *)pe.generation.generated,PE_CODE_BYTES);
}
static void peo_entered(int sig,siginfo_t *si,ucontext_t *uc) {
    pe_need(peo_wire.h[31] && !peo_wire.h[32] && !peo_capturing && pe_ready() &&
        pe.p.phase==LI2_PE_EXECUTING && pe_active && pe_busy,PE_STATE,108);
    peo_capturing=1;peo_wire.h[32]=1;peo_wire.h[33]=peo_wire.raw_ingress[0];
    pe_need(!li2_lifecycle_pe_observe_memory((uintptr_t)pe.before.frame.greg[REG_RSP],0,
        &peo_wire.before_memory),PE_STATE,109);
    pe_need(!le_capture(&peo_wire.returned,sig,si,uc),PE_FRAME,100);
    pe_tls(&peo_wire.returned);
    peo_copy(&peo_wire.entered_progress,&pe.p,sizeof pe.p);
    peo_copy(&peo_wire.entered_source,li2_pe_source_progress(),sizeof peo_wire.entered_source);
    peo_copy(&peo_wire.entered_rseq,li2_pe_rseq_progress(),sizeof peo_wire.entered_rseq);
    peo_copy(&peo_wire.entered_state,li2_rseq_snapshot(),sizeof peo_wire.entered_state);
    peo_copy(&peo_wire.entered_fetch,li2_lifecycle_fetch_progress(),sizeof peo_wire.entered_fetch);
    peo_publication(0);peo_wire.h[34]=*(const volatile uint64_t *)(li2_pe_rseq_progress()->address+8);
    peo_wire.h[35]=1;peo_capturing=0;
}
static void peo_terminal(unsigned failed) {
    if(!peo_ready || !peo_wire.h[32] || peo_wire.h[36])return;
    if(peo_capturing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    peo_capturing=1;peo_wire.h[36]=1;peo_wire.h[37]=failed;peo_wire.h[38]=peo_wire.raw_ingress[0];
    /* Memory observation does not grant execution or cleanup. Its own exact
       maps prefix is retained; failure cannot be reported as observed bytes. */
    peo_wire.h[39]=(uint64_t)li2_lifecycle_pe_observe_memory(
        (uintptr_t)pe.before.frame.greg[REG_RSP],failed,&peo_wire.after_memory);
    peo_copy(&peo_wire.terminal_frame,&pe.after,sizeof pe.after);
    if(peo_wire.terminal_frame.complete)pe_tls(&peo_wire.terminal_frame);
    peo_copy(&peo_wire.owner,&pe,sizeof pe);
    peo_copy(&peo_wire.terminal_source,li2_pe_source_progress(),sizeof peo_wire.terminal_source);
    peo_copy(&peo_wire.terminal_rseq,li2_pe_rseq_progress(),sizeof peo_wire.terminal_rseq);
    peo_copy(&peo_wire.terminal_state,li2_rseq_snapshot(),sizeof peo_wire.terminal_state);
    peo_publication(1);peo_wire.h[40]=*(const volatile uint64_t *)(li2_pe_rseq_progress()->address+8);
    peo_wire.h[41]=1;peo_wire.h[42]=pe_busy;peo_wire.h[43]=pe_active;peo_wire.h[44]=pe_failing;
    peo_wire.h[45]=selected_pending_route;peo_wire.h[46]=selected_step_pending;
    peo_registry(&peo_wire.terminal_registry);peo_capturing=0;
}
static void peo_finish(unsigned status,unsigned code,long detail) {
    if(!peo_ready || peo_finished)return;
    peo_finished=1;peo_wire.h[47]=1;peo_wire.h[48]=status;peo_wire.h[49]=code;peo_wire.h[50]=(uint64_t)detail;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&peo_wire.sink_terminal,0,0,0,0);
    peo_wire.h[51]=(uint64_t)flags;peo_wire.h[52]=(uint64_t)result;
    const struct stat *a=&peo_wire.sink_initial,*b=&peo_wire.sink_terminal;
    if(result || flags!=(long)peo_wire.h[16] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof peo_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&peo_wire+at),sizeof peo_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof peo_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof peo_wire)return;
    const uint64_t footer[]={PEO_FOOTER,2,sizeof peo_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
