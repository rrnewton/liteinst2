/* Finite real-handler maps reuse controls. This is not a replacement for the
   unchanged 18-pair cache oracle and fourteen terminal publisher controls. */
#define _GNU_SOURCE
#include "lifecycle_loader.h"
#include "private_code_query.h"
#include "tf_continuation.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#define PAGE 4096UL
#define FP_BYTES 65536UL
struct action {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;};
struct frame {uint64_t observed,fp_address,fp_bytes;greg_t greg[NGREG];uint64_t mask;unsigned char fp[FP_BYTES];};
struct record {
    uint64_t magic,version,bytes,mode,verified,fixture_error,operation_failed,events;
    uint64_t source,probe,hole,pid,tid,source_changes,real_signals,adapter_injections,state_injections;
    long operation_result,cleanup_result,cleanup_sync;
    unsigned char source_before[15],source_after[15];
    struct li2_maps_stats stats[8];
    struct li2_private_code_query query[8];
    struct li2_fetch_ref borrow;
    struct li2_fetch_progress fetch_before,fetch_after;
    struct li2_fetch_view source_view;
    struct li2_fetch_page source_pages[2];
    struct li2_fetch_backing source_backing[2];
    struct li2_tf_continuation guard;
    struct frame frames[3];
};
static struct record li2_maps_record;
static uintptr_t source,probe,hole;
static volatile sig_atomic_t in_handler;
static uint64_t signal_mask;
static unsigned char elf[3*PAGE];
extern long kernel_raw(long,long,long,long,long,long,long);
extern void fixture_restorer(void);
long raw(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(kernel_raw,n,a,b,c,d,e,f);
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
void *memcpy(void *to,const void *from,size_t n) {unsigned char *d=to;const unsigned char *s=from;for(size_t i=0;i<n;i++)d[i]=s[i];return to;}
void *memset(void *to,int value,size_t n) {unsigned char *d=to;for(size_t i=0;i<n;i++)d[i]=(unsigned char)value;return to;}
int equal(const void *a,const void *b,size_t n) {const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static int write_all(int fd,const void *p,size_t n) {const char *s=p;size_t at=0;while(at<n){long r=RAW(SYS_write,fd,s+at,n-at,0,0,0);if(r<=0)return 0;at+=(size_t)r;}return 1;}
static _Noreturn void finish(int expected) {
    li2_maps_phase_end();
    if(source) {
        li2_maps_record.cleanup_result=RAW(SYS_mprotect,source,2*PAGE,PROT_READ,0,0,0);
        li2_maps_record.cleanup_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
        if(li2_maps_record.cleanup_result || li2_maps_record.cleanup_sync)li2_maps_record.fixture_error=999;
    }
    li2_maps_stats_read(&li2_maps_record.stats[7]);
    li2_maps_record.bytes=sizeof li2_maps_record;
    const char ok[]="LI2_MAPS_PHASE_OK\n",failed[]="LI2_MAPS_PHASE_EXPECTED_FAILURE\n",bad[]="LI2_MAPS_PHASE_FIXTURE_FAILURE\n";
    int status=li2_maps_record.fixture_error?124:(expected?125:0);
    if(!write_all(3,&li2_maps_record,sizeof li2_maps_record))status=124;
    const char *line=status==124?bad:expected?failed:ok;
    size_t n=status==124?sizeof bad-1:expected?sizeof failed-1:sizeof ok-1;
    if(!write_all(1,line,n))status=124;
    (void)RAW(SYS_exit_group,status,0,0,0,0,0);__builtin_trap();
}
static void need(int condition,unsigned error) {if(!condition){if(!li2_maps_record.fixture_error)li2_maps_record.fixture_error=error;finish(0);}}
static _Noreturn void lifecycle_fail(unsigned code,long detail) {(void)detail;li2_maps_record.fixture_error=1000+code;finish(0);}
static int protected_range(uintptr_t a,size_t n) {(void)a;(void)n;return 0;}
static uint32_t u32(const unsigned char *p) {return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void capture(struct frame *out,const ucontext_t *uc) {
    need(uc && !out->observed,101);out->observed=1;
    memcpy(out->greg,uc->uc_mcontext.gregs,sizeof out->greg);
    memcpy(&out->mask,&uc->uc_sigmask,sizeof out->mask);
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    need(out->fp_address && !(out->fp_address&15),102);
    const unsigned char *p=(const void *)out->fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        need(n>=580 && n<=FP_BYTES && x>=576 && x<=n-4 && u32(p+n-4)==UINT32_C(0x46505845),103);
    }
    out->fp_bytes=n;memcpy(out->fp,p,n);
}
static void unchanged(const struct frame *saved,const ucontext_t *uc) {
    need(equal(saved->greg,uc->uc_mcontext.gregs,sizeof saved->greg) &&
         equal(&saved->mask,&uc->uc_sigmask,sizeof saved->mask) &&
         saved->fp_address==(uintptr_t)uc->uc_mcontext.fpregs &&
         equal(saved->fp,uc->uc_mcontext.fpregs,saved->fp_bytes),104);
}
static void query(unsigned index,uintptr_t first,int prot,int expected) {
    need(index<8 && !li2_maps_record.query[index].attempted,105);
    int r=li2_lifecycle_private_code_query(first,PAGE,prot,&li2_maps_record.query[index]);
    need(r==expected && li2_maps_record.query[index].result==expected &&
         li2_maps_record.query[index].complete==(unsigned)!expected,106);
}
static void same_acquisition(const struct li2_fetch_map_progress *a,const struct li2_fetch_map_progress *b) {
    need(a->observation.acquisition_id && a->observation.acquisition_id==b->observation.acquisition_id &&
         a->observation.handler_id==b->observation.handler_id &&
         a->observation.mutation_epoch==b->observation.mutation_epoch &&
         b->observation.kind==LI2_MAPS_REUSED && !b->observation.io_performed &&
         a->fd==b->fd && a->last_read==b->last_read && a->close_result==b->close_result &&
         a->bytes==b->bytes && a->rows==b->rows && a->opened==1 && b->opened==1 &&
         a->close_started==1 && b->close_started==1 && a->closed==1 && b->closed==1,107);
}
static void fresh_after(const struct li2_fetch_map_progress *a,const struct li2_fetch_map_progress *b) {
    need(b->observation.acquisition_id>a->observation.acquisition_id &&
         b->observation.io_performed==1 && b->observation.kind!=LI2_MAPS_REUSED &&
         b->observation.mutation_epoch>a->observation.mutation_epoch,108);
}
static long denied(long n,long a,long b,long c,long d,long e,long f) {
    need(n==SYS_mprotect && a==(long)probe && b==PAGE && c==PROT_READ && !d && !e && !f,109);
    ++li2_maps_record.adapter_injections;return -EACCES; /* Named nonissued error, never kernel evidence. */
}
static void handler(int sig,siginfo_t *si,void *ptr) {
    li2_maps_event_boundary(); /* Same first-action production boundary. */
    ucontext_t *uc=ptr;
    if(in_handler) {
        capture(&li2_maps_record.frames[2],uc);
        li2_maps_stats_read(&li2_maps_record.stats[6]);
        need(li2_maps_record.mode==4 && sig==SIGTRAP && si && si->si_code==SI_TKILL &&
             si->si_pid==(int)li2_maps_record.pid && li2_maps_record.real_signals==1 &&
             !li2_maps_record.stats[6].active && !li2_maps_record.stats[6].valid,110);
        ++li2_maps_record.events;li2_maps_record.operation_failed=1;li2_maps_record.verified=1;finish(1);
    }
    in_handler=1;need(si && uc && sig==SIGSEGV && si->si_signo==SIGSEGV &&
        si->si_code==SEGV_ACCERR && !si->si_errno && uc->uc_mcontext.gregs[REG_TRAPNO]==14 &&
        uc->uc_mcontext.gregs[REG_ERR]==21 && (uc->uc_mcontext.gregs[REG_CSGSFS]&0xffff)==0x33,111);
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    need(pc==source+(li2_maps_record.events?PAGE:0) && (uintptr_t)si->si_addr==pc,112);
    uint64_t saved_mask=0;memcpy(&saved_mask,&uc->uc_sigmask,8);need(saved_mask==signal_mask,113);
    capture(&li2_maps_record.frames[li2_maps_record.events],uc);++li2_maps_record.events;
    need(!li2_maps_phase_begin(),114);li2_maps_stats_read(&li2_maps_record.stats[li2_maps_record.events==1?0:4]);
    if(li2_maps_record.events==2) {
        need(li2_maps_record.mode==3,115);query(4,probe,PROT_READ|PROT_EXEC,0);
        fresh_after(&li2_maps_record.query[3].maps,&li2_maps_record.query[4].maps);
        need(li2_maps_record.query[4].maps.observation.handler_id>li2_maps_record.query[3].maps.observation.handler_id,116);
        for(unsigned i=0;i<NGREG;i++)if(i!=REG_RIP && i!=REG_CR2)
            need(li2_maps_record.frames[0].greg[i]==li2_maps_record.frames[1].greg[i],117);
        need(li2_maps_record.frames[1].greg[REG_RIP]==(greg_t)(source+PAGE) &&
             li2_maps_record.frames[0].fp_bytes==li2_maps_record.frames[1].fp_bytes &&
             equal(li2_maps_record.frames[0].fp,li2_maps_record.frames[1].fp,li2_maps_record.frames[0].fp_bytes) &&
             equal(&li2_maps_record.frames[0].mask,&li2_maps_record.frames[1].mask,sizeof(uint64_t)),118);
        unchanged(&li2_maps_record.frames[1],uc);li2_maps_record.verified=1;finish(0);
    }
    need(!li2_lifecycle_fetch_prepare(source,15,&li2_maps_record.borrow),119);
    li2_maps_record.fetch_before=*li2_lifecycle_fetch_progress();
    need(!li2_lifecycle_fetch_view(&li2_maps_record.borrow,&li2_maps_record.source_view),120);
    need(li2_maps_record.source_view.page_count==1 && li2_maps_record.source_view.length==15,154);
    for(size_t i=0;i<li2_maps_record.source_view.page_count;i++) {
        li2_maps_record.source_pages[i]=li2_maps_record.source_view.pages[i];
        li2_maps_record.source_backing[i]=li2_maps_record.source_view.backing[i];
    }
    memcpy(li2_maps_record.source_before,(void *)source,15);
    query(0,probe,PROT_READ|PROT_EXEC,0);
    same_acquisition(&li2_maps_record.fetch_before.preparation,&li2_maps_record.query[0].maps);
    need(!li2_lifecycle_tf_continuation(&li2_maps_record.borrow,source+PAGE,&li2_maps_record.guard) &&
         li2_maps_record.guard.complete && li2_maps_record.guard.page.address==source+PAGE &&
         li2_maps_record.guard.page.generation!=li2_maps_record.source_pages[0].generation,121);
    same_acquisition(&li2_maps_record.query[0].maps,&li2_maps_record.guard.maps);
    li2_maps_stats_read(&li2_maps_record.stats[1]);
    need(li2_maps_record.stats[1].acquisitions==li2_maps_record.stats[0].acquisitions+1 &&
         li2_maps_record.stats[1].reuses>li2_maps_record.stats[0].reuses && li2_maps_record.stats[1].active && li2_maps_record.stats[1].valid,122);
    if(li2_maps_record.mode==5) {
        need(!RAW(SYS_mprotect,source,PAGE,PROT_READ|PROT_WRITE,0,0,0),123);
        *(volatile unsigned char *)source=0x91;li2_maps_record.source_changes=1;
        need(!RAW(SYS_mprotect,source,PAGE,PROT_READ,0,0,0) && !RAW(SYS_membarrier,32,0,0,0,0,0),124);
        int error=li2_lifecycle_fetch_validate(&li2_maps_record.borrow,0,PROT_READ);
        li2_maps_record.fetch_after=*li2_lifecycle_fetch_progress();memcpy(li2_maps_record.source_after,(void *)source,15);
        need(error==LI2_FETCH_SOURCE && li2_maps_record.fetch_after.first_error==LI2_FETCH_SOURCE &&
             li2_maps_record.source_before[0]==0x90 && li2_maps_record.source_after[0]==0x91 &&
             equal(li2_maps_record.source_before+1,li2_maps_record.source_after+1,14),125);
        fresh_after(&li2_maps_record.fetch_before.preparation,&li2_maps_record.fetch_after.validation);
        unchanged(&li2_maps_record.frames[0],uc);li2_maps_record.operation_failed=1;li2_maps_record.verified=1;finish(1);
    }
    need(!li2_lifecycle_fetch_release(&li2_maps_record.borrow),126);
    li2_maps_record.fetch_after=*li2_lifecycle_fetch_progress();need(!li2_maps_record.fetch_after.held,127);
    if(li2_maps_record.mode==0) {
        query(1,probe+PAGE,PROT_READ|PROT_EXEC,0);
        same_acquisition(&li2_maps_record.query[0].maps,&li2_maps_record.query[1].maps);
        li2_maps_record.operation_result=RAW(SYS_getuid,0,0,0,0,0,0); /* Unknown to the reuse whitelist. */
        need(li2_maps_record.operation_result>=0,128);query(2,probe,PROT_READ|PROT_EXEC,0);
        fresh_after(&li2_maps_record.query[1].maps,&li2_maps_record.query[2].maps);
    } else if(li2_maps_record.mode==1) {
        li2_maps_record.operation_result=RAW(SYS_mprotect,probe,PAGE,PROT_READ,0,0,0);need(!li2_maps_record.operation_result,129);
        query(1,probe,PROT_READ|PROT_EXEC,LI2_FETCH_PAGE);fresh_after(&li2_maps_record.query[0].maps,&li2_maps_record.query[1].maps);
        li2_maps_record.operation_failed=1;
    } else if(li2_maps_record.mode==2) {
        query(1,hole,PROT_READ|PROT_WRITE,0);same_acquisition(&li2_maps_record.query[0].maps,&li2_maps_record.query[1].maps);
        li2_maps_record.operation_result=RAW(SYS_mprotect,hole,2*PAGE,PROT_READ,0,0,0);
        need(li2_maps_record.operation_result==-ENOMEM,130);
        query(2,hole,PROT_READ,0);fresh_after(&li2_maps_record.query[1].maps,&li2_maps_record.query[2].maps);
        need(li2_maps_record.query[2].maps.observation.kind==LI2_MAPS_DIRECT,131);
        query(3,hole,PROT_READ|PROT_WRITE,LI2_FETCH_PAGE);li2_maps_record.operation_failed=1;
    } else if(li2_maps_record.mode==3) {
        need(!RAW(SYS_mprotect,source,PAGE,PROT_READ|PROT_EXEC,0,0,0) && !RAW(SYS_membarrier,32,0,0,0,0,0),132);
        query(3,probe,PROT_READ|PROT_EXEC,0); /* Genuine ready snapshot immediately before execution. */
        li2_maps_stats_read(&li2_maps_record.stats[2]);need(li2_maps_record.stats[2].valid && li2_maps_record.stats[2].active,133);
        unchanged(&li2_maps_record.frames[0],uc);li2_maps_phase_end();li2_maps_stats_read(&li2_maps_record.stats[3]);
        need(!li2_maps_record.stats[3].active && !li2_maps_record.stats[3].valid,134);in_handler=0;return;
    } else if(li2_maps_record.mode==4) {
        li2_maps_stats_read(&li2_maps_record.stats[2]);need(li2_maps_record.stats[2].valid && li2_maps_record.stats[2].active,135);
        li2_maps_record.real_signals=1;(void)RAW(SYS_tgkill,li2_maps_record.pid,li2_maps_record.tid,SIGTRAP,0,0,0);need(0,136);
    } else if(li2_maps_record.mode==6) {
        li2_maps_record.operation_result=li2_maps_raw(denied,SYS_mprotect,probe,PAGE,PROT_READ,0,0,0);
        need(li2_maps_record.operation_result==-EACCES && li2_maps_record.adapter_injections==1,137);
        query(1,probe,PROT_READ|PROT_EXEC,0);fresh_after(&li2_maps_record.query[0].maps,&li2_maps_record.query[1].maps);
        need(li2_maps_record.query[1].maps.observation.kind==LI2_MAPS_DIRECT,138);li2_maps_record.operation_failed=1;
    } else if(li2_maps_record.mode==7 || li2_maps_record.mode==8) {
        li2_maps_stats_read(&li2_maps_record.stats[2]);
        need(!li2_maps_test_saturate((unsigned)li2_maps_record.mode-7),151);
        li2_maps_record.state_injections=1;
        /* Actual uncertain syscall boundary triggers the saturating path. */
        li2_maps_record.operation_result=RAW(SYS_getuid,0,0,0,0,0,0);
        need(li2_maps_record.operation_result>=0,152);
        query(1,probe,PROT_READ|PROT_EXEC,LI2_FETCH_STATE);
        li2_maps_stats_read(&li2_maps_record.stats[3]);
        need(li2_maps_record.stats[3].poisoned && !li2_maps_record.stats[3].valid &&
             !li2_maps_record.stats[3].active &&
             li2_maps_record.stats[3].fresh_calls==li2_maps_record.stats[2].fresh_calls &&
             li2_maps_record.stats[3].acquisitions==li2_maps_record.stats[2].acquisitions &&
             (li2_maps_record.mode==7?li2_maps_record.stats[3].invalidations:
                                       li2_maps_record.stats[3].mutation_epoch)==UINT64_MAX &&
             !li2_maps_record.query[1].maps.opened &&
             !li2_maps_record.query[1].maps.observation.acquisition_id,153);
        li2_maps_record.operation_failed=1;
    } else need(0,139);
    unchanged(&li2_maps_record.frames[0],uc);li2_maps_stats_read(&li2_maps_record.stats[5]);li2_maps_record.verified=1;
    finish((int)li2_maps_record.operation_failed);
}
static uintptr_t allocate(size_t bytes,int prot) {
    long p=RAW(SYS_mmap,0,bytes,prot,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(!(p<0 && p>=-4095),140);return (uintptr_t)p;
}
int fixture_main(unsigned long *stack) {
    li2_maps_record.magic=UINT64_C(0x3150414d32494c);li2_maps_record.version=1;
    need(stack && stack[0]==2,141);const char *mode=(void *)stack[2];
    need(mode && mode[0]>='0' && mode[0]<='8' && !mode[1],142);li2_maps_record.mode=(unsigned)(mode[0]-'0');
    li2_maps_record.pid=RAW(SYS_getpid,0,0,0,0,0,0);li2_maps_record.tid=RAW(SYS_gettid,0,0,0,0,0,0);
    need(li2_maps_record.pid==li2_maps_record.tid && li2_maps_record.pid,143);
    Elf64_Ehdr *h=(void *)elf;memcpy(h->e_ident,"\177ELF\2\1\1",7);
    h->e_type=ET_DYN;h->e_machine=EM_X86_64;h->e_version=1;h->e_ehsize=sizeof *h;
    h->e_phoff=sizeof *h;h->e_phentsize=sizeof(Elf64_Phdr);h->e_phnum=2;
    Elf64_Phdr *ph=(void *)(elf+h->e_phoff);
    ph[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R,.p_filesz=PAGE,.p_memsz=PAGE,.p_align=PAGE};
    ph[1]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_offset=PAGE,.p_vaddr=PAGE,.p_filesz=2*PAGE,.p_memsz=2*PAGE,.p_align=PAGE};
    memset(elf+PAGE,0x90,2*PAGE);elf[PAGE+1]=0xe9;
    uint32_t displacement=PAGE-6;memcpy(elf+PAGE+2,&displacement,4);elf[2*PAGE]=0xcc;
    long fd=RAW(SYS_memfd_create,"li2-maps-phase",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    need(fd>=0 && write_all((int)fd,elf,sizeof elf) && !RAW(SYS_fcntl,fd,F_ADD_SEALS,15,0,0,0),144);
    int input=(int)fd;const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};
    li2_lifecycle_initialize(&input,1,&hooks);
    const long args[6]={0,2*PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,PAGE};long mapped=0;
    need(li2_lifecycle_dispatch(SYS_mmap,args,&mapped) && mapped>0,145);source=(uintptr_t)mapped;
    probe=allocate(2*PAGE,PROT_READ|PROT_EXEC);hole=allocate(3*PAGE,PROT_READ|PROT_WRITE);
    need(!RAW(SYS_munmap,hole+PAGE,PAGE,0,0,0,0),146);
    uintptr_t alt=allocate(512*1024+2*PAGE,PROT_NONE);
    need(!RAW(SYS_mprotect,alt+PAGE,512*1024,PROT_READ|PROT_WRITE,0,0,0),147);
    stack_t ss={.ss_sp=(void *)(alt+PAGE),.ss_size=512*1024};
    need(!RAW(SYS_sigaltstack,&ss,0,0,0,0,0),148);
    signal_mask=UINT64_MAX & ~(UINT64_C(1)<<(SIGSEGV-1)) & ~(UINT64_C(1)<<(SIGTRAP-1)) &
        ~(UINT64_C(1)<<(SIGKILL-1)) & ~(UINT64_C(1)<<(SIGSTOP-1));
    struct action action={handler,SA_SIGINFO|SA_ONSTACK|0x04000000,fixture_restorer,signal_mask};
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0) && !RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0) &&
         !RAW(SYS_rt_sigprocmask,SIG_SETMASK,&signal_mask,0,8,0,0),149);
    li2_maps_record.source=source;li2_maps_record.probe=probe;li2_maps_record.hole=hole;
    ((void (*)(void))source)();need(0,150);return 0;
}
