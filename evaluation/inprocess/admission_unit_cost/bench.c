#define _GNU_SOURCE
#include "decoder.h"
#include "native_policy.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/membarrier.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

/* Component timings, not a loader implementation or admission authority. */
#define PAGE 4096U
#define WINDOW (PAGE+28U)
#define MAP_CAP (256U*1024U)
#define ALT_CAP (512U*1024U)
#define REPEATS 10U
static unsigned char arena[16U*1024U*1024U] __attribute__((aligned(64)));
static unsigned char windows[3][WINDOW];
static unsigned char maps_buffer[MAP_CAP];
static struct li2_decoded decoded_rows[WINDOW];
static struct li2_scan baseline_scan[3];
static struct li2_decoder_stats initial_stats;
static unsigned char *code_page,*alt,*predecessor;
static unsigned char residency;
static volatile sig_atomic_t fault_mode,handling;
static volatile uint64_t fault_count,handler_mprotect;
static volatile uint64_t sink;
extern unsigned unit_cost_native_policy_lease(const unsigned char *,size_t);
extern void unit_cost_fault_return(void);
__asm__(".text\n.globl unit_cost_fault_return\n.type unit_cost_fault_return,@function\n"
        "unit_cost_fault_return:\nret\n.size unit_cost_fault_return,.-unit_cost_fault_return\n");

static inline long raw(long n,long a,long b,long c) {
    long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;
}
static _Noreturn void fail(unsigned code) {
    (void)raw(SYS_exit_group,(long)code,0,0);__builtin_trap();
}
_Noreturn void li2_decoder_abort(uint32_t reason) {(void)reason;fail(124);}
static void need(int ok,unsigned code) {if(!ok)fail(code);}
static uint64_t now(void) {
    struct timespec t;need(!clock_gettime(CLOCK_MONOTONIC_RAW,&t),10);
    need(t.tv_sec>=0 && t.tv_nsec>=0 && t.tv_nsec<1000000000,11);
    return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;
}
static void protect(int prot) {need(!raw(SYS_mprotect,(long)code_page,PAGE,prot),12);}
static void call_page(void) {((void(*)(void))(uintptr_t)code_page)();}
static void handler(int sig,siginfo_t *si,void *context) {
    unsigned char marker;ucontext_t *u=context;
    if(handling || !fault_mode || sig!=SIGSEGV || !si || !u ||
       si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       si->si_addr!=code_page || (uintptr_t)u->uc_mcontext.gregs[REG_RIP]!=(uintptr_t)code_page ||
       (uintptr_t)u->uc_mcontext.gregs[REG_CR2]!=(uintptr_t)code_page ||
       u->uc_mcontext.gregs[REG_TRAPNO]!=14 || u->uc_mcontext.gregs[REG_ERR]!=21 ||
       ((uint64_t)u->uc_mcontext.gregs[REG_EFL]&0x100) ||
       (uintptr_t)&marker<(uintptr_t)alt || (uintptr_t)&marker>=(uintptr_t)alt+ALT_CAP)fail(120);
    handling=1;++fault_count;
    if(fault_mode==1) {
        if(raw(SYS_mprotect,(long)code_page,PAGE,PROT_READ|PROT_EXEC))fail(121);
        ++handler_mprotect;
    } else if(fault_mode==2) {
        /* Separate diagnostic control: sigreturn to an ordinary RET, no grant. */
        u->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)unit_cost_fault_return;
    } else fail(122);
    handling=0;
}
static uint64_t hash(const unsigned char *p,size_t n) {
    uint64_t h=UINT64_C(1469598103934665603);
    for(size_t i=0;i<n;i++)h=(h^p[i])*UINT64_C(1099511628211);
    return h;
}
static void load_window(const char *path,unsigned i) {
    int fd=open(path,O_RDONLY|O_CLOEXEC);need(fd>=0,13);size_t n=0;
    while(n<WINDOW) {ssize_t k=read(fd,windows[i]+n,WINDOW-n);need(k>0,14);n+=(size_t)k;}
    unsigned char b;need(read(fd,&b,1)==0 && !close(fd),15);
}
struct count {uint64_t mp,signals,opens,reads,closes,bytes,starts,candidates,policy,minor,checksum,sync,mincore;};
struct sample {const char *name;int sample;unsigned iterations;uint64_t elapsed,minor_faults,major_faults;struct count c;};
static struct sample samples[256];static unsigned used;
static const uint64_t pages[3]={0x5000,0x2000,UINT64_C(0x200021000)};
static const char *names[]={"empty_loop","raw_getpid","rx_ret_call","mprotect_same_rx",
    "mprotect_r_rx_ret_pair","nx_signal_ucontext_ret","nx_fault_grant_ret_cycle",
    "maps_open_close","devnull_read","maps_fresh_open_read_close","minor_first_write",
    "decoder_scan_ls","decoder_scan_true","decoder_scan_helper",
    "native_policy_ls","native_policy_true","native_policy_helper",
    "source_lease_policy_ls","source_lease_policy_true","source_lease_policy_helper",
    "membarrier_sync_core","mincore_absent_predecessor"};
static unsigned iterations(unsigned test) {
    if(test==5 || test==6)return 2000;
    if(test==7 || test==9)return 500;
    if(test==10)return 256;
    if(test>=11 && test<=13)return 64;
    if(test>=14 && test<=16)return 2000;
    return 20000;
}
static size_t maps_read(int fd,struct count *c) {
    size_t n=0;
    for(;;) {
        need(n<MAP_CAP,16);long k=raw(SYS_read,fd,(long)(maps_buffer+n),MAP_CAP-n);++c->reads;
        need(k>=0 && (uint64_t)k<=MAP_CAP-n,17);if(!k)break;n+=(size_t)k;
    }
    need(n && maps_buffer[n-1]=='\n',18);c->bytes+=n;c->checksum+=n;return n;
}
static void measure(unsigned test,int sample,unsigned n,const char *override_name) {
    need(used<256,19);struct sample *out=&samples[used++];out->name=override_name?override_name:names[test];
    out->sample=sample;out->iterations=n;struct count *c=&out->c;int fd=-1;unsigned char *minor=NULL;
    if(test==8){fd=open("/dev/null",O_RDONLY|O_CLOEXEC);need(fd>=0,20);}
    if(test==10){minor=mmap(NULL,(size_t)n*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(minor!=MAP_FAILED,21);need(!madvise(minor,(size_t)n*PAGE,MADV_NOHUGEPAGE),57);}
    protect(PROT_READ|PROT_EXEC);
    if(test==5)protect(PROT_READ);
    fault_count=handler_mprotect=0;fault_mode=test==5?2:test==6?1:0;
    struct rusage ru0,ru1;need(!getrusage(RUSAGE_SELF,&ru0),58);
    __asm__ volatile("":::"memory");uint64_t begin=now();
    for(unsigned i=0;i<n;i++) {
        switch(test) {
        case 0:__asm__ volatile("":::"memory");break;
        case 1:need(raw(SYS_getpid,0,0,0)>0,22);break;
        case 2:call_page();break;
        case 3:protect(PROT_READ|PROT_EXEC);++c->mp;break;
        case 4:protect(PROT_READ);protect(PROT_READ|PROT_EXEC);c->mp+=2;call_page();break;
        case 5:call_page();break;
        case 6:protect(PROT_READ);++c->mp;call_page();break;
        case 7:case 9: {
            long maps=raw(SYS_openat,AT_FDCWD,(long)"/proc/self/maps",O_RDONLY|O_CLOEXEC);need(maps>=0,23);++c->opens;
            if(test==9)(void)maps_read((int)maps,c);
            need(!raw(SYS_close,maps,0,0),24);++c->closes;break;
        }
        case 8:need(!raw(SYS_read,fd,(long)maps_buffer,PAGE),25);++c->reads;break;
        case 10:((volatile unsigned char *)minor)[(size_t)i*PAGE]=1;++c->minor;break;
        case 20:need(!raw(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0),60);++c->sync;break;
        case 21:need(raw(SYS_mincore,(long)predecessor,PAGE,(long)&residency)==-ENOMEM,61);++c->mincore;break;
        default: {
            unsigned d=(test-11)%3;
            if(test<=13) {
                struct li2_scan scan;
                need(li2_decoder_scan_page(pages[d]-14,windows[d],WINDOW,pages[d],0,0,decoded_rows,WINDOW,&scan)==LI2_OK,26);
                need(!memcmp(&scan,&baseline_scan[d],sizeof scan),27);
                c->starts+=scan.starts;c->candidates+=scan.candidates;c->checksum+=scan.written;
            } else {
                unsigned result=test<=16?li2_native_policy(windows[d],WINDOW):unit_cost_native_policy_lease(windows[d],WINDOW);
                c->policy|=result;c->checksum+=result;
            }
        }
        }
    }
    uint64_t end=now();__asm__ volatile("":::"memory");need(end>=begin,28);out->elapsed=end-begin;
    need(!getrusage(RUSAGE_SELF,&ru1)&&ru1.ru_minflt>=ru0.ru_minflt&&ru1.ru_majflt>=ru0.ru_majflt,59);
    out->minor_faults=(uint64_t)(ru1.ru_minflt-ru0.ru_minflt);out->major_faults=(uint64_t)(ru1.ru_majflt-ru0.ru_majflt);
    c->signals=fault_count;c->mp+=handler_mprotect;fault_mode=0;
    need(c->signals==((test==5||test==6)?n:0),29);
    need(handler_mprotect==(test==6?n:0) && !handling,30);
    if(test==3)need(c->mp==n,31);else if(test==4||test==6)need(c->mp==2*n,32);else need(!c->mp,33);
    if(test==7||test==9)need(c->opens==n && c->closes==n,34);else need(!c->opens&&!c->closes,35);
    if(test==8)need(c->reads==n&&!c->bytes,36);
    if(test==9)need(c->reads>=2*n && c->bytes>0,37);
    if(test>=11 && test<=13)need(c->starts==(uint64_t)n*(PAGE+14),38);
    if(test>=17 && test<=19)need(c->policy==LI2_NATIVE_BLOCK_STATE && c->checksum==(uint64_t)n*LI2_NATIVE_BLOCK_STATE,39);
    need(c->sync==(test==20?n:0) && c->mincore==(test==21?n:0),62);
    if(test==10) {for(unsigned i=0;i<n;i++)need(minor[(size_t)i*PAGE]==1,40);need(!munmap(minor,(size_t)n*PAGE),41);}
    if(fd>=0)need(!close(fd),42);
    sink+=c->checksum+c->starts+c->signals;
}
int main(int argc,char **argv) {
    need(argc==4 && sysconf(_SC_PAGESIZE)==PAGE,43);
    for(unsigned i=0;i<3;i++)load_window(argv[i+1],i);
    struct sample *init=&samples[used++];init->name="decoder_initialize";init->sample=-1;init->iterations=1;
    struct rusage init_ru0,init_ru1;need(!getrusage(RUSAGE_SELF,&init_ru0),68);
    uint64_t init_begin=now();uint32_t init_result=li2_decoder_initialize(arena,sizeof arena,&initial_stats);
    init->elapsed=now()-init_begin;
    need(!getrusage(RUSAGE_SELF,&init_ru1)&&init_ru1.ru_minflt>=init_ru0.ru_minflt&&init_ru1.ru_majflt>=init_ru0.ru_majflt,69);
    init->minor_faults=(uint64_t)(init_ru1.ru_minflt-init_ru0.ru_minflt);init->major_faults=(uint64_t)(init_ru1.ru_majflt-init_ru0.ru_majflt);
    need(!init_result && initial_stats.phase==2 && !initial_stats.first_fatal_reason && !initial_stats.reserved,44);
    for(unsigned i=0;i<3;i++) {
        need(!li2_decoder_scan_page(pages[i]-14,windows[i],WINDOW,pages[i],0,0,decoded_rows,WINDOW,&baseline_scan[i]),45);
        need(baseline_scan[i].complete==1 && baseline_scan[i].starts==PAGE+14,46);
    }
    code_page=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(code_page!=MAP_FAILED,47);
    memset(code_page,0x90,PAGE);code_page[0]=0xc3;protect(PROT_READ|PROT_EXEC);call_page();
    alt=mmap(NULL,ALT_CAP,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(alt!=MAP_FAILED,48);memset(alt,0,ALT_CAP);
    memset(maps_buffer,0,sizeof maps_buffer);
    predecessor=mmap(NULL,2U*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(predecessor!=MAP_FAILED,63);predecessor[PAGE]=1;
    need(!munmap(predecessor,PAGE),64);
    need(raw(SYS_mincore,(long)predecessor,PAGE,(long)&residency)==-ENOMEM,65);
    long supported=raw(SYS_membarrier,MEMBARRIER_CMD_QUERY,0,0);
    if(supported<0 || !(supported&MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) ||
       !(supported&MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)) {
        fprintf(stderr,"UNSUPPORTED_MEMBARRIER query=%ld\n",supported);fflush(stderr);fail(66);
    }
    long registered=raw(SYS_membarrier,MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,0,0);
    if(registered) {fprintf(stderr,"FAILED_MEMBARRIER_REGISTER result=%ld\n",registered);fflush(stderr);fail(67);}
    stack_t ss={.ss_sp=alt,.ss_size=ALT_CAP};need(!sigaltstack(&ss,NULL),49);
    sigset_t empty;sigemptyset(&empty);need(!sigprocmask(SIG_SETMASK,&empty,NULL),50);
    struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO|SA_ONSTACK;sigemptyset(&sa.sa_mask);need(!sigaction(SIGSEGV,&sa,NULL),51);
    measure(6,-1,1,"first_nx_fault_grant_ret_cycle");measure(5,-1,1,"first_nx_ucontext_ret_control");
    for(unsigned round=0;round<=REPEATS;round++) {
        /* Alternating complete order, no discarded measurements or retry. */
        for(unsigned j=0;j<22;j++){unsigned t=round%2?21-j:j;measure(t,(int)round,iterations(t),NULL);}
    }
    struct li2_decoder_stats final_stats;need(!li2_decoder_stats(&final_stats)&&!memcmp(&final_stats,&initial_stats,sizeof final_stats),52);
    need(used==245,53);
    puts("name,sample,iterations,elapsed_ns,mprotect_calls,signals,opens,reads,closes,read_bytes,scan_starts,scan_candidates,policy_mask,minor_pages,checksum,minor_faults,major_faults,sync_core_calls,mincore_calls");
    for(unsigned i=0;i<used;i++) {const struct sample *s=&samples[i];const struct count *c=&s->c;
        printf("%s,%d,%u,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n",s->name,s->sample,s->iterations,s->elapsed,c->mp,c->signals,c->opens,c->reads,c->closes,c->bytes,c->starts,c->candidates,c->policy,c->minor,c->checksum,s->minor_faults,s->major_faults,c->sync,c->mincore);
    }
    for(unsigned i=0;i<3;i++)fprintf(stderr,"WINDOW %u %u %016"PRIx64" starts=%u candidates=%u invalid=%u truncated=%u\n",i,WINDOW,hash(windows[i],WINDOW),baseline_scan[i].starts,baseline_scan[i].candidates,baseline_scan[i].invalid_starts,baseline_scan[i].truncated_starts);
    fprintf(stderr,"INIT abi=%u phase=%u arena=%"PRIu64" retained=%"PRIu64" allocations=%"PRIu64" deallocations=%"PRIu64" sync_query=%ld sync_register=%ld\n",initial_stats.abi_version,initial_stats.phase,initial_stats.arena_bytes,initial_stats.retained_high_water,initial_stats.allocation_calls,initial_stats.deallocation_calls,supported,registered);
    need(!fflush(stdout)&&!fflush(stderr),54);
    ss.ss_flags=SS_DISABLE;ss.ss_sp=NULL;ss.ss_size=0;need(!sigaltstack(&ss,NULL),55);
    need(!munmap(code_page,PAGE)&&!munmap(alt,ALT_CAP)&&!munmap(predecessor+PAGE,PAGE),56);return 0;
}
