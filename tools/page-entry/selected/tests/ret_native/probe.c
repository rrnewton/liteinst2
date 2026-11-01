#define _GNU_SOURCE
#include <asm/prctl.h>
#include <cpuid.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define PAGE 4096U
#define FP_BYTES 65536U
#define STACK_BYTES (4U*PAGE)
#define ALT_BYTES (256U*1024U)
#define CASES 32U
#define CHUNK 32U
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define DF UINT64_C(0x400)
#define MAGIC UINT64_C(0x3154455232494c)
#define RECORD UINT64_C(0x3152455232494c)
#define END UINT64_C(0x3145455232494c)

/* Entire actual kernel frames remain private binary observations. No field is
   normalized to assume RET fault-order or stack-pointer commitment. Unused FP storage is zero. */
struct frame {
    uint64_t h[16];
    int64_t greg[23];
    unsigned char mask[128],info[128],context[968],fp[FP_BYTES];
};
struct lane_record {
    uint64_t h[32];
    int64_t bootstrap_greg[23];
    struct frame before,after;
    unsigned char stack_before[STACK_BYTES],stack_after[STACK_BYTES];
    unsigned char source[4U*PAGE];
};
_Static_assert(sizeof(ucontext_t)==968 && sizeof(siginfo_t)==128 && sizeof(sigset_t)==128,
               "exact Linux x86-64 observation ABI");
_Static_assert(NGREG==23 && sizeof(greg_t)==8 && sizeof(struct frame)==67072,
               "all original GREG and FP storage");
_Static_assert(sizeof(struct lane_record)==183736 &&
               256+CHUNK*sizeof(struct lane_record)+64 < 16U*1024U*1024U,
               "unchanged bounded raw output");

uint64_t probe_seed[16],probe_flags,probe_pc;
extern void probe_enter(void),probe_return(void),probe_reload(void);
extern unsigned char probe_scratch_end[];
static const unsigned greg_index[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,
    REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static uintptr_t code_base,stack_base,target_base,alt_base;
static uint64_t header[32];
static struct lane_record record;
static volatile sig_atomic_t phase,handler_busy,events;
static unsigned chunk_first,chunk_count,records_written,cpu;
static int output_started;

static long raw(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d;
    register long r8 __asm__("r8")=e;
    register long r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),
                     "r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
static void copy(void *to,const void *from,size_t n) {
    unsigned char *a=to;const volatile unsigned char *b=from;
    while(n--)*a++=*b++;
}
static int equal(const void *av,const void *bv,size_t n) {
    const volatile unsigned char *a=av,*b=bv;
    while(n--)if(*a++!=*b++)return 0;
    return 1;
}
static uint32_t word32(const void *p) {uint32_t v;copy(&v,p,4);return v;}
static int write_all(int fd,const void *vp,size_t n) {
    const unsigned char *p=vp;
    while(n) {
        long r=raw(SYS_write,fd,(long)p,(long)n,0,0,0);
        if(r==-4)continue;
        if(r<=0 || (size_t)r>n)return 0;
        p+=(size_t)r;n-=(size_t)r;
    }
    return 1;
}
__attribute__((noreturn)) static void fail(unsigned code) {
    record.h[14]=code;
    if(output_started)(void)write_all(1,&record,sizeof record);
    static const char message[]="ret diagnostic incomplete; inspect retained raw record\n";
    (void)write_all(2,message,sizeof(message)-1);
    raw(SYS_exit_group,125,0,0,0,0,0);__builtin_unreachable();
}
static void need(int yes,unsigned code) {if(!yes)fail(code);}
static void capture(struct frame *f,int sig,const siginfo_t *si,const ucontext_t *uc) {
    uintptr_t sp=(uintptr_t)&sp,fp=(uintptr_t)uc->uc_mcontext.fpregs;
    need(sp>=alt_base && sp<alt_base+ALT_BYTES &&
         fp>=alt_base && fp<=alt_base+ALT_BYTES-512,10);
    size_t bytes=512;
    if(word32((const void *)(fp+464))==UINT32_C(0x46505853)) {
        bytes=word32((const void *)(fp+468));
        need(bytes>=576 && bytes<=FP_BYTES && fp<=alt_base+ALT_BYTES-bytes &&
             word32((const void *)(fp+bytes-4))==UINT32_C(0x46505845) &&
             word32((const void *)(fp+480))<=bytes-4,11);
    }
    unsigned actual_cpu=~0U;
    unsigned long fs=0,gs=0;
    need(!raw(SYS_arch_prctl,ARCH_GET_FS,(long)&fs,0,0,0,0) &&
         !raw(SYS_arch_prctl,ARCH_GET_GS,(long)&gs,0,0,0,0) &&
         !raw(SYS_getcpu,(long)&actual_cpu,0,0,0,0,0) && actual_cpu==cpu,12);
    f->h[0]=(uint64_t)sig;f->h[1]=(uint64_t)(int64_t)si->si_code;
    f->h[2]=(uint64_t)(int64_t)si->si_errno;f->h[3]=(uintptr_t)si->si_addr;
    f->h[4]=uc->uc_flags;f->h[5]=(uintptr_t)uc->uc_link;f->h[6]=fp;f->h[7]=bytes;
    f->h[8]=fs;f->h[9]=gs;f->h[10]=sp;f->h[11]=actual_cpu;f->h[12]=(uint64_t)phase;
    f->h[13]=(uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO];
    f->h[14]=(uint64_t)uc->uc_mcontext.gregs[REG_ERR];
    f->h[15]=(uint64_t)uc->uc_mcontext.gregs[REG_CR2];
    copy(f->greg,uc->uc_mcontext.gregs,sizeof f->greg);
    copy(f->mask,&uc->uc_sigmask,sizeof f->mask);copy(f->info,si,sizeof f->info);
    copy(f->context,uc,sizeof f->context);copy(f->fp,(const void *)fp,bytes);
}
static void handler(int sig,siginfo_t *si,void *context) {
    ucontext_t *uc=context;
    if(handler_busy)fail(20);
    handler_busy=1;++events;
    if(phase==0) {
        capture(&record.before,sig,si,uc);
        need(sig==SIGSEGV && si->si_code==SEGV_ACCERR &&
             (uintptr_t)si->si_addr==probe_pc &&
             (uint64_t)uc->uc_mcontext.gregs[REG_RIP]==probe_pc &&
             uc->uc_mcontext.gregs[REG_TRAPNO]==14 &&
             ((uint64_t)uc->uc_mcontext.gregs[REG_ERR]&16)==16,21);
        for(unsigned i=0;i<16;i++)need((uint64_t)uc->uc_mcontext.gregs[greg_index[i]]==probe_seed[i],22);
        need(((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&~RF)==probe_flags,23);
        /* An invalid RSP must reach the instruction through ordinary MOV/JMP,
           not be rejected first by the kernel's signal-return machinery. */
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_reload;
        uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
        uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(RF|TF);
        copy(record.bootstrap_greg,uc->uc_mcontext.gregs,sizeof record.bootstrap_greg);
        phase=1;
        need(!raw(SYS_mprotect,(long)code_base,PAGE,PROT_READ|PROT_EXEC,0,0,0),24);
    } else if(phase==1) {
        capture(&record.after,sig,si,uc);
        need(sig==SIGTRAP || sig==SIGSEGV || sig==SIGBUS || sig==SIGILL,25);
        phase=2;
        /* Only the recovery frame changes. The complete actual frame is above. */
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_return;
        uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
        uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(TF|RF|DF|UINT64_C(0x40000));
    } else fail(26);
    handler_busy=0;
}

struct configuration {unsigned reg,group,item;int permissions[4];uint64_t sp,target,flags;};
static uint64_t flags(unsigned value) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t r=UINT64_C(0x202);
    for(unsigned i=0;i<6;i++)if(value&(1U<<i))r|=UINT64_C(1)<<bits[i];
    return r;
}
static struct configuration configuration(unsigned id) {
    need(id<CASES,30);
    struct configuration c={.reg=4,.permissions={PROT_NONE,PROT_READ|PROT_WRITE,
        PROT_READ|PROT_WRITE,PROT_NONE},.sp=stack_base+2U*PAGE+512,
        .target=target_base+64,.flags=flags((id*7U)&63U)|((id&1U)?DF:0)};
    const uint64_t targets[4]={target_base+64,target_base+PAGE+64,
        UINT64_C(0x0100000000000000),UINT64_C(0x8000000000000000)};
    if(id<20) {
        c.group=0;c.item=id;c.target=targets[id%4U];
        switch(id/4U) {
        case 0:break;
        case 1:c.sp++;break;
        case 2:c.sp=stack_base+2U*PAGE-1U;break;
        case 3:c.sp=stack_base+2U*PAGE-4U;break;
        case 4:c.sp=stack_base+2U*PAGE-7U;break;
        }
    } else if(id<24) {
        c.group=1;c.item=id-20;c.target=targets[c.item];
        c.permissions[1]=PROT_READ;c.permissions[2]=PROT_READ;
    } else if(id<30) {
        c.group=2;c.item=id-24;
        if(!c.item)c.permissions[2]=PROT_NONE;
        else if(c.item<=3) {
            const unsigned below[3]={1U,4U,7U};
            c.sp=stack_base+2U*PAGE-below[c.item-1U];c.permissions[2]=PROT_NONE;
        } else {
            c.sp=stack_base+2U*PAGE-(c.item==4?1U:4U);c.permissions[1]=PROT_NONE;
        }
    } else {
        c.group=3;c.item=id-30;
        c.sp=c.item?UINT64_C(0x8000000000001000):UINT64_C(0x0100000000001000);
    }
    return c;
}
static void lane(unsigned id) {
    struct configuration c=configuration(id);
    memset(&record,0,sizeof record);
    const unsigned call_bytes=1U;
    uint64_t original_next=probe_pc+call_bytes;
    need(!mprotect((void *)code_base,2U*PAGE,PROT_READ|PROT_WRITE) &&
         !mprotect((void *)stack_base,STACK_BYTES,PROT_READ|PROT_WRITE),50);
    unsigned char *code=(void *)code_base,*stack=(void *)stack_base;
    for(unsigned i=0;i<2U*PAGE;i++)code[i]=0xcc;
    for(unsigned i=0;i<STACK_BYTES;i++)stack[i]=(unsigned char)(0x5aU+37U*i+id);
    *(unsigned char *)(uintptr_t)probe_pc=0xc3;
    if(c.sp>=stack_base && c.sp<=stack_base+STACK_BYTES-8U)
        copy((void *)(uintptr_t)c.sp,&c.target,8);
    for(unsigned i=0;i<16;i++)probe_seed[i]=UINT64_C(0x13579bdf00110000)+UINT64_C(0x100010001)*i+id;
    probe_seed[4]=c.sp;probe_flags=c.flags;
    record.h[0]=RECORD;record.h[1]=sizeof record;record.h[2]=id;record.h[3]=0;
    record.h[4]=c.reg;record.h[5]=c.group;record.h[6]=c.item;record.h[7]=probe_pc;
    record.h[8]=original_next;record.h[9]=c.target;record.h[10]=c.sp;record.h[11]=c.flags;
    record.h[12]=call_bytes;record.h[17]=call_bytes;record.h[18]=0;
    for(unsigned i=0;i<4;i++)record.h[20+i]=(uint64_t)c.permissions[i];
    record.h[24]=PROT_READ|PROT_EXEC;record.h[25]=PROT_READ;
    copy(record.stack_before,stack,STACK_BYTES);copy(record.source,code,2U*PAGE);
    copy(record.source+2U*PAGE,(const void *)target_base,2U*PAGE);
    for(unsigned i=0;i<4;i++)need(!mprotect(stack+i*PAGE,PAGE,c.permissions[i]),52);
    need(!mprotect(code,2U*PAGE,PROT_READ),53);
    phase=0;events=0;handler_busy=0;probe_enter();
    need(phase==2 && events==2 && !handler_busy,54);
    record.h[15]=(uint64_t)phase;record.h[16]=(uint64_t)events;
    /* Post-stop reopening only. It cannot change the already captured fault. */
    need(!mprotect(code,2U*PAGE,PROT_READ) &&
         !mprotect(stack,STACK_BYTES,PROT_READ|PROT_WRITE),55);
    copy(record.stack_after,stack,STACK_BYTES);
    need(equal(code,record.source,2U*PAGE) &&
         equal((const void *)target_base,record.source+2U*PAGE,2U*PAGE),56);
    record.h[13]=1;
    need(write_all(1,&record,sizeof record),57);++records_written;
}
int main(int argc,char **argv) {
    need(argc==2 && argv[1][0]=='0' && !argv[1][1],60);
    unsigned chunk=(unsigned)(argv[1][0]-'0');chunk_first=chunk*CHUNK;
    chunk_count=CASES-chunk_first;if(chunk_count>CHUNK)chunk_count=CHUNK;
    need(sysconf(_SC_PAGESIZE)==PAGE,61);
    cpu_set_t affinity;CPU_ZERO(&affinity);
    need(!sched_getaffinity(0,sizeof affinity,&affinity) && CPU_COUNT(&affinity)==1,62);
    int actual_cpu=sched_getcpu();need(actual_cpu>=0 && CPU_ISSET(actual_cpu,&affinity),63);cpu=(unsigned)actual_cpu;
    unsigned long cet=0;long cet_result=raw(SYS_arch_prctl,0x5005,(long)&cet,0,0,0,0);
    /* Exactly the current production prerequisite; never disable CET here. */
    need((!cet_result && !cet)||cet_result==-22||cet_result==-38,64);
    unsigned a,b,c,d;need(__get_cpuid(1,&a,&b,&c,&d) && (c&(1U<<26)) && (c&(1U<<27)),65);
    uint32_t xlo,xhi;__asm__ volatile("xgetbv":"=a"(xlo),"=d"(xhi):"c"(0));
    uint64_t xcr0=((uint64_t)xhi<<32)|xlo;need((xcr0&3)==3,66);
    __cpuid_count(13,0,a,b,c,d);need(b>=512 && b<=FP_BYTES,67);
    code_base=(uintptr_t)mmap(0,2U*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    stack_base=(uintptr_t)mmap(0,STACK_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    target_base=(uintptr_t)mmap(0,2U*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    uintptr_t alternate=(uintptr_t)mmap(0,ALT_BYTES+2U*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(code_base!=(uintptr_t)MAP_FAILED && stack_base!=(uintptr_t)MAP_FAILED &&
         target_base!=(uintptr_t)MAP_FAILED && alternate!=(uintptr_t)MAP_FAILED,68);
    alt_base=alternate+PAGE;
    need(!mprotect((void *)alt_base,ALT_BYTES,PROT_READ|PROT_WRITE),69);
    memset((void *)target_base,0xcc,2U*PAGE);
    need(!mprotect((void *)target_base,PAGE,PROT_READ|PROT_EXEC) &&
         !mprotect((void *)(target_base+PAGE),PAGE,PROT_READ),70);
    probe_pc=code_base+0x100;
    stack_t alt={.ss_sp=(void *)alt_base,.ss_size=ALT_BYTES};need(!sigaltstack(&alt,0),71);
    struct sigaction action;memset(&action,0,sizeof action);action.sa_sigaction=handler;
    action.sa_flags=SA_SIGINFO|SA_ONSTACK;sigfillset(&action.sa_mask);
    const int signals[4]={SIGSEGV,SIGBUS,SIGILL,SIGTRAP};
    for(unsigned i=0;i<4;i++)need(!sigaction(signals[i],&action,0),72);
    sigset_t empty;sigemptyset(&empty);need(!sigprocmask(SIG_SETMASK,&empty,0),73);
    header[0]=MAGIC;header[1]=1;header[2]=sizeof header;header[3]=sizeof record;
    header[4]=sizeof(struct frame);header[5]=sizeof(ucontext_t);header[6]=sizeof(siginfo_t);
    header[7]=FP_BYTES;header[8]=STACK_BYTES;header[9]=4U*PAGE;header[10]=CASES;header[11]=chunk;
    header[12]=chunk_first;header[13]=chunk_count;header[14]=chunk_count;
    header[15]=(uint64_t)getpid();header[16]=cpu;header[17]=(uint64_t)cet_result;header[18]=cet;
    header[19]=xcr0;header[20]=b;header[21]=code_base;header[22]=stack_base;header[23]=target_base;
    header[24]=alt_base;header[25]=ALT_BYTES;header[26]=0;header[27]=CHUNK;
    header[28]=(uintptr_t)probe_reload;header[29]=(uintptr_t)probe_scratch_end;
    need(write_all(1,header,sizeof header),74);output_started=1;
    for(unsigned id=chunk_first;id<chunk_first+chunk_count;id++)lane(id);
    need(records_written==chunk_count,75);
    uint64_t end[8]={END,1,records_written,sizeof header+records_written*sizeof record+64,
                    0,0,0,0};
    need(write_all(1,end,sizeof end),76);
    return 0;
}
