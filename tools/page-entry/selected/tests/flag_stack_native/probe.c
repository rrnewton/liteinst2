#define _GNU_SOURCE
#include <asm/prctl.h>
#include <cpuid.h>
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
#include "flag_stack.h"
#include "tf_owner.h"

#define PAGE 4096U
#define FP_BYTES 65536U
#define STACK_BYTES (4U*PAGE)
#define ALT_BYTES (256U*1024U)
#define CASES 18U
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define DF UINT64_C(0x400)
#define AC UINT64_C(0x40000)
#define NT UINT64_C(0x4000)
#define MAGIC UINT64_C(0x314e534632494c)
#define RECORD UINT64_C(0x3152534632494c)
#define END UINT64_C(0x3145534632494c)
struct frame {
    uint64_t h[16];
    int64_t greg[23];
    unsigned char mask[128],info[128],context[968],fp[FP_BYTES];
};
struct transition { uint64_t address,bytes,permissions,phase;int64_t result; };
struct lane_record {
    uint64_t h[64];
    int64_t resumed_greg[23];
    struct frame before,after;
    struct li2_fs_descriptor descriptor;
    struct li2_write_footprint footprint;
    struct transition protection[16];
    unsigned char stack_before[STACK_BYTES],stack_after[STACK_BYTES];
    unsigned char source[2U*PAGE],image[PAGE];
};
_Static_assert(sizeof(ucontext_t)==968 && sizeof(siginfo_t)==128 && sizeof(sigset_t)==128,
               "exact Linux x86-64 observation ABI");
_Static_assert(NGREG==23 && sizeof(greg_t)==8 && sizeof(struct frame)==67072,
               "all original GREG and FP storage");
_Static_assert(sizeof(struct transition)==40 && sizeof(struct lane_record)==180664 &&
               512+2U*CASES*sizeof(struct lane_record)+64 < 16U*1024U*1024U,
               "one fixed full-state placement below original capture bound");
uint64_t probe_seed[16],probe_flags,probe_pc;
_Alignas(8) uint64_t probe_handler_flags;
extern void probe_enter(void),probe_return(void),probe_reload(void);
extern void probe_handler_entry(int,siginfo_t *,void *);
extern unsigned char probe_scratch_end[];
static const unsigned greg_index[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,
    REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static uintptr_t code_base,stack_base,alt_base,image_base,original_pc;
static uint64_t header[64];
static struct lane_record record;
static _Alignas(64) unsigned char arena[16U<<20];
static volatile sig_atomic_t phase,handler_busy,events;
static unsigned records_written,cpu,protect_count;
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
    static const char message[]="flag-stack diagnostic incomplete; inspect retained raw record\n";
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
static void protect(uintptr_t address,size_t bytes,int permissions) {
    need(protect_count<16,27);
    struct transition *t=&record.protection[protect_count++];
    t->address=address;t->bytes=bytes;t->permissions=(uint64_t)permissions;t->phase=(uint64_t)phase;
    t->result=raw(SYS_mprotect,(long)address,(long)bytes,permissions,0,0,0);
    need(!t->result,28);
}
/* The assembly entry captures live handler flags and clears live AC/NT/DF/TF
   with aligned operations before this C body. It never edits the kernel UC. */
void probe_handler(int sig,siginfo_t *si,void *vp) {
    ucontext_t *uc=vp;
    if(handler_busy)fail(20);
    handler_busy=1;++events;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(phase==0) {
        capture(&record.before,sig,si,uc);record.h[26]=probe_handler_flags;
        need(sig==SIGSEGV && si->si_code==SEGV_ACCERR &&
             (uintptr_t)si->si_addr==original_pc && pc==original_pc &&
             uc->uc_mcontext.gregs[REG_TRAPNO]==14 && uc->uc_mcontext.gregs[REG_ERR]==21,21);
        for(unsigned i=0;i<16;i++)need((uint64_t)uc->uc_mcontext.gregs[greg_index[i]]==probe_seed[i],22);
        need((uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(probe_flags|RF),23);
        phase=1;
        protect(record.h[3]?image_base:code_base,PAGE,PROT_READ|PROT_EXEC);
        if(record.h[24]) {
            /* The inherited invalid-RSP bootstrap is explicit and separately
               recorded. No qualification of a fabricated sigreturn RSP. */
            probe_pc=record.h[3]?image_base:original_pc;
            uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_reload;
            uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
            uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(RF|TF|DF|AC|NT);
        } else if(record.h[3])uc->uc_mcontext.gregs[REG_RIP]=(greg_t)image_base;
        copy(record.resumed_greg,uc->uc_mcontext.gregs,sizeof record.resumed_greg);
    } else if(phase==1) {
        capture(&record.after,sig,si,uc);record.h[27]=probe_handler_flags;
        need(sig==SIGTRAP || sig==SIGSEGV || sig==SIGBUS || sig==SIGILL,25);
        /* Stop at the FIRST real post-instruction/fault event. TF/NT/AC and
           #DB-versus-NX priority remain raw observations. No replay follows. */
        phase=2;
        protect(code_base,2U*PAGE,PROT_READ);protect(image_base,PAGE,PROT_READ);
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_return;
        uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
        uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(TF|RF|DF|AC|NT);
    } else fail(26);
    handler_busy=0;
}
struct configuration { unsigned operation,kind;uint64_t sp,flags,word;int upper; };
static struct configuration configuration(unsigned id) {
    need(id<CASES,30);
    struct configuration c={.operation=id<6 || id==16?LI2_FS_PUSHFQ:LI2_FS_POPFQ,
        .sp=stack_base+2U*PAGE+512,.flags=0x202,.word=0x202,.upper=3};
    switch(id) {
    case 0:c.flags=0xed7;break;
    case 1:break;
    case 2:c.flags|=AC;break;
    case 3:c.flags|=AC;c.sp++;c.kind=1;break;
    case 4:c.upper=PROT_READ;c.kind=2;break;
    case 5:c.sp=stack_base+2U*PAGE+4;c.upper=PROT_NONE;c.kind=2;break;
    case 6:c.word=0xad7;break;
    case 7:c.word=0x602;break;
    case 8:c.word=0x40202;break;
    case 9:c.word=0x302;c.kind=3;break;
    case 10:c.word=0x4202;c.kind=4;break;
    case 11:c.word=0x33202;break; /* RF/VM/IOPL attempted; CPU owns ignored bits. */
    case 12:c.flags|=AC;c.sp++;c.kind=1;break;
    case 13:c.upper=PROT_NONE;c.kind=2;break;
    case 14:c.sp=stack_base+2U*PAGE-4;c.upper=PROT_NONE;c.kind=2;break;
    case 15:c.flags|=AC;break; /* Real POP clears AC, unlike case8 setting it. */
    case 16:c.sp=UINT64_C(0x0100000000000008);c.kind=5;break;
    case 17:c.sp=UINT64_C(0x0100000000000000);c.kind=5;break;
    default:fail(31);
    }
    return c;
}
static void lane(unsigned id,unsigned which) {
    struct configuration c=configuration(id);
    memset(&record,0,sizeof record);protect_count=0;phase=0;
    protect(code_base,2U*PAGE,PROT_READ|PROT_WRITE);
    protect(image_base,PAGE,PROT_READ|PROT_WRITE);
    protect(stack_base,STACK_BYTES,PROT_READ|PROT_WRITE);
    unsigned char *code=(void *)code_base,*stack=(void *)stack_base;
    memset(code,0xcc,2U*PAGE);memset((void *)image_base,0xcc,PAGE);
    for(unsigned i=0;i<STACK_BYTES;i++)stack[i]=(unsigned char)(0x5aU+37U*i+id);
    if(c.operation==LI2_FS_POPFQ && c.sp>=stack_base && c.sp<=stack_base+STACK_BYTES-8)
        copy((void *)c.sp,&c.word,8);
    *(unsigned char *)original_pc=c.operation==LI2_FS_PUSHFQ?0x9c:0x9d;
    need(!li2_fs_describe(original_pc,(const void *)original_pc,15,&record.descriptor) &&
         !li2_fs_validate(&record.descriptor) &&
         !li2_fs_emit(&record.descriptor,(void *)image_base) &&
         !li2_fs_write(&record.descriptor,c.sp,&record.footprint),40);
    for(unsigned i=0;i<16;i++)probe_seed[i]=UINT64_C(0x13579bdf00110000)+UINT64_C(0x100010001)*i+id;
    probe_seed[4]=c.sp;probe_flags=c.flags;probe_pc=original_pc;
    record.h[0]=RECORD;record.h[1]=sizeof record;record.h[2]=id;record.h[3]=which;
    record.h[4]=c.operation;record.h[5]=c.kind;record.h[6]=original_pc;record.h[7]=original_pc+1;
    record.h[8]=image_base;record.h[9]=c.sp;record.h[10]=c.flags;record.h[11]=c.word;
    record.h[12]=(uint64_t)c.upper;record.h[24]=c.kind==5;
    copy(record.stack_before,stack,STACK_BYTES);copy(record.source,code,2U*PAGE);
    copy(record.image,(const void *)image_base,PAGE);
    protect(stack_base+2U*PAGE,PAGE,c.upper);
    protect(code_base,2U*PAGE,PROT_READ);protect(image_base,PAGE,PROT_READ);
    events=0;handler_busy=0;probe_enter();
    need(phase==2 && events==2 && !handler_busy,54);
    record.h[15]=(uint64_t)phase;record.h[16]=(uint64_t)events;
    protect(stack_base,STACK_BYTES,PROT_READ|PROT_WRITE);
    copy(record.stack_after,stack,STACK_BYTES);
    need(equal(code,record.source,2U*PAGE) && equal((const void *)image_base,record.image,PAGE),56);
    record.h[25]=protect_count;record.h[13]=1;
    need(write_all(1,&record,sizeof record),58);++records_written;
}
static uintptr_t fixed(uintptr_t first,size_t n) {
    void *p=mmap((void *)first,n,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    need(p==(void *)first,59);return first;
}
static unsigned controls(void) {
    unsigned completed=0;
    const unsigned offsets[16]={0,8,16,20,24,28,32,36,40,44,48,52,56,71,72,76};
    const uint64_t stacks[4]={0,7,8,UINT64_MAX};
    for(unsigned op=0;op<2;op++) {
        unsigned char source[15];memset(source,0xcc,sizeof source);source[0]=op?0x9d:0x9c;
        struct li2_fs_descriptor d;
        unsigned char image[16],want[16]={0,0xff,0x25,1,0,0,0,0xcc,1,0x10};
        want[0]=source[0];
        need(!li2_fs_describe(0x1000,source,15,&d) && !li2_fs_validate(&d) &&
             !li2_fs_emit(&d,image) && equal(image,want,sizeof image),80);++completed;
        struct li2_fs_descriptor short_d;
        need(!li2_fs_describe(0x1000,source,1,&short_d) && !li2_fs_validate(&short_d) &&
             short_d.decoded.available==1 && !short_d.decoded.bytes[1],81);++completed;
        for(unsigned i=0;i<4;i++) {
            struct li2_write_footprint f,w={.pc=0x1000,.next_pc=0x1001,.abi_version=1,
                .policy=op?LI2_WRITE_NONE:stacks[i]>=8?LI2_WRITE_RANGE:LI2_WRITE_UNSUPPORTED,
                .code=op?320:317,.length=1};
            if(!op && stacks[i]>=8){w.first=stacks[i]-8;w.end=stacks[i];}
            need(!li2_fs_write(&d,stacks[i],&f) && equal(&f,&w,sizeof f),82);++completed;
        }
        for(unsigned i=0;i<16;i++) {
            struct li2_fs_descriptor bad=d;
            ((unsigned char *)&bad)[offsets[i]]^=1;
            unsigned char untouched[16];memset(untouched,0xa5,sizeof untouched);copy(image,untouched,16);
            struct li2_write_footprint out,prior;memset(&prior,0xa5,sizeof prior);out=prior;
            need(li2_fs_validate(&bad)==LI2_FS_CORRUPT &&
                 li2_fs_emit(&bad,image)==LI2_FS_CORRUPT && equal(image,untouched,16) &&
                 li2_fs_write(&bad,0x2000,&out)==LI2_FS_CORRUPT && equal(&out,&prior,sizeof out),83);
            ++completed;
        }
    }
    const unsigned char refused[10][3]={{0x66,0x9c},{0x66,0x9d},{0x48,0x9c},{0x48,0x9d},
        {0xf0,0x9c},{0xf3,0x9d},{0xcf},{0x90},{0x50},{0x58}};
    struct li2_fs_descriptor d;
    for(unsigned i=0;i<10;i++) {
        need(li2_fs_describe(0x1000,refused[i],3,&d)==LI2_FS_FORM,84);++completed;
    }
    const unsigned char source[16]={0x9c};
    need(li2_fs_describe(0x1000,source,0,&d)==LI2_FS_ARGUMENT,85);++completed;
    need(li2_fs_describe(0x1000,source,16,&d)==LI2_FS_ARGUMENT,85);++completed;
    need(li2_fs_describe(UINTPTR_MAX,source,1,&d)==LI2_FS_ARGUMENT,85);++completed;
    need(li2_fs_describe(0x1000,0,1,&d)==LI2_FS_ARGUMENT,85);++completed;
    need(li2_fs_describe(0x1000,source,1,0)==LI2_FS_ARGUMENT,85);++completed;
    need(li2_fs_validate(0)==LI2_FS_ARGUMENT,85);++completed;
    need(completed==60,86);return completed;
}
extern size_t li2_tf_refusal_count(void);
extern int li2_tf_refusal_controls(size_t *,size_t *,uint32_t *,struct li2_tf_classification *);
int main(int argc,char **argv) {
    need(argc==2 && (argv[1][0]=='0' || argv[1][0]=='1') && !argv[1][1],60);
    unsigned placement=(unsigned)(argv[1][0]-'0');
    need(sysconf(_SC_PAGESIZE)==PAGE,61);
    cpu_set_t affinity;CPU_ZERO(&affinity);
    need(!sched_getaffinity(0,sizeof affinity,&affinity) && CPU_COUNT(&affinity)==1,62);
    int actual_cpu=sched_getcpu();need(actual_cpu>=0 && CPU_ISSET(actual_cpu,&affinity),63);cpu=(unsigned)actual_cpu;
    unsigned long cet=0;long cet_result=raw(SYS_arch_prctl,0x5005,(long)&cet,0,0,0,0);
    need((!cet_result && !cet)||cet_result==-22||cet_result==-38,64);
    unsigned a,b,c,d;need(__get_cpuid(1,&a,&b,&c,&d) && (c&(1U<<26)) && (c&(1U<<27)),65);
    uint32_t xlo,xhi;__asm__ volatile("xgetbv":"=a"(xlo),"=d"(xhi):"c"(0));
    uint64_t xcr0=((uint64_t)xhi<<32)|xlo;need((xcr0&3)==3,66);
    __cpuid_count(13,0,a,b,c,d);need(b>=512 && b<=FP_BYTES,67);
    code_base=fixed(placement?UINT64_C(0x200000000):UINT64_C(0x41000000),2U*PAGE);
    image_base=fixed(placement?UINT64_C(0x42000000):UINT64_C(0x300000000),PAGE);
    stack_base=fixed(UINT64_C(0x600000000),STACK_BYTES);
    uintptr_t alternate=(uintptr_t)mmap(0,ALT_BYTES+2U*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(alternate!=(uintptr_t)MAP_FAILED,68);alt_base=alternate+PAGE;
    need(!mprotect((void *)alt_base,ALT_BYTES,PROT_READ|PROT_WRITE),69);
    original_pc=code_base+PAGE-1;
    stack_t alt={.ss_sp=(void *)alt_base,.ss_size=ALT_BYTES};need(!sigaltstack(&alt,0),71);
    struct sigaction action;memset(&action,0,sizeof action);action.sa_sigaction=probe_handler_entry;
    action.sa_flags=SA_SIGINFO|SA_ONSTACK;sigfillset(&action.sa_mask);
    const int signals[4]={SIGSEGV,SIGBUS,SIGILL,SIGTRAP};
    for(unsigned i=0;i<4;i++)need(!sigaction(signals[i],&action,0),72);
    sigset_t empty;sigemptyset(&empty);need(!sigprocmask(SIG_SETMASK,&empty,0),73);
    struct li2_decoder_stats stats;need(!li2_decoder_initialize(arena,sizeof arena,&stats),77);
    size_t completed=0,failed_index=0;uint32_t result=0;struct li2_tf_classification last;
    need(li2_tf_refusal_count()==47 && !li2_tf_refusal_controls(&completed,&failed_index,&result,&last) &&
         completed==47 && failed_index==SIZE_MAX && !result,78);
    unsigned descriptor_controls=controls();
    header[0]=MAGIC;header[1]=1;header[2]=sizeof header;header[3]=sizeof record;
    header[4]=sizeof(struct frame);header[5]=sizeof(ucontext_t);header[6]=sizeof(siginfo_t);
    header[7]=FP_BYTES;header[8]=STACK_BYTES;header[9]=PAGE;header[10]=CASES;header[11]=placement;
    header[12]=0;header[13]=CASES;header[14]=2U*CASES;
    header[15]=(uint64_t)getpid();header[16]=cpu;header[17]=(uint64_t)cet_result;header[18]=cet;
    header[19]=xcr0;header[20]=b;header[21]=code_base;header[22]=stack_base;header[23]=image_base;
    header[24]=alt_base;header[25]=ALT_BYTES;header[26]=47;
    header[28]=(uintptr_t)probe_reload;header[29]=(uintptr_t)probe_scratch_end;
    header[30]=sizeof(struct li2_fs_descriptor);header[31]=sizeof(struct li2_write_footprint);
    header[32]=sizeof(struct transition);header[33]=16;header[34]=(uintptr_t)probe_handler_entry;
    header[35]=descriptor_controls;
    need(write_all(1,header,sizeof header),74);output_started=1;
    for(unsigned id=0;id<CASES;id++)for(unsigned which=0;which<2;which++)lane(id,which);
    need(records_written==2U*CASES,75);
    uint64_t end[8]={END,1,records_written,sizeof header+records_written*sizeof record+64,0,0,0,0};
    need(write_all(1,end,sizeof end),76);return 0;
}
