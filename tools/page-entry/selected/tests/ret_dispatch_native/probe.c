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
#include "linked_ret_dispatch.h"
#include "linked_jmp_domain.h"


#define PAGE 4096U
#define FP_BYTES 65536U
#define STACK_BYTES (4U*PAGE)
#define ALT_BYTES (256U*1024U)
#define CASES 16U
#define LANES 24U
#define TRACES 64U
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define DF UINT64_C(0x400)
#define MAGIC UINT64_C(0x314e524432494c)
#define RECORD UINT64_C(0x3152524432494c)
#define END UINT64_C(0x3145524432494c)

/* Complete actual frames are retained. Typed recovery is a second value and
   never overwrites the raw frame. No owner-admission authority is claimed. */
struct frame {
    uint64_t h[16];
    int64_t greg[23];
    unsigned char mask[128],info[128],context[968],fp[FP_BYTES];
};
struct trace {
    uint64_t pc,flags,gpr[16],spill[6];
    struct li2_rd_recovered recovered;
};
struct transition { uint64_t address,bytes,permissions,phase;int64_t result; };
struct lane_record {
    uint64_t h[64];
    int64_t bootstrap_greg[23];
    struct frame before,after,mutation_frame;
    struct li2_rd_recovered recovered;
    struct li2_rd_plan plan;
    struct trace trace[TRACES];
    struct transition protection[32];
    uint64_t mutation[4];
    unsigned char stack_before[STACK_BYTES],stack_after[STACK_BYTES];
    unsigned char source[PAGE],image[2U*LI2_JD_IMAGE_BYTES],rows[PAGE];
    unsigned char directory[LI2_JD_DOMAIN_BYTES],window[PAGE],target[2U*PAGE];
    unsigned char spill_before[PAGE],spill_after[PAGE];
};
_Static_assert(sizeof(ucontext_t)==968 && sizeof(siginfo_t)==128 && sizeof(sigset_t)==128,
               "exact Linux x86-64 observation ABI");
_Static_assert(NGREG==23 && sizeof(greg_t)==8 && sizeof(struct frame)==67072,
               "all original GREG and FP storage");
_Static_assert(sizeof(struct trace)==368 && sizeof(struct transition)==40 &&
               sizeof(struct lane_record)==368544 &&
               512+LANES*sizeof(struct lane_record)+64 < 16U*1024U*1024U,
               "fixed complete chunks under the original strict capture bound");

uint64_t probe_seed[16],probe_flags,probe_pc;
extern void probe_enter(void),probe_return(void),probe_reload(void);
extern unsigned char probe_scratch_end[];
static const unsigned greg_index[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,
    REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static uintptr_t code_base,stack_base,target_base,alt_base,image_base[2],rows_base;
static uintptr_t directory_base,window_base,spill_base,original_pc;
static uint64_t header[64];
static struct lane_record record;
static _Alignas(64) unsigned char arena[16U<<20];
static volatile sig_atomic_t phase,handler_busy,events;
static unsigned records_written,cpu,trace_count,protect_count;
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
    static const char message[]="ret-emitter diagnostic incomplete; inspect retained raw record\n";
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
    need(protect_count<32,27);
    struct transition *t=&record.protection[protect_count++];
    t->address=address;t->bytes=bytes;t->permissions=(uint64_t)permissions;t->phase=(uint64_t)phase;
    t->result=raw(SYS_mprotect,(long)address,(long)bytes,permissions,0,0,0);
    need(!t->result,28);
}
static void recovered(uintptr_t pc,const ucontext_t *uc,struct li2_rd_recovered *out) {
    uint64_t registers[16],spills[6];
    for(unsigned i=0;i<16;i++)registers[i]=(uint64_t)uc->uc_mcontext.gregs[greg_index[i]];
    copy(spills,(const void *)spill_base,sizeof spills);
    int result=pc==record.plan.binding.loaded_miss?
        li2_rd_recover_loaded_miss(&record.plan,pc,registers,(uint64_t)uc->uc_mcontext.gregs[REG_EFL],spills,out):
        li2_rd_recover(&record.plan,pc,registers,(uint64_t)uc->uc_mcontext.gregs[REG_EFL],spills,out);
    need(!result && out->complete==1,29);
}
static void handler(int sig,siginfo_t *si,void *context) {
    ucontext_t *uc=context;
    if(handler_busy)fail(20);
    handler_busy=1;++events;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(phase==0) {
        capture(&record.before,sig,si,uc);
        need(sig==SIGSEGV && si->si_code==SEGV_ACCERR &&
             (uintptr_t)si->si_addr==probe_pc && pc==probe_pc &&
             uc->uc_mcontext.gregs[REG_TRAPNO]==14 &&
             ((uint64_t)uc->uc_mcontext.gregs[REG_ERR]&16)==16,21);
        for(unsigned i=0;i<16;i++)need((uint64_t)uc->uc_mcontext.gregs[greg_index[i]]==probe_seed[i],22);
        need(((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&~RF)==probe_flags,23);
        phase=1;
        if(record.h[3])protect(image_base[0],LI2_JD_IMAGE_BYTES,PROT_READ|PROT_EXEC);
        else if(record.h[24]!=2)protect(code_base,PAGE,PROT_READ|PROT_EXEC);
        if(record.h[24]==4) {
            /* Valid stack only: TF starts at the real first instruction through
               the actual signal-return frame, never inside reload assembly. */
            uc->uc_mcontext.gregs[REG_EFL]=(greg_t)(probe_flags|TF);
        } else {
            /* Retain the original invalid-RSP-safe bootstrap unchanged. */
            uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_reload;
            uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
            uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(RF|TF);
        }
        copy(record.bootstrap_greg,uc->uc_mcontext.gregs,sizeof record.bootstrap_greg);
    } else if(phase==1) {
        if(record.h[24]==4 && record.h[3]) {
            need(sig==SIGTRAP && si->si_code==TRAP_TRACE && (uintptr_t)si->si_addr==pc,80);
            if(pc!=record.h[18]) {
                need(trace_count<TRACES,81);
                struct trace *t=&record.trace[trace_count++];
                t->pc=pc;t->flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
                for(unsigned i=0;i<16;i++)t->gpr[i]=(uint64_t)uc->uc_mcontext.gregs[greg_index[i]];
                copy(t->spill,(const void *)spill_base,sizeof t->spill);
                recovered(pc,uc,&t->recovered);
                if(pc==record.h[34]) {
                    need(!record.mutation[0] && t->recovered.target_valid==1 &&
                         t->recovered.target==record.h[9] && t->recovered.original_rsp==record.h[10],82);
                    capture(&record.mutation_frame,sig,si,uc);
                    uint64_t old=0;copy(&old,(const void *)record.h[10],8);
                    need(old==record.h[9],83);
                    record.mutation[0]=pc;record.mutation[1]=old;record.mutation[2]=record.h[35];
                    copy((void *)record.h[10],&record.mutation[2],8);record.mutation[3]=1;
                }
                if(pc==record.plan.generated+record.plan.record.transfer_offset)
                    copy(&record.recovered,&t->recovered,sizeof record.recovered);
                handler_busy=0;return;
            }
            need(record.mutation[3]==1 && record.recovered.phase==LI2_RD_COMMITTED,84);
        } else if(record.h[24]==3 && record.h[3]) {
            need(pc==record.plan.generated+record.plan.record.load_offset,85);
            recovered(pc,uc,&record.recovered);
        } else if(record.h[24]==1 && record.h[3]) {
            need(sig==SIGSEGV && si->si_code==SEGV_ACCERR && pc==record.plan.binding.loaded_miss &&
                 (uintptr_t)si->si_addr==pc && uc->uc_mcontext.gregs[REG_TRAPNO]==14 &&
                 ((uint64_t)uc->uc_mcontext.gregs[REG_ERR]&16)==16,86);
            recovered(pc,uc,&record.recovered);
        }
        capture(&record.after,sig,si,uc);
        need(sig==SIGTRAP || sig==SIGSEGV || sig==SIGBUS || sig==SIGILL,25);
        phase=2;
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_return;
        uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
        uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(TF|RF|DF|UINT64_C(0x40000));
    } else fail(26);
    handler_busy=0;
}
struct configuration {
    unsigned group,item,kind,row;
    int permissions[4];
    uint64_t sp,target,flags,first,end;
};
static uint64_t flags(unsigned value) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t r=UINT64_C(0x202);
    for(unsigned i=0;i<6;i++)if(value&(1U<<i))r|=UINT64_C(1)<<bits[i];
    return r;
}
static struct configuration configuration(unsigned id) {
    need(id<CASES,30);
    struct configuration c={.permissions={PROT_NONE,PROT_READ|PROT_WRITE,
        PROT_READ|PROT_WRITE,PROT_NONE},.sp=stack_base+2U*PAGE+512,
        .target=target_base+64,.flags=flags(7U*id)|(id&1U?DF:0),.row=id%3U};
    c.first=stack_base+2U*PAGE+256;c.end=c.first+512;
    if(id<6) {c.group=0;c.item=id;c.sp=c.first+(id/2U)*256U;}
    else if(id<10) {
        c.group=1;c.item=id-6;c.kind=1;
        if(c.item==0)c.target=target_base+192;
        else if(c.item==1)c.target=target_base+PAGE+64;
        else c.target=c.item==2?UINT64_C(0x0100000000000000):UINT64_C(0x8000000000000000);
    } else if(id<12) {
        c.group=2;c.item=id-10;c.kind=2;c.sp=c.item?c.end+1:c.first-1;
    } else if(id<14) {
        c.group=3;c.item=id-12;c.kind=3;c.permissions[2]=PROT_NONE;
        if(c.item) {c.sp=stack_base+2U*PAGE-4;c.first=c.sp-256;c.end=c.first+512;}
    } else {c.group=4;c.item=id-14;c.kind=4;}
    return c;
}
static void lane(unsigned id,unsigned which) {
    struct configuration c=configuration(id);
    memset(&record,0,sizeof record);protect_count=trace_count=0;phase=0;
    protect(code_base,PAGE,PROT_READ|PROT_WRITE);
    for(unsigned i=0;i<2;i++)protect(image_base[i],LI2_JD_IMAGE_BYTES,PROT_READ|PROT_WRITE);
    protect(rows_base,PAGE,PROT_READ|PROT_WRITE);
    protect(directory_base,LI2_JD_DOMAIN_BYTES,PROT_READ|PROT_WRITE);
    protect(window_base,PAGE,PROT_READ|PROT_WRITE);
    protect(spill_base,PAGE,PROT_READ|PROT_WRITE);
    protect(target_base,2U*PAGE,PROT_READ|PROT_WRITE);
    protect(stack_base,STACK_BYTES,PROT_READ|PROT_WRITE);
    unsigned char *code=(void *)code_base,*stack=(void *)stack_base;
    memset(code,0xcc,PAGE);memset((void *)target_base,0xcc,2U*PAGE);
    for(unsigned i=0;i<2;i++)memset((void *)image_base[i],0xcc,LI2_JD_IMAGE_BYTES);
    memset((void *)rows_base,0,PAGE);memset((void *)directory_base,0,LI2_JD_DOMAIN_BYTES);
    memset((void *)window_base,0,PAGE);
    for(unsigned i=0;i<PAGE;i++)((unsigned char *)spill_base)[i]=(unsigned char)(0xa7U+19U*i+id);
    for(unsigned i=0;i<STACK_BYTES;i++)stack[i]=(unsigned char)(0x5aU+37U*i+id);
    copy(stack+(c.sp-stack_base),&c.target,8);
    unsigned n=1;unsigned char *instruction=(void *)original_pc;instruction[0]=0xc3;
    uintptr_t cached=image_base[id&1U]+512;
    struct li2_jd_domain_directory *directory=(void *)directory_base;
    directory->version=1;directory->count=3;directory->serial=73;
    for(unsigned i=0;i<3;i++)directory->row[i]=(struct li2_jd_domain_row){
        .pc=target_base+64U+32U*i,.generated=cached,.generation=91U+i,.slot=id&1U,.head=1};
    if(c.kind!=1)directory->row[c.row].pc=c.target;
    /* All directory keys remain distinct in the positive cases. */
    if(c.kind!=1 && c.row)directory->row[0].pc=target_base+64U+32U*c.row;
    struct li2_rd_window *window=(void *)window_base;
    *window=(struct li2_rd_window){.version=1,.owner=rows_base,.serial=73,.first=c.first,.end=c.end};
    struct li2_rd_binding binding={.rows=rows_base,.image={image_base[0],image_base[1]},
        .heads=1,.head=0,.directory=directory_base,.window=window_base,.loaded_miss=window_base+128};
    need(!li2_rd_emit(original_pc,instruction,15,image_base[0],spill_base,&binding,&record.plan) &&
         !li2_rd_validate(&record.plan),40);
    need(record.plan.record.image_bytes==285 && record.plan.record.boundaries==53 &&
         record.plan.record.load_offset==68 && record.plan.record.save_offset==72 &&
         record.plan.record.commit_offset==274 && record.plan.record.transfer_offset==279 &&
         record.plan.record.miss_offset==227 && record.plan.record.loaded_miss_offset==190,41);
    copy((void *)image_base[0],record.plan.image,512);
    need(equal((const void *)image_base[0],record.plan.image,512),42);
    for(unsigned i=0;i<16;i++)probe_seed[i]=UINT64_C(0x13579bdf00110000)+UINT64_C(0x100010001)*i+id;
    probe_seed[4]=c.sp;probe_flags=c.flags;probe_pc=which?image_base[0]:original_pc;
    record.h[0]=RECORD;record.h[1]=sizeof record;record.h[2]=id;record.h[3]=which;
    record.h[4]=4;record.h[5]=c.group;record.h[6]=c.item;record.h[7]=original_pc;
    record.h[8]=original_pc+n;record.h[9]=c.target;record.h[10]=c.sp;record.h[11]=c.flags;
    record.h[12]=n;record.h[17]=probe_pc;record.h[18]=cached;
    for(unsigned i=0;i<4;i++)record.h[20+i]=(uint64_t)c.permissions[i];
    record.h[24]=c.kind;record.h[25]=c.item;record.h[26]=c.first;record.h[27]=c.end;
    record.h[28]=3;record.h[29]=c.row;record.h[30]=1;
    record.h[33]=binding.loaded_miss;record.h[34]=c.kind==4?image_base[0]+(c.item?79U:72U):0;
    record.h[35]=c.kind==4?target_base+192:0;
    copy(record.stack_before,stack,STACK_BYTES);copy(record.source,code,PAGE);
    for(unsigned i=0;i<2;i++)copy(record.image+i*LI2_JD_IMAGE_BYTES,(const void *)image_base[i],LI2_JD_IMAGE_BYTES);
    copy(record.rows,(const void *)rows_base,PAGE);copy(record.directory,(const void *)directory_base,LI2_JD_DOMAIN_BYTES);
    copy(record.window,(const void *)window_base,PAGE);copy(record.target,(const void *)target_base,2U*PAGE);
    copy(record.spill_before,(const void *)spill_base,PAGE);
    for(unsigned i=0;i<4;i++)protect(stack_base+i*PAGE,PAGE,c.permissions[i]);
    protect(code_base,PAGE,PROT_READ);
    protect(image_base[0],LI2_JD_IMAGE_BYTES,PROT_READ);
    protect(image_base[1],LI2_JD_IMAGE_BYTES,PROT_READ|PROT_EXEC);
    protect(rows_base,PAGE,PROT_READ);protect(directory_base,LI2_JD_DOMAIN_BYTES,PROT_READ);
    protect(window_base,PAGE,PROT_READ);protect(target_base,PAGE,PROT_READ|PROT_EXEC);
    protect(target_base+PAGE,PAGE,PROT_READ);
    events=0;handler_busy=0;probe_enter();
    need(phase==2 && (unsigned)events==(c.kind==4 && which?2U+trace_count:2U) && !handler_busy,54);
    record.h[15]=(uint64_t)phase;record.h[16]=(uint64_t)events;record.h[19]=trace_count;
    record.h[31]=record.recovered.complete;
    /* Only now reopen the stack for the complete fault/partial-store snapshot. */
    protect(stack_base,STACK_BYTES,PROT_READ|PROT_WRITE);
    protect(code_base,PAGE,PROT_READ);
    for(unsigned i=0;i<2;i++)protect(image_base[i],LI2_JD_IMAGE_BYTES,PROT_READ);
    copy(record.stack_after,stack,STACK_BYTES);copy(record.spill_after,(const void *)spill_base,PAGE);
    need(equal(code,record.source,PAGE) && equal((const void *)rows_base,record.rows,PAGE) &&
         equal((const void *)directory_base,record.directory,LI2_JD_DOMAIN_BYTES) &&
         equal((const void *)window_base,record.window,PAGE) && equal((const void *)target_base,record.target,2U*PAGE),56);
    for(unsigned i=0;i<2;i++)need(equal((const void *)image_base[i],record.image+i*LI2_JD_IMAGE_BYTES,LI2_JD_IMAGE_BYTES),57);
    record.h[32]=protect_count;record.h[13]=1;
    need(write_all(1,&record,sizeof record),58);++records_written;
}
static uintptr_t allocation(size_t n,int low) {
    void *p=mmap(0,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|(low?MAP_32BIT:0),-1,0);
    need(p!=MAP_FAILED && !((uintptr_t)p&(PAGE-1U)),59);return(uintptr_t)p;
}
int main(int argc,char **argv) {
    need((argc==1 || (argc==2 && !strcmp(argv[1],"--high"))) && argv[0],60);
    unsigned high=argc==2;
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
    if(high) {
        /* One actual high allocation keeps every remaining RIP-relative edge
           local. The independently allocated low window is deliberately far. */
        code_base=allocation(24U*PAGE,0);stack_base=allocation(STACK_BYTES,0);
        target_base=code_base+PAGE;image_base[0]=code_base+3U*PAGE;
        image_base[1]=code_base+11U*PAGE;rows_base=code_base+19U*PAGE;
        directory_base=code_base+20U*PAGE;spill_base=code_base+23U*PAGE;
        window_base=allocation(PAGE,1);
        need(window_base+PAGE<=UINT64_C(0x80000000) &&
             code_base>window_base+PAGE+UINT64_C(0x7fffffff) &&
             code_base<UINT64_C(0x800000000000)-24U*PAGE,78);
    } else {
        code_base=allocation(PAGE,1);stack_base=allocation(STACK_BYTES,0);target_base=allocation(2U*PAGE,1);
        for(unsigned i=0;i<2;i++)image_base[i]=allocation(LI2_JD_IMAGE_BYTES,1);
        rows_base=allocation(PAGE,1);directory_base=allocation(LI2_JD_DOMAIN_BYTES,1);
        window_base=allocation(PAGE,1);spill_base=allocation(PAGE,1);
    }
    uintptr_t alternate=(uintptr_t)mmap(0,ALT_BYTES+2U*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(alternate!=(uintptr_t)MAP_FAILED,68);alt_base=alternate+PAGE;
    need(!mprotect((void *)alt_base,ALT_BYTES,PROT_READ|PROT_WRITE),69);
    original_pc=code_base+0x100;
    stack_t alt={.ss_sp=(void *)alt_base,.ss_size=ALT_BYTES};need(!sigaltstack(&alt,0),71);
    struct sigaction action;memset(&action,0,sizeof action);action.sa_sigaction=handler;
    action.sa_flags=SA_SIGINFO|SA_ONSTACK;sigfillset(&action.sa_mask);
    const int signals[4]={SIGSEGV,SIGBUS,SIGILL,SIGTRAP};
    for(unsigned i=0;i<4;i++)need(!sigaction(signals[i],&action,0),72);
    sigset_t empty;sigemptyset(&empty);need(!sigprocmask(SIG_SETMASK,&empty,0),73);
    struct li2_decoder_stats stats;need(!li2_decoder_initialize(arena,sizeof arena,&stats),77);
    header[0]=MAGIC;header[1]=1;header[2]=sizeof header;header[3]=sizeof record;
    header[4]=sizeof(struct frame);header[5]=sizeof(ucontext_t);header[6]=sizeof(siginfo_t);
    header[7]=FP_BYTES;header[8]=STACK_BYTES;header[9]=PAGE;header[10]=CASES;header[11]=0;
    header[12]=0;header[13]=CASES;header[14]=LANES;
    header[15]=(uint64_t)getpid();header[16]=cpu;header[17]=(uint64_t)cet_result;header[18]=cet;
    header[19]=xcr0;header[20]=b;header[21]=code_base;header[22]=stack_base;header[23]=target_base;
    header[24]=alt_base;header[25]=ALT_BYTES;header[27]=LANES;
    header[28]=(uintptr_t)probe_reload;header[29]=(uintptr_t)probe_scratch_end;
    header[30]=image_base[0];header[31]=image_base[1];header[32]=rows_base;
    header[33]=directory_base;header[34]=window_base;header[35]=spill_base;
    header[36]=sizeof(struct li2_rd_plan);header[37]=sizeof(struct li2_rd_recovered);
    header[38]=sizeof(struct trace);header[39]=TRACES;header[40]=sizeof(struct transition);header[41]=32;
    need(write_all(1,header,sizeof header),74);output_started=1;
    for(unsigned id=0;id<CASES;id++) {
        if(id<6 || (id>=12 && id<14))lane(id,0);
        lane(id,1);
    }
    need(records_written==LANES,75);
    uint64_t end[8]={END,1,records_written,sizeof header+records_written*sizeof record+64,0,0,0,0};
    need(write_all(1,end,sizeof end),76);return 0;
}
