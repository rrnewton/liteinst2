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
#include "helper_tf.h"
#include "tf_owner.h"

#define PAGE 4096U
#define FP_BYTES 65536U
#define STACK_BYTES (4U*PAGE)
#define ALT_BYTES (256U*1024U)
#define CASES 44U
#define CHUNK_CASES 22U
#define DATA_BYTES (2U*PAGE)
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define DF UINT64_C(0x400)
#define AC UINT64_C(0x40000)
#define NT UINT64_C(0x4000)
#define MAGIC UINT64_C(0x314e544832494c)
#define RECORD UINT64_C(0x3152544832494c)
#define END UINT64_C(0x3145544832494c)
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
    struct li2_decoded descriptor;
    struct li2_tf_classification classification;
    struct li2_write_footprint footprint;
    struct transition protection[16];
    unsigned char stack_before[STACK_BYTES],stack_after[STACK_BYTES];
    unsigned char source[2U*PAGE],data_before[DATA_BYTES],data_after[DATA_BYTES];
};
_Static_assert(sizeof(ucontext_t)==968 && sizeof(siginfo_t)==128 && sizeof(sigset_t)==128,
               "exact Linux x86-64 observation ABI");
_Static_assert(NGREG==23 && sizeof(greg_t)==8 && sizeof(struct frame)==67072,
               "all original GREG and FP storage");
_Static_assert(sizeof(struct transition)==40 && sizeof(struct lane_record)==192984 &&
               512+2U*CHUNK_CASES*sizeof(struct lane_record)+64 < 16U*1024U*1024U,
               "one fixed full-state placement below original capture bound");
uint64_t probe_seed[16],probe_flags,probe_pc,probe_pending;
_Alignas(8) uint64_t probe_handler_flags;
extern void probe_enter(void),probe_return(void),probe_reload(void);
extern void probe_handler_entry(int,siginfo_t *,void *);
extern unsigned char probe_scratch_end[];
static const unsigned greg_index[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,
    REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static uintptr_t code_base,stack_base,alt_base,data_base,original_pc;
static uint64_t header[64];
static struct lane_record record;
static _Alignas(64) unsigned char arena[16U<<20];
static volatile sig_atomic_t phase,handler_busy,events;
static unsigned records_written,cpu,protect_count;
static int output_started;
static uint64_t diagnostic_case=UINT64_MAX,diagnostic_stage=UINT64_MAX;
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
    static const char message[]="helper-TF diagnostic incomplete; inspect retained raw record\n";
    (void)write_all(2,message,sizeof(message)-1);
    char detail[]="helper-TF failure code=0000000000000000 case=0000000000000000 stage=0000000000000000\n";
    const uint64_t values[3]={code,diagnostic_case,diagnostic_stage};
    const unsigned offsets[3]={23,45,68};
    static const char digits[]="0123456789abcdef";
    for(unsigned field=0;field<3;field++)for(unsigned i=0;i<16;i++)
        detail[offsets[field]+i]=digits[(values[field]>>(60-4*i))&15];
    (void)write_all(2,detail,sizeof(detail)-1);
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
/* An observation lane, not an RX/source permit or production signal owner.
   The reference executes with TF clear; the paired original-PC lane sets only
   TF in its actual initial NX frame. Both stop at the first genuine event. */
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
        phase=1;protect(code_base,PAGE,PROT_READ|PROT_EXEC);
        if(record.h[3])uc->uc_mcontext.gregs[REG_EFL]|=(greg_t)TF;
        copy(record.resumed_greg,uc->uc_mcontext.gregs,sizeof record.resumed_greg);
    } else if(phase==1) {
        capture(&record.after,sig,si,uc);record.h[27]=probe_handler_flags;
        need(sig==SIGTRAP || sig==SIGSEGV || sig==SIGBUS || sig==SIGILL || sig==SIGFPE,25);
        phase=2;protect(code_base,2U*PAGE,PROT_READ);
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_return;
        uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
        uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(TF|RF|DF|AC|NT);
    } else fail(26);
    handler_busy=0;
}
struct configuration { unsigned form,kind,pending;uint64_t sp,flags,operand;int data_upper,stack_upper; };
static struct configuration configuration(unsigned id) {
    need(id<CASES,30);
    struct configuration c={.form=id,.sp=stack_base+2U*PAGE+512,
        .flags=(id&1)?0x647:0xad7,.operand=data_base+128,.data_upper=3,.stack_upper=3};
    if(id>=29 && id<35) {
        static const unsigned forms[6]={7,8,9,10,11,12};
        c.form=forms[id-29];c.pending=1;c.kind=id>=32?2:0;
    }
    if(id>=35) {
        static const unsigned forms[9]={0,0,0,2,7,8,12,20,28};
        c.form=forms[id-35];c.kind=1;
        if(id==35){c.sp=stack_base+2U*PAGE+128;c.stack_upper=0;}
        else {
            c.operand=data_base+PAGE+64;c.data_upper=id==36?1:0;
            if(id==37 || id==42 || id==43)c.operand=data_base+PAGE-4;
            if(id==38 || id==41)c.operand=data_base+PAGE-1;
        }
    }
    return c;
}
static unsigned form_bytes(unsigned id,unsigned char b[15],uint32_t *code,unsigned *family,unsigned *width) {
    memset(b,0xcc,15);*width=0;*family=LI2_HELPER_TF_X87;
    if(id==0){b[0]=0x8f;b[1]=0x05;*code=298;*family=LI2_TF_STACK;*width=8;return 6;}
    if(id<=6){b[0]=0x8c;b[1]=(unsigned char)(5+8*(id-1));*code=288;*family=LI2_TF_INTEGER;*width=2;return 6;}
    if(id==7 || id==8){b[0]=id==7?0xd9:0xdd;b[1]=0x3d;*code=id==7?520:615;*width=2;return 6;}
    if(id==9){b[0]=0xdb;b[1]=0xe3;*code=582;return 2;}
    if(id==10 || id==11){b[0]=0xd9;b[1]=id==10?0xe8:0xeb;*code=id==10?530:533;return 2;}
    if(id==12){b[0]=0xd9;b[1]=0x2d;*code=515;return 6;}
    need(id<29,31);unsigned reg=(id-13)%8;
    b[0]=0xc4;b[1]=0xe1;b[2]=0xf8;b[3]=id<21?0x90:0x91;b[4]=(unsigned char)(5+8*reg);
    *code=id<21?1919:1923;*family=LI2_TF_SIMD;*width=id<21?0:8;return 9;
}
static void emit_displacement(unsigned char *b,unsigned length,uintptr_t operand,uintptr_t next) {
    if(length==2)return;
    int64_t delta=(int64_t)operand-(int64_t)next;
    need(delta>=INT32_MIN && delta<=INT32_MAX,32);
    int32_t d=(int32_t)delta;copy(b+(length==9?5:2),&d,4);
}
static void lane(unsigned id,unsigned which) {
    diagnostic_case=id;diagnostic_stage=0x100+which;
    struct configuration c=configuration(id);
    memset(&record,0,sizeof record);protect_count=0;phase=0;
    protect(code_base,2U*PAGE,PROT_READ|PROT_WRITE);
    protect(stack_base,STACK_BYTES,PROT_READ|PROT_WRITE);
    protect(data_base,DATA_BYTES,PROT_READ|PROT_WRITE);
    unsigned char *code=(void *)code_base,*stack=(void *)stack_base,*data=(void *)data_base;
    memset(code,0xcc,2U*PAGE);
    for(unsigned i=0;i<STACK_BYTES;i++)stack[i]=(unsigned char)(0x5aU+37U*i+id);
    for(unsigned i=0;i<DATA_BYTES;i++)data[i]=(unsigned char)(0x39U+23U*i+id);
    unsigned char bytes[15];uint32_t wanted_code;unsigned family,width;
    unsigned length=form_bytes(c.form,bytes,&wanted_code,&family,&width);
    original_pc=code_base+PAGE-length;emit_displacement(bytes,length,c.operand,original_pc+length);
    copy((void *)original_pc,bytes,length);
    if(c.form==12){uint16_t cw=0x0b7f;copy((void *)c.operand,&cw,2);}
    for(unsigned i=0;i<16;i++)probe_seed[i]=UINT64_C(0x13579bdf00110000)+UINT64_C(0x100010001)*i+id;
    probe_seed[4]=c.sp;probe_flags=c.flags;probe_pc=original_pc;probe_pending=c.pending;
    struct li2_write_registers regs={0};copy(regs.gpr,probe_seed,sizeof probe_seed);
    need(!li2_decoder_decode(original_pc,(const void *)original_pc,15,&record.descriptor) &&
         !li2_helper_tf_classify(&record.descriptor,&record.classification) &&
         !li2_helper_tf_entry(&record.descriptor) &&
         !li2_helper_tf_write(&record.descriptor,&regs,&record.footprint),40);
    struct li2_tf_classification expected={.pc=original_pc,.next_pc=original_pc+length,
        .abi_version=1,.policy=1,.code=wanted_code,.length=length,.flow=1,.family=family};
    struct li2_write_footprint wanted={.pc=original_pc,.next_pc=original_pc+length,
        .first=width?c.operand:0,.end=width?c.operand+width:0,.abi_version=1,
        .policy=width?LI2_WRITE_RANGE:LI2_WRITE_NONE,.code=wanted_code,.length=length};
    need(equal(&record.classification,&expected,sizeof expected) && equal(&record.footprint,&wanted,sizeof wanted),41);
    record.h[0]=RECORD;record.h[1]=sizeof record;record.h[2]=id;record.h[3]=which;
    record.h[4]=c.form;record.h[5]=c.kind;record.h[6]=original_pc;record.h[7]=original_pc+length;
    record.h[8]=c.operand;record.h[9]=c.sp;record.h[10]=c.flags;record.h[11]=c.pending;
    record.h[12]=(uint64_t)c.data_upper;record.h[17]=(uint64_t)c.stack_upper;
    record.h[18]=length;record.h[19]=wanted_code;record.h[20]=family;record.h[21]=width;
    copy(record.stack_before,stack,STACK_BYTES);copy(record.source,code,2U*PAGE);copy(record.data_before,data,DATA_BYTES);
    protect(stack_base+2U*PAGE,PAGE,c.stack_upper);
    protect(data_base+PAGE,PAGE,c.data_upper);
    protect(code_base,2U*PAGE,PROT_READ);
    events=0;handler_busy=0;probe_enter();
    need(phase==2 && events==2 && !handler_busy,54);
    record.h[15]=(uint64_t)phase;record.h[16]=(uint64_t)events;
    protect(stack_base,STACK_BYTES,PROT_READ|PROT_WRITE);
    protect(data_base,DATA_BYTES,PROT_READ|PROT_WRITE);
    copy(record.stack_after,stack,STACK_BYTES);copy(record.data_after,data,DATA_BYTES);
    need(equal(code,record.source,2U*PAGE),56);
    record.h[25]=protect_count;record.h[13]=1;
    need(write_all(1,&record,sizeof record),58);++records_written;
}
static uintptr_t fixed(uintptr_t first,size_t n) {
    void *p=mmap((void *)first,n,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    need(p==(void *)first,59);return first;
}
static unsigned controls(void) {
    unsigned completed=0;struct li2_write_registers regs={0};
    static const unsigned offsets[13]={0,8,16,20,24,28,32,36,40,44,48,52,71};
    for(unsigned id=0;id<29;id++) {
        diagnostic_case=id;diagnostic_stage=0;
        unsigned char bytes[15];uint32_t code;unsigned family,width;
        unsigned n=form_bytes(id,bytes,&code,&family,&width);emit_displacement(bytes,n,0x4000,0x2000+n);
        struct li2_decoded d;struct li2_tf_classification c;struct li2_write_footprint f;
        need(!li2_decoder_decode(0x2000,bytes,15,&d) && !li2_helper_tf_classify(&d,&c) &&
             !li2_helper_tf_entry(&d) && !li2_helper_tf_write(&d,&regs,&f) &&
             c.code==code && c.family==family && c.length==n && c.flow==1 && c.policy==1 &&
             f.policy==(width?2U:1U) && f.first==(width?0x4000U:0U) && f.end==(width?0x4000U+width:0U),80);++completed;
        for(unsigned j=0;j<13;j++) {
            diagnostic_stage=1+j;
            struct li2_decoded changed=d;((unsigned char *)&changed)[offsets[j]]^=1;
            need(li2_helper_tf_classify(&changed,&c)!=0 && !c.policy &&
                 li2_helper_tf_entry(&changed)!=0 && li2_helper_tf_write(&changed,&regs,&f)!=0 && !f.policy,81);++completed;
        }
        if(width)for(unsigned geometry=0;geometry<3;geometry++) {
            diagnostic_stage=32+geometry;
            uint64_t pc=geometry?UINT64_MAX-0x100:0x100;
            int32_t displacement=geometry==0?-0x200:geometry==1?0x100:(int32_t)(0x100-n-(width-2));
            copy(bytes+(n==9?5:2),&displacement,4);
            need(!li2_decoder_decode(pc,bytes,15,&d) && !li2_helper_tf_classify(&d,&c) &&
                 !li2_helper_tf_entry(&d) && !li2_helper_tf_write(&d,&regs,&f) &&
                 f.policy==LI2_WRITE_UNSUPPORTED && !f.first && !f.end,87);++completed;
        }
    }
    static const unsigned char forms[12][8]={{0x8f,0x07},{0x66,0x8f,0x05},{0x48,0x8c,0x05},{0x8c,0x35},
        {0x9b,0xd9,0x3d},{0x9b,0xdd,0x3d},{0x9b,0xdb,0xe3},{0xd9,0x28},{0xd9,0x38},
        {0xc5,0xf8,0x90,0x05},{0xc4,0xe1,0xf8,0x90,0x00},{0x9c}};
    for(unsigned i=0;i<12;i++) {
        diagnostic_case=i;diagnostic_stage=64;
        struct li2_decoded d={.pc=0x2000,.available=8};copy(d.bytes,forms[i],8);
        struct li2_tf_classification c;struct li2_write_footprint f;
        need(li2_helper_tf_classify(&d,&c)==LI2_HT_FORM && !c.policy &&
             li2_helper_tf_entry(&d)==LI2_HT_FORM && li2_helper_tf_write(&d,&regs,&f)==LI2_HT_FORM && !f.policy,82);++completed;
    }
    diagnostic_case=completed;diagnostic_stage=65;
    need(completed==469,83);diagnostic_case=diagnostic_stage=UINT64_MAX;return completed;
}
extern size_t li2_tf_refusal_count(void);
extern int li2_tf_refusal_controls(size_t *,size_t *,uint32_t *,struct li2_tf_classification *);
int main(int argc,char **argv) {
    need(argc==3 && (argv[1][0]=='0' || argv[1][0]=='1') && !argv[1][1] &&
         (argv[2][0]=='0' || argv[2][0]=='1') && !argv[2][1],60);
    unsigned placement=(unsigned)(argv[1][0]-'0'),chunk=(unsigned)(argv[2][0]-'0');
    need(sysconf(_SC_PAGESIZE)==PAGE,61);
    cpu_set_t affinity;CPU_ZERO(&affinity);
    need(!sched_getaffinity(0,sizeof affinity,&affinity) && CPU_COUNT(&affinity)==1,62);
    int actual_cpu=sched_getcpu();need(actual_cpu>=0 && CPU_ISSET(actual_cpu,&affinity),63);cpu=(unsigned)actual_cpu;
    unsigned long cet=0;long cet_result=raw(SYS_arch_prctl,0x5005,(long)&cet,0,0,0,0);
    need((!cet_result && !cet)||cet_result==-22||cet_result==-38,64);
    unsigned a,b,c,d;need(__get_cpuid(1,&a,&b,&c,&d) && (c&UINT32_C(0x0c000000))==UINT32_C(0x0c000000),65);
    unsigned leaf1=c;__cpuid_count(7,0,a,b,c,d);unsigned leaf7=b;
    need((leaf7&UINT32_C(0x40010000))==UINT32_C(0x40010000),66);
    uint32_t xlo,xhi;__asm__ volatile("xgetbv":"=a"(xlo),"=d"(xhi):"c"(0));
    uint64_t xcr0=((uint64_t)xhi<<32)|xlo;need((xcr0&0xe7)==0xe7,67);
    __cpuid_count(13,0,a,b,c,d);need(b>=576 && b<=FP_BYTES,68);unsigned xbytes=b;
    __cpuid_count(13,5,a,b,c,d);need(a==64 && b>=576 && b+64<=xbytes && !(c&1),69);
    unsigned mask_offset=b;
    code_base=fixed(placement?UINT64_C(0x200000000):UINT64_C(0x41000000),2U*PAGE);
    data_base=fixed(placement?code_base-4U*PAGE:code_base+4U*PAGE,DATA_BYTES);
    stack_base=fixed(UINT64_C(0x600000000),STACK_BYTES);
    uintptr_t alternate=(uintptr_t)mmap(0,ALT_BYTES+2U*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(alternate!=(uintptr_t)MAP_FAILED,70);alt_base=alternate+PAGE;
    need(!mprotect((void *)alt_base,ALT_BYTES,PROT_READ|PROT_WRITE),71);
    stack_t alt={.ss_sp=(void *)alt_base,.ss_size=ALT_BYTES};need(!sigaltstack(&alt,0),72);
    struct sigaction action;memset(&action,0,sizeof action);action.sa_sigaction=probe_handler_entry;
    action.sa_flags=SA_SIGINFO|SA_ONSTACK;sigfillset(&action.sa_mask);
    const int signals[5]={SIGSEGV,SIGBUS,SIGILL,SIGTRAP,SIGFPE};
    sigset_t mask;sigfillset(&mask);
    for(unsigned i=0;i<5;i++){need(!sigaction(signals[i],&action,0),73);sigdelset(&mask,signals[i]);}
    need(!sigprocmask(SIG_SETMASK,&mask,0),74);
    uint64_t actual_mask=0;need(!raw(SYS_rt_sigprocmask,0,0,(long)&actual_mask,8,0,0),75);
    struct li2_decoder_stats stats;need(!li2_decoder_initialize(arena,sizeof arena,&stats),77);
    size_t completed=0,failed_index=0;uint32_t result=0;struct li2_tf_classification last;
    need(li2_tf_refusal_count()==47 && !li2_tf_refusal_controls(&completed,&failed_index,&result,&last) &&
         completed==47 && failed_index==SIZE_MAX && !result,78);
    unsigned descriptor_controls=controls();
    header[0]=MAGIC;header[1]=1;header[2]=sizeof header;header[3]=sizeof record;
    header[4]=sizeof(struct frame);header[5]=sizeof(ucontext_t);header[6]=sizeof(siginfo_t);
    header[7]=FP_BYTES;header[8]=STACK_BYTES;header[9]=PAGE;header[10]=CASES;header[11]=placement;
    header[12]=chunk*CHUNK_CASES;header[13]=CHUNK_CASES;header[14]=2U*CHUNK_CASES;
    header[15]=(uint64_t)getpid();header[16]=cpu;header[17]=(uint64_t)cet_result;header[18]=cet;
    header[19]=xcr0;header[20]=xbytes;header[21]=code_base;header[22]=stack_base;header[23]=data_base;
    header[24]=alt_base;header[25]=ALT_BYTES;header[26]=47;header[27]=descriptor_controls;
    header[28]=(uintptr_t)probe_reload;header[29]=(uintptr_t)probe_scratch_end;
    header[30]=sizeof(struct li2_decoded);header[31]=sizeof(struct li2_write_footprint);
    header[32]=sizeof(struct transition);header[33]=16;header[34]=(uintptr_t)probe_handler_entry;
    header[35]=sizeof(struct li2_tf_classification);header[36]=actual_mask;
    header[37]=leaf1;header[38]=leaf7;header[39]=mask_offset;
    uint16_t selectors[6];
    __asm__ volatile("mov %%es,%0;mov %%cs,%1;mov %%ss,%2;mov %%ds,%3;mov %%fs,%4;mov %%gs,%5":
        "=m"(selectors[0]),"=m"(selectors[1]),"=m"(selectors[2]),"=m"(selectors[3]),"=m"(selectors[4]),"=m"(selectors[5]));
    for(unsigned i=0;i<6;i++)header[40+i]=selectors[i];
    need(write_all(1,header,sizeof header),76);output_started=1;
    for(unsigned id=chunk*CHUNK_CASES;id<(chunk+1)*CHUNK_CASES;id++)for(unsigned which=0;which<2;which++)lane(id,which);
    need(records_written==2U*CHUNK_CASES,79);
    uint64_t end[8]={END,1,records_written,sizeof header+records_written*sizeof record+64,0,0,0,0};
    need(write_all(1,end,sizeof end),84);return 0;
}
