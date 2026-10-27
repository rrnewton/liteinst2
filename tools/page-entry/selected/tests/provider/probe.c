#define _GNU_SOURCE
#include "fixture.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>

#define PAGE 4096
#define RF UINT64_C(0x10000)
#define TF UINT64_C(0x100)
#define SA_RESTORER_RAW UINT64_C(0x04000000)
#define ALT_BYTES (256*1024)
static unsigned char arena[16*1024*1024] __attribute__((aligned(64)));
static unsigned char kernel_before[FP_BYTES],kernel_after[FP_BYTES];
static unsigned char uc_before[UC_BYTES],uc_after[UC_BYTES];
static unsigned char stack_before[STACK_BYTES],stack_after[STACK_BYTES];
static unsigned char original_source[16],request_source[16],image_before[2*PAGE];
static ucontext_t original_uc;
static uint64_t header[64];
static struct li2_decoded decoded;
static struct li2_selected_hardware hardware,request_hardware;
static struct li2_selected_completion completion;
static struct li2_selected_script script;
static struct li2_decoder_stats init_stats,final_stats;
static unsigned char *program,*subject,*alt_mapping;
static size_t instruction_bytes;
static unsigned kind,width,reg,mechanism,control,layout,prefix;
static int record_fd;
static volatile sig_atomic_t in_handler,fault_count,returned;
struct kernel_action { void (*handler)(int,siginfo_t *,void *); uint64_t flags; void (*restorer)(void); uint64_t mask; };
static struct kernel_action previous_segv,previous_ill;
static stack_t previous_stack;
static uint64_t previous_mask,application_mask;
extern void fixture_restorer(void);
#ifdef NESTED_VARIANT
extern unsigned char __li2_native_random_page[],__li2_native_random_code_end[],__li2_native_random_page_end[];
#endif
long fixture_raw(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;
    long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define RAW(n,a,b,c,d,e,f) fixture_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
void fixture_copy(void *d,const void *s,size_t n) { unsigned char *o=d;const unsigned char *i=s;for(size_t k=0;k<n;k++)o[k]=i[k]; }
int fixture_equal(const void *a,const void *b,size_t n) { const unsigned char *x=a,*y=b;for(size_t k=0;k<n;k++)if(x[k]!=y[k])return 0;return 1; }
static void write_all(const void *data,size_t n) {
    const unsigned char *p=data;while(n){long k=RAW(SYS_write,record_fd,p,n,0,0,0);if(k<=0 || (size_t)k>n){RAW(SYS_exit_group,124,0,0,0,0,0);__builtin_trap();}p+=k;n-=(size_t)k;}
}
_Noreturn void fixture_die(unsigned code,unsigned detail) {
    uint64_t failure[8]={RECORD_MAGIC,0,code,detail,(uint64_t)completion.phase,(uint64_t)completion.native_attempts,(uint64_t)returned,(uint64_t)fault_count};
    write_all(failure,sizeof failure);RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void require(int yes,unsigned code,unsigned detail){if(!yes)fixture_die(code,detail);}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static size_t fp_capture(const ucontext_t *uc,unsigned char *out) {
    uintptr_t p=(uintptr_t)uc->uc_mcontext.fpregs,lo=(uintptr_t)alt_mapping+PAGE,hi=lo+ALT_BYTES;
    require(p>=lo && p<=hi-512 && !(p&15),10,1);
    const unsigned char *b=(const void *)p;size_t n=512;
    if(u32(b+464)==UINT32_C(0x46505853)) {
        n=u32(b+468);size_t x=u32(b+480);
        require(n>=580 && n<=FP_BYTES && n<=hi-p && x>=576 && x<=n-4,10,2);
        require(u32(b+n-4)==UINT32_C(0x46505845),10,3);
    }
    fixture_copy(out,b,n);return n;
}
static void nested(int sig,siginfo_t *si,ucontext_t *uc) {
#ifdef NESTED_VARIANT
    require(control==38 && sig==SIGSEGV && si->si_code==SEGV_ACCERR &&
            uc->uc_mcontext.gregs[REG_TRAPNO]==14 && uc->uc_mcontext.gregs[REG_ERR]==21 &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]>=(uintptr_t)__li2_native_random_page &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]<(uintptr_t)__li2_native_random_code_end &&
            (uintptr_t)si->si_addr==(uintptr_t)uc->uc_mcontext.gregs[REG_RIP] &&
            completion.phase==LI2_SELECTED_NATIVE_ENTERED && completion.native_attempts==1 && !returned &&
            !completion.value && !completion.carry,11,1);
    /* The outer header already retains its FP prefix; nested format is separate. */
    uint64_t nested_header[64]={0};
    nested_header[0]=RECORD_MAGIC;nested_header[1]=2;nested_header[2]=sig;nested_header[3]=si->si_code;
    nested_header[4]=completion.phase;nested_header[5]=completion.native_attempts;nested_header[6]=returned;nested_header[7]=fault_count;
    nested_header[8]=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];nested_header[9]=(uintptr_t)__li2_native_random_page;
    nested_header[10]=(uintptr_t)__li2_native_random_code_end;nested_header[11]=(uintptr_t)__li2_native_random_page_end;
    nested_header[12]=uc->uc_mcontext.gregs[REG_TRAPNO];nested_header[13]=uc->uc_mcontext.gregs[REG_ERR];
    write_all(nested_header,sizeof nested_header);RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
#else
    (void)sig;(void)si;(void)uc;fixture_die(11,2);
#endif
}
static void handler(int sig,siginfo_t *si,void *opaque) {
    ucontext_t *uc=opaque;
    if(in_handler)nested(sig,si,uc);
    in_handler=1;++fault_count;
    require(fault_count==1 && sig==SIGSEGV && si && uc && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR &&
            !si->si_errno && uc->uc_mcontext.gregs[REG_RIP]==(greg_t)fixture_target &&
            uc->uc_mcontext.gregs[REG_TRAPNO]==14 && uc->uc_mcontext.gregs[REG_ERR]==21 &&
            (uintptr_t)si->si_addr>=fixture_target && (uintptr_t)si->si_addr<fixture_target+instruction_bytes &&
            (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(fixture_pre[16]|RF),12,1);
    require(fixture_equal(program,image_before,2*PAGE),12,2);
    uint64_t actual_mask=0;fixture_copy(&actual_mask,&uc->uc_sigmask,8);require(actual_mask==application_mask,12,3);
    fixture_copy(&original_uc,uc,sizeof *uc);
    struct li2_selected_request request={&decoded,request_source,instruction_bytes,fixture_pre[16],LI2_SELECTED_NX_KNOWN_INPUT,si};
    siginfo_t supplied=*si;
    if(control>=4 && control<=11)request.fault=&supplied;
    switch(control) {
    case 1:request.logical_flags|=TF;break;case 2:request.logical_flags|=RF;break;
    case 3:request.logical_flags^=1;break;case 4:supplied.si_signo=SIGILL;break;
    case 5:supplied.si_code=SEGV_MAPERR;break;case 6:uc->uc_mcontext.gregs[REG_TRAPNO]=13;break;
    case 7:uc->uc_mcontext.gregs[REG_ERR]=5;break;case 8:uc->uc_mcontext.gregs[REG_CSGSFS]&=~3;break;
    case 9:uc->uc_mcontext.gregs[REG_RIP]++;break;case 10:supplied.si_addr=(void *)decoded.next_pc;break;
    case 11:request.origin=99;break;case 12:request_hardware.leaf0[0]=0;break;
    case 13:script.kind=LI2_CPUID;break;case 14:script.width_bits=8;break;
    case 15:script.value=UINT64_C(0x10000);break;case 16:script.carry=2;break;
    case 17:script.carry=0;script.value=1;break;case 18:script.reserved=1;break;
    case 19:request_source[instruction_bytes-1]^=1;break;
    case 20:decoded.next_pc++;break;case 21:decoded.kind=LI2_CPUID;break;
    case 22:decoded.available--;break;case 23:decoded.length=0;break;case 24:decoded.reserved=1;break;
    case 25:decoded.bytes[0]^=1;break;
    case 26:request.source_bytes=instruction_bytes-1;require(!li2_decoder_decode(fixture_target,request.source,request.source_bytes,&decoded),12,4);break;
    case 28:request.source_bytes=0;break;case 29:request.logical_flags&=~UINT64_C(2);break;
    case 30:request_hardware.abi_version=0;break;case 31:request_hardware.reserved=1;break;
    case 33:request.origin=LI2_SELECTED_ORIGINAL_CONTEXT;break;
    case 34:request.origin=LI2_SELECTED_ORIGINAL_CONTEXT;request.fault=0;break;
    case 35:uc->uc_mcontext.gregs[REG_EFL]^=1;break;
    case 39:decoded.abi_version=0;break;case 40:decoded.decode_status=LI2_INVALID;break;
    case 41:decoded.code^=1;break;case 42:decoded.destination^=1;break;
    case 43:decoded.width_bits=8;break;case 44:decoded.step_disposition^=1;break;
    case 45:decoded.pc++;break;case 46:decoded.bytes[15]^=1;break;
    case 47:request.source_bytes=16;break;case 48:request.fault=0;break;default:break;
    }
    header[22]=(uintptr_t)uc->uc_mcontext.fpregs;header[20]=fp_capture(uc,kernel_before);
    fixture_copy(uc_before,uc,sizeof *uc);
    /* Both the actual Rust decoder and this deliberate assembly clobber may
       change live vector registers. The complete kernel-owned frame is the authority. */
    fixture_vector_clobber();
    int status=mechanism==LI2_SELECTED_NATIVE?
        li2_selected_complete_native(uc,&request,&request_hardware,&completion):
        li2_selected_complete_scripted(uc,&request,control==32?0:&script,&completion);
    ++returned;header[8]=(unsigned)status;
    header[23]=(uintptr_t)uc->uc_mcontext.fpregs;header[21]=fp_capture(uc,kernel_after);
    fixture_copy(uc_after,uc,sizeof *uc);
    require(header[22]==header[23] && header[20]==header[21] &&
            fixture_equal(kernel_before,kernel_after,header[20]),13,1);
    require(fixture_equal(program,image_before,2*PAGE),13,2);
    if(status) {
        require(fixture_equal(uc_before,uc_after,sizeof *uc),13,3);
        /* A refusal is never a successful emulation. This fixture-only escape
           restores its own actual input and skips to the independent capture;
           it is separately labeled and is not used as a product continuation. */
        fixture_copy(uc,&original_uc,sizeof *uc);
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(fixture_target+instruction_bytes);
        uc->uc_mcontext.gregs[REG_EFL]=(greg_t)fixture_pre[16];
    } else if(control==36) {
        unsigned slot=reg==12?REG_R13:REG_R12;uc->uc_mcontext.gregs[slot]^=1;
    } else if(control==37) {
        /* SSE is non-initialized by the independent pre-entry seed. */
        ((unsigned char *)uc->uc_mcontext.fpregs)[160]^=1;
    }
    in_handler=0;
}
static unsigned number(const char *s) {
    char *end;errno=0;unsigned long n=strtoul(s,&end,10);if(errno || !*s || *end || n>UINT32_MAX)fixture_die(1,1);return (unsigned)n;
}
static void singleton(void) {
    require(RAW(SYS_getpid,0,0,0,0,0,0)==RAW(SYS_gettid,0,0,0,0,0,0),2,1);
    DIR *d=opendir("/proc/self/task");require(d!=0,2,2);unsigned n=0;struct dirent *e;
    errno=0;while((e=readdir(d)))if(e->d_name[0]!='.')++n;
    int read_error=errno,close_error=closedir(d);require(!read_error && !close_error && n==1,2,3);
}
static size_t encode(unsigned char *out) {
    size_t n=0;
    if(control==27){out[0]=0x0f;out[1]=0xa2;return 2;}
    if(prefix==1)out[n++]=0x2e;
    if(prefix==2)out[n++]=0x67;
    if(prefix==3){require(width==16 && reg<8 && kind!=LI2_RDPID,3,1);out[n++]=0x48;}
    if(prefix==4)out[n++]=0xf0; /* Invalid LOCK, deliberately refused. */
    if(kind==LI2_RDPID)out[n++]=0xf3;
    else if(width==16)out[n++]=0x66;
    unsigned rex=(width==64 && kind!=LI2_RDPID?8:0)|(reg>=8?1:0);
    if(rex)out[n++]=0x40|rex;
    out[n++]=0x0f;out[n++]=0xc7;
    out[n++]=(kind==LI2_RDRAND?0xf0:0xf8)|(reg&7);
    if(prefix==5)out[n-1]&=~0xc0; /* Memory form, deliberately refused. */
    if(prefix==6){for(unsigned i=0;i<15;i++)out[i]=0x66;n=15;}
    return n;
}
int main(int argc,char **argv) {
    if(argc!=9)return 2;
    record_fd=(int)number(argv[1]);mechanism=number(argv[2]);kind=number(argv[3]);width=number(argv[4]);
    reg=number(argv[5]);control=number(argv[6]);layout=number(argv[7]);prefix=number(argv[8]);
    require(record_fd>2 && (mechanism==1 || mechanism==2) && kind>=2 && kind<=4 && reg<16 && control<=48 && layout<=1 && prefix<=6,1,2);
    require((kind==4 && width==64) || (kind!=4 && (width==16 || width==32 || width==64)),1,3);
    require(sizeof(ucontext_t)<=UC_BYTES && sizeof(greg_t)==8 && NGREG==23,1,4);
#ifndef NESTED_VARIANT
    require(control!=38,1,5);
#else
    require(control==38 && mechanism==1 && kind==2 && width==64 && reg==0 && !layout && !prefix,1,6);
#endif
    singleton();require(!fixture_xstate_prepare(),4,1);
    require(!li2_selected_observe_hardware(&hardware),4,2);request_hardware=hardware;
    require(!li2_decoder_initialize(arena,sizeof arena,&init_stats),4,3);
    program=mmap(0,3*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);require(program!=MAP_FAILED,5,1);
    subject=mmap(0,18*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);require(subject!=MAP_FAILED,5,2);
    require(!mprotect(subject+PAGE,16*PAGE,PROT_READ|PROT_WRITE),5,3);
    alt_mapping=mmap(0,ALT_BYTES+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);require(alt_mapping!=MAP_FAILED,5,4);
    require(!mprotect(alt_mapping+PAGE,ALT_BYTES,PROT_READ|PROT_WRITE),5,5);
    instruction_bytes=encode(original_source);fixture_copy(request_source,original_source,16);
    fixture_target=(uintptr_t)program+PAGE-(layout?1:instruction_bytes);
    fixture_copy((void *)fixture_target,original_source,instruction_bytes);
    unsigned char *next=(void *)(fixture_target+instruction_bytes);
    const unsigned char jump[6]={0xff,0x25,0,0,0,0};fixture_copy(next,jump,6);
    uintptr_t entry=(uintptr_t)fixture_post_entry;fixture_copy(next+6,&entry,8);
    fixture_copy(image_before,program,2*PAGE);
    require(!li2_decoder_decode(fixture_target,request_source,instruction_bytes,&decoded),6,1);
    if(prefix<4 && control!=27)require(decoded.decode_status==LI2_VALID && decoded.kind==kind && decoded.width_bits==width && decoded.destination==reg && decoded.length==instruction_bytes,6,2);
    for(unsigned i=0;i<16;i++)fixture_input[i]=UINT64_C(0xa112233445566700)+i*UINT64_C(0x01010101010101);
    fixture_input[4]=(uintptr_t)subject+15*PAGE;
    uint64_t flags;__asm__ volatile("pushfq; pop %0":"=r"(flags));
    fixture_input[16]=(flags&~(TF|RF|UINT64_C(0x400)))|UINT64_C(0x8d5)|2;
    for(size_t i=0;i<STACK_BYTES;i++)((unsigned char *)(uintptr_t)fixture_input[4]-STACK_BYTES/2)[i]=(unsigned char)(19+i*29);
    fixture_copy(stack_before,(void *)(uintptr_t)(fixture_input[4]-STACK_BYTES/2),STACK_BYTES);
    script=(struct li2_selected_script){kind,width,kind==4?0:1,0,kind==4?UINT64_C(0xc00dcafe):width==16?UINT64_C(0xbeef):width==32?UINT64_C(0xface9876):UINT64_C(0xfedcba9876543210)};
    /* CF0 is an explicitly scripted reference case, bound by the runner's environment delta. */
    const char *cf0=getenv("LI2_FIXTURE_SCRIPT_CF0");
    if(cf0){require(fixture_equal(cf0,"1",2) && mechanism==2 && kind!=4 && !control,1,7);script.carry=0;script.value=0;}
    require(!RAW(SYS_sigaltstack,0,&previous_stack,0,0,0,0) && (previous_stack.ss_flags&SS_DISABLE),7,1);
    require(!RAW(SYS_rt_sigaction,SIGSEGV,0,&previous_segv,8,0,0) && !previous_segv.handler,7,2);
    require(!RAW(SYS_rt_sigaction,SIGILL,0,&previous_ill,8,0,0) && !previous_ill.handler,7,3);
    require(!RAW(SYS_rt_sigprocmask,SIG_SETMASK,0,&previous_mask,8,0,0),7,4);
    require(!(previous_mask&((UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGILL-1)))),7,5);
    application_mask=UINT64_MAX&~((UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGILL-1))|(UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
    stack_t alt={.ss_sp=alt_mapping+PAGE,.ss_flags=0,.ss_size=ALT_BYTES};
    require(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),7,6);
    struct kernel_action action={handler,SA_SIGINFO|SA_ONSTACK|SA_NODEFER|SA_RESTORER_RAW,fixture_restorer,application_mask};
    require(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0) && !RAW(SYS_rt_sigaction,SIGILL,&action,0,8,0,0),7,7);
    require(!RAW(SYS_rt_sigprocmask,SIG_SETMASK,&application_mask,0,8,0,0),7,8);
    require(!RAW(SYS_mprotect,program,PAGE,PROT_READ,0,0,0) && !RAW(SYS_mprotect,program+PAGE,PAGE,PROT_READ|PROT_EXEC,0,0,0) && !RAW(SYS_mprotect,program+2*PAGE,PAGE,PROT_NONE,0,0,0),8,1);
    long query=RAW(SYS_membarrier,0,0,0,0,0,0);
    require(query>=0 && (query&96)==96 && !RAW(SYS_membarrier,64,0,0,0,0,0) && !RAW(SYS_membarrier,32,0,0,0,0,0),8,2);
#ifdef NESTED_VARIANT
    require(((uintptr_t)__li2_native_random_page&4095)==0 && (uintptr_t)__li2_native_random_page_end-(uintptr_t)__li2_native_random_page==PAGE && (uintptr_t)__li2_native_random_code_end>(uintptr_t)__li2_native_random_page,8,3);
    require(!RAW(SYS_mprotect,__li2_native_random_page,PAGE,PROT_READ,0,0,0) && !RAW(SYS_membarrier,32,0,0,0,0,0),8,4);
#endif
    fixture_enter();
    require(fault_count==1 && returned==1 && !in_handler,14,1);
    fixture_copy(stack_after,(void *)(uintptr_t)(fixture_input[4]-STACK_BYTES/2),STACK_BYTES);
    require(!RAW(SYS_rt_sigaction,SIGSEGV,&previous_segv,0,8,0,0) && !RAW(SYS_rt_sigaction,SIGILL,&previous_ill,0,8,0,0),14,2);
    require(!RAW(SYS_sigaltstack,&previous_stack,0,0,0,0,0) && !RAW(SYS_rt_sigprocmask,SIG_SETMASK,&previous_mask,0,8,0,0),14,3);
    struct kernel_action restored_segv={0},restored_ill={0};stack_t restored_stack={0};uint64_t restored_mask=0;
    require(!RAW(SYS_rt_sigaction,SIGSEGV,0,&restored_segv,8,0,0) && !RAW(SYS_rt_sigaction,SIGILL,0,&restored_ill,8,0,0) &&
            fixture_equal(&restored_segv,&previous_segv,sizeof previous_segv) && fixture_equal(&restored_ill,&previous_ill,sizeof previous_ill),14,6);
    require(!RAW(SYS_sigaltstack,0,&restored_stack,0,0,0,0) && restored_stack.ss_sp==previous_stack.ss_sp &&
            restored_stack.ss_size==previous_stack.ss_size && restored_stack.ss_flags==previous_stack.ss_flags &&
            !RAW(SYS_rt_sigprocmask,SIG_SETMASK,0,&restored_mask,8,0,0) && restored_mask==previous_mask,14,7);
    require(fixture_equal(program,image_before,2*PAGE),14,4);
    require(!li2_decoder_stats(&final_stats) && fixture_equal(&init_stats,&final_stats,sizeof init_stats),14,5);
    header[0]=RECORD_MAGIC;header[1]=1;header[2]=kind;header[3]=width;header[4]=reg;header[5]=mechanism;header[6]=control;
    header[9]=completion.phase;header[10]=completion.native_attempts;header[11]=fault_count;header[13]=fixture_target;
    header[14]=fixture_target+instruction_bytes;header[15]=instruction_bytes;header[16]=fixture_pre[16];header[17]=fixture_enabled;header[18]=fixture_mask;
    for(unsigned i=0;i<8;i++)if(fixture_components[i].size)++header[19];
    header[24]=sizeof(ucontext_t);header[25]=offsetof(ucontext_t,uc_mcontext.gregs);header[26]=offsetof(ucontext_t,uc_mcontext.fpregs);header[27]=returned;
    header[29]=completion.value;header[30]=completion.carry;header[31]=completion.output_destination;header[32]=completion.output_flags;
    header[33]=script.value;header[34]=script.carry;header[35]=layout;header[36]=prefix;header[37]=init_stats.retained_high_water;
    header[38]=init_stats.allocation_calls;header[39]=init_stats.deallocation_calls;
    header[40]=hardware.leaf0[0];header[41]=hardware.leaf1[2];header[42]=hardware.leaf7[1];header[43]=hardware.leaf7[2];
    header[44]=completion.status;header[45]=completion.frame_flags;header[46]=completion.logical_flags;
    write_all(header,sizeof header);write_all(fixture_components,sizeof fixture_components);
    write_all(fixture_pre,sizeof fixture_pre);write_all(fixture_post,sizeof fixture_post);
    write_all(fixture_pre_fp,FP_BYTES);write_all(fixture_post_fp,FP_BYTES);
    write_all(kernel_before,FP_BYTES);write_all(kernel_after,FP_BYTES);write_all(uc_before,UC_BYTES);write_all(uc_after,UC_BYTES);
    write_all(stack_before,STACK_BYTES);write_all(stack_after,STACK_BYTES);write_all(original_source,16);write_all(request_source,16);write_all(&hardware,sizeof hardware);write_all(&final_stats,sizeof final_stats);
    require(!munmap(program,3*PAGE) && !munmap(subject,18*PAGE) && !munmap(alt_mapping,ALT_BYTES+2*PAGE),15,1);
    puts("LI2_PROVIDER_CAPTURE 1");return 0;
}
