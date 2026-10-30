/* Finite original / actual TF owner / sealed closed-CFG component.
   No runtime-loader, arbitrary application, rseq or fault-resumption claim. */
#define _GNU_SOURCE
#include "plan.h"
#include "machine.h"
#include "tf_owner.h"
#include "sha256.h"
#include <asm/prctl.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/rseq.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#define PAGE 4096UL
#define DATA (32*1024UL)
#define STACK (128*1024UL)
#define LOGICAL_STACK 160UL
#define SAMPLES 10
#define SEALS (F_SEAL_SEAL|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_WRITE)
uint64_t region_seed[16],region_input_flags,region_xcr0,region_target;
struct region_live region_before,region_after;
unsigned char region_fp_before[REGION_FP] __attribute__((aligned(64)));
unsigned char region_fp_after[REGION_FP] __attribute__((aligned(64)));
long raw(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;long r;
    __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static void bytes(void *d,const void *s,size_t n){unsigned char *x=d;const unsigned char *y=s;for(size_t i=0;i<n;i++)x[i]=y[i];}
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
#ifdef LI2_FAST_EQUAL
    /* GCC's alias-anything, alignment-one integer type permits the same
       immutable byte ranges as the scalar path. Each load is wholly inside
       the requested range; neither alignment nor a readable suffix is needed.
       No vector/string instruction or application-state normalization is used. */
    typedef uint64_t word __attribute__((__may_alias__,__aligned__(1)));
    _Static_assert(sizeof(word)==8 && __alignof__(word)==1,"bounded unaligned word");
    while(n>=sizeof(word)) {
        if(*(const word *)(const void *)x!=*(const word *)(const void *)y)return 0;
        x+=sizeof(word);y+=sizeof(word);n-=sizeof(word);
    }
#endif
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static void zero(void *d,size_t n){
#if defined(LI2_FAST_MEMSET) && LI2_FAST_MEMSET
    /* Exact production bridge memset instruction/constraint body, with fill0.
       Every requested byte is still reset; application flags remain saved. */
    int c=0;
    __asm__ volatile("cld; rep stosb" : "+D"(d), "+c"(n)
                     : "a"((unsigned char)c) : "memory","cc");
#else
    unsigned char *p=d;for(size_t i=0;i<n;i++)p[i]=0;
#endif
}
static int write_all(int fd,const void *p,size_t n){const unsigned char *s=p;while(n){long k=RAW(SYS_write,fd,s,n,0,0,0);if(k<=0||(size_t)k>n)return 0;s+=k;n-=(size_t)k;}return 1;}
struct owned_mapping {uintptr_t at;size_t n;int fd;struct stat stat;unsigned char expected[8192];};
static struct owned_mapping source,image;
static struct region_plan plan;
static void *plan_handle;
static uintptr_t guard,stack_area,data_area,fault_area,alt_area;
static unsigned char original_data[DATA],original_stack[LOGICAL_STACK];
static unsigned unroll,trips,lane,handling,started,ended,selftest,fault_mode;
static uint64_t app_mask,expected_next,expected_flags,xsave_bytes,prepare_ns,first_error;
static struct li2_step_session session;
static struct li2_tf_owner step;
static unsigned char decoder_arena[2*1024*1024] __attribute__((aligned(64)));
static char maps[256*1024];
static struct rseq rseq_probe __attribute__((aligned(32)));
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
struct observation {
    struct region_live before,after;
    unsigned char xbefore[REGION_FP],xafter[REGION_FP];
    struct li2_step_frame entry,exit;
    unsigned char stack[LOGICAL_STACK],data[DATA];
    uint64_t nx,trace,completed,guard_exits,raw_fault_pc,logical_fault_pc,fs,gs;
};
_Static_assert(sizeof(struct observation)==296000,"fixed complete observation wire");
_Static_assert(sizeof(struct region_plan)==5256 && sizeof(struct li2_step_frame)==65792,"fixed descriptor/frame wire");
static struct observation current,qualified[3];
static uint64_t cold[3],hot[3][SAMPLES],event_rows[3][SAMPLES+1][4];
static uint64_t handler_count,tf_count,step_count,entry_count,exit_count;
static uint64_t xlayout[64][3],authority_controls;
static const unsigned char region_policy[]="li2-region-v1;closed-read-only-scalar;sole-external-entry;no-resume;Legacy128;disabled-entry-ret;sealed-original-NX;generation-owned";
static unsigned char source_identity[32];
static int audit_mapping(const struct owned_mapping *,int);
static int dump(void);
static void retire(void);
static _Noreturn void die(unsigned code){if(!first_error)first_error=code;retire();(void)dump();(void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
static void need(int ok,unsigned code){if(!ok)die(code);}
_Noreturn void li2_decoder_abort(uint32_t code){die(1000+code);}
static uint32_t u32(const unsigned char *p){uint32_t x;bytes(&x,p,4);return x;}
static uint64_t now(void){struct timespec t;need(!RAW(SYS_clock_gettime,CLOCK_MONOTONIC_RAW,&t,0,0,0,0)&&t.tv_sec>=0&&t.tv_nsec>=0&&t.tv_nsec<1000000000,10);need((uint64_t)t.tv_sec<UINT64_MAX/1000000000,11);return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;}
static void sync_core(void){need(!RAW(SYS_membarrier,32,0,0,0,0,0),12);}
static void source_prot(int prot){need(!RAW(SYS_mprotect,source.at,source.n,prot,0,0,0),13);sync_core();need(audit_mapping(&source,prot),14);}
static void singleton(void){char out[8192];long fd=RAW(SYS_openat,AT_FDCWD,"/proc/self/status",O_RDONLY|O_CLOEXEC,0,0,0);need(fd>=0,137);long n=RAW(SYS_read,fd,out,sizeof(out)-1,0,0,0);need(n>0&&n<(long)sizeof(out)-1&&!RAW(SYS_close,fd,0,0,0,0,0),138);out[n]=0;unsigned threads=0,tracer=0;const char *p=out;while(*p){if(!strncmp(p,"Threads:\t1\n",11))threads++;if(!strncmp(p,"TracerPid:\t0\n",13))tracer++;while(*p&&*p!='\n')p++;if(*p)p++;}need(threads==1&&tracer==1,139);}
static int read_maps(void){long fd=RAW(SYS_openat,AT_FDCWD,"/proc/self/maps",O_RDONLY|O_CLOEXEC,0,0,0);if(fd<0)return 0;size_t n=0;int ok=1;for(;;){if(n==sizeof(maps)-1){ok=0;break;}long k=RAW(SYS_read,fd,maps+n,sizeof(maps)-1-n,0,0,0);if(k<0){ok=0;break;}if(!k)break;n+=(size_t)k;}if(RAW(SYS_close,fd,0,0,0,0,0))ok=0;maps[n]=0;return ok;}
static __attribute__((always_inline)) inline uint64_t number(const char **p,unsigned radix,int *ok){uint64_t v=0;unsigned count=0;while(**p){unsigned c=(unsigned char)**p,x;if(c>='0'&&c<='9')x=c-'0';else if(c>='a'&&c<='f')x=c-'a'+10;else break;if(x>=radix)break;if(v>(UINT64_MAX-x)/radix){*ok=0;return 0;}v=v*radix+x;++*p;++count;}if(!count)*ok=0;return v;}
static int mapping_rows(uintptr_t address,size_t size,int prot,const struct stat *st){
    if(!read_maps()||!size||address>UINTPTR_MAX-size)return 0;unsigned found=0,aliases=0;const char *p=maps;
    while(*p){int ok=1;uint64_t lo=number(&p,16,&ok);if(*p++!='-')return 0;uint64_t hi=number(&p,16,&ok);if(!ok||lo>=hi||*p++!=' ')return 0;
        char r=*p++,w=*p++,x=*p++,share=*p++;if(*p++!=' ')return 0;uint64_t off=number(&p,16,&ok);if(*p++!=' ')return 0;uint64_t ma=number(&p,16,&ok);if(*p++!=':')return 0;uint64_t mi=number(&p,16,&ok);if(*p++!=' ')return 0;while(*p==' ')p++;uint64_t ino=number(&p,10,&ok);if(!ok)return 0;
        if(lo<=address&&address<hi){int actual=(r=='r'?PROT_READ:0)|(w=='w'?PROT_WRITE:0)|(x=='x'?PROT_EXEC:0);if(++found!=1||address+size>hi||actual!=prot||share!='p')return 0;if(st&&(lo!=address||hi!=address+size||off||ino!=(uint64_t)st->st_ino||ma!=major(st->st_dev)||mi!=minor(st->st_dev)))return 0;}
        if(st&&ino==(uint64_t)st->st_ino&&ma==major(st->st_dev)&&mi==minor(st->st_dev)){if(++aliases!=1||lo!=address||hi!=address+size||w!='-'||share!='p')return 0;}
        while(*p&&*p!='\n')p++;if(*p=='\n')p++;
    }
    return found==1&&(!st||aliases==1);
}
static int audit_mapping(const struct owned_mapping *m,int prot){struct stat st;if(!m->at||m->fd<0||RAW(SYS_fstat,m->fd,&st,0,0,0,0)||st.st_dev!=m->stat.st_dev||st.st_ino!=m->stat.st_ino||st.st_size!=(off_t)m->n||RAW(SYS_fcntl,m->fd,F_GET_SEALS,0,0,0,0)!=SEALS)return 0;return mapping_rows(m->at,m->n,prot,&st)&&same((void *)m->at,m->expected,m->n);}
static void sealed(struct owned_mapping *m,const unsigned char *data,size_t n,uintptr_t at,int prot){
    need(n&&n<=sizeof(m->expected)&&!(n&(PAGE-1)),20);m->n=n;m->fd=(int)RAW(SYS_memfd_create,"li2-region",MFD_ALLOW_SEALING|MFD_CLOEXEC,0,0,0,0);need(m->fd>=0,21);
    need(!RAW(SYS_ftruncate,m->fd,n,0,0,0,0)&&write_all(m->fd,data,n),22);
    need(!RAW(SYS_fcntl,m->fd,F_ADD_SEALS,SEALS,0,0,0)&&!RAW(SYS_fstat,m->fd,&m->stat,0,0,0,0),23);
    long a=RAW(SYS_mmap,at,n,prot,MAP_PRIVATE|(at?MAP_FIXED_NOREPLACE:0),m->fd,0);need(a>0&&(!at||(uintptr_t)a==at),24);m->at=(uintptr_t)a;bytes(m->expected,data,n);sync_core();need(audit_mapping(m,prot),25);
}
static void retire(void){
    /* No plan/control can die while its bytes remain executable. First error
       stays authoritative; every independent revoke/unmap/close is attempted. */
    if(source.at&&RAW(SYS_mprotect,source.at,source.n,PROT_READ,0,0,0)&&!first_error)first_error=90;
    if(image.at&&RAW(SYS_mprotect,image.at,image.n,PROT_NONE,0,0,0)&&!first_error)first_error=91;
    if((source.at||image.at)&&RAW(SYS_membarrier,32,0,0,0,0,0)&&!first_error)first_error=92;
    if(image.at){if(RAW(SYS_munmap,image.at,image.n,0,0,0,0)){if(!first_error)first_error=93;}else image.at=0;}
    if(!image.at&&plan_handle&&!handling){region_plan_destroy(plan_handle);plan_handle=NULL;}
    if(source.at){if(RAW(SYS_munmap,source.at,source.n,0,0,0,0)){if(!first_error)first_error=94;}else source.at=0;}
    if(image.fd>=0){if(RAW(SYS_close,image.fd,0,0,0,0,0)&&!first_error)first_error=95;image.fd=-1;}
    if(source.fd>=0){if(RAW(SYS_close,source.fd,0,0,0,0,0)&&!first_error)first_error=96;source.fd=-1;}
}
static void frame(struct li2_step_frame *out,const ucontext_t *uc){
    zero(out,sizeof(*out));bytes(out->greg,uc->uc_mcontext.gregs,sizeof(out->greg));bytes(&out->mask,&uc->uc_sigmask,8);
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;need(out->fp_address&&!(out->fp_address&15),30);const unsigned char *p=(void *)out->fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)){n=u32(p+468);size_t x=u32(p+480);need(n>=580&&n<=REGION_FP&&x>=576&&x<=n-4&&u32(p+n-4)==UINT32_C(0x46505845),31);}
    out->fp_bytes=n;bytes(out->fp,p,n);out->initialized=n;need(out->mask==app_mask,32);
}
static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc){return sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==pc&&(uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==14&&g[REG_ERR]==21;}
static int authenticate(void *ctx,const struct li2_step_page *p,int prot){return ctx!=&source||p->address!=source.at||p->object!=(uint64_t)source.stat.st_ino||p->generation!=1||p->offset||p->closed_prot!=PROT_READ||p->open_prot!=(PROT_READ|PROT_EXEC)||!audit_mapping(&source,prot);}
static int continuation(void *ctx,uintptr_t pc){if(ctx!=&source)return 1;if(pc==guard)return !mapping_rows(guard,PAGE,PROT_READ,NULL);for(size_t i=0;i<plan.heads;i++)if(plan.body[i].original==pc)return !audit_mapping(&source,PROT_READ);return 1;}
static void complete_fault(const struct li2_step_frame *actual,int from_step);
static void failure(void *ctx,const struct li2_step_owner *o){
    if(ctx==&source&&fault_mode==2&&lane==2&&o->first_error==LI2_STEP_FOREIGN_EVENT&&o->phase==LI2_STEP_FAILED&&step.unexpected_frame_observed&&!o->trace_seen&&o->revoked[0]&&!o->revoke_result[0]&&o->revoke_sync_started&&!o->revoke_sync){complete_fault(&o->after,1);return;}
    if(!first_error)first_error=2000+o->first_error;(void)dump();
}
static void arm(uintptr_t pc,uint64_t flags,int test){
    zero(&step,sizeof(step));struct li2_step_request req;zero(&req,sizeof(req));need(!li2_decoder_decode(pc,(void *)pc,15,&req.decoded),40);
    req.page_count=1;req.original_flags=flags;req.pages[0]=(struct li2_step_page){source.at,(uint64_t)source.stat.st_ino,1,0,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{&source,authenticate,failure},continuation};int rc=test?li2_step_arm(&step.step,&session,&hooks.step,&req,1):li2_tf_arm(&step,&session,&hooks,&req);need(!rc,41);
}
static void handler(int sig,siginfo_t *si,void *ptr){
    need(!handling&&si&&ptr,42);handling=1;handler_count++;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(selftest){
        if(step.step.phase==LI2_STEP_ARMED)li2_step_begin(&step.step,sig,si,uc);
        else if(step.step.phase==LI2_STEP_RUNNING)li2_step_trace(&step.step,sig,si,uc);
        else{need(step.step.phase==LI2_STEP_COMPLETE&&nx(sig,si,g,source.at+PAGE-15),43);g[REG_RIP]=(greg_t)(uintptr_t)region_capture;ended=1;}
        handling=0;return;
    }
    if(lane==2&&step.step.phase==LI2_STEP_RUNNING){
        if(sig!=SIGTRAP)li2_tf_unexpected(&step,sig,si,uc);
        li2_tf_trace(&step,sig,si,uc);need(step.step.phase==LI2_STEP_COMPLETE&&!step.step.first_error&&step.continuation_complete,44);
        tf_count++;step_count++;expected_next=(uint64_t)g[REG_RIP];expected_flags=(uint64_t)g[REG_EFL];handling=0;return;
    }
    if(nx(sig,si,g,guard)){
        need(started&&!ended,45);frame(&current.exit,uc);exit_count++;ended=1;
        if(lane==0)source_prot(PROT_READ);else need(audit_mapping(&source,PROT_READ),46);
        need(!region_callback_count(),47);g[REG_RIP]=(greg_t)(uintptr_t)region_capture;handling=0;return;
    }
    if(fault_mode&&started&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==fault_area&&g[REG_TRAPNO]==14&&g[REG_ERR]==4){
        frame(&current.exit,uc);current.raw_fault_pc=pc;
        if(lane==0){need(pc==source.at+6,48);current.logical_fault_pc=pc;source_prot(PROT_READ);ended=1;g[REG_RIP]=(greg_t)(uintptr_t)region_capture;handling=0;return;}
        need(lane==1,49);complete_fault(&current.exit,0);__builtin_trap();
    }
    need(nx(sig,si,g,pc),50);
    if(lane==1){need(!started&&pc==source.at&&audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ|PROT_EXEC),51);frame(&current.entry,uc);started=1;entry_count++;g[REG_RIP]=(greg_t)plan.entry;}
    else if(lane==2){need(pc==expected_next&&(uint64_t)g[REG_EFL]==(expected_flags|LI2_STEP_RF),52);if(!started){frame(&current.entry,uc);started=1;}entry_count++;arm(pc,expected_flags,0);li2_tf_begin(&step,sig,si,uc);}
    else die(53);
    handling=0;
}
static void snapshot(struct observation *o){o->before=region_before;o->after=region_after;bytes(o->xbefore,region_fp_before,REGION_FP);bytes(o->xafter,region_fp_after,REGION_FP);bytes(o->stack,(void *)(region_seed[4]-128),LOGICAL_STACK);bytes(o->data,(void *)data_area,DATA);o->nx=entry_count+exit_count;o->trace=tf_count;o->completed=step_count;o->guard_exits=exit_count;need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&o->fs,0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&o->gs,0,0,0,0),54);}
static void prepare_input(void){
    zero(&current,sizeof(current));zero(&region_before,sizeof(region_before));zero(&region_after,sizeof(region_after));zero(region_fp_before,REGION_FP);zero(region_fp_after,REGION_FP);
    bytes((void *)data_area,original_data,DATA);bytes((void *)(region_seed[4]-128),original_stack,LOGICAL_STACK);started=ended=handling=0;entry_count=exit_count=tf_count=step_count=0;zero(&step,sizeof(step));
    expected_next=source.at;expected_flags=region_input_flags;region_target=source.at;
}
static uint64_t invoke_lane(unsigned which){
    lane=which;prepare_input();need(audit_mapping(&image,PROT_READ|PROT_EXEC)&&audit_mapping(&source,PROT_READ),55);
    if(which==0){source_prot(PROT_READ|PROT_EXEC);started=1;}
    uint64_t start=now();region_enter();uint64_t end=now();need(end>=start&&ended&&!handling,56);snapshot(&current);return end-start;
}
static uint64_t model_result(void){uint64_t value=0;const uint64_t *a=(void *)original_data;for(size_t i=0;i<(size_t)unroll*trips;i++)value=(value+a[i])^region_seed[8];return value;}
static void check_seed(const unsigned char *x){
    uint16_t fcw,fsw;bytes(&fcw,x,2);bytes(&fsw,x+2,2);need(fcw==0x37f&&fsw==0x3000&&x[4]==0xc0&&u32(x+24)==0x1f80,129);
    uint64_t bv,comp;bytes(&bv,x+512,8);bytes(&comp,x+520,8);need((bv&0xe7)==0xe7&&!comp,130);
    for(unsigned r=0;r<32;r++)for(unsigned q=0;q<8;q++){uint64_t want=UINT64_C(0x3141592653589793)+(uint64_t)r*8+q+1,got;size_t off;
        if(r>=16){need(xlayout[7][0]&&xlayout[7][2]>=1024,131);off=(size_t)xlayout[7][1]+(r-16)*64+q*8;}
        else if(q>=4){need(xlayout[6][0]&&xlayout[6][2]>=512,132);off=(size_t)xlayout[6][1]+r*32+(q-4)*8;}
        else if(q>=2){need(xlayout[2][0]&&xlayout[2][2]>=256,133);off=(size_t)xlayout[2][1]+r*16+(q-2)*8;}
        else off=160+r*16+q*8;need(off+8<=xsave_bytes,134);bytes(&got,x+off,8);need(got==want,135);}
    const uint64_t masks[8]={UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(0xaaaaaaaa55555555),UINT64_C(0x0f0ff0f0a5a55a5a),UINT64_C(0x1111222233334444),UINT64_C(0x8877665544332211),UINT64_C(0xffff00000000ffff),UINT64_C(0x5a5a5a5aa5a5a5a5)};
    need(xlayout[5][0]&&xlayout[5][2]>=64&&same(x+xlayout[5][1],masks,64),136);
}
static void check_success(unsigned which){
    check_seed(current.xbefore);check_seed(current.xafter);
    need(!fault_mode&&current.guard_exits==1&&!region_callback_count(),60);uint64_t instructions=4+(uint64_t)trips*(4*unroll+2);
    need(which==2?(current.nx==instructions+1&&current.trace==instructions&&current.completed==instructions):(current.nx==(which==0?1:2)&&!current.trace&&!current.completed),61);
    need(current.before.flags==region_input_flags&&current.after.flags==UINT64_C(0x246)&&!current.before.reserved&&!current.after.reserved,62);
    for(unsigned i=0;i<16;i++){uint64_t want=region_seed[i];if(i==0)want=model_result();if(i==1)want=0;if(i==2)want=((uint64_t *)original_data)[(size_t)trips*unroll-1];if(i==4)want+=8;if(i==6)want+=(uint64_t)trips*unroll*8;need(current.before.gpr[i]==region_seed[i]&&current.after.gpr[i]==want&&(uint64_t)current.exit.greg[regs[i]]==want,63);}
    need((uint64_t)current.exit.greg[REG_RIP]==guard&&(uint64_t)current.exit.greg[REG_EFL]==(UINT64_C(0x246)|LI2_STEP_RF)&&current.exit.greg[REG_TRAPNO]==14&&current.exit.greg[REG_ERR]==21,64);
    need(same(current.before.selectors,current.after.selectors,sizeof(current.before.selectors))&&same(current.xbefore,current.xafter,REGION_FP),65);
    if(which){for(unsigned i=0;i<16;i++)need((uint64_t)current.entry.greg[regs[i]]==region_seed[i],127);need((uint64_t)current.entry.greg[REG_RIP]==source.at&&(uint64_t)current.entry.greg[REG_EFL]==(region_input_flags|LI2_STEP_RF)&&current.entry.fp_bytes==current.exit.fp_bytes&&same(current.entry.fp,current.exit.fp,REGION_FP),128);}
    need(same(current.stack,original_stack,LOGICAL_STACK)&&same(current.data,original_data,DATA),66);
    if(which){const struct observation *n=&qualified[0];need(same(&current.before,&n->before,sizeof(n->before))&&same(&current.after,&n->after,sizeof(n->after))&&same(current.xbefore,n->xbefore,REGION_FP)&&same(current.xafter,n->xafter,REGION_FP),67);need(current.exit.fp_bytes==n->exit.fp_bytes&&same(current.exit.fp,n->exit.fp,REGION_FP)&&current.exit.mask==n->exit.mask&&current.fs==n->fs&&current.gs==n->gs,68);for(unsigned i=0;i<NGREG;i++)need(current.exit.greg[i]==n->exit.greg[i],69);}
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ|PROT_EXEC),70);
}
static void complete_fault(const struct li2_step_frame *actual,int from_step){
    const struct observation *n=&qualified[0];need(fault_mode&&started&&!ended&&n->logical_fault_pc==source.at+6,71);
    uintptr_t logical=0;if(from_step){need((uintptr_t)actual->greg[REG_RIP]==source.at+6,72);logical=source.at+6;}else{
        for(size_t i=0;i<plan.heads;i++)if(plan.body[i].generated==(uint64_t)actual->greg[REG_RIP]){need(!logical,73);logical=plan.body[i].original;}
        need(logical==source.at+6&&same((void *)(uintptr_t)actual->greg[REG_RIP],source.expected+6,3),74);
        unsigned hits=0;for(size_t i=0;i<plan.ranges;i++)if(plan.pc[i].start<=(uint64_t)actual->greg[REG_RIP]&&(uint64_t)actual->greg[REG_RIP]<plan.pc[i].end){need(plan.pc[i].original==logical,75);hits++;}need(hits==1,76);
    }
    for(unsigned i=0;i<NGREG;i++){uint64_t want=(uint64_t)n->exit.greg[i];if(i==REG_RIP)want=from_step?logical:(uint64_t)actual->greg[i];if(i==REG_EFL&&from_step)want|=LI2_STEP_TF;need((uint64_t)actual->greg[i]==want,77);}
    need(actual->fp_bytes==n->exit.fp_bytes&&same(actual->fp,n->exit.fp,REGION_FP)&&actual->mask==n->exit.mask,78);
    need(same((void *)data_area,original_data,DATA)&&same((void *)(region_seed[4]-128),original_stack,LOGICAL_STACK),79);
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.fs,0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.gs,0,0,0,0)&&current.fs==n->fs&&current.gs==n->gs,140);
    current.before=region_before;bytes(current.xbefore,region_fp_before,REGION_FP);bytes(current.stack,(void *)(region_seed[4]-128),LOGICAL_STACK);bytes(current.data,(void *)data_area,DATA);
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ|PROT_EXEC),152);
    current.exit=*actual;current.raw_fault_pc=(uint64_t)actual->greg[REG_RIP];current.logical_fault_pc=logical;current.nx=entry_count;current.trace=tf_count;current.completed=step_count;qualified[lane]=current;ended=1;
    need(!region_callback_count(),80);retire();need(!first_error,81);need(dump(),82);
    printf("{\"schema\":1,\"status\":\"required_read_failure\",\"lane\":%u,\"qualified_fault\":1,\"completed_operation\":0,\"cleanup\":1}\n",lane);fflush(stdout);
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int dump(void){
    /* Native wire is private; whole actual initial/final FP/GPR/data bytes are
       retained. No addresses or raw states are copied into the public summary. */
    uint64_t h[24]={UINT64_C(0x314647435232494c),1,24,unroll,trips,fault_mode,first_error,region_xcr0,xsave_bytes,prepare_ns,plan.source,plan.entry,plan.image_bytes,plan.heads,plan.ranges,guard,region_seed[4],data_area,sizeof(struct observation),sizeof(struct region_plan),sizeof(struct li2_step_frame),region_callback_count(),source.at==0&&image.at==0,handler_count};
    return write_all(3,h,sizeof(h))&&write_all(3,region_seed,sizeof(region_seed))&&write_all(3,&plan,sizeof(plan))&&write_all(3,qualified,sizeof(qualified))&&write_all(3,cold,sizeof(cold))&&write_all(3,hot,sizeof(hot))&&write_all(3,event_rows,sizeof(event_rows))&&write_all(3,xlayout,sizeof(xlayout))&&write_all(3,source.expected,sizeof(source.expected))&&write_all(3,image.expected,sizeof(image.expected))&&write_all(3,&authority_controls,8);
}
static void make_source(void){uint64_t start=now();unsigned char page[PAGE];memset(page,0xcc,sizeof(page));size_t at=0;const unsigned char head[]={0x31,0xc0,0x85,0xc9,0x74,0};bytes(page,head,sizeof(head));at=sizeof(head);const unsigned char body[]={0x48,0x8b,0x16,0x48,0x01,0xd0,0x4c,0x31,0xc0,0x48,0x83,0xc6,0x08};for(unsigned i=0;i<unroll;i++){bytes(page+at,body,sizeof(body));at+=sizeof(body);}page[at++]=0xff;page[at++]=0xc9;page[at++]=0x75;page[at]=(unsigned char)(6-(at+1));at++;size_t ret=at;page[at++]=0xc3;page[5]=(unsigned char)(ret-6);page[PAGE-16]=0x90;need(at<=80,83);sealed(&source,page,PAGE,0,PROT_READ);uint64_t leaders[]={source.at,source.at+6,source.at+ret};unsigned char identity_input[sizeof(region_policy)+8+PAGE];bytes(identity_input,region_policy,sizeof(region_policy));uint64_t code_bytes=at;bytes(identity_input+sizeof(region_policy),&code_bytes,8);bytes(identity_input+sizeof(region_policy)+8,(void *)source.at,PAGE);digest(identity_input,sizeof(identity_input),source_identity);plan_handle=region_plan_create(source.at,(void *)source.at,at,leaders,3,source.at+ret,(uint64_t)source.stat.st_ino,1,source_identity,&plan);need(plan_handle&&same(plan.source_identity,source_identity,32)&&plan.abi==1&&plan.source==source.at&&plan.source_bytes==at&&plan.allocation_bytes<=8192&&plan.allocation_bytes&&!(plan.allocation&(PAGE-1))&&!(plan.allocation_bytes&(PAGE-1))&&plan.image>=plan.allocation&&plan.image_bytes<=plan.allocation_bytes&&plan.image-plan.allocation<=plan.allocation_bytes-plan.image_bytes,84);unsigned char emitted[8192];memset(emitted,0xcc,sizeof(emitted));bytes(emitted+plan.image-plan.allocation,plan.bytes,plan.image_bytes);sealed(&image,emitted,plan.allocation_bytes,plan.allocation,PROT_READ|PROT_EXEC);uint64_t end=now();need(end>=start,85);prepare_ns=end-start;need(plan.heads==4+4*unroll+2&&plan.saved_state_bytes<=REGION_FP&&(plan.saved_state_mask&region_xcr0)==plan.saved_state_mask,86);}
static void authority_checks(void){
    struct li2_step_page p={source.at,(uint64_t)source.stat.st_ino,1,0,PROT_READ,PROT_READ|PROT_EXEC};
    need(!authenticate(&source,&p,PROT_READ),141);
    p.generation=2;need(authenticate(&source,&p,PROT_READ)!=0,142);authority_controls++;p.generation=1;
    p.object++;need(authenticate(&source,&p,PROT_READ)!=0,143);authority_controls++;p.object--;
    p.offset=PAGE;need(authenticate(&source,&p,PROT_READ)!=0,144);authority_controls++;p.offset=0;
    need(authenticate(&source,&p,PROT_READ|PROT_EXEC)!=0,145);authority_controls++;
    for(unsigned i=0;i<2;i++){struct owned_mapping *m=i?&image:&source;
        long alias=RAW(SYS_mmap,0,m->n,PROT_READ|PROT_WRITE,MAP_PRIVATE,m->fd,0);need(alias>0,146);
        need(!audit_mapping(m,i?(PROT_READ|PROT_EXEC):PROT_READ),147);authority_controls++;
        need(!RAW(SYS_munmap,alias,m->n,0,0,0,0)&&audit_mapping(m,i?(PROT_READ|PROT_EXEC):PROT_READ),148);
        unsigned char value=0;need(RAW(SYS_pwrite64,m->fd,&value,1,0,0,0)==-EPERM,149);authority_controls++;
    }
    need(authority_controls==8&&!region_callback_count(),150);
}
static void setup(void){
    source.fd=image.fd=-1;need(getauxval(AT_PAGESZ)==PAGE&&RAW(SYS_getpid,0,0,0,0,0,0)==RAW(SYS_gettid,0,0,0,0,0,0),100);
    /* Registration must succeed: an existing glibc/application registration is
       a refusal. Then actual unregister establishes this finite no-rseq scope. */
    need(!RAW(SYS_rseq,&rseq_probe,sizeof(rseq_probe),0,UINT32_C(0x53053053),0,0)&&!RAW(SYS_rseq,&rseq_probe,sizeof(rseq_probe),RSEQ_FLAG_UNREGISTER,UINT32_C(0x53053053),0,0),101);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));need((c&0x0c000000)==0x0c000000,102);a=d=0;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0));region_xcr0=(uint64_t)d<<32|a;need((region_xcr0&0xe7)==0xe7,103);a=7;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));need((b&((1U<<16)|(1U<<30)))==((1U<<16)|(1U<<30)),104);a=13;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));xsave_bytes=b;need(xsave_bytes>=576&&xsave_bytes<=REGION_FP,105);
    for(unsigned k=2;k<64;k++)if(region_xcr0&(UINT64_C(1)<<k)){a=13;c=k;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));need(a&&b>=576&&(uint64_t)b+a<=xsave_bytes&&!(c&1),126);xlayout[k][0]=1;xlayout[k][1]=b;xlayout[k][2]=a;}
    unsigned long cet=0;long cr=RAW(SYS_arch_prctl,0x5005,&cet,0,0,0,0);need((!cr&&!cet)||cr==-EINVAL||cr==-ENOSYS,106);
    uint64_t initial=1;need(!RAW(SYS_rt_sigprocmask,0,0,&initial,8,0,0)&&!initial,107);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action,old;
    for(int sig=1;sig<=64;sig++)if(sig!=SIGKILL&&sig!=SIGSTOP)need(!RAW(SYS_rt_sigaction,sig,0,&old,8,0,0)&&!old.handler,108);
    app_mask=UINT64_MAX&~((UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGTRAP-1))|(UINT64_C(1)<<(SIGSYS-1))|(UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));need(!RAW(SYS_rt_sigprocmask,2,&app_mask,0,8,0,0),109);
    long p=RAW(SYS_mmap,0,512*1024+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,110);alt_area=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,512*1024,PROT_READ|PROT_WRITE,0,0,0),111);stack_t alt={.ss_sp=(void *)(p+PAGE),.ss_size=512*1024};need(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),112);
    action.handler=handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;action.restorer=region_restorer;action.mask=app_mask;for(unsigned i=0;i<3;i++){int sig=(int[]){SIGSEGV,SIGTRAP,SIGSYS}[i];need(!RAW(SYS_rt_sigaction,sig,&action,0,8,0,0),113);}
    need(!li2_step_session_init(&session,app_mask),114);struct li2_decoder_stats stats;need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&stats)&&stats.phase==2,115);
    p=RAW(SYS_mmap,0,STACK+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,116);stack_area=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),117);
    p=RAW(SYS_mmap,0,DATA,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,118);data_area=(uintptr_t)p;
    p=RAW(SYS_mmap,0,PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,119);fault_area=(uintptr_t)p;
    p=RAW(SYS_mmap,0,PAGE,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,120);guard=(uintptr_t)p;
    for(size_t i=0;i<DATA/8;i++)((uint64_t *)original_data)[i]=UINT64_C(0x123456789abcdef0)+(uint64_t)i*UINT64_C(0x102030405060708);
    for(unsigned i=0;i<16;i++)region_seed[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    region_seed[1]=trips;region_seed[4]=stack_area+PAGE+STACK-504;need((region_seed[4]&15)==8,151);region_seed[6]=fault_mode?fault_area:data_area;region_input_flags=0x202;
    for(size_t i=0;i<LOGICAL_STACK;i++)original_stack[i]=(unsigned char)(i*29+7);bytes(original_stack+128,&guard,8);
    make_source();authority_checks();prepare_input();selftest=1;region_target=source.at+PAGE-16;arm(region_target,region_input_flags,1);region_enter();need(ended&&session.self_test_complete&&step.step.phase==LI2_STEP_COMPLETE&&!step.step.first_error,121);selftest=0;
}
int main(int argc,char **argv){
    if(argc!=4)return 2;unroll=(unsigned)strtoul(argv[1],NULL,10);trips=(unsigned)strtoul(argv[2],NULL,10);fault_mode=(unsigned)strtoul(argv[3],NULL,10);
    if((unroll!=1&&unroll!=2&&unroll!=4)||(trips!=1&&trips!=16&&trips!=256)||fault_mode>2||(fault_mode&&(unroll!=4||trips!=1)))return 2;
    setup();singleton();
    if(fault_mode){(void)invoke_lane(0);need(current.logical_fault_pc==source.at+6&&current.exit.greg[REG_ERR]==4,122);qualified[0]=current;(void)invoke_lane(fault_mode==1?1:2);die(123);}
    for(unsigned l=0;l<3;l++){cold[l]=invoke_lane(l);check_success(l);qualified[l]=current;event_rows[l][0][0]=current.nx;event_rows[l][0][1]=current.trace;event_rows[l][0][2]=current.completed;event_rows[l][0][3]=current.guard_exits;}
    for(unsigned i=0;i<SAMPLES;i++)for(unsigned j=0;j<3;j++){unsigned l=(j+i)%3;hot[l][i]=invoke_lane(l);check_success(l);event_rows[l][i+1][0]=current.nx;event_rows[l][i+1][1]=current.trace;event_rows[l][i+1][2]=current.completed;event_rows[l][i+1][3]=current.guard_exits;}
    need(!region_callback_count(),124);retire();need(!first_error&&dump(),125);
    printf("{\"schema\":1,\"status\":\"passed_component\",\"unroll\":%u,\"trips\":%u,\"instructions\":%llu,\"prepare_ns\":%llu,\"cleanup\":1,\"callbacks\":0,\"cold_ns\":[",unroll,trips,(unsigned long long)(4+(uint64_t)trips*(4*unroll+2)),(unsigned long long)prepare_ns);
    for(unsigned l=0;l<3;l++)printf("%s%llu",l?",":"",(unsigned long long)cold[l]);printf("],\"hot_ns\":[");for(unsigned l=0;l<3;l++){printf("%s[",l?",":"");for(unsigned i=0;i<SAMPLES;i++)printf("%s%llu",i?",":"",(unsigned long long)hot[l][i]);printf("]");}printf("],\"events\":[");for(unsigned l=0;l<3;l++)printf("%s[%llu,%llu,%llu,%llu]",l?",":"",(unsigned long long)event_rows[l][0][0],(unsigned long long)event_rows[l][0][1],(unsigned long long)event_rows[l][0][2],(unsigned long long)event_rows[l][0][3]);puts("]}");return 0;
}
