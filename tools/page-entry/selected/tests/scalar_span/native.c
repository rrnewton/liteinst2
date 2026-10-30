/* Separate scalar-span component: original hardware TF reference versus
   generated hardware execution. Full actual state is compared; no production
   owner authority, guest-data prediction, fault resumption or timing credit. */
#define _GNU_SOURCE
#include "region_plan.h"
#include "machine.h"
#include "step_owner.h"
#include <asm/prctl.h>
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
#include <unistd.h>
#define PAGE 4096UL
#define DATA (2*PAGE)
#define STACK (128*1024UL)
#define ALT (512*1024UL)
#define LOGICAL_STACK 160UL
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


struct owned_mapping {uintptr_t at;size_t n;int fd;struct stat stat;unsigned char expected[PAGE];};
static struct owned_mapping source={.fd=-1},image={.fd=-1};
static struct li2_span_plan plan;
static struct li2_decoder_stats decoder_before,decoder_after;
static uintptr_t stack_area,data_area,alt_area,reservation,stack_fault;
static unsigned char original_data[DATA],original_stack[LOGICAL_STACK],original_operands[16];
static unsigned mode,lane,handling,started,ended,current_head;
static uint64_t app_mask,xsave_bytes,first_error,cleanup_done;
static uint64_t source_address,image_address,stack_address,data_address,alt_address;
static uint64_t reference_steps,exit_kind;
static uint64_t xlayout[64][3],head_checks,interior_misses,authority_checks;
static unsigned char decoder_arena[2*1024*1024] __attribute__((aligned(64)));
static char maps[256*1024];
static struct rseq rseq_probe __attribute__((aligned(32)));
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
struct observation {
    struct region_live before,after;
    unsigned char xbefore[REGION_FP],xafter[REGION_FP];
    struct li2_step_frame entry,exit;
    siginfo_t entry_si,exit_si;
    unsigned char stack[LOGICAL_STACK],data[DATA],operands[16];
    uint64_t trace[64];
    uint64_t meta[24]; /* lane,NX,TRACE,kind,raw/logicalPC,FS,GS,entry/exit,
       fault-address,head,source-offset,generated-offset,mask,restored-stack,
       expected-trace,whole-source-NX,whole-image-NX, before-FS/GS/mask,2 reserved */
};
static struct observation current,qualified[2];
_Static_assert(sizeof(struct observation)==272320,"actual object padding; wire explicitly emits 272288 bytes");
_Static_assert(sizeof(struct li2_span_plan)==57184,"complete actual plan");
_Static_assert(sizeof(struct li2_step_frame)==65792&&sizeof(siginfo_t)==128,"actual frame wire");
static int audit_mapping(const struct owned_mapping *,int);
static int dump(void);
static void retire(void);
static _Noreturn void die(unsigned code){if(!first_error)first_error=code;retire();(void)dump();(void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
static void need(int ok,unsigned code){if(!ok)die(code);}
_Noreturn void li2_decoder_abort(uint32_t code){die(1000+code);}
static uint32_t u32(const unsigned char *p){uint32_t x;bytes(&x,p,4);return x;}
static void sync_core(void){need(!RAW(SYS_membarrier,32,0,0,0,0,0),12);}
static void source_prot(int prot){need(!RAW(SYS_mprotect,source.at,source.n,prot,0,0,0),13);sync_core();need(audit_mapping(&source,prot),14);}
static void image_prot(int prot){need(!RAW(SYS_mprotect,image.at,image.n,prot,0,0,0),15);sync_core();need(audit_mapping(&image,prot),16);}
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
    /* Revoke both executable mappings before any return. Each independent
       cleanup is attempted; first error is never replaced by a later error. */
    if(source.at&&RAW(SYS_mprotect,source.at,source.n,PROT_READ,0,0,0)&&!first_error)first_error=90;
    if(image.at&&RAW(SYS_mprotect,image.at,image.n,PROT_NONE,0,0,0)&&!first_error)first_error=91;
    if((source.at||image.at)&&RAW(SYS_membarrier,32,0,0,0,0,0)&&!first_error)first_error=92;
    struct owned_mapping *owned[2]={&image,&source};
    for(unsigned i=0;i<2;i++){struct owned_mapping *m=owned[i];if(m->at){if(RAW(SYS_munmap,m->at,m->n,0,0,0,0)){if(!first_error)first_error=93;}else m->at=0;}if(m->fd>=0){if(RAW(SYS_close,m->fd,0,0,0,0,0)&&!first_error)first_error=94;m->fd=-1;}}
    if(handling)return; /* Failure on altstack exits nonreturningly, no false clean prefix. */
    if(reservation){if(RAW(SYS_munmap,reservation,2*PAGE,0,0,0,0)){if(!first_error)first_error=95;}else reservation=0;}
    if(data_area){if(RAW(SYS_munmap,data_area,DATA+PAGE,0,0,0,0)){if(!first_error)first_error=96;}else data_area=0;}
    if(stack_area){if(RAW(SYS_munmap,stack_area,STACK+2*PAGE,0,0,0,0)){if(!first_error)first_error=97;}else stack_area=0;}
    if(alt_area){stack_t disabled={.ss_flags=SS_DISABLE};if(RAW(SYS_sigaltstack,&disabled,0,0,0,0,0)){if(!first_error)first_error=98;}else if(RAW(SYS_munmap,alt_area,ALT+2*PAGE,0,0,0,0)){if(!first_error)first_error=99;}else alt_area=0;}
    cleanup_done=!first_error&&!source.at&&!image.at&&source.fd==-1&&image.fd==-1&&!reservation&&!data_area&&!stack_area&&!alt_area;
}
static void frame(struct li2_step_frame *out,const ucontext_t *uc){
    zero(out,sizeof(*out));bytes(out->greg,uc->uc_mcontext.gregs,sizeof(out->greg));bytes(&out->mask,&uc->uc_sigmask,8);
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;need(out->fp_address&&!(out->fp_address&15)&&out->fp_address>=alt_area+PAGE&&out->fp_address<=alt_area+PAGE+ALT-512,30);
    const unsigned char *p=(void *)out->fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)){n=u32(p+468);size_t x=u32(p+480);need(n>=580&&n<=REGION_FP&&n<=alt_area+PAGE+ALT-out->fp_address&&x>=576&&x==n-4&&u32(p+n-4)==UINT32_C(0x46505845),31);uint64_t comp;bytes(&comp,p+520,8);need(!comp,32);}
    out->fp_bytes=n;bytes(out->fp,p,n);out->initialized=n;need(out->mask==app_mask,33);
}

static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc){return sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==pc&&(uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==14&&g[REG_ERR]==21&&(uintptr_t)g[REG_CR2]==pc;}
#include "puzzles.h"
static uintptr_t fault_address(void){return data_address+DATA;}
static unsigned head_at(uintptr_t pc){for(unsigned i=0;i<heads;i++)if(pc==source.at+SPAN_ENTRY+offsets[i])return i;return heads;}
static unsigned exit_at(uintptr_t pc){return pc==source.at+SPAN_ENTRY+body_bytes?0:1;}
static void finish_event(ucontext_t *uc,const siginfo_t *si,unsigned kind,uintptr_t logical,unsigned head){
    need(started&&!ended,40);frame(&current.exit,uc);bytes(&current.exit_si,si,sizeof(*si));
    current.meta[3]=kind;current.meta[4]=(uint64_t)uc->uc_mcontext.gregs[REG_RIP];current.meta[5]=logical;
    current.meta[9]=1;current.meta[10]=kind==2?(uintptr_t)si->si_addr:0;current.meta[11]=head;
    current.meta[12]=kind==2?SPAN_ENTRY+offsets[head]:(unsigned)(logical-source.at);
    current.meta[13]=kind==2?generated_offsets[head]:UINT64_MAX;
    /* Capture the genuine terminal frame first; revoke executable ownership
       before restoring read access solely for post-terminal byte observation. */
    if(!lane)source_prot(PROT_READ);else image_prot(PROT_READ);
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ),41);
    current.meta[17]=current.meta[18]=1;
    if(stack_fault){need(!RAW(SYS_mprotect,stack_fault,PAGE,PROT_READ,0,0,0),42);need(mapping_rows(stack_fault,PAGE,PROT_READ,NULL),43);current.meta[15]=1;}
    if(!lane)uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)LI2_STEP_TF;
    else need(!(uc->uc_mcontext.gregs[REG_EFL]&LI2_STEP_TF),44);
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)region_capture;ended=1;
}
static void handler(int sig,siginfo_t *si,void *ptr){
    need(!handling&&si&&ptr,45);handling=1;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(!started){
        need(nx(sig,si,g,plan.entry)&&!ended&&audit_mapping(&source,PROT_READ)&&audit_mapping(&image,lane?PROT_READ|PROT_EXEC:PROT_READ),46);
        frame(&current.entry,uc);bytes(&current.entry_si,si,sizeof(*si));current.meta[1]++;current.meta[8]=1;started=1;current_head=0;
        need((uint64_t)g[REG_EFL]==(region_input_flags|LI2_STEP_RF),47);
        if(!lane){source_prot(PROT_READ|PROT_EXEC);g[REG_EFL]|=LI2_STEP_TF;}else g[REG_RIP]=(greg_t)plan.generated;
        handling=0;return;
    }
    if(!lane&&sig==SIGTRAP){
        need(si->si_code==TRAP_TRACE&&!si->si_errno&&g[REG_TRAPNO]==1&&!g[REG_ERR]&&(g[REG_EFL]&LI2_STEP_TF)&&reference_steps<heads&&current_head<heads,48);
        const struct li2_region_head *h=&plan.head[current_head];unsigned matched=0;
        for(unsigned j=0;j<h->successor_count;j++){unsigned k=h->successors[j];uintptr_t next=k<heads?source.at+plan.head[k].source_offset:plan.exit_pc[k-LI2_REGION_HEADS];if(pc==next)matched++;}
        need(matched==1,49);current.trace[reference_steps++]=pc;current.meta[2]++;
        unsigned at=exit_at(pc);if(at==0){need(!faulted&&reference_steps==expected_steps,50);exit_kind=1;finish_event(uc,si,1,pc,current_head);handling=0;return;}
        current_head=head_at(pc);need(current_head<heads,51);handling=0;return;
    }
    unsigned at=exit_at(pc);
    if(lane&&at==0&&nx(sig,si,g,pc)){
        need(!faulted&&!current.meta[2],52);current.meta[1]++;exit_kind=1;
        unsigned last=heads-1;
        finish_event(uc,si,1,pc,last);handling=0;return;
    }
    if(faulted&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==fault_address()&&g[REG_TRAPNO]==14&&g[REG_ERR]==4&&(uintptr_t)g[REG_CR2]==fault_address()){
        unsigned head=fault_head;struct li2_region_pc association;
        if(!lane)need(pc==plan.entry+offsets[head]&&current_head==head&&reference_steps==expected_steps&&(g[REG_EFL]&LI2_STEP_TF),53);
        else need(!li2_span_map_pc(&plan,pc,&association)&&association.kind==LI2_SPAN_PC_RIP_RELOCATED&&association.head_index==head&&association.source_offset==SPAN_ENTRY+offsets[head]&&association.source_length==lengths[head]&&association.generated_length==lengths[head]&&association.original_pc==plan.entry+offsets[head]&&association.generated_pc==plan.generated+generated_offsets[head]&&!current.meta[2],54);
        exit_kind=2;finish_event(uc,si,2,plan.entry+offsets[head],head);handling=0;return;
    }
    die(55);
}
static void prepare_input(void){
    zero(&current,sizeof(current));zero(&region_before,sizeof(region_before));zero(&region_after,sizeof(region_after));zero(region_fp_before,REGION_FP);zero(region_fp_after,REGION_FP);
    /* Reset all actually compared bytes before either lane, with no skipped
       operand or inaccessible-stack byte. Only permissions differ while live. */
    need(!RAW(SYS_mprotect,stack_area+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),56);
    bytes((void *)data_area,original_data,DATA);bytes((void *)(region_seed[4]-128),original_stack,LOGICAL_STACK);bytes((void *)(region_seed[4]+0x50),original_operands,16);
    if(stack_fault)need(!RAW(SYS_mprotect,stack_fault,PAGE,PROT_NONE,0,0,0)&&mapping_rows(stack_fault,PAGE,PROT_NONE,NULL),57);
    started=ended=handling=current_head=0;reference_steps=exit_kind=0;region_target=plan.entry;
}
static void invoke(unsigned which){
    lane=which;prepare_input();need(!li2_span_plan_validate(&plan),58);need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ),59);
    if(which)image_prot(PROT_READ|PROT_EXEC);
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[19],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[20],0,0,0,0)&&!RAW(SYS_rt_sigprocmask,0,0,&current.meta[21],8,0,0),76);
    region_enter();need(started&&ended&&!handling,60);bytes(&current.before,&region_before,sizeof(region_before));bytes(&current.after,&region_after,sizeof(region_after));
    bytes(current.xbefore,region_fp_before,REGION_FP);bytes(current.xafter,region_fp_after,REGION_FP);bytes(current.stack,(void *)(region_seed[4]-128),LOGICAL_STACK);bytes(current.data,(void *)data_area,DATA);bytes(current.operands,(void *)(region_seed[4]+0x50),16);
    current.meta[0]=lane;current.meta[16]=expected_steps;need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[6],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[7],0,0,0,0)&&!RAW(SYS_rt_sigprocmask,0,0,&current.meta[14],8,0,0),61);
}
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


static void check_observation(unsigned which){
    need(current.meta[3]==(faulted?2:1)&&current.meta[8]==1&&current.meta[9]==1&&current.meta[14]==app_mask&&current.meta[16]==expected_steps&&current.meta[17]==1&&current.meta[18]==1&&current.meta[19]==current.meta[6]&&current.meta[20]==current.meta[7]&&current.meta[21]==app_mask,62);
    need(current.meta[1]==(which&&!faulted?2:1)&&current.meta[2]==(which?0:expected_steps)&&current.meta[15]==(uint64_t)(stack_fault!=0),63);
    check_seed(current.xbefore);check_seed(current.xafter);check_seed(current.entry.fp);check_seed(current.exit.fp);
    need(current.before.flags==region_input_flags&&!current.before.reserved&&!current.after.reserved&&same(current.before.selectors,current.after.selectors,sizeof(current.before.selectors)),64);
    uint64_t selectors=(uint64_t)current.before.selectors[0]|(uint64_t)current.before.selectors[5]<<16|(uint64_t)current.before.selectors[4]<<32|(uint64_t)current.before.selectors[1]<<48;
    need((uint64_t)current.entry.greg[REG_CSGSFS]==selectors&&(uint64_t)current.exit.greg[REG_CSGSFS]==selectors,77);
    need(same(current.xbefore,current.xafter,REGION_FP)&&same(current.stack,original_stack,LOGICAL_STACK)&&same(current.data,original_data,DATA)&&same(current.operands,original_operands,16),65);
    for(unsigned i=0;i<16;i++)need(current.before.gpr[i]==region_seed[i]&&(uint64_t)current.entry.greg[regs[i]]==region_seed[i]&&current.after.gpr[i]==(uint64_t)current.exit.greg[regs[i]],66);
    need((uint64_t)current.entry.greg[REG_RIP]==plan.entry&&(uint64_t)current.entry.greg[REG_EFL]==(region_input_flags|LI2_STEP_RF)&&current.entry.greg[REG_TRAPNO]==14&&current.entry.greg[REG_ERR]==21&&(uint64_t)current.entry.greg[REG_CR2]==plan.entry,67);
    need(current.entry.fp_bytes==current.exit.fp_bytes&&same(current.entry.fp,current.exit.fp,REGION_FP)&&current.entry.mask==current.exit.mask,68);
    /* Full actual flags, AF included. Only the actual reference TF and
       kernel-origin RF are absent after the architectural capture JMP. */
    need((uint64_t)current.exit.greg[REG_EFL]==(current.after.flags|(which||faulted?LI2_STEP_RF:LI2_STEP_TF)|(!which&&faulted?LI2_STEP_TF:0))&&!(current.after.flags&(LI2_STEP_RF|LI2_STEP_TF)),69);
    if(which){const struct observation *n=&qualified[0];
        need(same(&current.before,&n->before,sizeof(n->before))&&same(&current.after,&n->after,sizeof(n->after))&&same(current.xbefore,n->xbefore,REGION_FP)&&same(current.xafter,n->xafter,REGION_FP),70);
        need(current.exit.fp_bytes==n->exit.fp_bytes&&same(current.exit.fp,n->exit.fp,REGION_FP)&&current.exit.mask==n->exit.mask&&current.meta[6]==n->meta[6]&&current.meta[7]==n->meta[7]&&current.meta[14]==n->meta[14],71);
        for(unsigned i=0;i<NGREG;i++){uint64_t want=(uint64_t)n->exit.greg[i];
            if(faulted){if(i==REG_RIP)want=plan.generated+generated_offsets[fault_head];if(i==REG_EFL)want&=~LI2_STEP_TF;}
            else {if(i==REG_EFL)want=(want&~LI2_STEP_TF)|LI2_STEP_RF;if(i==REG_ERR)want=21;if(i==REG_TRAPNO)want=14;if(i==REG_CR2)want=current.meta[5];}
            need((uint64_t)current.exit.greg[i]==want,72);}
        if(faulted)need(current.exit_si.si_signo==n->exit_si.si_signo&&current.exit_si.si_errno==n->exit_si.si_errno&&current.exit_si.si_code==n->exit_si.si_code&&current.exit_si.si_addr==n->exit_si.si_addr,73);
    }
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ)&&!li2_span_plan_validate(&plan),74);
}
static void plan_checks(void){
    unsigned size=generated_offsets[heads-1]+lengths[heads-1]+5;
    need(plan.version==1&&plan.ready==1&&plan.heads==heads&&plan.exits==1&&plan.maps==heads+1&&plan.stop_reason==LI2_REGION_STOP_UNSUPPORTED&&plan.source_bytes==body_bytes&&plan.image_bytes==size&&plan.decoder_calls==2*heads+2&&!plan.decoder_result&&plan.page==source.at&&plan.entry==source.at+SPAN_ENTRY&&plan.generated==image_address&&plan.boundary_pc==source.at+SPAN_ENTRY+body_bytes&&same(plan.source,source.expected,PAGE),160);
    need(plan.exit_pc[0]==plan.boundary_pc,162);
    for(unsigned i=0;i<heads;i++)need(plan.head[i].source_offset==SPAN_ENTRY+offsets[i]&&plan.head[i].source_length==lengths[i]&&plan.head[i].generated_offset==generated_offsets[i],161);
    for(unsigned at=0;at<plan.image_bytes;at++){struct li2_region_pc pc,empty={0};unsigned row=0;while(row<plan.maps&&plan.map[row].generated_offset!=at)row++;int result=li2_span_map_pc(&plan,image_address+at,&pc);
        if(row<plan.maps){need(!result&&same(&pc,&plan.map[row],sizeof(pc)),163);head_checks++;}
        else{need(result==LI2_REGION_PLAN_MISS&&same(&pc,&empty,sizeof(pc)),164);interior_misses++;}}
    need(head_checks==plan.maps&&interior_misses==plan.image_bytes-plan.maps,165);
}
static void authority_controls(void){
    for(unsigned i=0;i<2;i++){struct owned_mapping *m=i?&image:&source;long alias=RAW(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,m->fd,0);need(alias>0,166);need(!audit_mapping(m,PROT_READ),167);authority_checks++;need(!RAW(SYS_munmap,alias,PAGE,0,0,0,0)&&audit_mapping(m,PROT_READ),168);unsigned char value=0;need(RAW(SYS_pwrite64,m->fd,&value,1,0,0,0)==-EPERM,169);authority_checks++;}
}
static void make_source(void){
    long p=RAW(SYS_mmap,0,2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,170);reservation=(uintptr_t)p;source_address=reservation;image_address=reservation+PAGE;
    need(!RAW(SYS_munmap,reservation,2*PAGE,0,0,0,0),171);reservation=0;
    puzzle();sealed(&source,source_page,PAGE,source_address,PROT_READ);
    need(!li2_span_plan_page(source.at,(void *)source.at,source.at+SPAN_ENTRY,image_address,&plan),172);plan_checks();
    sealed(&image,plan.image,PAGE,image_address,PROT_READ);need(source.at+PAGE==image.at,173);authority_controls();
}
static void setup(void){
    need(getauxval(AT_PAGESZ)==PAGE&&RAW(SYS_getpid,0,0,0,0,0,0)==RAW(SYS_gettid,0,0,0,0,0,0),100);singleton();
    need(!RAW(SYS_rseq,&rseq_probe,sizeof(rseq_probe),0,UINT32_C(0x53053053),0,0)&&!RAW(SYS_rseq,&rseq_probe,sizeof(rseq_probe),RSEQ_FLAG_UNREGISTER,UINT32_C(0x53053053),0,0),101);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));need((c&0x0c000000)==0x0c000000,102);a=d=0;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0));region_xcr0=(uint64_t)d<<32|a;need((region_xcr0&0xe7)==0xe7,103);a=7;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));need((b&((1U<<16)|(1U<<30)))==((1U<<16)|(1U<<30)),104);a=13;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));xsave_bytes=b;need(xsave_bytes>=576&&xsave_bytes<=REGION_FP,105);
    for(unsigned k=2;k<64;k++)if(region_xcr0&(UINT64_C(1)<<k)){a=13;c=k;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));need(a&&b>=576&&(uint64_t)b+a<=xsave_bytes&&!(c&1),126);xlayout[k][0]=1;xlayout[k][1]=b;xlayout[k][2]=a;}
    unsigned long cet=0;long cr=RAW(SYS_arch_prctl,0x5005,&cet,0,0,0,0);need((!cr&&!cet)||cr==-EINVAL||cr==-ENOSYS,106);
    uint64_t initial=1;need(!RAW(SYS_rt_sigprocmask,0,0,&initial,8,0,0)&&!initial,107);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action,old;
    for(int sig=1;sig<=64;sig++)if(sig!=SIGKILL&&sig!=SIGSTOP)need(!RAW(SYS_rt_sigaction,sig,0,&old,8,0,0)&&!old.handler,108);
    app_mask=UINT64_MAX&~((UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGTRAP-1))|(UINT64_C(1)<<(SIGSYS-1))|(UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));need(!RAW(SYS_rt_sigprocmask,2,&app_mask,0,8,0,0),109);
    long q=RAW(SYS_membarrier,0,0,0,0,0,0);need(q>=0&&(q&96)==96&&!RAW(SYS_membarrier,64,0,0,0,0,0),110);
    long p=RAW(SYS_mmap,0,ALT+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,111);alt_area=alt_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,ALT,PROT_READ|PROT_WRITE,0,0,0),112);stack_t alt={.ss_sp=(void *)(p+PAGE),.ss_size=ALT};need(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),113);
    action.handler=handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;action.restorer=region_restorer;action.mask=app_mask;for(unsigned i=0;i<3;i++){int sig=(int[]){SIGSEGV,SIGTRAP,SIGSYS}[i];need(!RAW(SYS_rt_sigaction,sig,&action,0,8,0,0),114);}
    need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&decoder_before)&&decoder_before.abi_version==1&&decoder_before.phase==2&&!decoder_before.first_fatal_reason&&!decoder_before.reserved&&decoder_before.arena_bytes==sizeof(decoder_arena)&&decoder_before.retained_high_water&&decoder_before.retained_high_water<=sizeof(decoder_arena),115);
    p=RAW(SYS_mmap,0,STACK+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,116);stack_area=stack_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),117);
    p=RAW(SYS_mmap,0,DATA+PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,118);data_area=data_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p,DATA,PROT_READ|PROT_WRITE,0,0,0),119);

    for(size_t i=0;i<DATA;i++)original_data[i]=(unsigned char)(1+(i*17)%255);
    for(unsigned i=0;i<16;i++)region_seed[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    region_seed[0]=UINT64_C(0xfedcba9880000001);region_seed[1]=3;
    region_seed[2]=mode==2?data_area+DATA:data_area+512;
    region_seed[3]=UINT64_C(0x8877665544332211);
    region_seed[4]=stack_area+PAGE+STACK-504;
    if(mode==6||mode==7)region_seed[0]=mode==6?0:1;
    if(mode>=10){unsigned group=(mode-10)/8,variant=(mode-10)%8,width=group%2?64:32;
        region_seed[1]=variant==6?width:UINT64_C(0xfedcba988000003f);}
    need((region_seed[4]&15)==8&&region_seed[4]-128>=stack_area+PAGE&&region_seed[4]+0x60<=stack_area+PAGE+STACK,120);
    for(size_t i=0;i<LOGICAL_STACK;i++)original_stack[i]=(unsigned char)(i*29+7);
    uint64_t one=UINT64_C(0x8877665544332211),two=UINT64_C(0x1122334455667788);
    bytes(original_operands,&one,8);bytes(original_operands+8,&two,8);
    region_input_flags=mode%2?0x202:0xad7;
    make_source();
}
static int dump_observation(const struct observation *o){return write_all(3,&o->before,sizeof(o->before))&&write_all(3,&o->after,sizeof(o->after))&&write_all(3,o->xbefore,REGION_FP)&&write_all(3,o->xafter,REGION_FP)&&write_all(3,&o->entry,sizeof(o->entry))&&write_all(3,&o->exit,sizeof(o->exit))&&write_all(3,&o->entry_si,sizeof(o->entry_si))&&write_all(3,&o->exit_si,sizeof(o->exit_si))&&write_all(3,o->stack,LOGICAL_STACK)&&write_all(3,o->data,DATA)&&write_all(3,o->operands,16)&&write_all(3,o->trace,sizeof(o->trace))&&write_all(3,o->meta,sizeof(o->meta));}
static int dump(void){
    uint64_t h[48]={UINT64_C(0x314e50534332494c),1,48,mode,first_error,cleanup_done,region_xcr0,xsave_bytes,source_address,image_address,stack_address,data_address,alt_address,app_mask,sizeof(plan),sizeof(struct li2_step_frame),REGION_FP,DATA,LOGICAL_STACK,2,authority_checks,head_checks,interior_misses,region_input_flags,expected_steps,faulted,(uint64_t)source.stat.st_ino,(uint64_t)source.stat.st_dev,(uint64_t)image.stat.st_ino,(uint64_t)image.stat.st_dev,SEALS,0,region_seed[4]+0x50,region_seed[4]+0x58,faulted?fault_address():0,faulted?source_address+SPAN_ENTRY+offsets[fault_head]:source_address+SPAN_ENTRY+body_bytes,UINT64_C(272288),sizeof(decoder_before),heads,plan.blocks,1,plan.image_bytes,body_bytes,plan.maps,interior_misses,0,0,0};
    return write_all(3,h,sizeof(h))&&write_all(3,region_seed,sizeof(region_seed))&&write_all(3,xlayout,sizeof(xlayout))&&write_all(3,&decoder_before,sizeof(decoder_before))&&write_all(3,&decoder_after,sizeof(decoder_after))&&write_all(3,source.expected,PAGE)&&write_all(3,image.expected,PAGE)&&write_all(3,&plan,sizeof(plan))&&dump_observation(&qualified[0])&&dump_observation(&qualified[1]);
}
int main(int argc,char **argv){
    if(argc!=2)return 2;char *end;unsigned long value=strtoul(argv[1],&end,10);char canonical[16];snprintf(canonical,sizeof(canonical),"%lu",value);if(strcmp(canonical,argv[1])||*end||value>=SPAN_NATIVE_MODES)return 2;mode=(unsigned)value;setup();
    for(unsigned l=0;l<2;l++){invoke(l);check_observation(l);bytes(&qualified[l],&current,sizeof(current));}
    need(!li2_decoder_stats(&decoder_after)&&same(&decoder_before,&decoder_after,sizeof(decoder_before)),175);
    retire();need(cleanup_done&&!first_error&&dump(),122);
    printf("{\"schema\":1,\"mode\":%u,\"qualified_comparison\":1,\"completed_path\":%u,\"required_read_failure\":%u,\"cleanup\":1,\"reference_trace\":%llu,\"generated_trace\":0,\"exit_kind\":%u,\"authority_controls\":%llu,\"head_checks\":%llu,\"interior_misses\":%llu,\"postseal_equal\":1}\n",mode,!faulted,faulted,(unsigned long long)qualified[0].meta[2],faulted?2:1,(unsigned long long)authority_checks,(unsigned long long)head_checks,(unsigned long long)interior_misses);fflush(stdout);
    return faulted?125:0;
}
