/* Distinct bounded-unroll component oracle. The original lane uses an
   explicit TF observer solely to stop the same hardware loop after64 copies.
   The generated lane has no TF and reads data only through actual MOVZX.
   No production owner, fault resumption, whole-loop termination or timing claim. */
#define _GNU_SOURCE
#include "unrolled_hash.h"
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
static struct li2_unrolled_hash_plan plan;
static uintptr_t stack_area,data_area,alt_area,reservation;
static unsigned char original_data[DATA],original_stack[LOGICAL_STACK];
static unsigned mode,lane,handling,started,ended;
static uint64_t app_mask,xsave_bytes,first_error,cleanup_done;
static uint64_t source_address,image_address,stack_address,data_address,alt_address;
static uint64_t expected_pc,reference_steps,original_copies,exit_kind;
static uint64_t xlayout[64][3],negative_controls,head_checks,interior_misses;
static unsigned char decoder_arena[2*1024*1024] __attribute__((aligned(64)));
static char maps[256*1024];
static struct rseq rseq_probe __attribute__((aligned(32)));
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static const unsigned offsets[8]={0,3,7,11,14,17,20,22};
static const unsigned char literal[39]={0x48,0x89,0xd8,0x48,0x83,0xc1,0x01,0x48,0xc1,0xe0,0x05,0x48,0x01,0xc3,0x48,0x01,0xd3,0x0f,0xb6,0x11,0x84,0xd2,0x75,0xe8,0x89,0xdb,0x48,0x83,0x05,0xee,0xe4,0x02,0x00,0x01,0xb8,0xff,0xff,0xff,0xff};
/* Each mode runs hardware original followed by generated, with identical input.
   mode4 exits at head after64; it does not reach the NUL65 or complete a loop. */
static const unsigned nul_at[9]={1,2,63,64,65,2,64,0,0};
static const unsigned completed[9]={1,2,63,64,64,2,64,0,63};
struct observation {
    struct region_live before,after;
    unsigned char xbefore[REGION_FP],xafter[REGION_FP];
    struct li2_step_frame entry,exit;
    siginfo_t entry_si,exit_si;
    unsigned char stack[LOGICAL_STACK],data[DATA];
    uint64_t meta[16]; /* lane,NX,TRACE,completed-copies,exit-kind,raw/logical PC,
       FS,GS,entry/exit observed,generated-copy,source-offset,PF address,2 reserved */
};
static struct observation current,qualified[2];
_Static_assert(sizeof(struct li2_unrolled_hash_plan)==2528,"fixed complete plan wire");
_Static_assert(sizeof(struct li2_step_frame)==65792&&sizeof(siginfo_t)==128,"fixed frame wire");
static int audit_mapping(const struct owned_mapping *,int);
static int dump(void);
static void retire(void);
static _Noreturn void die(unsigned code){if(!first_error)first_error=code;retire();(void)dump();(void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
static void need(int ok,unsigned code){if(!ok)die(code);}
_Noreturn void li2_decoder_abort(uint32_t code){die(1000+code);}
static uint32_t u32(const unsigned char *p){uint32_t x;bytes(&x,p,4);return x;}
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
static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc){return sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==pc&&(uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==14&&g[REG_ERR]==21;}
static void finish_event(ucontext_t *uc,const siginfo_t *si,unsigned kind,uintptr_t logical,unsigned copy){
    need(started&&!ended,40);frame(&current.exit,uc);bytes(&current.exit_si,si,sizeof(*si));
    current.meta[4]=kind;current.meta[5]=(uint64_t)uc->uc_mcontext.gregs[REG_RIP];current.meta[6]=logical;
    current.meta[10]=1;current.meta[11]=copy;current.meta[12]=kind==3?17:22;current.meta[13]=kind==3?(uintptr_t)si->si_addr:0;
    if(!lane)source_prot(PROT_READ);else need(audit_mapping(&source,PROT_READ),41);
    /* Reference-only observer bit. Raw original TF frame above is retained.
       No AF/RF/status bit or FP byte is rewritten. Generated TF must be zero. */
    if(!lane)uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)LI2_STEP_TF;
    else need(!(uc->uc_mcontext.gregs[REG_EFL]&LI2_STEP_TF),42);
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)region_capture;ended=1;
}
static void handler(int sig,siginfo_t *si,void *ptr){
    need(!handling&&si&&ptr,43);handling=1;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(!started){
        need(nx(sig,si,g,source.at)&&!ended&&audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ|PROT_EXEC),44);
        frame(&current.entry,uc);bytes(&current.entry_si,si,sizeof(*si));current.meta[1]++;current.meta[9]=1;started=1;
        need((uint64_t)g[REG_EFL]==(region_input_flags|LI2_STEP_RF),45);
        if(!lane){source_prot(PROT_READ|PROT_EXEC);expected_pc=source.at+3;g[REG_EFL]|=LI2_STEP_TF;}
        else g[REG_RIP]=(greg_t)plan.entry;
        handling=0;return;
    }
    if(!lane&&sig==SIGTRAP){
        need(si->si_code==TRAP_TRACE&&!si->si_errno&&g[REG_TRAPNO]==1&&!g[REG_ERR]&&(g[REG_EFL]&LI2_STEP_TF)&&reference_steps<512,46);
        unsigned index=(unsigned)(reference_steps%8);
        if(index!=7)need(pc==expected_pc,47);
        else need(pc==source.at||pc==source.at+24,48);
        reference_steps++;current.meta[2]++;
        if(index==7){original_copies++;if(pc==source.at+24||original_copies==64){exit_kind=pc==source.at+24?2:1;finish_event(uc,si,(unsigned)exit_kind,pc,original_copies-1);handling=0;return;}}
        unsigned next=(unsigned)(reference_steps%8);expected_pc=next==7?0:source.at+offsets[next+1];
        handling=0;return;
    }
    if(lane&&(nx(sig,si,g,source.at)||nx(sig,si,g,source.at+24))){
        need(!current.meta[2],49);current.meta[1]++;exit_kind=pc==source.at?1:2;
        uint64_t delta=(uint64_t)g[REG_RCX]-region_seed[1];need(delta>=1&&delta<=64&&(exit_kind!=1||delta==64),50);original_copies=delta;
        finish_event(uc,si,(unsigned)exit_kind,pc,(unsigned)delta-1);handling=0;return;
    }
    if(mode>=7&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==data_area+DATA&&g[REG_TRAPNO]==14&&g[REG_ERR]==4){
        struct li2_unrolled_hash_pc association;unsigned copy=completed[mode];
        if(!lane)need(pc==source.at+17&&reference_steps==(uint64_t)copy*8+5&&(g[REG_EFL]&LI2_STEP_TF),51);
        else need(!li2_unrolled_hash_map_pc(&plan,pc,&association)&&association.kind==LI2_UNROLLED_HASH_COPIED_INSTRUCTION&&association.copy_index==copy&&association.source_offset==17&&association.source_length==3&&association.generated_length==3&&association.original_pc==source.at+17&&!current.meta[2],52);
        original_copies=copy;exit_kind=3;finish_event(uc,si,3,source.at+17,copy);handling=0;return;
    }
    die(53);
}
static void prepare_input(void){
    zero(&current,sizeof(current));zero(&region_before,sizeof(region_before));zero(&region_after,sizeof(region_after));zero(region_fp_before,REGION_FP);zero(region_fp_after,REGION_FP);
    bytes((void *)data_area,original_data,DATA);bytes((void *)(region_seed[4]-128),original_stack,LOGICAL_STACK);
    started=ended=handling=0;reference_steps=original_copies=exit_kind=0;region_target=source.at;
}
static void invoke(unsigned which){
    lane=which;prepare_input();need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ|PROT_EXEC),54);
    region_enter();need(started&&ended&&!handling,55);current.before=region_before;current.after=region_after;
    bytes(current.xbefore,region_fp_before,REGION_FP);bytes(current.xafter,region_fp_after,REGION_FP);bytes(current.stack,(void *)(region_seed[4]-128),LOGICAL_STACK);bytes(current.data,(void *)data_area,DATA);
    current.meta[0]=lane;current.meta[3]=original_copies;need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[7],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[8],0,0,0,0),56);
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
    need(current.meta[3]==completed[mode]&&current.meta[4]==(mode>=7?3:mode==4?1:2)&&current.meta[9]==1&&current.meta[10]==1,60);
    need(current.meta[1]==(which&&mode<7?2:1)&&current.meta[2]==(which?0:(uint64_t)completed[mode]*8+(mode>=7?5:0)),61);
    check_seed(current.xbefore);check_seed(current.xafter);
    need(current.before.flags==region_input_flags&&!current.before.reserved&&!current.after.reserved&&same(current.before.selectors,current.after.selectors,sizeof(current.before.selectors)),62);
    need(same(current.xbefore,current.xafter,REGION_FP)&&same(current.stack,original_stack,LOGICAL_STACK)&&same(current.data,original_data,DATA),63);
    for(unsigned i=0;i<16;i++){need(current.before.gpr[i]==region_seed[i]&&(uint64_t)current.entry.greg[regs[i]]==region_seed[i]&&current.after.gpr[i]==(uint64_t)current.exit.greg[regs[i]],64);if(i!=0&&i!=1&&i!=2&&i!=3)need(current.after.gpr[i]==region_seed[i],65);}
    need((uint64_t)current.entry.greg[REG_RIP]==source.at&&(uint64_t)current.entry.greg[REG_EFL]==(region_input_flags|LI2_STEP_RF)&&current.entry.greg[REG_TRAPNO]==14&&current.entry.greg[REG_ERR]==21,66);
    need(current.entry.fp_bytes==current.exit.fp_bytes&&same(current.entry.fp,current.exit.fp,REGION_FP)&&current.entry.mask==current.exit.mask,67);
    /* Full actual flags including undefined AF: no arithmetic flags model. */
    need((uint64_t)current.exit.greg[REG_EFL]==(current.after.flags|(which||mode>=7?LI2_STEP_RF:LI2_STEP_TF)|(!which&&mode>=7?LI2_STEP_TF:0)),68);
    /* Independent unsigned recurrence only for defined GPR effects. */
    uint64_t a=region_seed[0],b=region_seed[3],c=region_seed[1],d=region_seed[2];unsigned iterations=completed[mode]+(mode>=7?1:0);
    for(unsigned i=0;i<iterations;i++){a=b;c++;a<<=5;b+=a;b+=d;if(mode>=7&&i+1==iterations)break;need(c>=data_area&&c<data_area+DATA,69);d=original_data[c-data_area];}
    need(current.after.gpr[0]==a&&current.after.gpr[1]==c&&current.after.gpr[2]==d&&current.after.gpr[3]==b,70);
    if(which){const struct observation *n=&qualified[0];need(same(&current.before,&n->before,sizeof(n->before))&&same(&current.after,&n->after,sizeof(n->after))&&same(current.xbefore,n->xbefore,REGION_FP)&&same(current.xafter,n->xafter,REGION_FP),71);
        need(current.exit.fp_bytes==n->exit.fp_bytes&&same(current.exit.fp,n->exit.fp,REGION_FP)&&current.exit.mask==n->exit.mask&&current.meta[7]==n->meta[7]&&current.meta[8]==n->meta[8],72);
        /* Hardware original and cache signals differ by expected event type,
           raw RIP and the reference TF. Compare all16 actual GPRs, full flags
           via after-live above, full selectors/mask/FP, and real PF metadata. */
        if(mode>=7){for(unsigned i=0;i<NGREG;i++){uint64_t want=(uint64_t)n->exit.greg[i];if(i==REG_RIP)want=plan.entry+(uint64_t)completed[mode]*28+17;if(i==REG_EFL)want&=~LI2_STEP_TF;need((uint64_t)current.exit.greg[i]==want,73);}need(current.exit_si.si_signo==n->exit_si.si_signo&&current.exit_si.si_errno==n->exit_si.si_errno&&current.exit_si.si_code==n->exit_si.si_code&&current.exit_si.si_addr==n->exit_si.si_addr,74);}}
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ|PROT_EXEC),75);
}
static void supplied_controls(void){
    if(mode)return;struct li2_unrolled_hash_pc pc;unsigned lengths[8]={3,4,4,3,3,3,2,6};
    for(unsigned at=0;at<1797;at++){unsigned index=8,copy=at/28,off=at%28;for(unsigned j=0;j<8;j++)if(copy<64&&off==offsets[j])index=j;int head=index<8||at==1792;int result=li2_unrolled_hash_map_pc(&plan,plan.entry+at,&pc);
        if(head){need(!result&&pc.ready==1&&pc.version==1&&!pc.reserved&&pc.generated_pc==plan.entry+at&&pc.original_pc==source.at+(at==1792?22:offsets[index])&&pc.copy_index==(at==1792?63:copy)&&pc.source_length==(at==1792||index==7?2:lengths[index])&&pc.generated_length==(at==1792?5:lengths[index])&&pc.kind==(at==1792?3:index==7?2:1),160);head_checks++;}
        else{struct li2_unrolled_hash_pc empty={0};need(result==LI2_UNROLLED_HASH_MISS&&same(&pc,&empty,sizeof(pc)),161);interior_misses++;}}
    need(head_checks==513&&interior_misses==1284,162);
    struct li2_unrolled_hash_plan p;unsigned char input[39];
#define REFUSE(expr,want) do{need((expr)==(want),163);negative_controls++;}while(0)
    for(unsigned i=0;i<26;i++){bytes(input,literal,39);input[i]^=1;REFUSE(li2_unrolled_hash_plan_bytes(source.at,input,39,image.at,&p),LI2_UNROLLED_HASH_MISS);need(!p.ready,164);}
    REFUSE(li2_unrolled_hash_plan_bytes(source.at,literal,38,image.at,&p),LI2_UNROLLED_HASH_ARGUMENT);
    REFUSE(li2_unrolled_hash_plan_bytes(source.at,literal,40,image.at,&p),LI2_UNROLLED_HASH_ARGUMENT);
    REFUSE(li2_unrolled_hash_plan_bytes(source.at,literal,39,image.at,NULL),LI2_UNROLLED_HASH_ARGUMENT);
    REFUSE(li2_unrolled_hash_plan_bytes(UINTPTR_MAX-20,literal,39,image.at,&p),LI2_UNROLLED_HASH_ARGUMENT);
    REFUSE(li2_unrolled_hash_plan_bytes(source.at,literal,39,source.at+UINT64_C(0x80001000),&p),LI2_UNROLLED_HASH_MISS);
    REFUSE(li2_unrolled_hash_plan_bytes(source.at,literal,39,source.at-UINT64_C(0x80001000),&p),LI2_UNROLLED_HASH_MISS);
    REFUSE(li2_unrolled_hash_map_pc(&plan,plan.entry-1,&pc),LI2_UNROLLED_HASH_MISS);
    REFUSE(li2_unrolled_hash_map_pc(&plan,plan.entry+1797,&pc),LI2_UNROLLED_HASH_MISS);
    REFUSE(li2_unrolled_hash_map_pc(NULL,plan.entry,&pc),LI2_UNROLLED_HASH_ARGUMENT);
    REFUSE(li2_unrolled_hash_map_pc(&plan,plan.entry,NULL),LI2_UNROLLED_HASH_ARGUMENT);
#define SHAPE(change) do{p=plan;change;REFUSE(li2_unrolled_hash_map_pc(&p,p.entry,&pc),LI2_UNROLLED_HASH_SHAPE);}while(0)
    SHAPE(p.version++);SHAPE(p.ready=0);SHAPE(p.decoder_calls--);SHAPE(p.decoder_result=1);SHAPE(p.stop++);SHAPE(p.pc++);SHAPE(p.entry++);SHAPE(p.source[38]^=1);
    SHAPE(p.generated[0]^=1);SHAPE(p.generated[22]^=1);SHAPE(p.generated[23]^=1);SHAPE(p.generated[24]^=1);SHAPE(p.generated[63*28+21]^=1);SHAPE(p.generated[63*28+27]^=1);SHAPE(p.generated[1792]^=1);SHAPE(p.generated[1796]^=1);
    for(unsigned i=0;i<8;i++){SHAPE(p.instructions[i].code++);SHAPE(p.instructions[i].bytes[14]^=1);}
    SHAPE(p.guard.code++);SHAPE(p.guard.bytes[14]^=1);
#undef SHAPE
#undef REFUSE
    need(negative_controls==70,165);
}
static void authority_controls(void){
    for(unsigned i=0;i<2;i++){struct owned_mapping *m=i?&image:&source;long alias=RAW(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,m->fd,0);need(alias>0,166);need(!audit_mapping(m,i?(PROT_READ|PROT_EXEC):PROT_READ),167);need(!RAW(SYS_munmap,alias,PAGE,0,0,0,0)&&audit_mapping(m,i?(PROT_READ|PROT_EXEC):PROT_READ),168);unsigned char value=0;need(RAW(SYS_pwrite64,m->fd,&value,1,0,0,0)==-EPERM,169);}
}
static void make_source(void){
    long p=RAW(SYS_mmap,0,2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,170);reservation=(uintptr_t)p;source_address=reservation;image_address=reservation+PAGE;
    need(!RAW(SYS_munmap,reservation,2*PAGE,0,0,0,0),171);reservation=0;
    unsigned char page[PAGE];memset(page,0xcc,PAGE);bytes(page,literal,39);sealed(&source,page,PAGE,source_address,PROT_READ);
    need(!li2_unrolled_hash_plan_bytes(source.at,(void *)source.at,39,image_address,&plan)&&plan.ready==1&&plan.decoder_calls==9,172);
    memset(page,0xcc,PAGE);bytes(page,plan.generated,1797);sealed(&image,page,PAGE,image_address,PROT_READ|PROT_EXEC);
    need(source.at+PAGE==image.at,173);supplied_controls();authority_controls();
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
    struct li2_decoder_stats stats;need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&stats)&&stats.phase==2,115);
    p=RAW(SYS_mmap,0,STACK+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,116);stack_area=stack_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),117);
    p=RAW(SYS_mmap,0,DATA+PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,118);data_area=data_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p,DATA,PROT_READ|PROT_WRITE,0,0,0),119);
    for(size_t i=0;i<DATA;i++)original_data[i]=(unsigned char)(1+(i*17)%255);
    for(unsigned i=0;i<16;i++)region_seed[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    size_t first=mode==6?DATA-64:mode==7?DATA:mode==8?DATA-63:128;
    region_seed[1]=data_area+first-1;region_seed[2]=mode==5?UINT64_C(0xfedcba9876543280):UINT64_C(0x41);region_seed[3]=mode==5?UINT64_MAX-3:UINT64_C(0x123456789abcdef0);region_seed[4]=stack_area+PAGE+STACK-504;need((region_seed[4]&15)==8,120);
    region_input_flags=mode==5?0xad7:0x202; /* AF1 plus distinct original status bits in mode5. */
    if(nul_at[mode]){need(first+nul_at[mode]<=DATA,121);original_data[first+nul_at[mode]-1]=0;}
    for(size_t i=0;i<LOGICAL_STACK;i++)original_stack[i]=(unsigned char)(i*29+7);
    make_source();
}
static int dump_observation(const struct observation *o){return write_all(3,&o->before,sizeof(o->before))&&write_all(3,&o->after,sizeof(o->after))&&write_all(3,o->xbefore,REGION_FP)&&write_all(3,o->xafter,REGION_FP)&&write_all(3,&o->entry,sizeof(o->entry))&&write_all(3,&o->exit,sizeof(o->exit))&&write_all(3,&o->entry_si,sizeof(o->entry_si))&&write_all(3,&o->exit_si,sizeof(o->exit_si))&&write_all(3,o->stack,LOGICAL_STACK)&&write_all(3,o->data,DATA)&&write_all(3,o->meta,sizeof(o->meta));}
static int dump(void){
    uint64_t h[32]={UINT64_C(0x3148524c4e55494c),1,32,mode,first_error,cleanup_done,region_xcr0,xsave_bytes,source_address,image_address,stack_address,data_address,alt_address,app_mask,sizeof(plan),sizeof(struct li2_step_frame),REGION_FP,DATA,LOGICAL_STACK,2,negative_controls,head_checks,interior_misses,region_input_flags,completed[mode],nul_at[mode],mode>=7,(uint64_t)source.stat.st_ino,(uint64_t)source.stat.st_dev,(uint64_t)image.stat.st_ino,(uint64_t)image.stat.st_dev,SEALS};
    return write_all(3,h,sizeof(h))&&write_all(3,region_seed,sizeof(region_seed))&&write_all(3,xlayout,sizeof(xlayout))&&write_all(3,source.expected,PAGE)&&write_all(3,image.expected,PAGE)&&write_all(3,&plan,sizeof(plan))&&dump_observation(&qualified[0])&&dump_observation(&qualified[1]);
}
int main(int argc,char **argv){
    if(argc!=2||strlen(argv[1])!=1||argv[1][0]<'0'||argv[1][0]>'8')return 2;mode=(unsigned)(argv[1][0]-'0');setup();
    for(unsigned l=0;l<2;l++){invoke(l);check_observation(l);qualified[l]=current;}
    retire();need(cleanup_done&&!first_error&&dump(),122);
    printf("{\"schema\":1,\"mode\":%u,\"qualified_comparison\":1,\"completed_chunk\":%u,\"completed_loop\":%u,\"required_read_failure\":%u,\"cleanup\":1,\"reference_trace\":%llu,\"generated_trace\":0,\"exit_kind\":%u,\"negative_controls\":%llu,\"head_checks\":%llu,\"interior_misses\":%llu}\n",mode,mode<7,mode<7&&mode!=4,mode>=7,(unsigned long long)qualified[0].meta[2],mode>=7?3:mode==4?1:2,(unsigned long long)negative_controls,(unsigned long long)head_checks,(unsigned long long)interior_misses);fflush(stdout);
    return mode>=7?125:0;
}
