/* Additive native component: exact original hardware versus actual BMG2 and
   LPE13 emitted bytes. Three lanes (original TF, generated TF recovery, direct
   generated execution) compare all GPR/physical flags, complete signal FP,
   whole8192-byte data and160-byte logical stack. No owner or timing credit.
   Old scalar_span/native.c and its58 modes remain completely unchanged. */
#define _GNU_SOURCE
#include "persistent_loop_effects_plan.h"
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
#define HIST 256U
#define TRACE 4096U
#define BANK (2*1024*1024UL)
#define MAX_MAPPING (96*PAGE)
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

struct owned_mapping {uintptr_t at;size_t n;int fd;struct stat stat;unsigned char expected[MAX_MAPPING];};
static struct owned_mapping source={.fd=-1},image={.fd=-1},metadata={.fd=-1},directory={.fd=-1};
static uintptr_t stack_area,data_area,alt_area,reservation,slots_area,spill_area;
static unsigned mode,lane,handling,started,ended,form,source_bytes,faulted,fault_prot;
static unsigned source_reg,imul_dst,imul_src,loop_iterations,reference_count,reference_at,trace_count;
static uint64_t app_mask,xsave_bytes,first_error,cleanup_done,bank_address;
static uint64_t entry_pc,terminal_pc,generated_pc,fault_pc,store_ea;
static uint64_t xlayout[64][3],head_checks,interior_misses,authority_checks,recovery_checks;
static unsigned char decoder_arena[16*1024*1024] __attribute__((aligned(64)));
static struct li2_decoder_stats decoder_before,decoder_after;
static char maps[256*1024];
static struct rseq rseq_probe __attribute__((aligned(32)));
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static struct li2_mg_plan guard;
static struct li2_mg_table table;
static struct li2_pg_plan full,rebuild;
static struct li2_pg_compact compact,compact_copy;
static struct li2_le_witness witness,old_witness;
static union li2_pg_guard recovery;
static unsigned char source_page[2][PAGE],image_bytes[17*PAGE],metadata_bytes[MAX_MAPPING],directory_bytes[3*PAGE];
static unsigned char original_data[DATA],original_stack[LOGICAL_STACK];
struct state {uint64_t pc,gpr[16],flags;unsigned char data[DATA],stack[LOGICAL_STACK];};
static struct state history[HIST];
struct observed_boundary {uint64_t pc,original_pc,flags,gpr[16],reference,phase,kind;};
static struct observed_boundary trace[TRACE];
struct observation {
    struct region_live before,after;
    unsigned char xbefore[REGION_FP],xafter[REGION_FP];
    struct li2_step_frame entry,exit;
    siginfo_t entry_si,exit_si;
    unsigned char data[DATA],stack[LOGICAL_STACK];
    uint64_t meta[16]; /* lane,NX,TRACE,fault,FS0,GS0,mask0,FS1,GS1,mask1,
                         rawterminal,logicalterminal,reference,recoveries,0,0 */
};
static struct observation current,qualified[3];
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
static void frame(struct li2_step_frame *out,const ucontext_t *uc){
    zero(out,sizeof(*out));bytes(out->greg,uc->uc_mcontext.gregs,sizeof(out->greg));bytes(&out->mask,&uc->uc_sigmask,8);
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;need(out->fp_address&&!(out->fp_address&15)&&out->fp_address>=alt_area+PAGE&&out->fp_address<=alt_area+PAGE+ALT-512,30);
    const unsigned char *p=(void *)out->fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)){n=u32(p+468);size_t x=u32(p+480);need(n>=580&&n<=REGION_FP&&n<=alt_area+PAGE+ALT-out->fp_address&&x>=576&&x==n-4&&u32(p+n-4)==UINT32_C(0x46505845),31);uint64_t comp;bytes(&comp,p+520,8);need(!comp,32);}
    out->fp_bytes=n;bytes(out->fp,p,n);out->initialized=n;need(out->mask==app_mask,33);
}

static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc){return sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==pc&&(uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==14&&g[REG_ERR]==21&&(uintptr_t)g[REG_CR2]==pc;}
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
}static void handler(int,siginfo_t *,void *);
static uint64_t physical(uint64_t f){return f&~(LI2_STEP_TF|LI2_STEP_RF);}
static uintptr_t generated_terminal(void){return terminal_pc;}
static int imul_boundary(uintptr_t pc,uintptr_t *original,unsigned *phase){
    *original=0;*phase=0;if(pc==generated_pc){*original=entry_pc;*phase=LI2_MG_BEFORE;return 1;}
    if(pc==generated_pc+4){*original=terminal_pc;*phase=LI2_MG_AFTER;return 1;}return 0;
}
static unsigned char input_data[DATA],input_stack[LOGICAL_STACK];
static struct li2_step_frame sampled;
static unsigned completed_lanes;
static int loop_terminal(uintptr_t pc,uint64_t flags){return pc==terminal_pc&&(form!=2||(flags&64));}
static void state_at(struct state *s,uintptr_t pc,const greg_t *g){
    s->pc=pc;for(unsigned i=0;i<16;i++)s->gpr[i]=(uint64_t)g[regs[i]];s->flags=physical((uint64_t)g[REG_EFL]);
    /* A protected data page is not read during a fault attempt. Retain the
       actual pre-protection bytes here; only terminal restoration permits the
       second whole-memory observation. These are not live intermediate reads. */
    if(faulted){bytes(s->data,input_data,DATA);bytes(s->stack,input_stack,LOGICAL_STACK);}
    else{bytes(s->data,(void *)data_area,DATA);bytes(s->stack,(void *)(region_seed[4]-128),LOGICAL_STACK);}
}
static void original_state(uintptr_t pc,const greg_t *g){need(reference_count<HIST,201);state_at(&history[reference_count++],pc,g);}
static int equal_state(const struct state *s,const uint64_t r[16],uint64_t flags,uintptr_t pc){
    return s->pc==pc&&same(s->gpr,r,sizeof s->gpr)&&s->flags==physical(flags)&&
        (faulted||(same(s->data,(void *)data_area,DATA)&&same(s->stack,(void *)(region_seed[4]-128),LOGICAL_STACK)));
}
static void generated_state(uintptr_t pc,const greg_t *g){
    uint64_t r[16],spill[4];for(unsigned i=0;i<16;i++)r[i]=(uint64_t)g[regs[i]];bytes(spill,(void *)spill_area,sizeof spill);
    uintptr_t original=0;uint64_t flags=(uint64_t)g[REG_EFL];unsigned phase=0,kind=0;
    if(form==0){struct li2_mg_recovered v;need(!li2_bmg_recover(&guard,pc,r,flags,spill,&v)&&v.complete,202);
        bytes(r,v.gpr,sizeof r);flags=v.flags;original=v.original_pc;phase=v.phase;kind=LI2_PG_GUARD;
    }else if(form==1){need(imul_boundary(pc,&original,&phase),203);kind=LI2_PG_COPIED;
    }else{struct li2_pg_recovered v;need(!li2_lpe_compact_recover(&compact,pc,r,flags,spill,&recovery,&v)&&v.complete,204);
        bytes(r,v.gpr,sizeof r);flags=v.flags;original=v.original_pc;phase=v.phase;kind=v.kind;
    }
    need(reference_at<reference_count,205);
    if(!equal_state(&history[reference_at],r,flags,original)){
        need(reference_at+1<reference_count&&equal_state(&history[reference_at+1],r,flags,original),206);reference_at++;
    }
    need(trace_count<TRACE,207);struct observed_boundary *t=&trace[trace_count++];
    t->pc=pc;t->original_pc=original;t->flags=(uint64_t)g[REG_EFL];for(unsigned i=0;i<16;i++)t->gpr[i]=(uint64_t)g[regs[i]];
    t->reference=reference_at;t->phase=phase;t->kind=kind;recovery_checks++;
}
static void finish(ucontext_t *uc,const siginfo_t *si,unsigned fault){
    need(started&&!ended,208);frame(&current.exit,uc);bytes(&current.exit_si,si,sizeof *si);
    if(form==2)need(li2_lpe_compact_exit(&compact,terminal_pc,(uint64_t)uc->uc_mcontext.gregs[REG_EFL])==0,285);
    current.meta[3]=fault;current.meta[10]=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];current.meta[11]=fault?entry_pc:terminal_pc;
    current.meta[12]=reference_count;current.meta[13]=lane==1?recovery_checks:0;
    if(!lane)source_prot(PROT_READ);else image_prot(PROT_READ);
    if(faulted)need(!RAW(SYS_mprotect,data_area,DATA,PROT_READ|PROT_WRITE,0,0,0),209);
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ)&&audit_mapping(&metadata,PROT_READ)&&audit_mapping(&directory,PROT_READ),210);
    uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)LI2_STEP_TF;
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)region_capture;ended=1;
}
static void handler(int sig,siginfo_t *si,void *ptr){
    need(!handling&&si&&ptr,211);handling=1;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(!started){
        need(nx(sig,si,g,entry_pc)&&!ended&&audit_mapping(&source,PROT_READ)&&audit_mapping(&image,lane?PROT_READ|PROT_EXEC:PROT_READ),212);
        frame(&current.entry,uc);bytes(&current.entry_si,si,sizeof *si);current.meta[1]++;started=1;
        need((uint64_t)g[REG_EFL]==(region_input_flags|LI2_STEP_RF),213);
        if(!lane){original_state(pc,g);source_prot(PROT_READ|PROT_EXEC);g[REG_EFL]|=LI2_STEP_TF;}
        else{g[REG_RIP]=(greg_t)generated_pc;if(lane==1)g[REG_EFL]|=LI2_STEP_TF;}
        handling=0;return;
    }
    frame(&sampled,uc);need(sampled.fp_bytes==current.entry.fp_bytes&&same(sampled.fp,current.entry.fp,REGION_FP)&&sampled.mask==current.entry.mask,214);
    if(sig==SIGTRAP){
        need(lane!=2&&si->si_code==TRAP_TRACE&&!si->si_errno&&g[REG_TRAPNO]==1&&!g[REG_ERR]&&(g[REG_EFL]&LI2_STEP_TF),215);current.meta[2]++;
        if(!lane){
            need(pc>=entry_pc&&pc<=entry_pc+source_bytes,216);original_state(pc,g);
            if(loop_terminal(pc,(uint64_t)g[REG_EFL])){need(!faulted,217);finish(uc,si,0);handling=0;return;}
        }else if(pc==generated_terminal()){
            need(!faulted&&reference_at+1==reference_count,218);uint64_t r[16];for(unsigned i=0;i<16;i++)r[i]=(uint64_t)g[regs[i]];
            need(equal_state(&history[reference_count-1],r,(uint64_t)g[REG_EFL],terminal_pc),219);finish(uc,si,0);handling=0;return;
        }else generated_state(pc,g);
        handling=0;return;
    }
    if(lane&&pc==generated_terminal()&&nx(sig,si,g,pc)){
        need(!faulted&&lane==2&&!current.meta[2],220);current.meta[1]++;finish(uc,si,0);handling=0;return;
    }
    if(faulted&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==store_ea&&
       g[REG_TRAPNO]==14&&g[REG_ERR]==(fault_prot==PROT_NONE?6:7)&&(uintptr_t)g[REG_CR2]==store_ea){
        need(pc==(lane?fault_pc:entry_pc),221);
        if(lane==1)generated_state(pc,g);else if(lane==2){uint64_t r[16];for(unsigned i=0;i<16;i++)r[i]=(uint64_t)g[regs[i]];
            struct li2_mg_recovered v;uint64_t spill[4];bytes(spill,(void *)spill_area,sizeof spill);
            need(!li2_bmg_recover(&guard,pc,r,(uint64_t)g[REG_EFL],spill,&v)&&v.complete&&v.phase==LI2_MG_STORE&&equal_state(&history[0],v.gpr,v.flags,v.original_pc),222);}
        finish(uc,si,1);handling=0;return;
    }
    die(223);
}
static void prepare(unsigned which){
    lane=which;zero(&current,sizeof current);zero(&region_before,sizeof region_before);zero(&region_after,sizeof region_after);zero(region_fp_before,REGION_FP);zero(region_fp_after,REGION_FP);
    need(!RAW(SYS_mprotect,data_area,DATA,PROT_READ|PROT_WRITE,0,0,0),224);
    bytes((void *)data_area,original_data,DATA);bytes((void *)(region_seed[4]-128),original_stack,LOGICAL_STACK);
    bytes(input_data,(void *)data_area,DATA);bytes(input_stack,(void *)(region_seed[4]-128),LOGICAL_STACK);
    need(same(input_data,original_data,DATA)&&same(input_stack,original_stack,LOGICAL_STACK),225);
    zero((void *)spill_area,PAGE);zero((void *)slots_area,PAGE);
    if(faulted)need(!RAW(SYS_mprotect,data_area+PAGE,PAGE,fault_prot,0,0,0)&&mapping_rows(data_area+PAGE,PAGE,fault_prot,NULL),226);
    started=ended=handling=0;reference_at=0;region_target=entry_pc;
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ)&&audit_mapping(&metadata,PROT_READ)&&audit_mapping(&directory,PROT_READ),227);
    if(form==0)need(!li2_bmg_validate(&guard),228);
    if(form==2)need(!li2_lpe_compact_validate(&compact,&rebuild,&compact_copy,&witness)&&same(&compact,&compact_copy,sizeof compact),229);
    if(which)image_prot(PROT_READ|PROT_EXEC);
}
static void invoke(unsigned which){
    prepare(which);need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[4],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[5],0,0,0,0)&&!RAW(SYS_rt_sigprocmask,0,0,&current.meta[6],8,0,0),230);
    region_enter();need(started&&ended&&!handling,231);
    bytes(&current.before,&region_before,sizeof region_before);bytes(&current.after,&region_after,sizeof region_after);
    bytes(current.xbefore,region_fp_before,REGION_FP);bytes(current.xafter,region_fp_after,REGION_FP);bytes(current.data,(void *)data_area,DATA);bytes(current.stack,(void *)(region_seed[4]-128),LOGICAL_STACK);
    current.meta[0]=which;need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[7],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[8],0,0,0,0)&&!RAW(SYS_rt_sigprocmask,0,0,&current.meta[9],8,0,0),232);
}
static void observations(unsigned which){
    need(current.meta[3]==faulted&&current.meta[4]==current.meta[7]&&current.meta[5]==current.meta[8]&&current.meta[6]==app_mask&&current.meta[9]==app_mask,233);
    need(current.meta[1]==(which==2&&!faulted?2:1)&&(which!=2||!current.meta[2]),234);
    check_seed(current.xbefore);check_seed(current.xafter);check_seed(current.entry.fp);check_seed(current.exit.fp);
    need(current.before.flags==region_input_flags&&!current.before.reserved&&!current.after.reserved&&same(current.before.selectors,current.after.selectors,sizeof current.before.selectors),235);
    need(same(current.xbefore,current.xafter,REGION_FP)&&same(current.entry.fp,current.exit.fp,REGION_FP)&&current.entry.fp_bytes==current.exit.fp_bytes&&current.entry.mask==current.exit.mask,236);
    need(current.entry.mask==app_mask&&same(current.stack,original_stack,LOGICAL_STACK),237);
    for(unsigned i=0;i<16;i++)need(current.before.gpr[i]==region_seed[i]&&(uint64_t)current.entry.greg[regs[i]]==region_seed[i]&&current.after.gpr[i]==(uint64_t)current.exit.greg[regs[i]],238);
    uint64_t selectors=(uint64_t)current.before.selectors[0]|(uint64_t)current.before.selectors[5]<<16|(uint64_t)current.before.selectors[4]<<32|(uint64_t)current.before.selectors[1]<<48;
    need((uint64_t)current.entry.greg[REG_CSGSFS]==selectors&&(uint64_t)current.exit.greg[REG_CSGSFS]==selectors,277);
    need((uintptr_t)current.entry.greg[REG_RIP]==entry_pc&&(uint64_t)current.entry.greg[REG_EFL]==(region_input_flags|LI2_STEP_RF)&&current.entry.greg[REG_TRAPNO]==14&&current.entry.greg[REG_ERR]==21&&(uintptr_t)current.entry.greg[REG_CR2]==entry_pc,278);
    need(current.after.flags==physical((uint64_t)current.exit.greg[REG_EFL]),239);
    if(!which){
        if(form==0){unsigned char expected[DATA];bytes(expected,original_data,DATA);if(!faulted)expected[store_ea-data_area]=(unsigned char)(mode<16?region_seed[source_reg]:mode==20?region_seed[15]:mode==21||mode==26?region_seed[2]:mode==27?region_seed[0]:(mode==16?0:mode==17?1:mode==18?0x80:mode==19?0xff:0xcc));need(same(current.data,expected,DATA),240);}
        if(form==1){uint64_t want[16];bytes(want,region_seed,sizeof want);want[imul_dst]=region_seed[imul_dst]*region_seed[imul_src];need(same(current.after.gpr,want,sizeof want)&&same(current.data,original_data,DATA),241);}
        if(form==2){unsigned char expected[DATA];bytes(expected,original_data,DATA);for(unsigned i=0;i<loop_iterations;i++)expected[i]=(unsigned char)(mode<38?0xcc:1+(17U*i)%255U);need(same(current.data,expected,DATA),242);}
    }else{
        const struct observation *n=&qualified[0];
        need(same(current.entry.greg,n->entry.greg,sizeof n->entry.greg)&&same(&current.entry_si,&n->entry_si,sizeof n->entry_si)&&same(current.entry.fp,n->entry.fp,REGION_FP)&&current.entry.fp_bytes==n->entry.fp_bytes&&current.entry.mask==n->entry.mask,279);
        need(same(&current.before,&n->before,sizeof n->before)&&same(&current.after,&n->after,sizeof n->after)&&same(current.xbefore,n->xbefore,REGION_FP)&&same(current.xafter,n->xafter,REGION_FP)&&same(current.data,n->data,DATA)&&same(current.stack,n->stack,LOGICAL_STACK),243);
        need(current.exit.fp_bytes==n->exit.fp_bytes&&same(current.exit.fp,n->exit.fp,REGION_FP)&&current.exit.mask==n->exit.mask&&current.meta[7]==n->meta[7]&&current.meta[8]==n->meta[8],244);
        for(unsigned i=0;i<NGREG;i++){
            uint64_t want=(uint64_t)n->exit.greg[i];
            if(i==REG_RIP)want=faulted?fault_pc:terminal_pc;
            if(i==REG_EFL)want=physical(want)|(which==1?LI2_STEP_TF:0)|(faulted||which==2?LI2_STEP_RF:0);
            if(!faulted&&which==2){if(i==REG_ERR)want=21;if(i==REG_TRAPNO)want=14;if(i==REG_CR2)want=terminal_pc;}
            need((uint64_t)current.exit.greg[i]==want,245);
        }
        if(faulted)need(same(&current.exit_si,&n->exit_si,sizeof n->exit_si),246);
    }
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ)&&audit_mapping(&metadata,PROT_READ)&&audit_mapping(&directory,PROT_READ),247);
}
static void put32(unsigned char *b,uint32_t v){for(unsigned i=0;i<4;i++)b[i]=(unsigned char)(v>>(8*i));}
static void relative(unsigned char *b,uintptr_t next,uintptr_t target){int64_t d=(int64_t)target-(int64_t)next;need(d>=INT32_MIN&&d<=INT32_MAX,248);put32(b,(uint32_t)d);}
static void source_bytes_for_case(void){
    memset(source_page,0xcc,sizeof source_page);unsigned char *b=source_page[0]+256;entry_pc=bank_address+256;form=mode<28?0:mode<36?1:2;
    store_ea=data_area+128;source_reg=mode;faulted=mode>=24&&mode<28;fault_prot=(mode==25||mode==27)?PROT_NONE:PROT_READ;
    if(faulted)store_ea=data_area+PAGE;
    if(mode<16){unsigned n=0;if(mode>=4)b[n++]=(unsigned char)(0x40|(mode>=8?4:0));b[n++]=0x88;b[n++]=(unsigned char)(0x47|((mode&7)<<3));b[n++]=0xff;source_bytes=n;region_seed[7]=store_ea+1;}
    else if(mode<20){b[0]=0xc6;b[1]=0x00;b[2]=(unsigned char[]){0,1,0x80,0xff}[mode-16];source_bytes=3;region_seed[0]=store_ea;}
    else if(mode==20){const unsigned char v[]={0x47,0x88,0x7c,0x88,0xf0};bytes(b,v,sizeof v);source_bytes=sizeof v;region_seed[8]=store_ea+16-12;region_seed[9]=3;}
    else if(mode==21||mode==26){b[0]=0x88;b[1]=0x15;relative(b+2,entry_pc+6,store_ea);source_bytes=6;}
    else if(mode==22){b[0]=0xc6;b[1]=4;b[2]=0x25;need(store_ea<=INT32_MAX,249);put32(b+3,(uint32_t)store_ea);b[7]=0xcc;source_bytes=8;}
    else if(mode==23){store_ea=data_area+PAGE-1;b[0]=0xc6;b[1]=0;b[2]=0xcc;source_bytes=3;region_seed[0]=store_ea;}
    else if(mode==24){b[0]=0x88;b[1]=0x07;source_bytes=2;source_reg=0;region_seed[7]=store_ea;}
    else if(mode==25){b[0]=0xc6;b[1]=0;b[2]=0xcc;source_bytes=3;region_seed[0]=store_ea;}
    else if(mode==27){b[0]=0x88;b[1]=0;source_bytes=2;region_seed[0]=store_ea;}
    else if(mode<36){
        static const unsigned dest[]={0,0,0,0,8,8,9,0},src[]={6,6,6,6,15,15,9,4};
        static const uint64_t left[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffffffff),UINT64_MAX,UINT64_C(0x8000000000000001),3};
        static const uint64_t right[]={UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX,2,2,0,0};
        unsigned k=mode-28;imul_dst=dest[k];imul_src=src[k];region_seed[imul_dst]=left[k];if(imul_src!=imul_dst&&imul_src!=4)region_seed[imul_src]=right[k];
        b[0]=(unsigned char)(0x48|(imul_dst>=8?4:0)|(imul_src>=8?1:0));b[1]=0x0f;b[2]=0xaf;b[3]=(unsigned char)(0xc0|((imul_dst&7)<<3)|(imul_src&7));source_bytes=4;
    }else if(mode<38){
        const unsigned char v[]={0xc6,0x00,0xcc,0x48,0x83,0xc0,1,0x48,0x39,0xc2,0x75,0xf4};bytes(b,v,sizeof v);source_bytes=sizeof v;loop_iterations=mode==36?17:1;
        region_seed[0]=data_area;region_seed[2]=data_area+loop_iterations;
    }else{
        const unsigned char v[]={0x89,0xd0,0x48,0x83,0xc1,1,0x48,0x0f,0xaf,0xc6,0x48,0xc1,0xe8,0x27,0x8d,0x44,0x02,1,0x83,0xc2,0x11,0x88,0x41,0xff,0x81,0xfa,0,0,0,0,0x75,0xe0};
        bytes(b,v,sizeof v);source_bytes=sizeof v;loop_iterations=mode==38?17:1;put32(b+26,17*loop_iterations);
        region_seed[1]=data_area;region_seed[2]=0;region_seed[6]=UINT64_C(0x80808081);
    }
    terminal_pc=entry_pc+source_bytes-(form==2?2:0);
}
static void plan_bytes(void){
    uintptr_t pages[2]={bank_address,bank_address+PAGE};
    struct li2_pg_layout layout={{bank_address+0x10000,bank_address+0x18000},bank_address+0x20000,slots_area,spill_area,bank_address+0xa0000};
    generated_pc=layout.generated[0];memset(image_bytes,0xcc,sizeof image_bytes);zero(metadata_bytes,sizeof metadata_bytes);zero(directory_bytes,sizeof directory_bytes);
    const struct li2_mg_range excluded[]={{bank_address,bank_address+2*PAGE},{bank_address+0x10000,bank_address+0x21000},
        {bank_address+0x40000,bank_address+0xa3000},{spill_area,spill_area+PAGE},{slots_area,slots_area+PAGE}};
    uintptr_t table_at=bank_address+0x40000+(form==2?offsetof(struct li2_pg_compact,table):0);
    need(!li2_mg_table_build(excluded,5,table_at,&table),250);
    size_t image_n=PAGE,metadata_n=2*PAGE;
    const unsigned char *b=source_page[0]+256;
    if(form==0){need(!li2_bmg_emit(entry_pc,b,source_bytes,generated_pc,spill_area,terminal_pc,&table,&guard)&&!li2_bmg_validate(&guard)&&guard.ready&&guard.version==2,251);
        bytes(image_bytes,guard.image,guard.image_bytes);bytes(metadata_bytes,&table,sizeof table);fault_pc=generated_pc+guard.store_offset;
        for(unsigned at=0;at<guard.image_bytes;at++){unsigned j=0;while(j<guard.boundaries&&guard.boundary[j].offset!=at)j++;
            uint64_t r[16]={0},spill[4]={0};struct li2_mg_recovered got,z={0};int e=li2_bmg_recover(&guard,generated_pc+at,r,0,spill,&got);
            if(j<guard.boundaries){need(!e&&got.complete,252);head_checks++;}else{need(e==LI2_MG_CORRUPT&&same(&got,&z,sizeof got),253);interior_misses++;}}
    }else if(form==1){
        struct li2_span_decoded d;need(!li2_decoder_loop_scalar_describe(entry_pc,b,4,&d)&&d.version==3&&d.ready&&d.flags_written==(1|2048)&&d.flags_undefined==(4|16|64|128),254);
        bytes(image_bytes,b,4);image_bytes[4]=0xe9;relative(image_bytes+5,generated_pc+9,terminal_pc);bytes(metadata_bytes,&table,sizeof table);
        for(unsigned at=0;at<9;at++){uintptr_t original;unsigned phase;int ok=imul_boundary(generated_pc+at,&original,&phase);
            if(at==0||at==4){need(ok&&original==(at?terminal_pc:entry_pc)&&phase==(at?LI2_MG_AFTER:LI2_MG_BEFORE),275);head_checks++;}
            else{need(!ok&&!original&&!phase,276);interior_misses++;}}
    }else{
        int old=li2_le_choose(pages,source_page,entry_pc,&old_witness);need(old==LI2_LE_NO_ENVELOPE&&!li2_le_validate(pages,source_page,entry_pc,&old_witness,&witness),255);
        struct li2_pg_miss miss,empty={.version=13};
        need(!li2_lpe_plan_pages(pages,source_page,entry_pc,&layout,&table,&full,&miss,&witness)&&same(&miss,&empty,sizeof miss)&&full.version==13&&full.ready&&full.stores==1&&full.exits==1&&!full.links&&full.heads==(mode<38?4U:9U)&&full.member_heads[0]==full.heads&&!full.member_heads[1]&&full.source_mask==1&&full.source_bytes==source_bytes,256);
        need(!li2_lpe_plan_validate(&full,&rebuild,&witness)&&same(&full,&rebuild,sizeof full),257);
        need(!li2_lpe_compact_build(&full,&rebuild,&compact,&witness)&&!li2_lpe_compact_validate(&compact,&rebuild,&compact_copy,&witness)&&same(&compact,&compact_copy,sizeof compact),258);
        need(li2_lp_compact_validate(&compact,&rebuild,&compact_copy,&witness)==LI2_PG_CORRUPT,259);
        bytes(image_bytes,compact.image,sizeof compact.image);bytes(image_bytes+2*LI2_PE_IMAGE_BYTES,compact.stub_image,PAGE);image_n=sizeof image_bytes;
        bytes(metadata_bytes,&compact,sizeof compact);metadata_n=(sizeof compact+PAGE-1)&~(PAGE-1);
        static const unsigned cc_offsets[]={0,3,7,10},sentinel_offsets[]={0,2,6,10,14,18,21,24,30};
        const unsigned *offsets=mode<38?cc_offsets:sentinel_offsets;
        for(unsigned h=0;h<compact.heads;h++){
            need(compact.original[h].decoded.pc==entry_pc+offsets[h]&&compact.head[h].source_page==0&&compact.head[h].source_offset==256+offsets[h],280);
            need(compact.head[h].source_length&&compact.head[h].source_offset>=256&&compact.head[h].source_offset<256+source_bytes,260);
            if(compact.head[h].kind==LI2_PE_MOV)need(compact.instruction[h].mov.version==2&&compact.guard[h].mov.version==2,261);
            if(compact.original[h].decoded.code==2072)need(compact.original[h].version==3,262);
            const struct li2_pe_head *head=&compact.head[h];unsigned last=h+1==compact.heads;
            need(head->successor_count==(last?2U:1U)&&head->successors[0]==(last?0U:h+1)&&head->successors[1]==(last?LI2_PG_HEADS:0U),281);
            if(last)need(head->kind==LI2_PG_DIRECT&&compact.instruction[h].direct.version==1&&compact.guard[h].direct.version==1&&compact.instruction[h].direct.external_mask==2&&compact.exit_pc[0]==terminal_pc,282);
            for(unsigned at=0;at<LI2_PE_SLOT_BYTES;at++){
                unsigned expected=0;
                if(head->kind==LI2_PE_MOV){for(unsigned j=0;j<compact.guard[h].mov.boundaries;j++)expected+=compact.guard[h].mov.boundary[j].offset==at;}
                else if(head->kind==LI2_PG_DIRECT){for(unsigned j=0;j<compact.guard[h].direct.boundaries;j++)expected+=compact.guard[h].direct.boundary[j].offset==at;}
                else expected=at==0||at==head->source_length;
                uint64_t r[16]={0},spill[4]={0};struct li2_pg_recovered got,z={0};
                int e=li2_lpe_compact_recover(&compact,generated_pc+h*LI2_PE_SLOT_BYTES+at,r,0,spill,&recovery,&got);
                if(expected){need(expected==1&&!e&&got.complete,283);head_checks++;}
                else{if(head->kind!=LI2_PG_DIRECT&&at<head->generated_length){z.member=0;z.head=h;z.link=UINT32_MAX;}need(e==LI2_PG_MISS&&same(&got,&z,sizeof got),284);interior_misses++;}
            }
        }
    }
    sealed(&source,(unsigned char *)source_page,sizeof source_page,bank_address,PROT_READ);
    sealed(&image,image_bytes,image_n,generated_pc,PROT_READ);
    sealed(&metadata,metadata_bytes,metadata_n,bank_address+0x40000,PROT_READ);
    sealed(&directory,directory_bytes,sizeof directory_bytes,bank_address+0xa0000,PROT_READ);
    for(unsigned i=0;i<4;i++){struct owned_mapping *m=(struct owned_mapping *[]){&source,&image,&metadata,&directory}[i];
        long a=RAW(SYS_mmap,0,m->n,PROT_READ|PROT_WRITE,MAP_PRIVATE,m->fd,0);need(a>0&&!audit_mapping(m,PROT_READ),263);authority_checks++;
        need(!RAW(SYS_munmap,a,m->n,0,0,0,0)&&audit_mapping(m,PROT_READ),264);unsigned char byte=0;need(RAW(SYS_pwrite64,m->fd,&byte,1,0,0,0)==-EPERM,265);authority_checks++;}
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
    long p=RAW(SYS_mmap,0,ALT+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,111);alt_area=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,ALT,PROT_READ|PROT_WRITE,0,0,0),112);stack_t alt={.ss_sp=(void *)(p+PAGE),.ss_size=ALT};need(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),113);
    action.handler=handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;action.restorer=region_restorer;action.mask=app_mask;for(unsigned i=0;i<3;i++){int sig=(int[]){SIGSEGV,SIGTRAP,SIGSYS}[i];need(!RAW(SYS_rt_sigaction,sig,&action,0,8,0,0),114);}
    need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&decoder_before)&&decoder_before.abi_version==1&&decoder_before.phase==2&&!decoder_before.first_fatal_reason&&!decoder_before.reserved&&decoder_before.arena_bytes==sizeof(decoder_arena)&&decoder_before.retained_high_water&&decoder_before.retained_high_water<=sizeof(decoder_arena),115);
    p=RAW(SYS_mmap,0,STACK+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,116);stack_area=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),117);
    bank_address=UINT64_C(0x10000000);p=RAW(SYS_mmap,bank_address,BANK,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);need(p==(long)bank_address,266);reservation=(uintptr_t)p;
    need(!RAW(SYS_munmap,reservation,BANK,0,0,0,0),267);reservation=0;
    spill_area=bank_address+0xb0000;slots_area=bank_address+0xb1000;data_area=bank_address+0xc0000;
    need(RAW(SYS_mmap,spill_area,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)spill_area,268);
    need(RAW(SYS_mmap,slots_area,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)slots_area,269);
    need(RAW(SYS_mmap,data_area,DATA+PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)data_area&&!RAW(SYS_mprotect,data_area,DATA,PROT_READ|PROT_WRITE,0,0,0),270);
    for(size_t i=0;i<DATA;i++)original_data[i]=(unsigned char)(1+(i*17)%255);
    for(unsigned i=0;i<16;i++)region_seed[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    region_seed[4]=stack_area+PAGE+STACK-504;need((region_seed[4]&15)==8&&region_seed[4]-128>=stack_area+PAGE&&region_seed[4]+LOGICAL_STACK<=stack_area+PAGE+STACK,271);
    for(size_t i=0;i<LOGICAL_STACK;i++)original_stack[i]=(unsigned char)(i*29+7);
    region_input_flags=mode&1?0x202:0xed7;
    source_bytes_for_case();plan_bytes();
}
static void retire(void){
    if(source.at&&RAW(SYS_mprotect,source.at,source.n,PROT_READ,0,0,0)&&!first_error)first_error=90;
    if(image.at&&RAW(SYS_mprotect,image.at,image.n,PROT_NONE,0,0,0)&&!first_error)first_error=91;
    if((source.at||image.at)&&RAW(SYS_membarrier,32,0,0,0,0,0)&&!first_error)first_error=92;
    struct owned_mapping *owned[]={&image,&source,&metadata,&directory};
    for(unsigned i=0;i<4;i++){struct owned_mapping *m=owned[i];if(m->at){if(RAW(SYS_munmap,m->at,m->n,0,0,0,0)){if(!first_error)first_error=93;}else m->at=0;}if(m->fd>=0){if(RAW(SYS_close,m->fd,0,0,0,0,0)&&!first_error)first_error=94;m->fd=-1;}}
    if(handling)return;
    uintptr_t *at[]={&reservation,&data_area,&slots_area,&spill_area,&stack_area};const size_t n[]={BANK,DATA+PAGE,PAGE,PAGE,STACK+2*PAGE};
    for(unsigned i=0;i<5;i++)if(*at[i]){if(RAW(SYS_munmap,*at[i],n[i],0,0,0,0)){if(!first_error)first_error=95+i;}else *at[i]=0;}
    if(alt_area){stack_t disabled={.ss_flags=SS_DISABLE};if(RAW(SYS_sigaltstack,&disabled,0,0,0,0,0)){if(!first_error)first_error=98;}else if(RAW(SYS_munmap,alt_area,ALT+2*PAGE,0,0,0,0)){if(!first_error)first_error=99;}else alt_area=0;}
    cleanup_done=!first_error&&!source.at&&!image.at&&!metadata.at&&!directory.at&&source.fd==-1&&image.fd==-1&&metadata.fd==-1&&directory.fd==-1&&!reservation&&!data_area&&!slots_area&&!spill_area&&!stack_area&&!alt_area;
}
_Static_assert(32*sizeof(uint64_t)+sizeof(region_seed)+sizeof(xlayout)+2*sizeof(struct li2_decoder_stats)+
    sizeof(source_page)+sizeof(image_bytes)+sizeof(guard)+sizeof(compact)+sizeof(history)+sizeof(trace)+sizeof(qualified)<16U*1024U*1024U,"whole finite native wire under original16MiB bound");
static int dump(void){
    /* Fixed raw observation objects include all initialized zero padding.
       These bytes are actual snapshots; expected descriptor models are separate. */
    uint64_t h[32]={UINT64_C(0x314650453332494c),1,32,mode,first_error,cleanup_done,completed_lanes,form,
        region_xcr0,xsave_bytes,bank_address,entry_pc,terminal_pc,generated_pc,fault_pc,store_ea,
        faulted,fault_prot,reference_count,trace_count,head_checks,interior_misses,authority_checks,recovery_checks,
        sizeof(struct observation),sizeof(struct state),sizeof(struct observed_boundary),sizeof(compact),sizeof(guard),source_bytes,loop_iterations,region_input_flags};
    return write_all(3,h,sizeof h)&&write_all(3,region_seed,sizeof region_seed)&&write_all(3,xlayout,sizeof xlayout)&&
        write_all(3,&decoder_before,sizeof decoder_before)&&write_all(3,&decoder_after,sizeof decoder_after)&&
        write_all(3,source_page,sizeof source_page)&&write_all(3,image_bytes,sizeof image_bytes)&&write_all(3,&guard,sizeof guard)&&write_all(3,&compact,sizeof compact)&&
        write_all(3,history,sizeof history)&&write_all(3,trace,sizeof trace)&&write_all(3,qualified,sizeof qualified);
}
int main(int argc,char **argv){
    if(argc!=2)return 2;char *end;unsigned long v=strtoul(argv[1],&end,10);char canonical[16];snprintf(canonical,sizeof canonical,"%lu",v);if(*end||strcmp(canonical,argv[1])||v>=40)return 2;mode=(unsigned)v;
    setup();for(unsigned l=0;l<3;l++){invoke(l);observations(l);bytes(&qualified[l],&current,sizeof current);completed_lanes++;}
    need(reference_count&&(faulted?reference_count==1:reference_count>1)&&trace_count&&recovery_checks==trace_count,272);
    need(!li2_decoder_stats(&decoder_after)&&same(&decoder_before,&decoder_after,sizeof decoder_before),273);
    retire();need(cleanup_done&&!first_error&&dump(),274);
    printf("{\"schema\":1,\"mode\":%u,\"lanes\":3,\"reference_states\":%u,\"generated_boundaries\":%u,\"full_physical_flags\":true,\"fp_bytes\":65536,\"data_bytes\":8192,\"stack_bytes\":160,\"required_write_fault\":%u,\"policy13_loop\":%u,\"loop_iterations\":%u,\"terminal_branch_before\":%u,\"authority_controls\":%llu,\"postseal_equal\":true,\"cleanup\":true,\"owner_execution\":false}\n",mode,reference_count,trace_count,faulted,form==2,loop_iterations,form==2,(unsigned long long)authority_checks);fflush(stdout);
    return faulted?125:0;
}
