/* Unexecuted paired sibling of the native-v1 loader reference.
   A real E9 predecessor executes in both lanes. Native installs reference
   handlers; maintained requests logical RX and leaves every handler to the
   actual runtime. No owner wire, admission selector or equivalence claim. */
#define _GNU_SOURCE
#include "fixture.h"
#include <asm/prctl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#define STACK_BASE UINT64_C(0x500000100000)
#define STACK_EXTENT (128U*1024U)
#define ALT_BYTES (512U*1024U)
#define MASK UINT64_C(0xffffffffbffbfae7)
#define TF LP_TF
#define RF LP_RF
__attribute__((section(".li2_ua_state"))) struct ua_live ua_input,ua_before,ua_after;
__attribute__((section(".li2_ua_state"))) unsigned char ua_before_live[UA_LIVE],ua_after_live[UA_LIVE];
__attribute__((section(".li2_ua_state"))) uintptr_t ua_target;
static struct lp_prefix prefix;
static struct lp_suffix suffix;
static struct lp_model model;
static unsigned mode,placement,native,handling,started,ended,frames,fault_seen,actions_installed;
static uint64_t steps,first_error,undefined_events,current_machine[8];
static uintptr_t source_page,base,endpoint,alt_area;
struct kernel_action { void (*handler)(int,siginfo_t *,void *); unsigned long flags; void (*restorer)(void); uint64_t mask; };
extern void direct_frontier_restorer(void);
static struct kernel_action old_actions[2];
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
_Static_assert(sizeof(ucontext_t)==968 && offsetof(ucontext_t,uc_mcontext.gregs)==40 && offsetof(ucontext_t,uc_mcontext.fpregs)==224 && offsetof(ucontext_t,uc_sigmask)==296 && offsetof(ucontext_t,uc_stack)==16 && offsetof(siginfo_t,si_addr)==16,"actual Linux signal ABI");
_Static_assert(sizeof(struct ua_live)==152 && sizeof(struct ua_frame)==66784,"whole original live/frame types");
_Static_assert(sizeof(prefix)+sizeof(suffix)<16U*1024U*1024U,"whole native stream within unchanged16MiB ceiling");
void copy(void *,const void *,size_t);int same(const void *,const void *,size_t);
void ua_stack_pattern(unsigned char *,size_t);
static long raw(long n,long a,long b,long c,long d,long e,long f){
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;long r;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static _Noreturn void die(unsigned n){if(!first_error)first_error=n;(void)RAW(SYS_exit_group,99,0,0,0,0,0);__builtin_trap();}
static void need(int yes,unsigned n){if(!yes)die(n);}
static int output(const void *p,size_t n){const unsigned char *b=p;while(n){long k=RAW(SYS_write,1,b,n,0,0,0);if(k<=0||(size_t)k>n)return 0;b+=k;n-=(size_t)k;}return 1;}
static uint32_t u32(const unsigned char *p){uint32_t x;copy(&x,p,4);return x;}
static uint64_t u64(const unsigned char *p){uint64_t x;copy(&x,p,8);return x;}
static int alt_range(const void *p,size_t n){uintptr_t a=(uintptr_t)p;return alt_area&&a>=alt_area+UA_PAGE&&a<=alt_area+UA_PAGE+ALT_BYTES&&n<=alt_area+UA_PAGE+ALT_BYTES-a;}

static void retain(int sig,const siginfo_t *si,const ucontext_t *uc,unsigned kind) {
    need(frames<LP_FRAMES&&alt_range(si,sizeof *si)&&alt_range(uc,sizeof *uc),20);
    struct ua_frame *f=&suffix.frame[frames];
    const unsigned char *p=(const void *)uc->uc_mcontext.fpregs;
    need(!((uintptr_t)p&15)&&alt_range(p,512),21);size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        need(n>=580&&n<=UA_FP&&x>=576&&x==n-4&&alt_range(p,n)&&u32(p+n-4)==UINT32_C(0x46505845)&&!u64(p+520),22);
    }
    need(n>=580,23);f->h[0]=1;f->h[1]=kind;f->h[2]=steps;f->h[3]=mode;f->h[4]=(unsigned)sig;
    f->h[5]=(uintptr_t)si;f->h[6]=(uintptr_t)uc;f->h[7]=sizeof *uc;f->h[8]=(uintptr_t)p;
    f->h[9]=n;f->h[10]=alt_area+UA_PAGE;f->h[11]=ALT_BYTES;
    copy(f->si,si,sizeof *si);copy(f->uc,uc,sizeof *uc);copy(f->fp,p,n);++frames;
}
static void state(const greg_t *g,uint64_t undefined,uint64_t causal) {
    for(unsigned i=0;i<16;i++)need((uint64_t)g[regs[i]]==model.g[i],100+i);
    uint64_t actual=(uint64_t)g[REG_EFL],want=model.flags|causal;
    need(((actual^want)&~undefined)==0,116);
    /* Preserve observed undefined bits for every later instruction. Complete
       actual flags remain in every UC; the future paired comparator must
       compare those bits literally, including TEST AF and SHL AF/OF. */
    model.flags=(model.flags&~undefined)|(actual&undefined);
    if(undefined)++undefined_events;
}
static void handler(int sig,siginfo_t *si,void *ptr) {
    need(native&&!handling&&si&&ptr,30);handling=1;
    ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    need(!ended&&!si->si_errno&&si->si_signo==sig,31);
    need(u64((const unsigned char *)&uc->uc_sigmask)==MASK,32);
    if(!started) {
        need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&(uintptr_t)si->si_addr==ua_target&&pc==ua_target&&
            g[REG_ERR]==21&&g[REG_TRAPNO]==14&&(uintptr_t)g[REG_CR2]==ua_target,33);
        state(g,0,RF);retain(sig,si,uc,0);started=1;
        need(!RAW(SYS_mprotect,source_page,LP_SOURCE,PROT_READ|PROT_EXEC,0,0,0),34);
        g[REG_EFL]|=(greg_t)TF;handling=0;return;
    }
    if(sig==SIGSEGV) {
        unsigned off=mode==5?18:56;
        need((mode==5||mode==6)&&steps==lp_steps[mode]&&pc==base+off&&pc==model.pc&&
            si->si_code==SEGV_ACCERR&&(uintptr_t)si->si_addr==LP_GUARD&&
            (uintptr_t)g[REG_CR2]==LP_GUARD&&g[REG_TRAPNO]==14&&g[REG_ERR]==4,35);
        state(g,0,TF|RF);retain(sig,si,uc,2);fault_seen=ended=1;
        /* Explicit native-only recovery after the full actual read fault.
           This is not an owner completion and does not execute the read. */
        g[REG_RIP]=(greg_t)endpoint;g[REG_EFL]&=~(greg_t)(TF|RF);handling=0;return;
    }
    need(sig==SIGTRAP&&si->si_code==TRAP_TRACE&&g[REG_ERR]==0&&g[REG_TRAPNO]==1&&
        (uintptr_t)g[REG_CR2]==ua_target&&steps<lp_steps[mode],36);
    uint64_t undefined=0;need(lp_advance(&model,prefix.data,&undefined),37);++steps;
    need(pc==model.pc&&(uintptr_t)si->si_addr==pc,38);state(g,undefined,TF);retain(sig,si,uc,1);
    if(pc==endpoint) {
        need(mode<5&&steps==lp_steps[mode],39);ended=1;g[REG_EFL]&=~(greg_t)TF;
    }
    handling=0;
}
static void hardware(void){
 unsigned leaves[3]={0,1,7};
 for(unsigned i=0;i<67;i++){
  unsigned leaf=i<3?leaves[i]:13,sub=i<3?0:i-3,a,b,c,d;
  __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
  uint32_t *r=prefix.hardware[i];r[0]=leaf;r[1]=sub;r[2]=a;r[3]=b;r[4]=c;r[5]=d;
 }
 need(prefix.hardware[0][2]>=13&&(prefix.hardware[1][4]&0x0c000000)==0x0c000000&&(prefix.hardware[2][3]&0x40010000)==0x40010000,50);
 unsigned a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
 prefix.h[14]=(uint64_t)a|((uint64_t)d<<32);prefix.h[15]=prefix.hardware[3][3];
 prefix.h[26]=(uint64_t)RAW(SYS_arch_prctl,0x1021,&prefix.h[27],0,0,0,0);
 prefix.h[28]=(uint64_t)RAW(SYS_arch_prctl,0x1022,&prefix.h[29],0,0,0,0);
 need(!prefix.h[26]&&!prefix.h[28],55);
 need((prefix.h[14]&0xe7)==0xe7&&prefix.h[15]>=576&&prefix.h[15]<=UA_FP,51);
 for(unsigned i=2;i<64;i++)if(prefix.h[14]&(UINT64_C(1)<<i)){
  const uint32_t *r=prefix.hardware[3+i];need(r[2]&&r[3]>=576&&(uint64_t)r[3]+r[2]<=prefix.h[15]&&!(r[4]&1),52);
 }
}
static void machine(uint64_t out[8]){
 need(!RAW(SYS_rt_sigprocmask,0,0,&out[0],8,0,0)&&out[0]==MASK,53);
 need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&out[1],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&out[2],0,0,0,0),54);
 uint16_t cs,ss,ds,es,fs,gs;__asm__ volatile("mov %%cs,%0;mov %%ss,%1;mov %%ds,%2;mov %%es,%3;mov %%fs,%4;mov %%gs,%5":"=r"(cs),"=r"(ss),"=r"(ds),"=r"(es),"=r"(fs),"=r"(gs));
 out[3]=cs;out[4]=ss;out[5]=(uint64_t)ds|((uint64_t)es<<16);out[6]=(uint64_t)fs|((uint64_t)gs<<16);out[7]=0;
}

static void native_setup(void) {
    long a=RAW(SYS_mmap,0,ALT_BYTES+2*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(a>0,60);alt_area=(uintptr_t)a;
    need(!RAW(SYS_mprotect,alt_area+UA_PAGE,ALT_BYTES,PROT_READ|PROT_WRITE,0,0,0),61);
    stack_t st={.ss_sp=(void *)(alt_area+UA_PAGE),.ss_size=ALT_BYTES};
    need(!RAW(SYS_sigaltstack,&st,0,0,0,0,0),62);
    struct kernel_action action={.handler=handler,.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL,
        .restorer=direct_frontier_restorer,.mask=MASK};
    for(unsigned i=0;i<2;i++) {
        int sig=i?SIGTRAP:SIGSEGV;
        need(!RAW(SYS_rt_sigaction,sig,0,&old_actions[i],8,0,0)&&!old_actions[i].handler,63);
        need(!RAW(SYS_rt_sigaction,sig,&action,0,8,0,0),64);++actions_installed;
    }
}
static void stub(uintptr_t at) {
    const unsigned char jump[6]={0xff,0x25,0,0,0,0};
    copy((void *)at,jump,sizeof jump);copy((void *)(at+6),&endpoint,sizeof endpoint);
}
static void predecessor(void) {
    /* The five-byte original branch lives in previously unused source
       padding. Its target is the requested genuine body entry, not root0. */
    need(lp_predecessor_offset==-5&&lp_entry[mode]<88,142);
    uintptr_t from=base-5;int32_t displacement=(int32_t)lp_entry[mode];
    *(unsigned char *)from=0xe9;copy((void *)(from+1),&displacement,4);
}
static void prepare(void) {
    source_page=lp_source_page[placement];base=source_page+lp_base_offset[placement];
    endpoint=(uintptr_t)region_app_capture_high;
    need(!(source_page&(UA_PAGE-1))&&lp_base_offset[placement]>=124&&
         lp_base_offset[placement]+102<LP_SOURCE&&
         ((base+lp_entry[mode])&(UA_PAGE-1))<=UA_PAGE-15,143);
    need(loop_native_template_end-loop_native_template==144,70);
    need(RAW(SYS_mmap,source_page-UA_PAGE,LP_SOURCE+2*UA_PAGE,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)(source_page-UA_PAGE),71);
    need(!RAW(SYS_mprotect,source_page,LP_SOURCE,PROT_READ|PROT_WRITE,0,0,0),72);
    for(unsigned i=0;i<LP_SOURCE;i++)((unsigned char *)source_page)[i]=0xcc;
    copy((void *)base,loop_native_template,88);stub(base-124);stub(base+88);predecessor();
    /* Runtime lane: real logical RX request, actual permissions are governed
       by the unchanged runtime. Never install or weaken native handlers. */
    need(!RAW(SYS_mprotect,source_page,LP_SOURCE,PROT_READ|(native?0:PROT_EXEC),0,0,0),73);
    need(RAW(SYS_mmap,LP_DATA,UA_DATA+UA_PAGE,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)LP_DATA,74);
    need(!RAW(SYS_mprotect,LP_DATA,UA_DATA,PROT_READ|PROT_WRITE,0,0,0),75);
    need(RAW(SYS_mmap,STACK_BASE,STACK_EXTENT+2*UA_PAGE,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(long)STACK_BASE,76);
    need(!RAW(SYS_mprotect,STACK_BASE+UA_PAGE,STACK_EXTENT,PROT_READ|PROT_WRITE,0,0,0),77);
    lp_inputs(mode,&ua_input,prefix.data);
    ua_input.g[4]=STACK_BASE+UA_PAGE+STACK_EXTENT-504;need((ua_input.g[4]&15)==8,78);
    ua_stack_pattern(prefix.stack,UA_STACK);
    copy((void *)LP_DATA,prefix.data,UA_DATA);copy((void *)(ua_input.g[4]-128),prefix.stack,UA_STACK);
    need(!RAW(SYS_mprotect,LP_DATA,UA_DATA,PROT_READ,0,0,0),79);
    copy(&prefix.seed,&ua_input,sizeof ua_input);copy(prefix.source,(const void *)source_page,LP_SOURCE);
    need(same(prefix.source+(base-source_page),loop_native_template,88),80);
    ua_target=base-5;lp_model_init(&model,&ua_input,base,endpoint,mode);
    if(native)native_setup();
}
static void collect(void) {
    need(!handling,81);
    struct lp_model expected;const struct lp_model *want=&model;
    if(native) {
        need(started&&ended&&steps==lp_steps[mode]&&fault_seen==(mode>=5),81);
        need(frames==steps+1+(mode>=5),82);
    } else {
        /* These are postconditions from an independent original model, not
           observed TRACE/cancellation/publication counters. Fault cases must
           remain runtime failures and may never reach this success suffix. */
        need(mode<5&&!started&&!ended&&!steps&&!frames&&!fault_seen&&!undefined_events,144);
        lp_model_init(&expected,&ua_input,base,endpoint,mode);uint64_t unknown=0;
        for(unsigned i=0;i<lp_steps[mode];i++) {
            uintptr_t pc=expected.pc;uint64_t undefined=0,want_undefined=0;
            need(lp_advance(&expected,prefix.data,&undefined),145);
            if(pc>=base&&pc<base+88) {
                unsigned off=(unsigned)(pc-base);
                if(off==0||off==4||off==8||off==18||off==63||off==71||off==75||off==83)unknown=0;
                else if(off==32||off==59||off==79) {
                    unknown=(unknown&~UINT64_C(0x8c5))|UINT64_C(0x10);want_undefined=UINT64_C(0x10);
                } else if(off==48) {
                    unknown=(unknown&~UINT64_C(0xc5))|UINT64_C(0x810);want_undefined=UINT64_C(0x810);
                }
            }
            need(undefined==want_undefined,148);
        }
        need(expected.pc==endpoint&&!unknown,146);want=&expected;
    }
    need(same(ua_before.g,ua_input.g,sizeof ua_input.g)&&ua_before.flags==ua_input.flags&&
        same(ua_before.selectors,ua_after.selectors,sizeof ua_before.selectors),83);
    for(unsigned i=0;i<16;i++)need(ua_after.g[i]==want->g[i],120+i);
    need(ua_after.flags==want->flags,136);
    need(same(ua_before_live,ua_after_live,UA_LIVE),84);
    for(unsigned i=0;i<6;i++)need(want->backward[i]==lp_backwards[mode][i],85);
    for(unsigned i=0;i<2;i++)need(want->cut[i]==lp_cuts[mode][i],86);
    if(mode==2)need(ua_after.g[10]==UINT64_C(0xffffffff80000000),87);
    if(mode==3||mode==4)need(ua_after.g[2]==UINT64_C(0xfedcba9876543261),88);
    copy(&suffix.before,&ua_before,sizeof ua_before);copy(&suffix.after,&ua_after,sizeof ua_after);
    copy(suffix.before_live,ua_before_live,UA_LIVE);copy(suffix.after_live,ua_after_live,UA_LIVE);
    copy(suffix.source,(const void *)source_page,LP_SOURCE);copy(suffix.data,(const void *)LP_DATA,UA_DATA);
    copy(suffix.stack,(const void *)(ua_input.g[4]-128),UA_STACK);
    need(same(suffix.source,prefix.source,LP_SOURCE)&&same(suffix.data,prefix.data,UA_DATA)&&
        same(suffix.stack,prefix.stack,UA_STACK),89);
    machine(suffix.machine_after);copy(suffix.machine_before,current_machine,sizeof current_machine);
    need(same(suffix.machine_before,suffix.machine_after,sizeof current_machine),90);
    unsigned cpu=0,node=0;
    need(!RAW(SYS_getcpu,&cpu,&node,0,0,0,0)&&cpu==prefix.h[8]&&node==prefix.h[9],91);
    need(!RAW(SYS_mprotect,source_page,LP_SOURCE,PROT_READ,0,0,0),92);
}
static void cleanup(void) {
    if(native) {
        for(unsigned i=0;i<actions_installed;i++)
            need(!RAW(SYS_rt_sigaction,i?SIGTRAP:SIGSEGV,&old_actions[i],0,8,0,0),93);
        stack_t disabled={.ss_flags=SS_DISABLE};need(!RAW(SYS_sigaltstack,&disabled,0,0,0,0,0),94);
        need(!RAW(SYS_munmap,alt_area,ALT_BYTES+2*UA_PAGE,0,0,0,0),95);alt_area=0;
    } else need(!actions_installed&&!alt_area,147);
    need(!RAW(SYS_munmap,source_page-UA_PAGE,LP_SOURCE+2*UA_PAGE,0,0,0,0),96);
    need(!RAW(SYS_munmap,LP_DATA,UA_DATA+UA_PAGE,0,0,0,0),97);
    need(!RAW(SYS_munmap,STACK_BASE,STACK_EXTENT+2*UA_PAGE,0,0,0,0),98);suffix.h[5]=1;
}
int main(int argc,char **argv) {
    if(argc!=4||argv[1][0]<'0'||argv[1][0]>'1'||argv[1][1]||
       argv[2][0]<'0'||argv[2][0]>'6'||argv[2][1]||argv[3][0]<'0'||argv[3][0]>'3'||argv[3][1])return 2;
    native=argv[1][0]=='0';mode=(unsigned)(argv[2][0]-'0');placement=(unsigned)(argv[3][0]-'0');
    uint64_t *h=prefix.h;h[0]=LP_MAGIC;h[1]=LP_VERSION;h[2]=sizeof prefix;h[3]=sizeof suffix;h[4]=mode;h[5]=native;
    h[6]=(uint64_t)RAW(SYS_getpid,0,0,0,0,0,0);h[7]=(uint64_t)RAW(SYS_gettid,0,0,0,0,0,0);
    need(h[6]>0&&h[6]==h[7],137);unsigned cpu=0,node=0;
    need(!RAW(SYS_getcpu,&cpu,&node,0,0,0,0),138);h[8]=cpu;h[9]=node;
    hardware();machine(prefix.machine);prepare();
    h[10]=base;h[11]=source_page;h[12]=LP_DATA;h[13]=STACK_BASE;
    h[16]=placement;h[17]=mode>=5;h[18]=(uintptr_t)region_app_seed_x87;
    h[19]=sizeof(ucontext_t);h[20]=sizeof(struct ua_frame);h[21]=offsetof(ucontext_t,uc_mcontext.gregs);
    h[22]=offsetof(ucontext_t,uc_mcontext.fpregs);h[23]=offsetof(ucontext_t,uc_sigmask);
    h[24]=offsetof(ucontext_t,uc_stack);h[25]=offsetof(siginfo_t,si_addr);
    h[30]=lp_entry[mode];h[31]=UA_STACK;h[32]=mode>=5?LP_GUARD:0;h[33]=mode>=5?1:0;
    h[34]=endpoint;h[35]=ua_target;h[36]=lp_steps[mode];h[37]=LP_FRAMES;h[38]=LP_SOURCE;h[39]=UA_DATA;
    h[40]=LP_KEY;h[41]=LP_ROW;h[42]=LP_GUARD;h[43]=base-124;h[44]=base+88;
    h[45]=base+lp_entry[mode];h[46]=(uint64_t)(int64_t)lp_predecessor_offset;h[47]=5;h[48]=!native;
    h[49]=lp_steps[mode]-1;h[50]=lp_steps[mode]+1+(mode>=5);
    need(output(&prefix,sizeof prefix),139);machine(current_machine);
    need(same(current_machine,prefix.machine,sizeof current_machine),140);
    region_app_enter();collect();
    suffix.h[0]=LP_MAGIC^1;suffix.h[1]=LP_VERSION;suffix.h[2]=mode;suffix.h[3]=placement;suffix.h[4]=first_error;
    suffix.h[6]=started;suffix.h[7]=frames;suffix.h[8]=steps;suffix.h[9]=fault_seen;suffix.h[10]=ended;
    if(native) {
        for(unsigned i=0;i<6;i++)suffix.h[12+i]=model.backward[i];
        for(unsigned i=0;i<2;i++)suffix.h[18+i]=model.cut[i];
    }
    suffix.h[20]=undefined_events;suffix.h[23]=fault_seen;
    suffix.h[24]=!native;
    cleanup();need(!first_error&&output(&suffix,sizeof suffix),141);return 0;
}
