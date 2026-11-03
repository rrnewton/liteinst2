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
#include "linked_loop_direct.h"
#include "linked_jmp_domain.h"
#include "model.h"
#define PAGE 4096U
#define FP_BYTES 65536U
#define STACK_BYTES (4U*PAGE)
#define ALT_BYTES (256U*1024U)
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define DF UINT64_C(0x400)
#define MAGIC UINT64_C(0x31414c4632494c)
#define RECORD UINT64_C(0x31524c4632494c)
#define END UINT64_C(0x31454c4632494c)
#define TRACES 64U
#include "tests/direct_call_native/frame.h"
struct trace {
    uint64_t pc,flags,gpr[16],spill[4];
    struct li2_dd_recovered recovered;
};
struct lane_record {
    uint64_t h[64];
    struct frame before,after;
    struct li2_dd_aux_plan plan;
    struct trace trace[TRACES];
    unsigned char source[PAGE],code[PAGE],rows[PAGE],directory[LI2_JD_DOMAIN_BYTES];
    unsigned char stack_before[STACK_BYTES],stack_after[STACK_BYTES];
    unsigned char spill_before[PAGE],spill_after[PAGE],image[2U*LI2_JD_IMAGE_BYTES],target[PAGE];
};
_Static_assert(sizeof(ucontext_t)==968 && sizeof(siginfo_t)==128 && sizeof(sigset_t)==128 &&
    NGREG==23 && sizeof(greg_t)==8 && sizeof(struct frame)==67072,"exact whole Linux signal ABI");
_Static_assert(sizeof(struct trace)==328 && sizeof(struct lane_record)==293184 &&
    512+18U*sizeof(struct lane_record)+64<16U*1024U*1024U,"complete fixed native output below original bound");
uint64_t probe_seed[16],probe_flags,probe_pc;
extern void probe_enter(void),probe_return(void),probe_reload(void);
extern unsigned char probe_scratch_end[];
static uintptr_t alt_base,source_base,code_base,spill_base,stack_base,directory_base,rows_base,image_base[2],target_base;
static unsigned cpu,trace_count,events,written;
static int output_started;
static volatile sig_atomic_t phase,handler_busy;
static uint64_t header[64],visited;
static struct lane_record record;
static _Alignas(64) unsigned char arena[16U<<20];
static void need(int,unsigned);
#include "tests/direct_call_native/capture.inc"
__attribute__((noreturn)) static void fail(unsigned code) {
    record.h[14]=code;
    if(output_started)(void)write_all(1,&record,sizeof record);
    static const char message[]="far-AUX native diagnostic incomplete\n";
    (void)write_all(2,message,sizeof message-1);
    raw(SYS_exit_group,125,0,0,0,0,0);__builtin_unreachable();
}
static void need(int value,unsigned code) {if(!value)fail(code);}
static const unsigned greg_index[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,
    REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static void protect(uintptr_t at,size_t bytes,int prot) {
    need(!raw(SYS_mprotect,(long)at,(long)bytes,prot,0,0,0),30);
}
static void trace_frame(uintptr_t pc,const ucontext_t *uc) {
    need(trace_count<TRACES,31);struct trace *t=&record.trace[trace_count++];
    t->pc=pc;t->flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    for(unsigned i=0;i<16;i++)t->gpr[i]=(uint64_t)uc->uc_mcontext.gregs[greg_index[i]];
    copy(t->spill,(const void *)spill_base,sizeof t->spill);
    uint64_t before=far_aux_decoder_calls();
    need(!li2_ld_aux_recover(&record.plan,pc,t->gpr,t->flags,t->spill,&t->recovered) &&
        far_aux_decoder_calls()==before && t->recovered.complete==1 &&
        t->recovered.phase==LI2_DD_BEFORE && t->recovered.original_pc==header[21]+0xffa &&
        equal(t->recovered.gpr,probe_seed,sizeof probe_seed) &&
        (t->recovered.flags&~(TF|RF))==probe_flags &&
        (t->recovered.flags&(TF|RF))==(t->flags&(TF|RF)),32);
    unsigned matches=0;
    for(unsigned i=0;i<record.plan.value.record.boundaries;i++)
        if(pc==record.plan.value.generated+record.plan.value.record.boundary[i].offset) {
            ++matches;record.h[21]|=UINT64_C(1)<<i;
        }
    need(matches==1,33);
}
static void handler(int sig,siginfo_t *si,void *context) {
    if(handler_busy)fail(34);handler_busy=1;++events;ucontext_t *uc=context;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(phase==0) {
        capture(&record.before,sig,si,uc);
        need(sig==SIGSEGV && si->si_code==SEGV_ACCERR && (uintptr_t)si->si_addr==probe_pc &&
            pc==probe_pc && uc->uc_mcontext.gregs[REG_TRAPNO]==14 &&
            ((uint64_t)uc->uc_mcontext.gregs[REG_ERR]&16)==16,35);
        for(unsigned i=0;i<16;i++)need((uint64_t)uc->uc_mcontext.gregs[greg_index[i]]==probe_seed[i],36);
        need(((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&~RF)==probe_flags,37);
        if(record.h[3]==2)trace_frame(pc,uc);
        phase=1;
        if(record.h[3])protect(code_base,PAGE,PROT_READ|PROT_EXEC);
        else if(record.h[4]==0)protect(source_base,PAGE,PROT_READ|PROT_EXEC);
        if(record.h[3]==2)uc->uc_mcontext.gregs[REG_EFL]=(greg_t)(probe_flags|TF);
        else {
            uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_reload;
            uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
            uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(RF|TF);
        }
    } else if(phase==1) {
        if(record.h[3]==2) {
            need(sig==SIGTRAP && si->si_code==TRAP_TRACE && (uintptr_t)si->si_addr==pc,38);
            trace_frame(pc,uc);
            unsigned end=record.h[4]?record.plan.value.record.miss_offset:record.plan.value.record.hit_offset;
            if(pc!=code_base+end){handler_busy=0;return;}
        } else {
            uintptr_t expected=record.h[4]?source_base+0xffa:
                record.h[3]?image_base[1]+512:target_base+512;
            need(sig==SIGSEGV && si->si_code==SEGV_ACCERR && pc==expected &&
                (uintptr_t)si->si_addr==expected && uc->uc_mcontext.gregs[REG_TRAPNO]==14 &&
                ((uint64_t)uc->uc_mcontext.gregs[REG_ERR]&16)==16,39);
        }
        capture(&record.after,sig,si,uc);phase=2;
        uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)probe_return;
        uc->uc_mcontext.gregs[REG_RSP]=(greg_t)(uintptr_t)probe_scratch_end;
        uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)(TF|RF|DF|UINT64_C(0x40000));
    } else fail(40);
    handler_busy=0;
}
static uintptr_t allocation(uintptr_t at,size_t bytes) {
    void *p=mmap((void *)at,bytes,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|(at?MAP_FIXED_NOREPLACE:0),-1,0);
    need(p!=MAP_FAILED && (!at || (uintptr_t)p==at) && !((uintptr_t)p&(PAGE-1)),41);return(uintptr_t)p;
}
static void lane(unsigned id,unsigned which) {
    unsigned mode=id%3;uintptr_t pc=source_base+0xffa,target=target_base+512;
    memset(&record,0,sizeof record);phase=0;events=trace_count=0;handler_busy=0;
    protect(source_base,PAGE,3);protect(code_base,PAGE,3);protect(spill_base,PAGE,3);
    protect(directory_base,LI2_JD_DOMAIN_BYTES,3);protect(rows_base,PAGE,3);
    for(unsigned i=0;i<2;i++)protect(image_base[i],LI2_JD_IMAGE_BYTES,3);
    protect(target_base,PAGE,3);
    memset((void *)source_base,0xcc,PAGE);memset((void *)code_base,0,PAGE);
    memset((void *)rows_base,0,PAGE);memset((void *)directory_base,0,LI2_JD_DOMAIN_BYTES);
    for(unsigned i=0;i<2;i++)memset((void *)image_base[i],0xcc,LI2_JD_IMAGE_BYTES);
    memset((void *)target_base,0xcc,PAGE);
    for(unsigned i=0;i<STACK_BYTES;i++)((unsigned char *)stack_base)[i]=(unsigned char)(0x5a+37*i+id);
    for(unsigned i=0;i<PAGE;i++)((unsigned char *)spill_base)[i]=(unsigned char)(0xa7+19*i+id);
    unsigned char *b=(void *)pc;int64_t delta=(int64_t)target-(int64_t)(pc+5);
    need(delta>=INT32_MIN && delta<=INT32_MAX,42);b[0]=0xe9;
    for(unsigned i=0;i<4;i++)b[i+1]=(unsigned char)((uint32_t)delta>>(8*i));
    struct li2_dd_aux_binding binding={.owner={.rows=rows_base,
        .image={image_base[0],image_base[1]},.heads=1,.head=0,.directory=directory_base},
        .code=code_base,.spill=spill_base};
    struct li2_dd_aux_plan near;
    need(li2_dd_aux_emit(pc,b,5,&binding,&near)==LI2_DD_RELOCATION && !near.ready &&
        !li2_ld_aux_emit(pc,b,5,&binding,&record.plan) && !li2_ld_aux_validate(&record.plan) &&
        record.plan.version==2 && record.plan.value.record.version==2,43);
    copy((void *)code_base,record.plan.value.image,512);
    struct li2_jd_domain_directory *directory=(void *)directory_base;
    directory->version=1;directory->serial=73;directory->count=mode==2?0:2;
    if(directory->count) {
        directory->row[0]=(struct li2_jd_domain_row){target+1,image_base[0]+512,90,0,1};
        directory->row[1]=(struct li2_jd_domain_row){target+(mode==1?2:0),image_base[1]+512,91,1,1};
    }
    for(unsigned i=0;i<16;i++)probe_seed[i]=UINT64_C(0x13579bdf00110000)+UINT64_C(0x100010001)*i+id;
    probe_seed[4]=stack_base+2*PAGE+512;probe_flags=id<3?0x202:0xed7;
    probe_pc=which?code_base:pc;
    record.h[0]=RECORD;record.h[1]=sizeof record;record.h[2]=id;record.h[3]=which;record.h[4]=mode;
    record.h[5]=pc;record.h[6]=target;record.h[7]=code_base;record.h[8]=image_base[1]+512;
    record.h[9]=probe_flags;record.h[10]=probe_seed[4];record.h[11]=directory->count;
    record.h[12]=far_aux_decoder_calls();
    copy(record.source,(void *)source_base,PAGE);copy(record.code,(void *)code_base,PAGE);
    copy(record.rows,(void *)rows_base,PAGE);copy(record.directory,(void *)directory_base,LI2_JD_DOMAIN_BYTES);
    copy(record.stack_before,(void *)stack_base,STACK_BYTES);copy(record.spill_before,(void *)spill_base,PAGE);
    for(unsigned i=0;i<2;i++)copy(record.image+i*LI2_JD_IMAGE_BYTES,(void *)image_base[i],LI2_JD_IMAGE_BYTES);
    copy(record.target,(void *)target_base,PAGE);
    protect(source_base,PAGE,1);protect(code_base,PAGE,1);protect(directory_base,LI2_JD_DOMAIN_BYTES,1);
    protect(rows_base,PAGE,1);protect(target_base,PAGE,1);
    for(unsigned i=0;i<2;i++)protect(image_base[i],LI2_JD_IMAGE_BYTES,1);
    probe_enter();
    need(phase==2 && !handler_busy && events==(which==2?trace_count:2),44);
    record.h[13]=far_aux_decoder_calls();need(record.h[13]==record.h[12],45);
    for(unsigned i=0;i<16;i++)need((uint64_t)record.after.greg[greg_index[i]]==probe_seed[i],46);
    need(((uint64_t)record.after.greg[REG_EFL]&~(TF|RF))==probe_flags &&
        equal(record.before.fp,record.after.fp,FP_BYTES) &&
        record.before.h[8]==record.after.h[8] && record.before.h[9]==record.after.h[9],47);
    protect(source_base,PAGE,1);protect(code_base,PAGE,1);
    copy(record.stack_after,(void *)stack_base,STACK_BYTES);copy(record.spill_after,(void *)spill_base,PAGE);
    need(equal(record.stack_before,record.stack_after,STACK_BYTES) &&
        equal(record.source,(void *)source_base,PAGE) && equal(record.code,(void *)code_base,PAGE) &&
        equal(record.rows,(void *)rows_base,PAGE) && equal(record.directory,(void *)directory_base,LI2_JD_DOMAIN_BYTES) &&
        equal(record.target,(void *)target_base,PAGE),48);
    for(unsigned i=0;i<2;i++)need(equal(record.image+i*LI2_JD_IMAGE_BYTES,(void *)image_base[i],LI2_JD_IMAGE_BYTES),49);
    if(!which)need(equal(record.spill_before,record.spill_after,PAGE),50);
    else {
        need(equal(record.spill_before+40,record.spill_after+40,PAGE-40),51);
        for(unsigned i=0;i<4;i++)need(((uint64_t *)record.spill_after)[i]==probe_seed[i],52);
        if(mode)need(equal(record.spill_before+32,record.spill_after+32,8),53);
        else need(((uint64_t *)record.spill_after)[4]==image_base[1]+512,54);
    }
    record.h[15]=phase;record.h[16]=events;record.h[17]=trace_count;record.h[18]=1;
    visited|=record.h[21];need(write_all(1,&record,sizeof record),55);++written;
}
int main(void) {
    need(sysconf(_SC_PAGESIZE)==PAGE,60);cpu_set_t affinity;CPU_ZERO(&affinity);
    need(!sched_getaffinity(0,sizeof affinity,&affinity) && CPU_COUNT(&affinity)==1,61);
    int current=sched_getcpu();need(current>=0 && CPU_ISSET(current,&affinity),62);cpu=(unsigned)current;
    unsigned long cet=0;long cr=raw(SYS_arch_prctl,0x5005,(long)&cet,0,0,0,0);
    need((!cr && !cet)||cr==-22||cr==-38,63);
    unsigned a,b,c,d;need(__get_cpuid(1,&a,&b,&c,&d) && (c&(1U<<26)) && (c&(1U<<27)),64);
    uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));
    uint64_t xcr0=((uint64_t)hi<<32)|lo;need((xcr0&3)==3,65);
    __cpuid_count(13,0,a,b,c,d);need(b>=512 && b<=FP_BYTES,66);unsigned xbytes=b;
    source_base=allocation(UINT64_C(0x700000000000),PAGE);target_base=allocation(source_base+0x2000,PAGE);
    code_base=allocation(0x10000000,PAGE);spill_base=allocation(0x10010000,PAGE);
    rows_base=allocation(0x12000000,PAGE);directory_base=allocation(0x13000000,LI2_JD_DOMAIN_BYTES);
    image_base[0]=allocation(0x11000000,LI2_JD_IMAGE_BYTES);image_base[1]=allocation(0x11008000,LI2_JD_IMAGE_BYTES);
    stack_base=allocation(0,STACK_BYTES);uintptr_t alt=allocation(0,ALT_BYTES+2*PAGE);
    protect(alt,PAGE,0);protect(alt+PAGE+ALT_BYTES,PAGE,0);alt_base=alt+PAGE;
    stack_t stack={.ss_sp=(void *)alt_base,.ss_size=ALT_BYTES};need(!sigaltstack(&stack,0),67);
    struct sigaction action;memset(&action,0,sizeof action);action.sa_sigaction=handler;
    action.sa_flags=SA_SIGINFO|SA_ONSTACK;sigfillset(&action.sa_mask);
    const int signals[4]={SIGSEGV,SIGBUS,SIGILL,SIGTRAP};
    for(unsigned i=0;i<4;i++)need(!sigaction(signals[i],&action,0),68);
    sigset_t empty;sigemptyset(&empty);need(!sigprocmask(SIG_SETMASK,&empty,0),69);
    struct li2_decoder_stats before,after;need(!li2_decoder_initialize(arena,sizeof arena,&before),70);
    struct model_counts models;far_aux_models(&models);
    header[0]=MAGIC;header[1]=1;header[2]=sizeof header;header[3]=sizeof record;header[4]=sizeof(struct frame);
    header[5]=sizeof(ucontext_t);header[6]=sizeof(siginfo_t);header[7]=FP_BYTES;header[8]=STACK_BYTES;
    header[9]=PAGE;header[10]=6;header[11]=3;header[12]=18;header[15]=(uint64_t)getpid();header[16]=cpu;
    header[17]=(uint64_t)cr;header[18]=cet;header[19]=xcr0;header[20]=xbytes;
    header[21]=source_base;header[22]=stack_base;header[23]=target_base;header[24]=alt_base;header[25]=ALT_BYTES;
    header[26]=code_base;header[27]=spill_base;header[28]=rows_base;header[29]=directory_base;
    header[30]=image_base[0];header[31]=image_base[1];header[32]=sizeof record.plan;
    header[33]=sizeof(struct trace);header[34]=TRACES;header[35]=sizeof(struct li2_dd_recovered);
    copy(header+48,&models,sizeof models);need(write_all(1,header,sizeof header),71);output_started=1;
    for(unsigned id=0;id<6;id++)for(unsigned which=0;which<3;which++)lane(id,which);
    need(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls &&
        written==18 && visited==((UINT64_C(1)<<37)-1),72);
    uint64_t end[8]={END,1,written,sizeof header+written*sizeof record+64,visited,0,0,0};
    need(write_all(1,end,sizeof end),73);return 0;
}
