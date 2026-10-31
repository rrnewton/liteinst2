/* Real original ADD versus emitted guard+the same ADD. This component proves
   integer/flags/memory/fault behavior, not production source/rseq/RX custody or
   guest signal-handler continuation. No signal metadata is rewritten to pass. */
#define _GNU_SOURCE
#include "linked_add_guard.h"
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#define PAGE 4096UL
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_ag_plan plan;
static struct li2_mg_table *table;
static unsigned char *block,*data,*guest_stack,*alternate;
static uint64_t seed[16],input_flags;
uint64_t ag_native_host_sp;
extern void ag_native_enter(void),ag_native_start(void),ag_native_return(void);
static const unsigned greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static volatile sig_atomic_t lane,stepping,armed,entered,finished,handling;
static unsigned pairs,fault_pairs,success_pairs,boundary_checks;
struct observation {
    uint64_t gpr[16],flags,raw_pc,logical_pc,trap,error,cr2,address;
    int signal,code,error_number;
    unsigned char memory[2*PAGE];
};
static struct observation current,reference;
static void require(int good){if(!good)_exit(121);}
static void handler(int sig,siginfo_t *si,void *opaque){
    require(!handling && armed && si && opaque);handling=1;
    ucontext_t *uc=opaque;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(!entered){
        require(sig==SIGTRAP && pc==(uintptr_t)ag_native_start && !finished);entered=1;
        for(unsigned i=0;i<16;i++)g[greg[i]]=(greg_t)seed[i];
        g[REG_EFL]=(greg_t)input_flags;g[REG_RIP]=(greg_t)(lane?plan.generated:plan.original.tf.pc);
        handling=0;return;
    }
    require(!finished);uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=(uint64_t)g[greg[i]];
    uint64_t flags=(uint64_t)g[REG_EFL],logical=0;struct li2_ag_recovered recovered={0};
    if(lane && pc>=plan.generated && pc-plan.generated<plan.image_bytes){
        require(!li2_ag_recover(&plan,pc,raw,flags,(const uint64_t *)(uintptr_t)plan.spill,&recovered) && recovered.complete);
        require(!memcmp(recovered.gpr,seed,sizeof seed));++boundary_checks;
        if(recovered.phase!=LI2_AG_AFTER){
            require(recovered.flags==((input_flags&~RF)|(flags&RF)));
            require(recovered.original_pc==plan.original.tf.pc);
            if(sig==SIGTRAP){require(stepping && si->si_code==TRAP_TRACE && g[REG_TRAPNO]==1 && !g[REG_ERR]);handling=0;return;}
            require(sig==SIGSEGV && recovered.phase==LI2_AG_RMW && pc==plan.generated+plan.rmw_offset);
        }else require(sig==SIGTRAP && stepping && si->si_code==TRAP_TRACE);
        memcpy(raw,recovered.gpr,sizeof raw);flags=recovered.flags;logical=recovered.original_pc;
    }else if(sig==SIGTRAP){
        uintptr_t expected=plan.original.tf.next_pc+(stepping?0U:1U);
        require(pc==expected && (!stepping || !lane));logical=plan.original.tf.next_pc;
    }else{
        require(!lane && sig==SIGSEGV && pc==plan.original.tf.pc);logical=pc;
    }
    if(sig==SIGSEGV)require(si->si_code==SEGV_ACCERR && !si->si_errno && g[REG_TRAPNO]==14 && !(g[REG_ERR]&16) && (uintptr_t)si->si_addr==(uintptr_t)g[REG_CR2]);
    else require(sig==SIGTRAP && g[REG_TRAPNO]==(stepping?1:3) && !g[REG_ERR]);
    memcpy(current.gpr,raw,sizeof raw);current.flags=flags;current.raw_pc=pc;current.logical_pc=logical;
    current.trap=(uint64_t)g[REG_TRAPNO];current.error=(uint64_t)g[REG_ERR];current.cr2=(uint64_t)g[REG_CR2];
    current.signal=sig;current.code=si->si_code;current.error_number=si->si_errno;current.address=(uintptr_t)si->si_addr;
    finished=1;g[REG_RIP]=(greg_t)(uintptr_t)ag_native_return;
    /* Cleanup only, after the complete raw/logical observation above. */
    g[REG_EFL]&=~(greg_t)(TF|UINT64_C(0x400));handling=0;
}
static uint64_t status(unsigned n){
    static const unsigned bit[]={0,2,4,6,7,11};uint64_t f=UINT64_C(0x202)|((uint64_t)(n&1)<<10);
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bit[i];return f;
}
static void put64(unsigned char *p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static void pattern(void){for(unsigned i=0;i<2*PAGE;i++)data[i]=(unsigned char)(i*13+5);}
static void run(unsigned which,unsigned fault,uint64_t old){
    assert(!mprotect(data,2*PAGE,PROT_READ|PROT_WRITE));pattern();
    unsigned source=plan.original.source_reg,base=plan.original.base;uintptr_t target=(uintptr_t)data+(fault>=3?PAGE-4:64);
    assert(base<16 && source<16);seed[base]=target;
    put64((unsigned char *)target,old);
    if(fault==1 || fault==2)assert(!mprotect(data,PAGE,fault==1?PROT_READ:PROT_NONE));
    if(fault>=3)assert(!mprotect(data+PAGE,PAGE,fault==3?PROT_READ:PROT_NONE));
    memset((void *)(uintptr_t)plan.spill,0xa5,32);memset(&current,0,sizeof current);
    lane=(sig_atomic_t)which;armed=1;entered=finished=handling=0;ag_native_enter();armed=0;
    assert(entered && finished && !handling && !memcmp(current.gpr,seed,sizeof seed));
    assert(!mprotect(data,2*PAGE,PROT_READ|PROT_WRITE));memcpy(current.memory,data,2*PAGE);
    if(!which){reference=current;return;}
    assert(!memcmp(current.gpr,reference.gpr,sizeof current.gpr) && current.flags==reference.flags && current.logical_pc==reference.logical_pc);
    assert(current.signal==reference.signal && current.code==reference.code && current.error_number==reference.error_number);
    assert(current.trap==reference.trap && current.error==reference.error && current.cr2==reference.cr2);
    assert(!memcmp(current.memory,reference.memory,sizeof current.memory));
    if(fault){
        assert(current.signal==SIGSEGV && current.raw_pc==plan.generated+plan.rmw_offset && reference.raw_pc==plan.original.tf.pc);
        assert(current.address==reference.address && current.logical_pc==plan.original.tf.pc);++fault_pairs;
    }else{
        assert(current.signal==SIGTRAP && current.logical_pc==plan.original.tf.next_pc);
        if(stepping)assert(current.raw_pc==plan.generated+plan.rmw_offset+plan.original.tf.length && reference.raw_pc==plan.original.tf.next_pc);
        else assert(current.raw_pc==reference.raw_pc && current.address==reference.address);
        ++success_pairs;
    }
    ++pairs;
}
static void form(unsigned actual){
    assert(!mprotect(block,2*PAGE,PROT_READ|PROT_WRITE));memset(block,0xcc,2*PAGE);
    unsigned char ordinary[]={0x48,0x01,0x07},loader[]={0x4d,0x01,0x75,0};
    const unsigned char *b=actual?loader:ordinary;unsigned n=actual?sizeof loader:sizeof ordinary;
    uintptr_t pc=(uintptr_t)block+64,generated=(uintptr_t)block+PAGE+64,spill=(uintptr_t)block+4*PAGE;
    memcpy((void *)pc,b,n);*(unsigned char *)(pc+n)=0xcc;
    assert(!li2_ag_emit(pc,b,n,generated,spill,pc+n,table,&plan) && !li2_ag_validate(&plan));
    memcpy((void *)generated,plan.image,plan.image_bytes);assert(!mprotect(block,2*PAGE,PROT_READ|PROT_EXEC));
    for(unsigned i=0;i<16;i++)seed[i]=UINT64_C(0x1122334400000000)+UINT64_C(0x1001001)*i;
    seed[4]=(uintptr_t)guest_stack+15*PAGE;
}
int main(void){
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    block=mmap(0,8*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(block!=MAP_FAILED);
    data=block+6*PAGE;table=(struct li2_mg_table *)(void *)(block+2*PAGE);
    const struct li2_mg_range exclusions[]={{(uintptr_t)block,(uintptr_t)block+5*PAGE}};
    assert(!li2_mg_table_build(exclusions,1,(uintptr_t)table,table));assert(!mprotect(table,2*PAGE,PROT_READ));
    guest_stack=mmap(0,18*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(guest_stack!=MAP_FAILED);
    assert(!mprotect(guest_stack+PAGE,16*PAGE,PROT_READ|PROT_WRITE));
    alternate=mmap(0,34*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(alternate!=MAP_FAILED);
    assert(!mprotect(alternate+PAGE,32*PAGE,PROT_READ|PROT_WRITE));
    stack_t alt={.ss_sp=alternate+PAGE,.ss_size=32*PAGE},old_alt;assert(!sigaltstack(&alt,&old_alt));
    struct sigaction action={0},old_trap,old_segv;action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO|SA_ONSTACK;
    assert(!sigemptyset(&action.sa_mask) && !sigaction(SIGTRAP,&action,&old_trap) && !sigaction(SIGSEGV,&action,&old_segv));
    const uint64_t old[]={UINT64_MAX,UINT64_C(0x7fffffffffffffff),15};
    const uint64_t add[]={1,1,1};
    for(unsigned f=0;f<2;f++){
        form(f);stepping=1;
        for(unsigned value=0;value<3;value++)for(unsigned flags=0;flags<64;flags++){
            seed[plan.original.source_reg]=add[value];input_flags=status(flags)|TF;
            run(0,0,old[value]);run(1,0,old[value]);
        }
        for(unsigned trace=0;trace<2;trace++)for(unsigned fault=1;fault<=4;fault++){
            stepping=(sig_atomic_t)trace;seed[plan.original.source_reg]=UINT64_MAX;input_flags=status(63)|(trace?TF:0);
            run(0,fault,16);run(1,fault,16);
        }
        stepping=0;input_flags=status(63);seed[plan.original.source_reg]=1;run(0,0,UINT64_MAX);run(1,0,UINT64_MAX);
    }
    assert(pairs==402 && success_pairs==386 && fault_pairs==16 && boundary_checks>0);
    assert(!li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    assert(!sigaction(SIGTRAP,&old_trap,0) && !sigaction(SIGSEGV,&old_segv,0) && !sigaltstack(&old_alt,0));
    assert(!munmap(alternate,34*PAGE) && !munmap(guest_stack,18*PAGE) && !munmap(block,8*PAGE));
    printf("{\"schema\":1,\"original_generated_pairs\":402,\"success_pairs\":386,\"fault_pairs\":16,\"postseal_equal\":1,\"emitted_instruction_execution\":1,\"production_qualification\":0}\n");return 0;
}
