/* Enter every real certified head of one complete two-page/two-member graph.
   This is an emitter semantic oracle, not page-owner or throughput evidence. */
#define _GNU_SOURCE
#include "persistent_group_compact.h"
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#define PAGE 4096UL
#define BLOCK (2U<<20)
#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch;
static struct li2_pg_compact rebuilt;
static union li2_pg_guard recovery;
static struct li2_pg_compact *plan;
static struct li2_jd_domain_directory *directory;
static unsigned char *block,*data,*stack,*alternate;
static uint64_t seed[16],input_flags;
uint64_t se_native_host_sp;
extern void se_native_enter(void),se_native_start(void),se_native_return(void);
static const unsigned greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static volatile sig_atomic_t lane,armed,entered,finished,handling;
static unsigned selected_head,pairs,success_pairs,fault_pairs,recoveries;
struct observation {
    uint64_t gpr[16],flags,raw_pc,logical_pc,trap,error,cr2,address;
    int signal,code,error_number;
    unsigned char source[2*PAGE],memory[2*PAGE],stack[2*PAGE];
};
static struct observation current,reference;
static void require(int good){if(!good)_exit(121);}
static void bytes(void *v,const void *w,size_t n){unsigned char *d=v;const unsigned char *s=w;for(size_t i=0;i<n;i++)d[i]=s[i];}
static void fill(void *v,unsigned char b,size_t n){unsigned char *d=v;for(size_t i=0;i<n;i++)d[i]=b;}
static int same(const void *v,const void *w,size_t n){const unsigned char *a=v,*b=w;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static uintptr_t target(unsigned i){return plan->layout.generated[i/64]+(i%64)*LI2_PE_SLOT_BYTES;}
static void handler(int sig,siginfo_t *si,void *opaque){
    require(!handling && armed && si && opaque);handling=1;
    ucontext_t *uc=opaque;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(!entered){
        require(sig==SIGTRAP && pc==(uintptr_t)se_native_start && !finished);entered=1;
        for(unsigned i=0;i<16;i++)g[greg[i]]=(greg_t)seed[i];
        g[REG_EFL]=(greg_t)input_flags;
        g[REG_RIP]=(greg_t)(lane?target(selected_head):plan->original[selected_head].decoded.pc);
        handling=0;return;
    }
    require(!finished);uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=(uint64_t)g[greg[i]];
    uint64_t flags=(uint64_t)g[REG_EFL],logical=pc;
    if(sig==SIGSEGV){
        require(si->si_code==SEGV_ACCERR && !si->si_errno && g[REG_TRAPNO]==14 && !(g[REG_ERR]&16));
        require((uintptr_t)si->si_addr==(uintptr_t)g[REG_CR2]);
        if(lane){
            struct li2_pg_recovered r;
            require(!li2_pg_compact_recover(plan,pc,raw,flags,(const uint64_t *)plan->layout.spill,&recovery,&r));
            require(r.complete==1 && r.kind==LI2_PG_GUARD && r.head==selected_head%64 && r.member==selected_head/64);
            require(r.original_pc==plan->original[selected_head].decoded.pc);
            bytes(raw,r.gpr,sizeof raw);flags=r.flags;logical=r.original_pc;
        }else require(pc==plan->original[selected_head].decoded.pc);
    }else require(sig==SIGTRAP && pc==(uintptr_t)block+PAGE+0x501 && si->si_code==SI_KERNEL && g[REG_TRAPNO]==3 && !g[REG_ERR]);
    bytes(current.gpr,raw,sizeof raw);current.flags=flags;current.raw_pc=pc;current.logical_pc=logical;
    current.trap=(uint64_t)g[REG_TRAPNO];current.error=(uint64_t)g[REG_ERR];current.cr2=(uint64_t)g[REG_CR2];
    current.signal=sig;current.code=si->si_code;current.error_number=si->si_errno;current.address=(uintptr_t)si->si_addr;
    finished=1;g[REG_RIP]=(greg_t)(uintptr_t)se_native_return;
    g[REG_EFL]&=~(greg_t)(TF|UINT64_C(0x400));handling=0;
}
static uint64_t status(unsigned n){
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t f=UINT64_C(0x202)|((uint64_t)(n&1)<<10);
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bits[i];return f;
}
static void one(unsigned which,unsigned fault){
    assert(!mprotect(data,2*PAGE,PROT_READ|PROT_WRITE));
    for(unsigned i=0;i<2*PAGE;i++){data[i]=(unsigned char)(i*13+5);stack[i]=(unsigned char)(i*29+7);}
    fill((void *)plan->layout.spill,0xa5,PAGE);fill(&current,0,sizeof current);
    if(fault)assert(!mprotect(data,PAGE,fault==1?PROT_READ:PROT_NONE));
    lane=(sig_atomic_t)which;armed=1;entered=finished=handling=0;se_native_enter();armed=0;
    assert(entered && finished && !handling);
    assert(!mprotect(data,2*PAGE,PROT_READ|PROT_WRITE));
    bytes(current.source,block,2*PAGE);bytes(current.memory,data,2*PAGE);bytes(current.stack,stack,2*PAGE);
    if(!which){reference=current;return;}
    assert(same(current.gpr,reference.gpr,sizeof current.gpr) && current.flags==reference.flags && current.logical_pc==reference.logical_pc);
    assert(current.signal==reference.signal && current.code==reference.code && current.error_number==reference.error_number);
    assert(current.trap==reference.trap && current.error==reference.error && current.cr2==reference.cr2 && current.address==reference.address);
    assert(same(current.source,reference.source,sizeof current.source) && same(current.memory,reference.memory,sizeof current.memory) && same(current.stack,reference.stack,sizeof current.stack));
    assert(same(current.source,plan->source,sizeof current.source));
    if(fault){assert(current.signal==SIGSEGV && same(current.gpr,seed,sizeof seed));++fault_pairs;}
    else {assert(current.raw_pc==reference.raw_pc && current.signal==SIGTRAP);++success_pairs;}
    ++pairs;
}
static void form(void){
    uintptr_t b=(uintptr_t)block,pages[2]={b,b+PAGE};
    struct li2_pg_layout layout={{b+0x10000,b+0x18000},b+0x20000,b+0x21000,b+0x22000,b+0xe0000};
    plan=(void *)(block+0x40000);directory=(void *)layout.directory;data=block+0x100000;
    fill(block,0xcc,2*PAGE);
    const unsigned char add[]={0x48,0x83,0xc0,1},mov0[]={0x48,0x89,0x07},mov1[]={0x48,0x89,0x47,8};
    for(unsigned i=0;i<32;i++){bytes(block+0x100+4*i,add,4);bytes(block+PAGE+0x100+4*i,add,4);}
    bytes(block+0x180,mov0,3);block[0x183]=0xe9;
    int32_t delta=(int32_t)((b+PAGE+0x100)-(b+0x188));bytes(block+0x184,&delta,4);
    bytes(block+PAGE+0x180,mov1,4);block[PAGE+0x184]=0xff;block[PAGE+0x185]=0xe2;
    struct li2_mg_table table;
    const struct li2_mg_range ranges[]={{b,b+2*PAGE},{b+0x10000,b+0x23000},
        {(uintptr_t)plan,(uintptr_t)plan+((sizeof *plan+PAGE-1)&~(PAGE-1))},
        {layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES}};
    assert(!li2_mg_table_build(ranges,4,(uintptr_t)&plan->table,&table));
    unsigned char source[2][PAGE];bytes(source,block,sizeof source);
    struct li2_pg_miss miss,empty={.version=LI2_PG_VERSION};
    assert(!li2_pg_plan_pages(pages,source,b+0x100,&layout,&table,&full,&miss) && same(&miss,&empty,sizeof miss));
    assert(full.heads==68 && full.member_heads[0]==64 && full.member_heads[1]==4 && full.stores==2 && full.exits==1 && full.links==1);
    assert(!li2_pg_plan_validate(&full,&scratch) && !li2_pg_compact_build(&full,&scratch,plan));
    assert(!li2_pg_compact_validate(plan,&scratch,&rebuilt) && same(plan,&rebuilt,sizeof *plan));
    bytes((void *)layout.generated[0],plan->image[0],LI2_PE_IMAGE_BYTES);
    bytes((void *)layout.generated[1],plan->image[1],LI2_PE_IMAGE_BYTES);
    bytes((void *)layout.stubs,plan->stub_image,LI2_PG_STUB_BYTES);
    fill((void *)layout.slots,0,PAGE);
    for(unsigned i=0;i<plan->links;i++)*(uint64_t *)plan->edge[i].slot=plan->edge[i].generated_target;
    fill(directory,0,LI2_JD_DOMAIN_BYTES);directory->version=1;directory->serial=1;directory->count=plan->heads;
    for(unsigned i=0;i<plan->heads;i++)directory->row[i]=(struct li2_jd_domain_row){.pc=plan->original[i].decoded.pc,.generated=target(i),.generation=1,.slot=0,.head=i};
    assert(plan->head[32].kind==LI2_PE_MOV && plan->head[66].kind==LI2_PE_MOV && plan->head[67].kind==LI2_PG_DISPATCH);
    assert(plan->original[64].decoded.pc==b+PAGE+0x178 && plan->original[67].decoded.pc==b+PAGE+0x184);
    assert(!mprotect(block,2*PAGE,PROT_READ|PROT_EXEC));
    assert(!mprotect((void *)layout.generated[0],17*PAGE,PROT_READ|PROT_EXEC));
    assert(!mprotect((void *)layout.slots,PAGE,PROT_READ));
    assert(!mprotect(plan,(sizeof *plan+PAGE-1)&~(PAGE-1),PROT_READ));
    assert(!mprotect(directory,LI2_JD_DOMAIN_BYTES,PROT_READ));
}
int main(void){
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    block=mmap(0,BLOCK,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(block!=MAP_FAILED);
    stack=mmap(0,4*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(stack!=MAP_FAILED);
    assert(!mprotect(stack+PAGE,2*PAGE,PROT_READ|PROT_WRITE));stack+=PAGE;
    alternate=mmap(0,34*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(alternate!=MAP_FAILED);
    assert(!mprotect(alternate+PAGE,32*PAGE,PROT_READ|PROT_WRITE));
    stack_t alt={.ss_sp=alternate+PAGE,.ss_size=32*PAGE},old_alt;assert(!sigaltstack(&alt,&old_alt));
    struct sigaction action={0},old_trap,old_segv;action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO|SA_ONSTACK;
    assert(!sigemptyset(&action.sa_mask) && !sigaction(SIGTRAP,&action,&old_trap) && !sigaction(SIGSEGV,&action,&old_segv));
    form();
    for(unsigned i=0;i<16;i++)seed[i]=UINT64_C(0x1122334400000000)+UINT64_C(0x1001001)*i;
    seed[2]=(uintptr_t)block+PAGE+0x500;seed[4]=(uintptr_t)stack+PAGE;seed[7]=(uintptr_t)data+64;
    const uint64_t poison[4]={UINT64_MAX,UINT64_C(0xdeadbeef),UINT64_C(0x12345678),UINT64_C(0xabcdef)};
    for(selected_head=0;selected_head<plan->heads;selected_head++)for(unsigned f=0;f<64;f++){
        input_flags=status(f);struct li2_pg_recovered r;
        assert(!li2_pg_compact_recover(plan,target(selected_head),seed,input_flags,poison,&recovery,&r));
        assert(r.complete==1 && r.member==selected_head/64 && r.head==selected_head%64 && r.original_pc==plan->original[selected_head].decoded.pc && r.flags==input_flags && same(r.gpr,seed,sizeof seed));++recoveries;
        one(0,0);one(1,0);
    }
    const unsigned stores[2]={32,66};
    for(unsigned i=0;i<2;i++)for(unsigned fault=1;fault<=2;fault++){
        selected_head=stores[i];input_flags=status(63);one(0,fault);one(1,fault);
    }
    assert(pairs==4356 && success_pairs==4352 && fault_pairs==4 && recoveries==4352);
    assert(!li2_decoder_stats(&after) && same(&before,&after,sizeof before));
    assert(!sigaction(SIGTRAP,&old_trap,0) && !sigaction(SIGSEGV,&old_segv,0) && !sigaltstack(&old_alt,0));
    assert(!munmap(alternate,34*PAGE) && !munmap(stack-PAGE,4*PAGE) && !munmap(block,BLOCK));
    printf("{\"schema\":1,\"heads\":68,\"source_pages\":2,\"members\":2,\"original_generated_pairs\":4356,\"success_pairs\":4352,\"fault_pairs\":4,\"poisoned_spill_recoveries\":4352,\"emitted_execution\":1,\"owner_qualification\":0}\n");
    return 0;
}
