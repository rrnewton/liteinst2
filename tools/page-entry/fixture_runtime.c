/* Closed first-entry fixture runtime. No target libc, TLS, heap or PLT calls.
   Launch/control wiring only: no general head proof, patch publication, or
   normal dynamic-linker lifecycle qualification. */
#include "bridge.h"
#include <linux/audit.h>
#define MAX_PAGES 8192
struct page { uintptr_t at; unsigned open; };
struct action { void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask; };
static struct page pages[MAX_PAGES];static size_t page_count;
static uintptr_t main_entry,interpreter_entry;
static volatile sig_atomic_t handling;
static unsigned long faults,cpuid_count,tsc_count,syscall_count,first_interp,first_main;

static void put_text(const char *s) { size_t n=0;while(s[n])++n;require(raw(SYS_write,2,(long)s,n,0,0,0)==(long)n,"report write"); }
static void number(unsigned long n) { char b[32];size_t used=0;do { b[used++]=(char)('0'+n%10);n/=10; }while(n);for(size_t i=0;i<used/2;++i){char c=b[i];b[i]=b[used-i-1];b[used-i-1]=c;}require(raw(SYS_write,2,(long)b,used,0,0,0)==(long)used,"report number"); }
static void report(void) {
    put_text("LI2_FIRST_ENTRY {\"scope\":\"first_entry_fixture\",\"source_patches\":0,\"main_initial_nx\":true,\"logical_phdr_restored_in_place\":true,\"interpreter_first_cpuid\":");number(first_interp);
    put_text(",\"main_first_rdtsc\":");number(first_main);put_text(",\"nx_faults\":");number(faults);
    put_text(",\"cpuid\":");number(cpuid_count);put_text(",\"rdtsc\":");number(tsc_count);put_text(",\"syscalls\":");number(syscall_count);put_text("}\n");
}
static int known(uintptr_t pc,size_t n) {
    if(!n||pc>UINTPTR_MAX-n)return 0;
    for(size_t at=0;at<n;++at) { int found=0;for(size_t i=0;i<page_count;++i)if(pc+at>=pages[i].at&&pc+at-pages[i].at<PAGE)found=1;if(!found)return 0; }
    return 1;
}
static void handler(int sig,siginfo_t *si,void *ptr) {
    require(!handling&&ptr&&si,"nested/invalid signal");handling=1;
    ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&g[REG_TRAPNO]==14&&(g[REG_ERR]&0x17)==0x15) {
        uintptr_t address=(uintptr_t)si->si_addr;require(known(pc,1)&&address>=pc&&address-pc<=14,"foreign fetch extent");
        uintptr_t page=address&~(PAGE-1);int found=0;
        for(size_t i=0;i<page_count;++i)if(pages[i].at==page) {
            require(!pages[i].open,"fetch on admitted page");require(raw(SYS_mprotect,page,PAGE,PROT_READ|PROT_EXEC,0,0,0)==0,"fetch admission");pages[i].open=1;++faults;found=1;break;
        }
        require(found,"unowned fetch page");
    } else if(sig==SIGSEGV&&si->si_code==SI_KERNEL&&g[REG_TRAPNO]==13&&g[REG_ERR]==0&&known(pc,2)) {
        const unsigned char *p=(const void *)pc;
        if(p[0]==15&&p[1]==0xa2) {
            uint32_t a=(uint32_t)g[REG_RAX],b,c=(uint32_t)g[REG_RCX],d;
            require(raw(SYS_arch_prctl,ARCH_SET_CPUID,1,0,0,0,0)==0,"native CPUID enable");
            __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
            require(raw(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0)==0,"CPUID rearm");
            g[REG_RAX]=a;g[REG_RBX]=b;g[REG_RCX]=c;g[REG_RDX]=d;g[REG_RIP]+=2;++cpuid_count;
            if(pc==interpreter_entry)++first_interp;
        } else if(p[0]==15&&p[1]==0x31) {
            uint32_t a,d;require(raw(SYS_prctl,PR_SET_TSC,PR_TSC_ENABLE,0,0,0,0)==0,"native TSC enable");
            __asm__ volatile("rdtsc":"=a"(a),"=d"(d)::"memory");
            require(raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0)==0,"TSC rearm");g[REG_RAX]=a;g[REG_RDX]=d;g[REG_RIP]+=2;++tsc_count;
            if(pc==main_entry)++first_main;
        } else li2_fail("unhandled selected/GP instruction");
    } else if(sig==SIGSYS) {
        require(si->si_code==2&&si->si_arch==AUDIT_ARCH_X86_64&&(uintptr_t)si->si_call_addr==pc&&pc>=2&&known(pc-2,2)&&*(const uint16_t *)(pc-2)==0x050f&&g[REG_RAX]==si->si_syscall&&(uintptr_t)g[REG_RCX]==pc,"SUD context");
        long n=si->si_syscall;++syscall_count;
        require(n==SYS_getpid||n==SYS_write||n==SYS_exit||n==SYS_exit_group,"startup syscall needs lifecycle integration");
        if(n==SYS_write)require(g[REG_RDI]==1&&g[REG_RDX]>=0&&g[REG_RDX]<=4096,"fixture write contract");
        if(n==SYS_exit||n==SYS_exit_group) {
            require(first_interp==1&&first_main==1&&cpuid_count==1&&tsc_count==1&&faults==2&&g[REG_RDI]==7,"first-entry fixture observations");report();
        }
        g[REG_RAX]=raw(n,g[REG_RDI],g[REG_RSI],g[REG_RDX],g[REG_R10],g[REG_R8],g[REG_R9]);g[REG_RCX]=pc;g[REG_R11]=g[REG_EFL];
        require(n!=SYS_exit&&n!=SYS_exit_group,"exit returned");
    } else li2_fail("foreign signal");
    handling=0;
}
static void register_image(const struct image *image) {
    for(size_t i=0;i<image->n;++i) {
        const Elf64_Phdr *p=&image->ph[i];if(p->p_type!=PT_LOAD||!(p->p_flags&PF_X)||!p->p_memsz)continue;
        require((p->p_flags&(PF_R|PF_W))==PF_R,"executable profile");uintptr_t first=image->bias+(p->p_vaddr&~(PAGE-1));uintptr_t end=image->bias+((p->p_vaddr+p->p_memsz+PAGE-1)&~(PAGE-1));
        for(uintptr_t a=first;a<end;a+=PAGE) { require(page_count<MAX_PAGES,"page table bound");for(size_t j=0;j<page_count;++j)require(pages[j].at!=a,"duplicate executable page");pages[page_count++]=(struct page){a,0}; }
    }
}
static int hex_digit(unsigned char c) { if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1; }
static uintptr_t hexadecimal(const char *buf,size_t n,size_t *at) { uintptr_t v=0;unsigned digits=0;while(*at<n&&hex_digit(buf[*at])>=0) { require(v<=UINTPTR_MAX/16,"maps address overflow");v=v*16+(unsigned)hex_digit(buf[(*at)++]);++digits; }require(digits,"maps address absent");return v; }
static void require_initial_nx(void) {
    static char maps[65536];long fd=raw(SYS_openat,-100,(long)"/proc/self/maps",0x80000,0,0,0);require(fd>=0,"maps open");size_t used=0;
    for(;;) { require(used<sizeof(maps),"maps capacity");long n=raw(SYS_read,fd,(long)(maps+used),sizeof(maps)-used,0,0,0);require(n>=0,"maps read");if(!n)break;used+=(size_t)n; }
    require(raw(SYS_close,fd,0,0,0,0,0)==0,"maps close");unsigned seen[MAX_PAGES]={0};size_t at=0;
    while(at<used) { uintptr_t a=hexadecimal(maps,used,&at);require(at<used&&maps[at++]=='-',"maps separator");uintptr_t b=hexadecimal(maps,used,&at);require(at+5<used&&maps[at++]==' ',"maps permissions");size_t perm=at;
        for(size_t i=0;i<page_count;++i)if(pages[i].at>=a&&pages[i].at<b) { require(b-pages[i].at>=PAGE&&maps[perm]=='r'&&maps[perm+1]=='-'&&maps[perm+2]=='-'&&maps[perm+3]=='p',"initial application page not private readonly NX");++seen[i]; }
        while(at<used&&maps[at]!='\n')++at;
        require(at<used,"maps truncated");++at;
    }
    for(size_t i=0;i<page_count;++i)require(seen[i]==1,"initial application page association");
}
void runtime_arm(const struct image *main,const struct image *interp,size_t minimum) {
    require(minimum&&minimum<=131072,"signal frame capacity");main_entry=main->entry;interpreter_entry=interp->entry;
    register_image(main);register_image(interp);require(page_count&&known(main_entry,2)&&known(interpreter_entry,2),"entry ownership");require_initial_nx();
    require(*(const uint16_t *)interpreter_entry==0xa20f&&*(const uint16_t *)main_entry==0x310f,"closed fixture entry opcodes");
    unsigned long cet=0;long c=raw(SYS_arch_prctl,0x5005,(long)&cet,0,0,0,0);require((c==0&&!cet)||c==-22||c==-38,"CET profile");
    uint64_t mask=0;require(raw(SYS_rt_sigprocmask,0,0,(long)&mask,8,0,0)==0&&!(mask&((1UL<<(SIGSEGV-1))|(1UL<<(SIGSYS-1)))),"initial signal mask");
    struct action old;require(raw(SYS_rt_sigaction,SIGSEGV,0,(long)&old,8,0,0)==0&&!old.handler,"initial SIGSEGV action");require(raw(SYS_rt_sigaction,SIGSYS,0,(long)&old,8,0,0)==0&&!old.handler,"initial SIGSYS action");
    size_t total=512*1024+2*PAGE;void *space=memory(total,PROT_NONE);require(raw(SYS_mprotect,(long)space+PAGE,total-2*PAGE,PROT_READ|PROT_WRITE,0,0,0)==0,"altstack protection");
    stack_t stack={.ss_sp=(char *)space+PAGE,.ss_flags=0,.ss_size=total-2*PAGE};require(raw(SYS_sigaltstack,(long)&stack,0,0,0,0,0)==0,"altstack installation");
    struct action action={handler,SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL,li2_restorer,UINT64_MAX&~(1UL<<(SIGSEGV-1))&~(1UL<<(SIGSYS-1))};
    require(raw(SYS_rt_sigaction,SIGSEGV,(long)&action,0,8,0,0)==0&&raw(SYS_rt_sigaction,SIGSYS,(long)&action,0,8,0,0)==0,"handler installation");
    require(raw(SYS_arch_prctl,ARCH_GET_CPUID,0,0,0,0,0)==1,"native CPUID initial state");int mode=0;require(raw(SYS_prctl,PR_GET_TSC,(long)&mode,0,0,0,0)==0&&mode==PR_TSC_ENABLE,"native TSC initial state");
    require(raw(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0)==0&&raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0)==0,"selected controls");
    require(raw(SYS_prctl,PR_SET_SYSCALL_USER_DISPATCH,PR_SYS_DISPATCH_ON,(long)li2_gateway_start,li2_gateway_end-li2_gateway_start,0,0)==0,"SUD installation");
}
