#define _GNU_SOURCE
#include <asm/prctl.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE 4096UL
extern long actual_clone(void *stack);
extern int protected_target(void);
volatile unsigned thread_seen;
struct kernel_action { void (*handler)(int); unsigned long flags; void (*restorer)(void); uint64_t mask; };
static long invoke(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d;
    register long r8 __asm__("r8")=e;
    register long r9 __asm__("r9")=f;
    __asm__ volatile("syscall":"+a"(n):"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return n;
}
static int same(const char *a,const char *b) { while(*a && *a==*b){++a;++b;}return *a==*b; }
static int error(long n) { return n<0 && n>=-4095; }
static void finish(int status) __attribute__((noreturn));
static void finish(int status) { (void)invoke(SYS_exit_group,status,0,0,0,0,0);__builtin_trap(); }
static void require(int condition) { if(!condition)finish(91); }
static void marker(const char *prefix,const char *name) {
    char line[96];size_t n=0;
    while(*prefix) { require(n<sizeof(line));line[n++]=*prefix++; }
    while(*name) { require(n<sizeof(line));line[n++]=*name++; }
    require(n<sizeof(line));line[n++]='\n';require(invoke(SYS_write,1,(long)line,n,0,0,0)==(long)n);
}
static void *memory(size_t bytes) {
    long p=invoke(SYS_mmap,0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    require(!error(p));return(void *)p;
}
static void replacement(int signal) { (void)signal; }
extern char **environ;
static int dependency_fd(void) {
    const char key[]="LI2_DEPENDENCY_FDS=";
    for(char **e=environ;*e;e++) {
        const char *p=*e;size_t i=0;
        while(i<sizeof(key)-1 && p[i]==key[i]) ++i;
        if(i!=sizeof(key)-1) continue;
        p+=i;unsigned fd=0,digits=0;
        while(*p && *p!=',') { require(*p>='0' && *p<='9' && fd<100000);fd=fd*10+(unsigned)(*p++-'0');++digits; }
        require(digits && fd>2);return(int)fd;
    }
    return -1;
}
static int fd_same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_mode==b->st_mode && a->st_rdev==b->st_rdev && a->st_size==b->st_size;
}
static int held_duplicate(int source,unsigned first,unsigned end) {
    struct stat original;require(!invoke(SYS_fstat,source,(long)&original,0,0,0,0));
    int found=-1;
    for(unsigned fd=first;fd<end;fd++) {
        long flags=invoke(SYS_fcntl,fd,F_GETFD,0,0,0,0);
        if(flags==-9) continue;
        require(flags>=0);struct stat actual;require(!invoke(SYS_fstat,fd,(long)&actual,0,0,0,0));
        if(flags==FD_CLOEXEC && fd_same(&actual,&original)) { require(found==-1);found=(int)fd; }
    }
    require(found>=0);return found;
}
static void fd_control(const char *name,const char *path) {
    int original=dependency_fd(),gated=original>=0,fd=-1;
    if(same(name,"fd_report_highbits")) {
        if(!gated) {
            require(invoke(SYS_fcntl,100,F_GETFD,0,0,0,0)==-9);
            require(invoke(SYS_fcntl,2,F_DUPFD_CLOEXEC,100,0,0,0)==100);
        }
        fd=held_duplicate(2,100,200);
    } else if(same(name,"fd_retained_highbits") || same(name,"fd_original_highbits")) {
        if(!gated) {
            original=(int)invoke(SYS_openat,AT_FDCWD,(long)path,O_RDONLY|O_CLOEXEC,0,0,0);require(original>=0);
            require(invoke(SYS_fcntl,200,F_GETFD,0,0,0,0)==-9);
            require(invoke(SYS_fcntl,original,F_DUPFD_CLOEXEC,200,0,0,0)==200);
        }
        struct stat actual;require(!invoke(SYS_fstat,original,(long)&actual,0,0,0,0) && S_ISREG(actual.st_mode) && actual.st_size>0);
        /* Bind the actual retained duplicate to the inherited registered source;
           the bounded search refuses ambiguity rather than assuming FD 200. */
        int retained=held_duplicate(original,200,234);
        fd=same(name,"fd_retained_highbits")?retained:original;
    } else {
        require(same(name,"fd_ordinary_highbits"));
        int source=(int)invoke(SYS_openat,AT_FDCWD,(long)path,O_RDONLY|O_CLOEXEC,0,0,0);require(source>=0);
        fd=(int)invoke(SYS_fcntl,source,F_DUPFD_CLOEXEC,300,0,0,0);require(fd>=300);
        struct stat a,b;require(!invoke(SYS_fstat,source,(long)&a,0,0,0,0) && !invoke(SYS_fstat,fd,(long)&b,0,0,0,0) && fd_same(&a,&b));
        require(!invoke(SYS_close,source,0,0,0,0,0));
    }
    struct stat before;require(!invoke(SYS_fstat,fd,(long)&before,0,0,0,0));
    require(invoke(SYS_fcntl,fd,F_GETFD,0,0,0,0)>=0);
    marker("ATTEMPT ",name);
    require(!invoke(SYS_close,(long)((1ULL<<32)|(unsigned)fd),0,0,0,0,0));
    require(invoke(SYS_fcntl,fd,F_GETFD,0,0,0,0)==-9);
}
int main(int argc,char **argv) {
    require(argc==3);
    const char *name=argv[1];long result;
    if(same(name,"fd_report_highbits") || same(name,"fd_retained_highbits") || same(name,"fd_original_highbits") || same(name,"fd_ordinary_highbits")) {
        fd_control(name,argv[2]);
    } else if(same(name,"query_mask")) {
        uint64_t observed=UINT64_MAX;
        marker("ATTEMPT ",name);
        result=invoke(SYS_rt_sigprocmask,SIG_BLOCK,0,(long)&observed,8,0,0);
        require(!result && observed==0);
    } else if(same(name,"query_altstack")) {
        stack_t observed={.ss_sp=(void *)1,.ss_size=1,.ss_flags=-1};
        marker("ATTEMPT ",name);
        result=invoke(SYS_sigaltstack,0,(long)&observed,0,0,0,0);
        require(!result && observed.ss_flags==SS_DISABLE && !observed.ss_sp && !observed.ss_size);
    } else if(same(name,"query_segv") || same(name,"query_sigsys") || same(name,"query_sigusr1") || same(name,"query_segv_highbits") || same(name,"query_sigsys_highbits")) {
        long signal=(same(name,"query_segv") || same(name,"query_segv_highbits"))?SIGSEGV:(same(name,"query_sigsys") || same(name,"query_sigsys_highbits"))?SIGSYS:SIGUSR1;
        /* The raw kernel syscall truncates its signal argument to int. */
        if(same(name,"query_segv_highbits") || same(name,"query_sigsys_highbits")) signal|=1UL<<32;
        struct kernel_action observed={replacement,~0UL,0,UINT64_MAX};
        marker("ATTEMPT ",name);
        result=invoke(SYS_rt_sigaction,signal,0,(long)&observed,8,0,0);
        require(!result && observed.handler==SIG_DFL && !observed.flags && !observed.restorer && !observed.mask);
    } else if(same(name,"thread")) {
        void *stack=memory(64*1024);require(!thread_seen);
        marker("ATTEMPT ",name);
        result=actual_clone((char *)stack+64*1024);
        require(result>0);
        /* Native success must create the actual child, not merely accept args.
           Child's assembly records entry then exits without a C stack return. */
        for(unsigned i=0;i<1000000 && !thread_seen;i++) (void)invoke(SYS_sched_yield,0,0,0,0,0,0);
        require(thread_seen==1);
    } else if(same(name,"gate_handler")) {
        struct kernel_action action={replacement,0,0,0},old,observed;
        marker("ATTEMPT ",name);
        result=invoke(SYS_rt_sigaction,SIGSEGV,(long)&action,(long)&old,8,0,0);require(!result);
        require(!invoke(SYS_rt_sigaction,SIGSEGV,0,(long)&observed,8,0,0) && observed.handler==replacement);
        require(!invoke(SYS_rt_sigaction,SIGSEGV,(long)&old,0,8,0,0));
    } else if(same(name,"gate_mask")) {
        uint64_t block=1ULL<<(SIGSYS-1),old=0,observed=0;
        marker("ATTEMPT ",name);
        result=invoke(SYS_rt_sigprocmask,SIG_BLOCK,(long)&block,(long)&old,8,0,0);require(!result);
        require(!invoke(SYS_rt_sigprocmask,SIG_BLOCK,0,(long)&observed,8,0,0) && (observed&block));
        require(!invoke(SYS_rt_sigprocmask,SIG_SETMASK,(long)&old,0,8,0,0));
    } else if(same(name,"gate_altstack")) {
        stack_t next={.ss_sp=memory(64*1024),.ss_size=64*1024},old,observed;
        marker("ATTEMPT ",name);
        result=invoke(SYS_sigaltstack,(long)&next,(long)&old,0,0,0,0);require(!result);
        require(!invoke(SYS_sigaltstack,0,(long)&observed,0,0,0,0) && observed.ss_sp==next.ss_sp && observed.ss_size==next.ss_size);
        require(!invoke(SYS_sigaltstack,(long)&old,0,0,0,0,0));
    } else if(same(name,"unsealed_execute")) {
        long fd=invoke(SYS_openat,AT_FDCWD,(long)argv[2],O_RDONLY|O_CLOEXEC,0,0,0);require(fd>=0);
        /* The supplied regular file has no immutable backing seal. */
        struct stat st;require(!invoke(SYS_fstat,fd,(long)&st,0,0,0,0) && (st.st_mode&S_IFMT)==S_IFREG && st.st_size==PAGE);
        marker("ATTEMPT ",name);
        result=invoke(SYS_mmap,0,PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0);require(!error(result));
        require(((int(*)(void))result)()==42);
        require(!invoke(SYS_munmap,result,PAGE,0,0,0,0));require(!invoke(SYS_close,fd,0,0,0,0,0));
    } else if(same(name,"protected_write") || same(name,"protected_unmap")) {
        uintptr_t page=(uintptr_t)protected_target;
        require(!(page&(PAGE-1)) && ((uintptr_t)main&~(PAGE-1))!=page && ((uintptr_t)invoke&~(PAGE-1))!=page);
        require(protected_target()==7);
        marker("ATTEMPT ",name);
        if(same(name,"protected_write")) {
            result=invoke(SYS_mprotect,page,PAGE,PROT_READ|PROT_WRITE,0,0,0);require(!result);
            require(*(const volatile unsigned char *)page==0xb8);*(volatile unsigned char *)(page+1)=9;
            require(!invoke(SYS_mprotect,page,PAGE,PROT_READ|PROT_EXEC,0,0,0));require(protected_target()==9);
        } else {
            result=invoke(SYS_munmap,page,PAGE,0,0,0,0);require(!result);
            require(invoke(SYS_mprotect,page,PAGE,PROT_READ|PROT_EXEC,0,0,0)==-12);
        }
    } else finish(92);
    marker("NATIVE_OK ",name);finish(0);
}
