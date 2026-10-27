/* Native/gated finite raw-fork fixture. Child uses no libc/atfork/TLS cache. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>

static long invoke(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
    __asm__ volatile("syscall":"+a"(n):"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return n;
}
static void stop(int n) __attribute__((noreturn));
static void stop(int n) { (void)invoke(SYS_exit_group,n,0,0,0,0,0);__builtin_trap(); }
static void check(int yes) { if(!yes)stop(91); }
static int same(const char *a,const char *b) { while(*a && *a==*b){a++;b++;}return *a==*b; }
static void message(const char *s,size_t n) { check(invoke(SYS_write,1,(long)s,n,0,0,0)==(long)n); }
static void cpuid(uint64_t out[4]) {
    uint64_t a=0,b,c=0,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
    out[0]=a;out[1]=b;out[2]=c;out[3]=d;
}
static uint64_t ticks(int serial) {
    uint64_t a,d,c=0;
    if(serial)__asm__ volatile("rdtscp":"=a"(a),"=d"(d),"=c"(c)::"memory");
    else __asm__ volatile("rdtsc":"=a"(a),"=d"(d)::"memory");
    check(a<=UINT32_MAX && d<=UINT32_MAX && c<=UINT32_MAX);return d<<32|a;
}
static void code(unsigned char *p,unsigned value) { p[0]=0xb8;p[1]=(unsigned char)value;p[2]=p[3]=p[4]=0;p[5]=0xc3; }
static unsigned call(unsigned char *p) { return ((unsigned(*)(void))(void *)p)(); }
static unsigned decimal(const char *s) {
    unsigned n=0,digits=0;while(*s){check(*s>='0'&&*s<='9'&&n<=(65535U-(*s-'0'))/10);n=n*10+*s++-'0';++digits;}
    check(digits&&n>2);return n;
}
static volatile unsigned cow_value=17;
int main(int argc,char **argv) {
    check(argc==2 || argc==4);const char *name=argv[1];
    int basic=same(name,"basic"),cp=same(name,"cpuid"),ts=same(name,"rdtsc"),tsp=same(name,"rdtscp"),cow=same(name,"cow");
    int badstatus=same(name,"efault_status"),badrusage=same(name,"efault_rusage"),high=same(name,"high_wait");
    int failed=same(name,"expect_child_failure"),nonblock=same(name,"wnohang");
    check(nonblock?(argc==4):(argc==2));
    unsigned pipe_read=nonblock?decimal(argv[2]):0,pipe_write=nonblock?decimal(argv[3]):0;
    check(basic||cp||ts||tsp||cow||badstatus||badrusage||high||failed||nonblock);
    uint64_t before[4]={0,0,0,0},time=0;
    if(cp)cpuid(before);
    if(ts||tsp)time=ticks(tsp);
    unsigned char *pages=0;
    if(cow) {
        long a=invoke(SYS_mmap,0,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        check(a>0);pages=(void *)a;code(pages,7);code(pages+4096,8);
        check(!invoke(SYS_mprotect,a,8192,PROT_READ|PROT_EXEC,0,0,0));check(call(pages)==7);
        /* Page two remains pending in the gated lane until after the fork. */
    }
    long actual=invoke(SYS_fork,0,0,0,0,0,0);check(actual>=0);
    if(!actual) {
        if(failed)stop(125);
        if(nonblock) { char byte=0;check(invoke(SYS_read,pipe_read,(long)&byte,1,0,0,0)==1 && byte=='G'); }
        if(cp) { uint64_t after[4];cpuid(after);for(unsigned i=0;i<4;i++)check(after[i]==before[i] && after[i]<=UINT32_MAX); }
        if(ts||tsp)check(ticks(tsp)>=time);
        if(cow) {
            check(cow_value==17 && call(pages)==7 && call(pages+4096)==8);cow_value=23;
            check(!invoke(SYS_mprotect,(long)pages,4096,PROT_READ|PROT_WRITE,0,0,0));code(pages,9);
            check(!invoke(SYS_mprotect,(long)pages,4096,PROT_READ|PROT_EXEC,0,0,0) && call(pages)==9);
            check(!invoke(SYS_munmap,(long)pages,8192,0,0,0,0));
        }
        message("CHILD_OK\n",9);stop(42);
    }
    int status=-1;struct rusage usage;long child=actual,options=0;
    if(high) { child|=1UL<<32;options=1UL<<32; }
    if(nonblock) {
        check(invoke(SYS_wait4,actual,(long)&status,WNOHANG,0,0,0)==0);
        const char byte='G';check(invoke(SYS_write,pipe_write,(long)&byte,1,0,0,0)==1);
    }
    long result=invoke(SYS_wait4,child,badstatus?1:(long)&status,options,badrusage?1:(long)&usage,0,0);
    if(badstatus||badrusage) {
        check(result==-14);
        check(invoke(SYS_wait4,actual,(long)&status,0,0,0,0)==-10);
    } else {
        check(result==actual && WIFEXITED(status) && WEXITSTATUS(status)==(failed?125:42));
    }
    if(cow) {
        check(cow_value==17 && call(pages)==7 && call(pages+4096)==8);
        check(!invoke(SYS_munmap,(long)pages,8192,0,0,0,0));
    }
    message("PARENT_OK\n",10);return 0;
}
