/* This separate pair supplements, and does not replace, fork_probe.c. */
#define _GNU_SOURCE
#include "continuation.h"
#include <cpuid.h>
#include <sys/syscall.h>
#include <sys/wait.h>
struct continuation_record continuation_record;
static long call6(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
    __asm__ volatile("syscall":"+a"(n):"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory","cc");return n;
}
static void stop(int n) __attribute__((noreturn));
static void stop(int n) { (void)call6(SYS_exit_group,n,0,0,0,0,0);__builtin_trap(); }
static void need(int ok) { if(!ok)stop(93); }
static unsigned fd(const char *s) {
    unsigned n=0,k=0;while(*s){need(*s>='0'&&*s<='9'&&n<=(65535U-(*s-'0'))/10);n=n*10+*s++-'0';++k;}
    need(k&&n>2);return n;
}
static void capability(void) {
    unsigned a,b,c,d,lo,hi;
    need(__get_cpuid(1,&a,&b,&c,&d)&&(c&0x0c000000)==0x0c000000);
    __asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));
    uint64_t mask=(uint64_t)hi<<32|lo;
    __cpuid_count(13,0,a,b,c,d);
    uint64_t supported=(uint64_t)d<<32|a;
    unsigned size=b;
    __cpuid_count(13,1,a,b,c,d);
    need((a&4)&&size>=576&&size<=65536&&(mask&3)==3&&!(mask&~supported));
    continuation_record.xcr0=mask;continuation_record.supported=supported;
    continuation_record.xsave_bytes=size;continuation_record.xgetbv1=1;
    for(unsigned bit=2;bit<64;bit++)if(mask&(1ULL<<bit)) {
        __cpuid_count(13,bit,a,b,c,d);
        need(a&&b>=576&&b<=size&&a<=size-b&&!(c&1));
        continuation_record.components[continuation_record.component_count++]=(struct component){bit,b,a,c};
    }
}
int main(int argc,char **argv) {
    need(argc==3);unsigned sinks[2]={fd(argv[1]),fd(argv[2])};need(sinks[0]!=sinks[1]);
    capability();long parent=call6(SYS_getpid,0,0,0,0,0,0);need(parent>0);
    long result=continuation_fork();need(result>=0);
    /* Nothing before the assembly endpoint was a write, C call, or diagnostic
       syscall. This metadata is populated only after that actual capture. */
    continuation_record.magic=0x314b524f4632494cULL;continuation_record.version=1;
    continuation_record.bytes=sizeof(continuation_record);continuation_record.role=result==0;
    continuation_record.pid=(uint64_t)call6(SYS_getpid,0,0,0,0,0,0);
    continuation_record.parent_pid=(uint64_t)parent;continuation_record.result=(uint64_t)result;
    need(call6(SYS_write,sinks[result==0],(long)&continuation_record,sizeof(continuation_record),0,0,0)==(long)sizeof(continuation_record));
    if(!result) { need(call6(SYS_write,1,(long)"CHILD_OK\n",9,0,0,0)==9);stop(42); }
    int status=-1;need(call6(SYS_wait4,result,(long)&status,0,0,0,0)==result);
    need(WIFEXITED(status)&&WEXITSTATUS(status)==42);
    need(call6(SYS_write,1,(long)"PARENT_OK\n",10,0,0,0)==10);return 0;
}
