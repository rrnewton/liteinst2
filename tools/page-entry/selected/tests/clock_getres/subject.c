/* Normal-loader/default-rseq whole-program checks. Modes5..8 must ONLY run
   under the gate: each tries an actual forbidden kernel output range. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
extern const ptrdiff_t __rseq_offset __attribute__((weak));
extern const unsigned int __rseq_size __attribute__((weak)),__rseq_flags __attribute__((weak));
static unsigned char page[4096] __attribute__((aligned(4096)));
static long call(long n,long a,long b,long c){long v;__asm__ volatile("syscall":"=a"(v):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return v;}
static int write_all(const void *v,size_t n){const unsigned char *p=v;while(n){long k=call(SYS_write,1,(long)p,(long)n);if(k<=0||(size_t)k>n)return 1;p+=k;n-=(size_t)k;}return 0;}
int main(int argc,char **argv){
    if(argc!=2||argv[1][0]<'0'||argv[1][0]>'8'||argv[1][1]||!&__rseq_offset||!&__rseq_size||!&__rseq_flags||__rseq_size<20||__rseq_flags)return 98;
    unsigned mode=(unsigned)(argv[1][0]-'0');uintptr_t address=(uintptr_t)__builtin_thread_pointer();ptrdiff_t offset=__rseq_offset;
    if(offset>=0){if((uintptr_t)offset>UINTPTR_MAX-address)return 98;address+=(uintptr_t)offset;}
    else {uintptr_t n=(uintptr_t)(-(offset+1))+1;if(n>address)return 98;address-=n;}
    if((address&31)||address>UINTPTR_MAX-32||*(const volatile uint64_t *)(address+8))return 98;
    for(size_t i=0;i<sizeof page;i++)page[i]=0xa5;
    uintptr_t destination=(uintptr_t)page;
    if(mode==1||mode==3)destination=0;
    if(mode==4&&call(SYS_mprotect,(long)page,sizeof page,PROT_READ))return 98;
    if(mode==5)destination=address+8;
    if(mode==6)destination=address+8-15;
    if(mode==7)destination=address+8+7;
    if(mode==8)destination=UINTPTR_MAX-15;
    long clock=mode==2||mode==3?-1:4;
    long result=call(SYS_clock_getres,clock,(long)destination,0);
    if(mode>=5)return 99;
    long expected=mode==2||mode==3?-22:mode==4?-14:0;
    if(result!=expected||*(const volatile uint64_t *)(address+8))return 97;
    if(mode==0){struct timespec value;memcpy(&value,page,16);if(value.tv_sec<0||value.tv_nsec<0||value.tv_nsec>=1000000000||!(value.tv_sec||value.tv_nsec))return 96;}
    for(size_t i=mode==0?16:0;i<sizeof page;i++)if(page[i]!=0xa5)return 95;
    uint64_t h[16]={UINT64_C(0x3150504152474b43),1,mode,(uint64_t)clock,(uint64_t)result,4096,address,0,(uint64_t)getpid()};
    return write_all(h,sizeof h)||write_all(page,sizeof page)?94:0;
}
