#define _GNU_SOURCE
#include "record.h"
#include <errno.h>
#include <sched.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Independent ungated hardware seed qualification. No ptrace, signal-frame
   rewriting, application code or production policy is involved. */
static struct psp_record record;
static unsigned char first[2][512] __attribute__((aligned(64)));
static unsigned char second[2][512] __attribute__((aligned(64)));
extern const unsigned char psp_begin_a[],psp_fip_a[],psp_begin_b[],psp_fip_b[];
static void copy(void *to,const void *from,size_t bytes) {
    unsigned char *d=to;const unsigned char *s=from;
    for(size_t i=0;i<bytes;i++)d[i]=s[i];
}
static void cpuid(struct psp_machine *m,unsigned slot,unsigned leaf,unsigned sub) {
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
    uint32_t *p=m->cpuid[slot];p[0]=leaf;p[1]=sub;p[2]=a;p[3]=b;p[4]=c;p[5]=d;
}
static int machine(unsigned index) {
    struct psp_machine *m=record.machine+index;uint64_t *h=m->h;
    h[0]=index;h[1]=1;unsigned cpu=0,node=0;
    h[4]=(uint64_t)syscall(SYS_getcpu,&cpu,&node,0);h[5]=cpu;h[6]=node;
    cpuid(m,0,0,0);cpuid(m,1,1,0);cpuid(m,2,7,0);
    if(m->cpuid[0][2]<13 || (m->cpuid[1][4]&UINT32_C(0x0c000000))!=UINT32_C(0x0c000000)) {
        h[3]=1;return -1;
    }
    for(unsigned i=0;i<64;i++)cpuid(m,3+i,13,i);
    uint32_t a,d;h[7]=1;
    __asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");h[8]=(uint64_t)d<<32|a;
    uint64_t supported=0,permitted=0;
    h[9]=(uint64_t)syscall(SYS_arch_prctl,0x1021,&supported);h[10]=supported;
    h[11]=(uint64_t)syscall(SYS_arch_prctl,0x1022,&permitted);h[12]=permitted;
    cpu=node=0;h[13]=(uint64_t)syscall(SYS_getcpu,&cpu,&node,0);h[14]=cpu;h[15]=node;
    if(h[4] || h[9] || h[11] || h[13] || h[5]!=h[14] || h[6]!=h[15]) {h[3]=2;return -1;}
    h[2]=1;return 0;
}
int main(void) {
    uint64_t *h=record.h;h[0]=UINT64_C(0x3150444545534150);h[1]=1;h[2]=sizeof record;h[3]=(uint64_t)getpid();
    cpu_set_t affinity;CPU_ZERO(&affinity);
    h[8]=(uint64_t)sched_getaffinity(0,sizeof affinity,&affinity);h[4]=(unsigned)CPU_COUNT(&affinity);
    if(h[8] || h[4]!=1 || machine(0)){h[7]=1;goto emit;}
    unsigned short cw[2]={0},sw[2]={0};
    /* Exactly the application's x87 seed. Full actual FXSAVE64 snapshots
       precede and follow its FNSTCW/FNSTSW capture instructions. There are no
       calls or compiler FP instructions between these two labelled seeds. */
    __asm__ volatile(
        ".globl psp_begin_a,psp_fip_a\npsp_begin_a:\nfninit; fld1; psp_fip_a: fldpi;"
        "fxsave64 %0; fnstcw %2; fnstsw %3; fxsave64 %1"
        :"=m"(first[0]),"=m"(second[0]),"=m"(cw[0]),"=m"(sw[0])::"memory");
    __asm__ volatile(
        ".globl psp_begin_b,psp_fip_b\npsp_begin_b:\nfninit; fld1; psp_fip_b: fldpi;"
        "fxsave64 %0; fnstcw %2; fnstsw %3; fxsave64 %1"
        :"=m"(first[1]),"=m"(second[1]),"=m"(cw[1]),"=m"(sw[1])::"memory");
    const unsigned char *begin[2]={psp_begin_a,psp_begin_b},*fip[2]={psp_fip_a,psp_fip_b};
    for(unsigned i=0;i<2;i++) {
        struct psp_seed *s=record.seed+i;
        s->h[0]=i;s->h[1]=(uintptr_t)begin[i];s->h[2]=(uintptr_t)fip[i];
        s->h[3]=1;s->h[4]=1;s->h[5]=cw[i];s->h[6]=sw[i];
        copy(s->code,begin[i],6);copy(s->fp[0],first[i],512);copy(s->fp[1],second[i],512);++h[6];
    }
    if(machine(1)){h[7]=2;goto emit;}
    CPU_ZERO(&affinity);h[9]=(uint64_t)sched_getaffinity(0,sizeof affinity,&affinity);h[5]=(unsigned)CPU_COUNT(&affinity);
    if(h[9] || h[5]!=1 || record.machine[0].h[5]!=record.machine[1].h[5]){h[7]=3;goto emit;}
    h[10]=1;
emit:;
    size_t at=0;while(at<sizeof record) {
        ssize_t n=write(1,(const unsigned char *)&record+at,sizeof record-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return 2;
        at+=(size_t)n;
    }
    return h[7]?1:0;
}
