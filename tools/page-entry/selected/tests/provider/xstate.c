#include "fixture.h"
uint64_t fixture_input[17],fixture_pre[24],fixture_post[24],fixture_host[8];
uint64_t fixture_target,fixture_mask,fixture_enabled;
unsigned char fixture_pre_fp[FP_BYTES] __attribute__((aligned(64)));
unsigned char fixture_post_fp[FP_BYTES] __attribute__((aligned(64)));
unsigned char fixture_host_fp[FP_BYTES] __attribute__((aligned(64)));
struct component fixture_components[8];
static void cpuid(unsigned leaf,unsigned sub,unsigned r[4]) {
    unsigned a=leaf,b,c=sub,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
    r[0]=a;r[1]=b;r[2]=c;r[3]=d;
}
static uint64_t xget(unsigned n) {
    unsigned a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(n):"memory");
    return ((uint64_t)d<<32)|a;
}
int fixture_xstate_prepare(void) {
    unsigned r[4];cpuid(0,0,r);if(r[0]<13)return 1;
    cpuid(1,0,r);if((r[2]&((1u<<26)|(1u<<27)))!=((1u<<26)|(1u<<27)))return 2;
    cpuid(13,1,r);if(!(r[0]&4))return 3;
    fixture_enabled=xget(0);cpuid(13,0,r);
    if(fixture_enabled&~((uint64_t)r[0]|(uint64_t)r[3]<<32))return 4;
    fixture_mask=fixture_enabled&UINT64_C(0x2e7);
    if((fixture_mask&3)!=3 || (xget(1)&fixture_enabled&~fixture_mask))return 5;
    unsigned n=0;
    for(unsigned b=2;b<64;b++)if(fixture_mask&(UINT64_C(1)<<b)) {
        if(n==8)return 6;
        cpuid(13,b,r);
        if(!r[0] || r[1]<576 || r[1]>FP_BYTES || r[0]>FP_BYTES-r[1] || (r[2]&1))return 7;
        fixture_components[n++]=(struct component){b,r[1],r[0],0};
    }
    return 0;
}
