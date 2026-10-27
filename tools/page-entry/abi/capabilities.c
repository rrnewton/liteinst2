#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>
int main(void) {
    unsigned a,b,c,d;
    if(!__get_cpuid(1,&a,&b,&c,&d)||(c&0x0c000000)!=0x0c000000)return 2;
    unsigned lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));
    uint64_t mask=((uint64_t)hi<<32)|lo;
    __cpuid_count(13,0,a,b,c,d);unsigned size=b;uint64_t supported=((uint64_t)d<<32)|a;
    __cpuid_count(13,1,a,b,c,d);
    if(!(a&4)||size<576||size>65536||(mask&3)!=3||(mask&~supported))return 3;
    printf("{\"xcr0\":%llu,\"supported\":%llu,\"xsave_size\":%u,\"xgetbv1\":true,\"components\":[",(unsigned long long)mask,(unsigned long long)supported,size);
    int comma=0;
    for(unsigned bit=2;bit<64;bit++)if(mask&(1ULL<<bit)) {
        __cpuid_count(13,bit,a,b,c,d);
        if(!a||b<576||b>size||a>size-b||(c&1))return 4;
        printf("%s{\"bit\":%u,\"offset\":%u,\"bytes\":%u,\"flags\":%u}",comma?",":"",bit,b,a,c);comma=1;
    }
    puts("]}");return 0;
}
