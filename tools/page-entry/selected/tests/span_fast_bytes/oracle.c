#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include "span_fast_bytes.h"
#define PAGE_BYTES 4096U
#define MAX_BYTES 276352U
/* These wrappers contain the actual production header, not a copied model. */
__attribute__((noinline,used)) void probe_copy(void *d,const void *s,size_t n) {li2_span_bytes_copy(d,s,n);}
__attribute__((noinline,used)) void probe_zero(void *d,size_t n) {li2_span_bytes_zero(d,n);}
__attribute__((noinline,used)) int probe_equal(const void *a,const void *b,size_t n) {return li2_span_bytes_equal(a,b,n);}
static unsigned char *mapping[2],*data[2];
static size_t extent;
static unsigned lengths,placements,mismatches,overlaps,zero_access,fp_cases,prefix_mismatches;
static unsigned char model[1024];
static _Alignas(16) unsigned char fp_before[512],fp_after[512];
static uint64_t flags(void) {uint64_t x;__asm__ volatile("pushfq; popq %0":"=r"(x)::"memory");return x;}
static unsigned char pattern(size_t i,unsigned side) {return (unsigned char)(i*131+(i>>8)*17+side*53+0xa5);}
static int allocate(size_t n) {
    extent=(n+32+PAGE_BYTES-1)&~(size_t)(PAGE_BYTES-1);
    for(unsigned j=0;j<2;j++) {
        void *p=mmap(0,extent+2*PAGE_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED)return 1;
        mapping[j]=p;data[j]=mapping[j]+PAGE_BYTES;
        if(mprotect(data[j],extent,PROT_READ|PROT_WRITE))return 2;
    }
    return 0;
}
static int writable(unsigned j,int yes) {return mprotect(data[j],extent,yes?PROT_READ|PROT_WRITE:PROT_READ)?3:0;}
static int release(void) {
    int e=0;
    for(unsigned j=0;j<2;j++)if(mapping[j]) {
        if(munmap(mapping[j],extent+2*PAGE_BYTES))e=4;
        mapping[j]=data[j]=0;
    }
    return e;
}
static int one(size_t n,size_t x,size_t y) {
    if(x>extent-n || y>extent-n || writable(0,1) || writable(1,1))return 5;
    for(size_t i=0;i<extent;i++){data[0][i]=pattern(i,0);data[1][i]=pattern(i,1);}
    if(writable(0,0) || flags()&1024)return 6;
    probe_copy(data[1]+y,data[0]+x,n);
    if(flags()&1024)return 7;
    for(size_t i=0;i<extent;i++) {
        unsigned char expected=i>=y && i-y<n?pattern(x+i-y,0):pattern(i,1);
        if(data[1][i]!=expected || data[0][i]!=pattern(i,0))return 8;
    }
    if(writable(1,0) || probe_equal(data[0]+x,data[1]+y,n)!=1 || flags()&1024)return 9;
    if(n) {
        size_t at[3]={0,n/2,n-1};
        for(unsigned k=0;k<3;k++) {
            if(writable(1,1))return 10;
            data[1][y+at[k]]^=0x80;
            if(writable(1,0) || probe_equal(data[0]+x,data[1]+y,n)!=0 ||
               probe_equal(data[1]+y,data[0]+x,n)!=0 || flags()&1024)return 11;
            if(writable(1,1))return 12;
            data[1][y+at[k]]^=0x80;++mismatches;
        }
    }
    if(writable(1,1))return 13;
    probe_zero(data[1]+y,n);
    if(flags()&1024)return 14;
    for(size_t i=0;i<extent;i++) {
        unsigned char expected=i>=y && i-y<n?0:pattern(i,1);
        if(data[1][i]!=expected || data[0][i]!=pattern(i,0))return 15;
    }
    ++placements;return 0;
}
static int length(size_t n) {
    int e=allocate(n);if(e)return e;
    size_t pairs[7][2]={{0,0},{1,7},{7,1},{15,15},{extent-n,0},{0,extent-n},{extent-n,extent-n}};
    for(unsigned i=0;i<7;i++)if((e=one(n,pairs[i][0],pairs[i][1])))return e;
    if(n<=33)for(size_t x=0;x<8;x++)for(size_t y=0;y<8;y++)if((e=one(n,x,y)))return e;
    /* PROT_NONE pointers and NULL are never touched for a zero length. */
    const void *p[4]={0,mapping[0],data[0]+extent,mapping[1]};
    for(unsigned i=0;i<4;i++)for(unsigned j=0;j<4;j++) {
        probe_copy((void *)p[i],p[j],0);probe_zero((void *)p[i],0);
        if(probe_equal(p[i],p[j],0)!=1 || flags()&1024)return 16;
        ++zero_access;
    }
    if((e=release()))return e;
    ++lengths;return 0;
}
static int overlap(void) {
    int e=allocate(1024);if(e)return e;
    for(unsigned distance=0;distance<=31;distance++)for(unsigned direction=0;direction<2;direction++) {
        size_t s=direction?64+distance:64,d=direction?64:64+distance,n=513;
        for(size_t i=0;i<1024;i++)model[i]=data[0][i]=pattern(i,distance);
        /* Forward byte semantics intentionally differ from memmove for d>s. */
        for(size_t i=0;i<n;i++)model[d+i]=model[s+i];
        probe_copy(data[0]+d,data[0]+s,n);
        if(flags()&1024)return 17;
        for(size_t i=0;i<1024;i++)if(data[0][i]!=model[i])return 18;
        if(probe_equal(data[0],model,1024)!=1)return 19;
        ++overlaps;
    }
    return release();
}
static int mismatch_before_guard(void) {
    int e=allocate(64);if(e)return e;
    for(unsigned left=1;left<8;left++)for(unsigned right=1;right<8;right++) {
        unsigned n=left<right?left:right;
        for(size_t i=0;i<extent;i++)data[0][i]=data[1][i]=0x53;
        data[1][extent-right+n-1]^=1;
        if(writable(0,0) || writable(1,0))return 25;
        /* Old byte equality returns at this mismatch before either guard;
           the full requested16 bytes intentionally are not all accessible. */
        if(probe_equal(data[0]+extent-left,data[1]+extent-right,16)!=0 ||
           probe_equal(data[1]+extent-right,data[0]+extent-left,16)!=0)return 26;
        prefix_mismatches+=2;
        if(writable(0,1) || writable(1,1))return 27;
    }
    return release();
}
static int fp(void) {
    int e=allocate(1024);if(e)return e;
    for(size_t i=0;i<512;i++)fp_before[i]=fp_after[i]=0;
    for(size_t i=0;i<1024;i++)data[0][i]=data[1][i]=pattern(i,0);
    __asm__ volatile("fninit; fld1; fldpi; pcmpeqd %%xmm0,%%xmm0; pcmpeqd %%xmm15,%%xmm15":::"memory");
    __asm__ volatile("fxsave64 %0":"=m"(fp_before)::"memory");
    probe_copy(data[1]+7,data[0]+1,513);
    __asm__ volatile("fxsave64 %0":"=m"(fp_after)::"memory");
    for(size_t i=0;i<512;i++)if(fp_before[i]!=fp_after[i])return 20;
    ++fp_cases;
    probe_zero(data[1],1024);
    __asm__ volatile("fxsave64 %0":"=m"(fp_after)::"memory");
    for(size_t i=0;i<512;i++)if(fp_before[i]!=fp_after[i])return 21;
    ++fp_cases;
    if(probe_equal(data[0],data[0],1024)!=1 || probe_equal(data[0],data[1],1024)!=0)return 22;
    __asm__ volatile("fxsave64 %0":"=m"(fp_after)::"memory");
    for(size_t i=0;i<512;i++)if(fp_before[i]!=fp_after[i])return 23;
    ++fp_cases;
    __asm__ volatile("fninit":::"memory");return release();
}
int main(void) {
    static const size_t sizes[]={0,1,2,3,7,8,9,15,16,17,31,32,33,63,64,65,4095,4096,65536,65792,70208,206848,MAX_BYTES};
    int error=0;
    for(size_t i=0;i<sizeof sizes/sizeof sizes[0]&&!error;i++)error=length(sizes[i]);
    if(!error)error=overlap();
    if(!error)error=mismatch_before_guard();
    if(!error)error=fp();
    int cleanup=release();if(!error)error=cleanup;
    if(!error && (lengths!=23 || placements!=993 || mismatches!=2766 || overlaps!=64 || zero_access!=368 || fp_cases!=3 || prefix_mismatches!=98))error=24;
    if(printf("{\"version\":1,\"status\":%d,\"lengths\":%u,\"placements\":%u,\"mismatches\":%u,\"overlaps\":%u,\"zero_access\":%u,\"fp_cases\":%u,\"prefix_mismatches\":%u}\n",
              error,lengths,placements,mismatches,overlaps,zero_access,fp_cases,prefix_mismatches)<0)return 126;
    return error?125:0;
}
