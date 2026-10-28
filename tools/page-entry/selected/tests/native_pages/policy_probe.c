/* Finite raw-byte oracle only: no page-ownership, mode or admission claim. */
#define _GNU_SOURCE
#include "native_policy.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { PAGE_BYTES=4096, HALO=14, WINDOW=PAGE_BYTES+2*HALO };
struct sample { unsigned length,want; unsigned char bytes[15]; };
/* Literal cores, independent of the implementation's switch/prefix walker. */
static const struct sample cores[]={
 {2,1,{0x0f,0xa2}}, {2,1,{0x0f,0x31}}, {3,2,{0x0f,0x01,0xf9}},
 {2,1,{0x0f,0x05}}, {2,1,{0x0f,0x34}}, {2,1,{0xcd,0x80}},
 {2,1,{0x0f,0xc7}}, {2,2,{0x0f,0x01}}, {2,2,{0x0f,0xae}},
 {2,2,{0x0f,0x07}}, {2,2,{0x0f,0x35}}, {2,2,{0x0f,0x37}},
 {2,2,{0x0f,0xaa}}, {3,2,{0x0f,0x38,0xf5}}, {3,2,{0x0f,0x38,0xf6}},
 {2,4,{0xc7,0xf8}}, {2,4,{0xc6,0xf8}}
};
static const struct sample prefixes[]={
 {0,0,{0}}, {1,0,{0x66}}, {1,0,{0xf2}}, {1,0,{0xf3}}, {1,0,{0xf0}},
 {9,0,{0x66,0x67,0x2e,0x3e,0x26,0x36,0x64,0x65,0x48}}
};
static const struct sample hle[]={
 {4,4,{0xf2,0xf0,0x01,0}}, {4,4,{0xf0,0xf2,0x01,0}},
 {4,4,{0xf3,0xf0,0x01,0}}, {4,4,{0xf0,0xf3,0x01,0}},
 {3,4,{0xf2,0x86,0}}, {3,4,{0xf2,0x87,0}},
 {3,4,{0xf3,0x86,0}}, {3,4,{0xf3,0x87,0}},
 {3,4,{0xf3,0x88,0}}, {3,4,{0xf3,0x89,0}},
 {4,4,{0xf3,0xc6,0,0}}, {7,4,{0xf3,0xc7,0,0,0,0,0}}
};
/* Barrier-free bytes, not declarations that every stream/mode may execute. */
static const struct sample allowed[]={
 {1,0,{0x90}}, {3,0,{0x48,0x89,0xd8}}, {4,0,{0x48,0x83,0xc0,1}},
 {4,0,{0x4c,0x8d,0x14,0x0b}}, {3,0,{0x48,0x39,0xd8}}, {2,0,{0x75,0xf9}},
 {5,0,{0xe8,0,0,0,0}}, {1,0,{0xc3}}, {1,0,{0x9c}}, {1,0,{0x9d}},
 {1,0,{0xcb}}, {3,0,{0xca,0,0}}, {2,0,{0x48,0xcf}},
 {5,0,{0xf0,0x41,0x0f,0xb1,0x17}}, {3,0,{0xf2,0x89,0}},
 {4,0,{0xf3,0x90,0x89,0}}, {2,0,{0x86,0}}, {2,0,{0x87,0}}
};
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
static unsigned char window[WINDOW];
static uint64_t counts[5],patterns[3],straddles[3];
static int check(const unsigned char *p,size_t n,unsigned want,unsigned group,size_t at) {
    unsigned got=li2_native_policy(p,n);++counts[group];
    if(got==want)return 0;
    fprintf(stderr,"{\"group\":%u,\"case\":%"PRIu64",\"offset\":%zu,\"expected\":%u,\"actual\":%u}\n",
            group,counts[group],at,want,got);return 1;
}
static int sweep(const unsigned char *p,size_t n,unsigned want,unsigned group) {
    ++patterns[group];
    for(size_t at=0;at+n<=WINDOW;at++) {
        memcpy(window+at,p,n);
        if(check(window,WINDOW,want,group,at))return 1;
        if((at<HALO && at+n>HALO) || (at<HALO+PAGE_BYTES && at+n>HALO+PAGE_BYTES))++straddles[group];
        memset(window+at,0x90,n);
    }
    return 0;
}
int main(void) {
    _Static_assert(LI2_NATIVE_BLOCK_SELECTED==1 && LI2_NATIVE_BLOCK_STATE==2 &&
                   LI2_NATIVE_BLOCK_TRANSACTION==4,"fixed public result bits");
    if(sysconf(_SC_PAGESIZE)!=PAGE_BYTES)return 2;
    memset(window,0x90,sizeof(window));
    for(size_t c=0;c<COUNT(cores);c++)for(size_t p=0;p<COUNT(prefixes);p++) {
        unsigned char bytes[15];size_t n=prefixes[p].length+cores[c].length;
        memcpy(bytes,prefixes[p].bytes,prefixes[p].length);
        memcpy(bytes+prefixes[p].length,cores[c].bytes,cores[c].length);
        if(sweep(bytes,n,cores[c].want,0))return 1;
    }
    for(size_t i=0;i<COUNT(hle);i++)if(sweep(hle[i].bytes,hle[i].length,4,1))return 1;
    for(unsigned hint=0xf2;hint<=0xf3;hint++)for(unsigned order=0;order<2;order++)
        for(unsigned gap=0;gap<=11;gap++) {
            unsigned char bytes[15];memset(bytes,0x66,sizeof(bytes));
            bytes[0]=order?0xf0:hint;bytes[gap+1]=order?hint:0xf0;
            bytes[gap+2]=1;bytes[gap+3]=0;
            if(sweep(bytes,gap+4,4,1))return 1;
        }
    for(size_t i=0;i<COUNT(allowed);i++)if(sweep(allowed[i].bytes,allowed[i].length,0,2))return 1;
    /* Complete ModRM byte domain at both halo and page seams. 0F C7 F8 also
       contains the raw C7 F8 transaction barrier, so both bits are required. */
    static const size_t offsets[]={0,1,12,13,14,15,4108,4109,4110,4111,4120,4121};
    static const unsigned char groups[]={0x01,0xae,0xc7};
    for(size_t g=0;g<COUNT(groups);g++)for(unsigned m=0;m<256;m++)
        for(size_t k=0;k<COUNT(offsets);k++) {
            size_t at=offsets[k];window[at]=0x0f;window[at+1]=groups[g];window[at+2]=m;
            unsigned want=g==2?(m==0xf8?5:1):2;
            if(check(window,WINDOW,want,3,at))return 1;
            memset(window+at,0x90,3);
        }
    /* Real inaccessible neighbors detect out-of-range reads on short inputs. */
    unsigned char *guard=mmap(0,3*PAGE_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(guard==MAP_FAILED || mprotect(guard+PAGE_BYTES,PAGE_BYTES,PROT_READ|PROT_WRITE))return 2;
    for(size_t n=0;n<=15;n++)for(unsigned edge=0;edge<2;edge++) {
        unsigned char *p=guard+(edge?2*PAGE_BYTES-n:PAGE_BYTES);memset(p,0x90,n);
        if(check(p,n,0,4,n))return 1;
    }
    for(size_t c=0;c<COUNT(cores);c++)for(size_t n=1;n<=cores[c].length;n++) {
        unsigned char *p=guard+2*PAGE_BYTES-n;memcpy(p,cores[c].bytes,n);
        unsigned want=n==cores[c].length || (c==2 && n==2)?cores[c].want:0;
        if(check(p,n,want,4,n))return 1;
    }
    if(munmap(guard,3*PAGE_BYTES))return 2;
    printf("{\"version\":1,\"window_bytes\":%u,\"patterns\":[%"PRIu64",%"PRIu64",%"PRIu64"],"
           "\"checks\":[%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"],"
           "\"pattern_straddles\":[%"PRIu64",%"PRIu64",%"PRIu64"]}\n",WINDOW,
           patterns[0],patterns[1],patterns[2],counts[0],counts[1],counts[2],counts[3],counts[4],
           straddles[0],straddles[1],straddles[2]);return 0;
}
