/* Pure fixture-helper oracle. The collector separately binds the actual
   helper's whole emitted body to the application and checks its native page. */
#define _GNU_SOURCE
#include "app.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void copy(void *,const void *,size_t);
static unsigned char source[UA_FP+64],destination[UA_FP+64],expected[UA_FP+64];
static unsigned char overlap[256],overlap_expected[256];
static unsigned disjoint_cases,overlap_cases,guard_cases,large_cases;

static void require(int yes,unsigned line) {
    if(!yes) { fprintf(stderr,"active-copy-oracle:%u\n",line);exit(1); }
}
#define CHECK(x) require((x),__LINE__)
static unsigned char pattern(size_t i,unsigned salt) {
    return (unsigned char)(i*37U+(i>>3)*11U+salt);
}
static void fill(unsigned char *p,size_t n,unsigned salt) {
    for(size_t i=0;i<n;i++)p[i]=pattern(i,salt);
}
static void reference(void *v,const void *w,size_t n) {
    volatile unsigned char *d=v;const volatile unsigned char *s=w;
    while(n--)*d++=*s++;
}
static void equal(const unsigned char *a,const unsigned char *b,size_t n) {
    for(size_t i=0;i<n;i++)CHECK(a[i]==b[i]);
}
static size_t length(unsigned i) {
    static const size_t extra[6]={63,64,65,127,128,129};
    CHECK(i<38);return i<32?i:extra[i-32];
}
static void disjoint(size_t n,unsigned sa,unsigned da) {
    size_t extent=n+32;CHECK(extent<=sizeof source && sa<8 && da<8);
    fill(source,extent,19);fill(destination,extent,211);fill(expected,extent,211);
    reference(expected+8+da,source+8+sa,n);
    copy(destination+8+da,source+8+sa,n);
    equal(destination,expected,extent);
    for(size_t i=0;i<extent;i++)CHECK(source[i]==pattern(i,19));
}
int main(void) {
    for(unsigned sa=0;sa<8;sa++)for(unsigned da=0;da<8;da++)for(unsigned i=0;i<38;i++) {
        disjoint(length(i),sa,da);++disjoint_cases;
    }
    for(unsigned align=0;align<8;align++)for(int delta=-16;delta<=16;delta++)for(unsigned i=0;i<38;i++) {
        size_t n=length(i),from=64+align,to=(size_t)((int)from+delta);
        CHECK(from+n<=sizeof overlap && to+n<=sizeof overlap);
        fill(overlap,sizeof overlap,73);fill(overlap_expected,sizeof overlap_expected,73);
        reference(overlap_expected+to,overlap_expected+from,n);
        copy(overlap+to,overlap+from,n);
        equal(overlap,overlap_expected,sizeof overlap);++overlap_cases;
    }
    const size_t large[3]={UA_LIVE,2*UA_PAGE,UA_FP};
    for(unsigned i=0;i<3;i++) { disjoint(large[i],1,5);++large_cases; }
    CHECK(sysconf(_SC_PAGESIZE)==UA_PAGE);
    unsigned char *sm=mmap(0,3*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    unsigned char *dm=mmap(0,3*UA_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(sm!=MAP_FAILED && dm!=MAP_FAILED && sm!=dm);
    unsigned char *s=sm+UA_PAGE,*d=dm+UA_PAGE;
    CHECK(!mprotect(s,UA_PAGE,PROT_READ|PROT_WRITE));
    CHECK(!mprotect(d,UA_PAGE,PROT_READ|PROT_WRITE));
    fill(s,UA_PAGE,29);CHECK(!mprotect(s,UA_PAGE,PROT_READ));
    for(unsigned ends=0;ends<4;ends++)for(unsigned i=0;i<35;i++) {
        size_t n=length(i),so=(ends&1)?UA_PAGE-n:0,at=(ends&2)?UA_PAGE-n:0;
        fill(d,UA_PAGE,157);fill(expected,UA_PAGE,157);
        reference(expected+at,s+so,n);copy(d+at,s+so,n);
        equal(d,expected,UA_PAGE);
        for(size_t j=0;j<UA_PAGE;j++)CHECK(s[j]==pattern(j,29));
        ++guard_cases;
    }
    CHECK(!munmap(sm,3*UA_PAGE) && !munmap(dm,3*UA_PAGE));
    CHECK(disjoint_cases==2432 && overlap_cases==10032 && guard_cases==140 && large_cases==3);
    puts("active-app-copy disjoint=2432 overlap=10032 guards=140 large=3");
    return 0;
}
