/* The actual shared production table predicate; no model of rseq/ownership. */
#include "initial_code_protection.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
_Static_assert(sizeof(uintptr_t)==8 && sizeof(size_t)==8,"fixed x86-64 oracle");
static int (*volatile predicate)(const struct li2_fork_range *,const unsigned char *,
                                size_t,uintptr_t,size_t,unsigned)=
    li2_initial_code_protection_intersects;
static unsigned cases,allowed,refused;
static void need(int ok) { if(!ok) exit(125); }
static void check(const struct li2_fork_range *ranges,const unsigned char *kinds,
                  size_t count,uintptr_t first,size_t bytes,unsigned prot,int want) {
    struct li2_fork_range saved[128];unsigned char saved_kinds[128];
    need(count<=128);memcpy(saved,ranges,count*sizeof *ranges);memcpy(saved_kinds,kinds,count);
    int got=predicate(ranges,kinds,count,first,bytes,prot);
    need(got==want && !memcmp(saved,ranges,count*sizeof *ranges) &&
         !memcmp(saved_kinds,kinds,count));
    ++cases;if(got)++refused;else ++allowed;
}
int main(int argc,char **argv) {
    (void)argv;need(argc==1);
    static const struct {
        size_t count;struct li2_fork_range ranges[3];unsigned char kinds[3];
    } tables[10]={
        {0,{{0,0}}, {0}},
        {1,{{0x1000,0x5000}}, {1}},
        {1,{{0x1000,0x5000}}, {0}},
        {2,{{0x1000,0x5000},{0x2000,0x3000}}, {1,0}},
        {2,{{0x1000,0x5000},{0x2000,0x3000}}, {0,1}},
        {3,{{0x1000,0x2000},{0x3000,0x4000},{0x2000,0x3000}}, {1,1,0}},
        {2,{{0x2000,0x3000},{0x1000,0x5000}}, {0,1}},
        {2,{{0x2000,0x3000},{0x1000,0x5000}}, {1,0}},
        {2,{{0x1000,0x2000},{0x2000,0x3000}}, {1,1}},
        {1,{{0x1000,0x5000}}, {2}}
    };
    static const struct { uintptr_t first;size_t bytes; } queries[12]={
        {0x800,0x800},{0x1000,0x1000},{0x2000,0x1000},{0x3000,0x1000},
        {0x4000,0x1000},{0x5000,0x1000},{0x1800,0x2000},{0x800,0x5000},
        {0x1fff,1},{0x2000,1},{0x2fff,1},{0x3000,1}
    };
    /* Literal overlap classes: 0 none, 1 initial only, 2 any strict. */
    static const unsigned char classes[10][12]={
        {0,0,0,0,0,0,0,0,0,0,0,0},
        {0,1,1,1,1,0,1,1,1,1,1,1},
        {0,2,2,2,2,0,2,2,2,2,2,2},
        {0,1,2,1,1,0,2,2,1,2,2,1},
        {0,2,2,2,2,0,2,2,2,2,2,2},
        {0,1,2,1,0,0,2,2,1,2,2,1},
        {0,1,2,1,1,0,2,2,1,2,2,1},
        {0,2,2,2,2,0,2,2,2,2,2,2},
        {0,1,1,0,0,0,1,1,1,1,1,0},
        {0,2,2,2,2,0,2,2,2,2,2,2}
    };
    static const unsigned prot[6]={PROT_READ,PROT_READ|PROT_EXEC,PROT_WRITE,
                                  PROT_READ|PROT_WRITE,PROT_NONE,
                                  PROT_READ|PROT_WRITE|PROT_EXEC};
    static const unsigned char want[3][6]={{0,0,0,0,0,0},{0,0,1,1,1,1},{1,1,1,1,1,1}};
    for(unsigned t=0;t<10;t++)for(unsigned q=0;q<12;q++)for(unsigned p=0;p<6;p++)
        check(tables[t].ranges,tables[t].kinds,tables[t].count,queries[q].first,
              queries[q].bytes,prot[p],want[classes[t][q]][p]);
    need(cases==720);
    struct li2_fork_range ranges[128];unsigned char kinds[128];
    for(unsigned i=0;i<128;i++){ranges[i]=(struct li2_fork_range){0x1000,0x5000};kinds[i]=1;}
    for(unsigned order=0;order<2;order++) {
        unsigned strict=order?0:127;
        ranges[strict]=(struct li2_fork_range){0x2000,0x3000};kinds[strict]=0;
        for(unsigned p=0;p<6;p++) {
            check(ranges,kinds,128,0x2000,1,prot[p],1);
            check(ranges,kinds,128,0x1000,1,prot[p],want[1][p]);
        }
        ranges[strict]=(struct li2_fork_range){0x1000,0x5000};kinds[strict]=1;
    }
    need(cases==744);
    check(ranges,kinds,0,0,0,PROT_READ,1);
    check(ranges,kinds,1,0x1000,0,PROT_READ,1);
    check(ranges,kinds,0,UINTPTR_MAX,1,PROT_READ,1);
    check(ranges,kinds,0,UINTPTR_MAX-1,2,PROT_READ,1);
    check(ranges,kinds,0,UINTPTR_MAX-1,1,PROT_READ,0);
    check(ranges,kinds,0,0,UINTPTR_MAX,PROT_READ|PROT_WRITE|PROT_EXEC,0);
    ranges[0]=(struct li2_fork_range){UINTPTR_MAX-4096,UINTPTR_MAX};kinds[0]=1;
    check(ranges,kinds,1,UINTPTR_MAX-1,1,PROT_READ,0);
    check(ranges,kinds,1,UINTPTR_MAX-1,1,PROT_WRITE,1);
    kinds[0]=0;check(ranges,kinds,1,UINTPTR_MAX-1,1,PROT_READ,1);
    kinds[0]=1;check(ranges,kinds,1,UINTPTR_MAX-1,2,PROT_READ|PROT_EXEC,1);
    need(cases==754 && allowed==273 && refused==481);
    need(printf("{\"version\":1,\"predicate_only\":1,\"cases\":754,\"allowed\":273,\"refused\":481,\"live_rseq\":0,\"live_owner\":0}\n")>0);
    need(!fflush(stdout) && !ferror(stdout));
    return 0;
}
