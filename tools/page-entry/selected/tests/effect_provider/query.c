#include "readonly_query.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
static void need(int value,int line) {
    ++checks;if(!value) {fprintf(stderr,"readonly query control line %d\n",line);exit(1);}
}
#define CHECK(x) need((x),__LINE__)
static void refused(long n,long a[6]) {
    struct li2_readonly_query out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    CHECK(!li2_readonly_query(n,a,&out));CHECK(!memcmp(&out,&before,sizeof(out)));
}
int main(void) {
    struct li2_readonly_query out;
    for(long command=0x1021;command<=0x1022;command++) {
        long a[6]={command,0x10000,0,0,0,0};
        CHECK(li2_readonly_query(SYS_arch_prctl,a,&out));
        CHECK(out.count==1 && out.write[0].address==0x10000 && out.write[0].bytes==8 &&
              !out.write[1].address && !out.write[1].bytes);
        a[1]=0;CHECK(li2_readonly_query(SYS_arch_prctl,a,&out));
        CHECK(out.count==1 && !out.write[0].address && out.write[0].bytes==8);
    }
    for(long how=0;how<=2;how++) {
        long a[6]={how,0,0x10000,8,0,0};
        CHECK(li2_readonly_query(SYS_rt_sigprocmask,a,&out));
        CHECK(out.count==1 && out.write[0].address==0x10000 && out.write[0].bytes==8);
        a[2]=0;CHECK(li2_readonly_query(SYS_rt_sigprocmask,a,&out) && !out.count);
        a[1]=0x10000;refused(SYS_rt_sigprocmask,a);
        a[1]=0;a[3]=16;refused(SYS_rt_sigprocmask,a);
    }
    for(unsigned mask=0;mask<4;mask++) {
        long a[6]={mask&1?0x10000:0,mask&2?0x20000:0,0,0,0,0};
        CHECK(li2_readonly_query(SYS_getcpu,a,&out));
        CHECK(out.count==(unsigned)(!!(mask&1)+!!(mask&2)));
        unsigned at=0;
        for(unsigned i=0;i<2;i++)if(a[i]) {
            CHECK(out.write[at].address==(uintptr_t)a[i] && out.write[at].bytes==4);++at;
        }
        a[2]=0x30000;refused(SYS_getcpu,a);
    }
    long a[6]={0x1023,0x10000,0,0,0,0};refused(SYS_arch_prctl,a);
    a[0]=0x1024;refused(SYS_arch_prctl,a);
    a[0]=3;a[1]=0;a[2]=0x10000;a[3]=8;refused(SYS_rt_sigprocmask,a);
    a[0]=-1;refused(SYS_rt_sigprocmask,a);
    refused(SYS_read,a);CHECK(!li2_readonly_query(SYS_getcpu,0,&out));
    printf("readonly query controls passed: %u\n",checks);return 0;
}
