#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static uint64_t sample(clockid_t id) {
    struct timespec t = {0};
    assert(clock_gettime(id,&t)==0);
    return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;
}
int main(void) {
    struct rlimit limit={0};
    assert(getrlimit(RLIMIT_CPU,&limit)==0);
    assert(limit.rlim_cur==20 && limit.rlim_max==20);
    volatile uint64_t value=1;
    puts("refresh,index,wall,thread,process");
    for(unsigned refresh=0;refresh<2;refresh++) {
        for(unsigned i=0;i<12;i++) {
            uint64_t w=sample(CLOCK_MONOTONIC);
            uint64_t t=refresh?sample(CLOCK_THREAD_CPUTIME_ID):0;
            uint64_t p=sample(CLOCK_PROCESS_CPUTIME_ID);
            printf("%u,%u,%"PRIu64",%"PRIu64",%"PRIu64"\n",refresh,i,w,t,p);
            for(unsigned j=0;j<100000;j++) value=value*17+7;
        }
    }
    assert(value!=0);
}
