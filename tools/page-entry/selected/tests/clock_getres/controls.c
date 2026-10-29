/* Supplied-state arithmetic only. Actual guard TU; no kernel registration or
   query is executed and no supplied state is counted as native evidence. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../rseq_guard.c"
static uint64_t area[4] __attribute__((aligned(32)));
static unsigned checks;
long raw(long n,long a,long b,long c,long d,long e,long f){(void)n;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;abort();}
static void check(int ok){if(!ok)abort();}
static void one(long clock,uintptr_t pointer,unsigned error,long detail,unsigned ranges,uintptr_t first,uintptr_t end,unsigned special){
    memset(area,0,sizeof area);state=(struct li2_rseq_state){0};
    state.initialized=state.registered=state.held=state.tls_complete=1;state.phase=LI2_RSEQ_ACTIVE;state.address=(uintptr_t)area;
    if(special==1)area[1]=1;
    if(special==2)state.held=0;
    long a[6]={clock,(long)pointer,0x1234,0x2345,0x3456,0x4567},saved[6];memcpy(saved,a,sizeof a);
    struct li2_rseq_state wanted=state;wanted.first_error=error;wanted.first_detail=detail;
    if(!special)wanted.syscall_checks=1;
    wanted.range_checks=ranges;wanted.last_first=first;wanted.last_end=end;
    check(li2_rseq_before_syscall(SYS_clock_getres,a)==(int)error);
    check(!memcmp(a,saved,sizeof a)&&!memcmp(&state,&wanted,sizeof state)&&area[1]==(special==1));checks++;
}
int main(void){
    uintptr_t w=(uintptr_t)area+8;
    for(unsigned i=0;i<2;i++){
        long clock=i?-1:4;
        one(clock,0,0,0,0,0,0,0);
        one(clock,w-16,0,0,1,w-16,w,0);one(clock,w+8,0,0,1,w+8,w+24,0);
        one(clock,w-15,LI2_RSEQ_OVERLAP,0,1,w-15,w+1,0);
        one(clock,w+7,LI2_RSEQ_OVERLAP,0,1,w+7,w+23,0);
        one(clock,w,LI2_RSEQ_OVERLAP,0,1,w,w+16,0);
        one(clock,UINTPTR_MAX-16,0,0,1,UINTPTR_MAX-16,UINTPTR_MAX,0);
        one(clock,UINTPTR_MAX-15,LI2_RSEQ_OVERFLOW,1,0,0,0,0);
        one(clock,0,LI2_RSEQ_WORD,0,0,0,0,1);
        one(clock,0,LI2_RSEQ_STATE,1,0,0,0,2);
    }
    check(checks==20);puts("LI2_CLOCK_GETRES_SUPPLIED 20 native_registration=0 kernel_queries=0");return 0;
}
