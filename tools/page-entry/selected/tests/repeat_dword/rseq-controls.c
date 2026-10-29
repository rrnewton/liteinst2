/* Supplied-state controls only: this includes the actual guard translation unit
   to set its private retained inputs. It does not register rseq, change page
   permissions or execute a target instruction. Link the actual step_owner.c
   for li2_repeat_width/candidate; discarded owner code grants no native proof. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rseq_guard.c"

static uint64_t area[4] __attribute__((aligned(32)));
static unsigned observations;
static void check(int yes) { if(!yes)abort(); }
long raw(long n,long a,long b,long c,long d,long e,long f) {
    (void)n;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;abort();
}
uint32_t li2_decoder_write_footprint(uint64_t pc,const unsigned char *bytes,size_t n,
    const struct li2_write_registers *regs,struct li2_write_footprint *out) {
    (void)pc;(void)bytes;(void)n;(void)regs;(void)out;abort();
}
static struct li2_decoded decoded(unsigned width) {
    struct li2_decoded d={0};d.abi_version=1;d.decode_status=LI2_VALID;
    d.pc=0x4000;d.code=width==4?345:346;d.length=width==4?2:3;
    d.available=d.length;d.next_pc=d.pc+d.length;d.bytes[0]=0xf3;
    d.bytes[1]=width==4?0xab:0x48;if(width==8)d.bytes[2]=0xab;
    return d;
}
static void reset(void) {
    memset(area,0,sizeof area);state=(struct li2_rseq_state){0};
    state.initialized=state.registered=state.held=state.tls_complete=1;
    state.phase=LI2_RSEQ_ACTIVE;state.address=(uintptr_t)area;
}
static void span_case(unsigned width,uint64_t n,uintptr_t at,unsigned df,
                      int error,long detail,uintptr_t first,uintptr_t end,
                      uint64_t ranges) {
    reset();struct li2_decoded d=decoded(width);ucontext_t uc={0};
    uc.uc_mcontext.gregs[REG_RCX]=(greg_t)n;uc.uc_mcontext.gregs[REG_RDI]=(greg_t)at;
    uc.uc_mcontext.gregs[REG_EFL]=(greg_t)(UINT64_C(0x247)|(df?UINT64_C(0x400):0));
    ucontext_t before=uc;struct li2_decoded before_d=d;
    int got=li2_rseq_check_instruction(&d,&uc);
    check(got==error && state.first_error==(unsigned)error && state.first_detail==detail);
    check(state.last_pc==d.pc && state.last_code==d.code &&
          state.last_policy==(n?LI2_WRITE_RANGE:LI2_WRITE_NONE));
    check(state.instruction_checks==1 && state.repeat_checks==1 && state.range_checks==ranges);
    check(state.last_first==first && state.last_end==end && !area[1]);
    struct li2_write_footprint empty={0};
    check(!memcmp(&state.last_footprint,&empty,sizeof empty));
    check(!memcmp(&uc,&before,sizeof uc) && !memcmp(&d,&before_d,sizeof d));
    ++observations;
}
static void widths(void) {
    check(!li2_repeat_width(0) && !li2_repeat_candidate(0));++observations;
    for(unsigned w=4;w<=8;w+=4) {
        struct li2_decoded d=decoded(w),q;
        check(li2_repeat_width(&d)==w && li2_repeat_candidate(&d));++observations;
        q=d;q.available=15;memset(q.bytes+d.length,0xcc,15-d.length);
        check(li2_repeat_width(&q)==w && li2_repeat_candidate(&q));++observations;
#define REFUSE(statement) do { q=d;statement;check(!li2_repeat_width(&q) && !li2_repeat_candidate(&q));++observations; } while(0)
        REFUSE(q.abi_version=2);REFUSE(q.reserved=1);REFUSE(q.decode_status=LI2_INVALID);
        REFUSE(q.kind=LI2_SYSCALL);REFUSE(q.code=w==4?346:345);
        REFUSE(q.length++);REFUSE(q.available=d.length-1);REFUSE(q.available=16);
        REFUSE(q.next_pc++);REFUSE(q.pc=UINTPTR_MAX;q.next_pc=1);
        REFUSE(q.bytes[0]=0xf2);REFUSE(q.bytes[1]=0xaa);
        REFUSE(memmove(q.bytes+1,q.bytes,d.length);q.bytes[0]=0x67;
               q.length++;q.available++;q.next_pc++);
        REFUSE(memmove(q.bytes+1,q.bytes,d.length);q.bytes[0]=0x66;
               q.length++;q.available++;q.next_pc++);
#undef REFUSE
    }
}
int main(void) {
    _Static_assert(sizeof(uintptr_t)==8 && sizeof(size_t)==8,"x86-64 span domain");
    widths();uintptr_t word=(uintptr_t)area+8;
    for(unsigned w=4;w<=8;w+=4) {
        for(unsigned df=0;df<2;df++)span_case(w,0,UINTPTR_MAX,df,0,0,0,0,0);
        span_case(w,1,word-w,0,0,0,word-w,word,1);
        span_case(w,1,word+8,0,0,0,word+8,word+8+w,1);
        span_case(w,1,word-w+1,0,LI2_RSEQ_OVERLAP,0,word-w+1,word+1,1);
        span_case(w,1,word+7,0,LI2_RSEQ_OVERLAP,0,word+7,word+7+w,1);
        span_case(w,3,word-2*w,0,LI2_RSEQ_OVERLAP,0,word-2*w,word+w,1);
        span_case(w,3,word-w,1,0,0,word-3*w,word,1);
        span_case(w,3,word+8+2*w,1,0,0,word+8,word+8+3*w,1);
        span_case(w,3,word+7+2*w,1,LI2_RSEQ_OVERLAP,0,word+7,word+7+3*w,1);
        span_case(w,3,word+w,1,LI2_RSEQ_OVERLAP,0,word-w,word+2*w,1);
        span_case(w,1,UINTPTR_MAX-w,0,0,0,UINTPTR_MAX-w,UINTPTR_MAX,1);
        span_case(w,1,UINTPTR_MAX-w+1,0,LI2_RSEQ_OVERFLOW,1,0,0,0);
        span_case(w,1,UINTPTR_MAX-w,1,0,0,UINTPTR_MAX-w,UINTPTR_MAX,1);
        span_case(w,1,UINTPTR_MAX-w+1,1,LI2_RSEQ_OVERFLOW,3,0,0,0);
        span_case(w,2,w-1,1,LI2_RSEQ_OVERFLOW,3,0,0,0);
        span_case(w,2,w,1,0,0,0,2*w,1);
        span_case(w,UINT64_MAX/w+1,0,0,LI2_RSEQ_OVERFLOW,2,0,0,0);
        span_case(w,UINT64_MAX/w+1,UINTPTR_MAX,1,LI2_RSEQ_OVERFLOW,2,0,0,0);
        uint64_t large_bytes=(UINT64_C(1)<<32)*w;
        check(word<=UINTPTR_MAX-8-large_bytes);
        span_case(w,UINT64_C(1)<<32,word+8,0,0,0,word+8,word+8+large_bytes,1);
        span_case(w,UINT64_MAX/w,0,0,LI2_RSEQ_OVERLAP,0,0,(UINT64_MAX/w)*w,1);
        reset();struct li2_decoded d=decoded(w);ucontext_t uc={0};area[1]=1;
        check(li2_rseq_check_instruction(&d,&uc)==LI2_RSEQ_WORD &&
              state.first_error==LI2_RSEQ_WORD && !state.instruction_checks &&
              !state.repeat_checks && !state.range_checks && area[1]==1);++observations;
        reset();state.held=0;
        check(li2_rseq_check_instruction(&d,&uc)==LI2_RSEQ_STATE &&
              state.first_error==LI2_RSEQ_STATE && !state.instruction_checks &&
              !state.repeat_checks && !state.range_checks);++observations;
    }
    check(observations==79);
    printf("LI2_REPEAT_RSEQ_SUPPLIED_PASS observations=%u native=0\n",observations);
    return 0;
}
