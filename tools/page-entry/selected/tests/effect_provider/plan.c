/* Pure supplied-plan controls. Link the actual admission Rust archive; no stub,
   decoder initialization, selected instruction, mapping or subject execution.
   This source has not been compiled or run during authoring. */
#include "oneshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
static void need(int ok,int line) {
    ++checks;
    if(!ok) {fprintf(stderr,"oneshot plan control line %d\n",line);exit(1);}
}
#define CHECK(x) need((x),__LINE__)
_Noreturn void li2_decoder_abort(uint32_t code) {
    fprintf(stderr,"unexpected decoder abort %u\n",code);exit(125);
}
static struct li2_oneshot_plan plan(unsigned kind,uint64_t pc) {
    static const unsigned char second[]={0,0x05,0x31,0xa2};
    CHECK(kind>=1 && kind<=3);
    struct li2_oneshot_plan p={.abi_version=1,.kind=kind,.sequence=9,
        .pc=pc,.next_pc=pc+2,.landing=pc+5+0x1234,
        .landing_allocation=81,.landing_generation=13,
        .page_count=1,.original={0x0f,second[kind],0x48,0x90,0xc3}};
    p.pages[0]=(struct li2_oneshot_page){pc&~UINT64_C(4095),17,23,4096};
    return p;
}
static void accepted(const struct li2_oneshot_plan *p,const unsigned char jump[5]) {
    struct li2_oneshot_plan expected=*p,out;
    memcpy(expected.redirect,jump,5);memset(&out,0xa5,sizeof(out));
    CHECK(li2_admission_oneshot_plan(p,&out)==LI2_ONESHOT_OK);
    CHECK(!memcmp(&out,&expected,sizeof(out)));
}
static void refused(const struct li2_oneshot_plan *p,int error) {
    struct li2_oneshot_plan out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    CHECK(li2_admission_oneshot_plan(p,&out)==error);
    CHECK(!memcmp(&out,&before,sizeof(out))); /* no partial output on refusal */
}
static void opcode_and_geometry(void) {
    const unsigned char small[]={0xe9,0x34,0x12,0,0},page[]={0xe9,0,0x10,0,0};
    for(unsigned kind=1;kind<=3;kind++) {
        struct li2_oneshot_plan p=plan(kind,LI2_ONESHOT_MIN_EXEC+0x2040);
        accepted(&p,small);
        /* Exact old/new class-opcode matching: all six wrong pairings refuse. */
        static const unsigned char second[]={0,0x05,0x31,0xa2};
        for(unsigned other=1;other<=3;other++)if(other!=kind) {
            struct li2_oneshot_plan bad=p;bad.original[1]=second[other];
            refused(&bad,LI2_ONESHOT_ENCODING);
        }
        struct li2_oneshot_plan bad=p;bad.original[0]=0x66;
        refused(&bad,LI2_ONESHOT_ENCODING);
        /* The five-byte publication window, not merely the two-byte effect,
           decides page dependencies. Both boundary positions are explicit. */
        p=plan(kind,LI2_ONESHOT_MIN_EXEC+0x2ffb);accepted(&p,small);
        p=plan(kind,LI2_ONESHOT_MIN_EXEC+0x2ffc);
        p.page_count=2;p.pages[1]=(struct li2_oneshot_page){LI2_ONESHOT_MIN_EXEC+0x3000,17,24,8192};
        p.landing=p.pc+5+0x1000;accepted(&p,page);
        bad=p;bad.page_count=1;refused(&bad,LI2_ONESHOT_GEOMETRY);
        bad=p;bad.pages[1].address+=4096;refused(&bad,LI2_ONESHOT_GEOMETRY);
        bad=p;bad.pages[1].allocation=0;refused(&bad,LI2_ONESHOT_GEOMETRY);
        bad=p;bad.pages[1].offset++;refused(&bad,LI2_ONESHOT_GEOMETRY);
        bad=p;bad.landing=p.pages[0].address;refused(&bad,LI2_ONESHOT_GEOMETRY);
        bad=p;bad.landing=p.pages[1].address;refused(&bad,LI2_ONESHOT_GEOMETRY);
        bad=p;bad.landing=LI2_ONESHOT_MIN_EXEC+0x4fff;refused(&bad,LI2_ONESHOT_GEOMETRY);
    }
    struct li2_oneshot_plan p=plan(LI2_ONESHOT_CPUID,LI2_ONESHOT_MIN_EXEC+0x2040),bad;
    bad=p;bad.kind=4;refused(&bad,LI2_ONESHOT_ENCODING);
    bad=p;bad.page_count=2;refused(&bad,LI2_ONESHOT_GEOMETRY);
    bad=p;bad.pages[0].generation=0;refused(&bad,LI2_ONESHOT_GEOMETRY);
    bad=p;bad.pages[1].allocation=1;refused(&bad,LI2_ONESHOT_ARGUMENT);
    bad=p;bad.reserved=1;refused(&bad,LI2_ONESHOT_ARGUMENT);
    bad=p;bad.reserved_bytes[5]=1;refused(&bad,LI2_ONESHOT_ARGUMENT);
    bad=p;bad.redirect[0]=0xe9;refused(&bad,LI2_ONESHOT_ARGUMENT);
    bad=p;bad.sequence=0;refused(&bad,LI2_ONESHOT_ARGUMENT);
    bad=p;bad.next_pc++;refused(&bad,LI2_ONESHOT_GEOMETRY);
    bad=p;bad.pc=LI2_ONESHOT_MIN_EXEC-1;refused(&bad,LI2_ONESHOT_ARGUMENT);
    bad=p;bad.pc=UINT64_MAX-2;refused(&bad,LI2_ONESHOT_GEOMETRY);
    refused(0,LI2_ONESHOT_ARGUMENT);
    CHECK(li2_admission_oneshot_plan(&p,0)==LI2_ONESHOT_ARGUMENT);
}
static void displacement_edges(void) {
    struct li2_oneshot_plan p=plan(LI2_ONESHOT_CPUID,UINT64_C(0x300000040));
    const unsigned char highest[]={0xe9,0xff,0xff,0xff,0x7f};
    const unsigned char lowest[]={0xe9,0,0,0,0x80};
    p.landing=p.pc+5+UINT64_C(0x7fffffff);accepted(&p,highest);
    p.landing++;refused(&p,LI2_ONESHOT_GEOMETRY);
    p.landing=p.pc+5-UINT64_C(0x80000000);accepted(&p,lowest);
    p.landing--;refused(&p,LI2_ONESHOT_GEOMETRY);
}
static void refused_transition(struct li2_oneshot_admission_state *s,unsigned old,unsigned next) {
    struct li2_oneshot_admission_state before=*s;
    CHECK(li2_admission_oneshot_transition(s,old,next)==LI2_ONESHOT_REUSE);
    CHECK(!memcmp(s,&before,sizeof(before)));
}
static void phase_rules(void) {
    struct li2_oneshot_admission_state s={0};
    CHECK(li2_admission_oneshot_bind(&s,9)==0 && s.phase==LI2_ONESHOT_BOUND && s.sequence==9);
    refused_transition(&s,LI2_ONESHOT_EMPTY,LI2_ONESHOT_BOUND);
    refused_transition(&s,LI2_ONESHOT_BOUND,LI2_ONESHOT_PUBLISHED);
    static const unsigned phases[]={LI2_ONESHOT_BOUND,LI2_ONESHOT_WRITING,LI2_ONESHOT_PUBLISHED,
        LI2_ONESHOT_LANDED,LI2_ONESHOT_CLOSING,LI2_ONESHOT_RESTORING,LI2_ONESHOT_RESTORED,LI2_ONESHOT_COMPLETED};
    for(unsigned i=1;i<sizeof(phases)/sizeof(phases[0]);i++) {
        CHECK(li2_admission_oneshot_transition(&s,phases[i-1],phases[i])==0);
        CHECK(s.phase==phases[i] && s.sequence==9 && !s.first_error && !s.first_detail && !s.reserved);
        CHECK(s.mutation_started==1 && s.published==(i>=2) && s.restored==(i>=6));
        refused_transition(&s,phases[i],phases[i]);
    }
    struct li2_oneshot_admission_state before=s;
    CHECK(li2_admission_oneshot_bind(&s,10)==LI2_ONESHOT_REUSE && !memcmp(&s,&before,sizeof(s)));
    refused_transition(&s,LI2_ONESHOT_COMPLETED,LI2_ONESHOT_BOUND);
    s=(struct li2_oneshot_admission_state){0};
    CHECK(li2_admission_oneshot_bind(&s,10)==0);
    CHECK(li2_admission_oneshot_transition(&s,LI2_ONESHOT_BOUND,LI2_ONESHOT_WRITING)==0);
    CHECK(li2_admission_oneshot_transition(&s,LI2_ONESHOT_WRITING,LI2_ONESHOT_PUBLISHED)==0);
    li2_admission_oneshot_fail(&s,LI2_ONESHOT_SOURCE,-55);
    CHECK(s.phase==LI2_ONESHOT_FAILED && s.first_error==LI2_ONESHOT_SOURCE && s.first_detail==-55 &&
        s.sequence==10 && s.mutation_started==1 && s.published==1 && !s.restored);
    before=s;li2_admission_oneshot_fail(&s,LI2_ONESHOT_BIND,99);
    CHECK(!memcmp(&s,&before,sizeof(s))); /* original error/prefix retained */
    refused_transition(&s,LI2_ONESHOT_FAILED,LI2_ONESHOT_RESTORED);
    CHECK(li2_admission_oneshot_bind(&s,11)==LI2_ONESHOT_REUSE);
    s=(struct li2_oneshot_admission_state){0};before=s;
    CHECK(li2_admission_oneshot_bind(&s,0)==LI2_ONESHOT_ARGUMENT && !memcmp(&s,&before,sizeof(s)));
    CHECK(li2_admission_oneshot_bind(0,1)==LI2_ONESHOT_ARGUMENT);
    CHECK(li2_admission_oneshot_transition(0,1,2)==LI2_ONESHOT_ARGUMENT);
}
int main(void) {
    opcode_and_geometry();displacement_edges();phase_rules();
    printf("oneshot pure-plan controls passed: %u\n",checks);return 0;
}
