/* Literal geometry puzzle for the actual shared policy, not an owner model.
   The unchanged D3 native/generated cohort must separately observe real NX,
   full close/release, registers, UC, FP, stack and all supplied controls. */
#include "tf_nx_page_boundary.h"

struct row { size_t count; uintptr_t first,second,next; int outside; };
static const struct row rows[]={
    {1,0x2000,0,0x2000,0}, /* first owned byte */
    {1,0x2000,0,0x2fff,0}, /* last owned byte */
    {1,0x2000,0,0x1fff,1}, /* immediately before */
    {1,0x2000,0,0x3000,1}, /* immediately after */
    {1,0x2000,0x3000,0x3000,1}, /* borrowed-only second page is not opened */
    {1,0x2000,0x3000,0x3fff,1},
    {2,0x2000,0x3000,0x2000,0},
    {2,0x2000,0x3000,0x2fff,0},
    {2,0x2000,0x3000,0x3000,0}, /* same second address, now genuinely opened */
    {2,0x2000,0x3000,0x3fff,0},
    {2,0x2000,0x3000,0x1fff,1},
    {2,0x2000,0x3000,0x4000,1},
    {2,0x3000,0x2000,0x2000,0}, /* both pages, independent of array order */
    {1,0,0,0,0},
    {1,UINTPTR_MAX-4095,0,UINTPTR_MAX,0}, /* no end-address overflow */
    {1,UINTPTR_MAX-4095,0,0,1}
};
static unsigned checked;
static int check(const struct li2_step_request *p,uintptr_t pc,int prior,int expected) {
    int actual=li2_tf_nx_page_boundary(p,pc,prior);
    if(actual!=expected)return 0;
    ++checked;return 1;
}
int main(void) {
    const int eligible[]={LI2_CHAIN_NO_FALLBACK,LI2_CHAIN_OLD_STEP};
    const int declined[]={LI2_CHAIN_DECODE_INVALID,LI2_CHAIN_DECODE_TRUNCATED,
        LI2_CHAIN_SELECTED,LI2_CHAIN_NOT_PLAIN,LI2_CHAIN_NOT_CLASSIFIED};
    _Static_assert(LI2_CHAIN_NO_FALLBACK==0 && LI2_CHAIN_OLD_STEP==4 &&
                   LI2_CHAIN_NOT_CLASSIFIED==6 && LI2_CHAIN_PAGE_BOUNDARY==7,
                   "old reasons retained and new reason cannot offer OLD_STEP");
    for(size_t i=0;i<sizeof rows/sizeof rows[0];i++) {
        const struct row *r=&rows[i];
        struct li2_step_request p={.page_count=r->count,
            .pages={{.address=r->first},{.address=r->second}}};
        for(size_t j=0;j<2;j++)
            if(!check(&p,r->next,eligible[j],r->outside?LI2_CHAIN_PAGE_BOUNDARY:eligible[j]))return 1;
    }
    for(size_t i=0;i<sizeof declined/sizeof declined[0];i++) {
        struct li2_step_request p={.page_count=1,.pages={{.address=0x2000}}};
        if(!check(&p,0x2000,declined[i],declined[i]) ||
           !check(&p,0x3000,declined[i],declined[i]) ||
           !check(0,0x3000,declined[i],declined[i]))return 1;
    }
    for(size_t i=0;i<2;i++) {
        struct li2_step_request p={0};
        if(!check(0,0x3000,eligible[i],-1) || !check(&p,0x3000,eligible[i],-1))return 1;
        p.page_count=3;
        if(!check(&p,0x3000,eligible[i],-1))return 1;
        p.page_count=1;p.pages[0].address=0x2001;
        if(!check(&p,0x3000,eligible[i],-1))return 1;
        p.page_count=2;p.pages[0].address=0x2000;p.pages[1].address=0x3001;
        if(!check(&p,0x2000,eligible[i],-1))return 1;
    }
    if(checked!=57)return 1;
    static const char result[]="LI2_TF_NX_PAGE_BOUNDARY cases=57 geometry=32 declined=15 malformed=10\n";
    long written;
    __asm__ volatile("syscall":"=a"(written):"a"(1L),"D"(1L),"S"(result),
                     "d"((long)sizeof result-1):"rcx","r11","memory");
    return written==(long)sizeof result-1?0:2;
}
__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n"
        "and $-16,%rsp\ncall main\nmov %eax,%edi\nmov $231,%eax\nsyscall\nud2\n"
        ".size _start,.-_start\n.section .note.GNU-stack,\"\",@progbits\n");
