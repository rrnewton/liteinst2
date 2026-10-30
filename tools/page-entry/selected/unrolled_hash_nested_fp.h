#ifndef LI2_UNROLLED_HASH_NESTED_FP_H
#define LI2_UNROLLED_HASH_NESTED_FP_H
/* Only the terminal UHO_NESTED qualification injection. No production gate,
   saved application state, or live FP register is changed by these saves. */
#include <stddef.h>
#include <stdint.h>
struct uho_nested_fp {
    /* version,started,complete,stack_first,stack_extent,rsp,copied,xcr0,
       pid,tid,signal,request_mask,save_zero,save_ones,seventh,reserved */
    uint64_t h[16];
    unsigned char zero[65536] __attribute__((aligned(64)));
    unsigned char ones[65536] __attribute__((aligned(64)));
    unsigned char stack[524288];
};
_Static_assert(__alignof__(struct uho_nested_fp)==64 &&
    offsetof(struct uho_nested_fp,zero)==128 &&
    offsetof(struct uho_nested_fp,ones)==65664 &&
    offsetof(struct uho_nested_fp,stack)==131200 &&
    sizeof(struct uho_nested_fp)==655488,"exact private scalar assembly layout");
/* Same seven-argument SysV shape as li2_raw6; only the first argument is the
   protected observation address. The caller supplies the ordinary zero seventh
   argument. This function uses no callee-saved register, stack store or call. */
extern long uho_nested_raw(struct uho_nested_fp *,long,long,long,long,long,long);
__asm__(
".pushsection .text\n"
".p2align 4\n"
".global uho_nested_raw\n.hidden uho_nested_raw\n.type uho_nested_raw,@function\n"
"uho_nested_raw:\n"
" mov %rdi,%r10\n"
" movq $1,8(%r10)\n"
" mov %rsp,40(%r10)\n"
" mov 8(%rsp),%rax\n mov %rax,112(%r10)\n test %rax,%rax\n jnz 9f\n"
" mov 24(%r10),%rsi\n cmp %rsi,%rsp\n jbe 9f\n"
" mov %rsp,%rax\n sub %rsi,%rax\n mov %rax,48(%r10)\n"
" add $16,%rax\n cmp 32(%r10),%rax\n ja 9f\n"
" cld\n"
/* Complementary whole buffers; both headers start zero because XSAVE updates
   only requested XSTATE_BV bits and does not write reserved header fields. */
" lea 128(%r10),%rdi\n xor %eax,%eax\n mov $8192,%ecx\n rep stosq\n"
" lea 65664(%r10),%rdi\n mov $-1,%rax\n mov $8192,%ecx\n rep stosq\n"
" lea 66176(%r10),%rdi\n xor %eax,%eax\n mov $8,%ecx\n rep stosq\n"
" mov 88(%r10),%rax\n mov %rax,%rdx\n shr $32,%rdx\n xsave64 128(%r10)\n"
" movq $1,96(%r10)\n"
" mov 88(%r10),%rax\n mov %rax,%rdx\n shr $32,%rdx\n xsave64 65664(%r10)\n"
" movq $1,104(%r10)\n"
/* The call's return word and seventh argument already exist at/above RSP.
   Retain every byte below this exact RSP; after this copy neither the shim nor
   li2_raw6 writes that range. The genuine nested FP pointer must be inside it. */
" mov 24(%r10),%rsi\n lea 131200(%r10),%rdi\n mov 48(%r10),%rcx\n rep movsb\n"
" movq $1,16(%r10)\n"
" mov 64(%r10),%rsi\n mov 72(%r10),%rdx\n mov 80(%r10),%rcx\n"
" xor %r8d,%r8d\n xor %r9d,%r9d\n mov $234,%edi\n jmp li2_raw6\n"
"9: mov $-22,%rax\n ret\n"
".size uho_nested_raw,.-uho_nested_raw\n.popsection\n");
#endif
