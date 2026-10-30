#ifndef LI2_SPAN_FAST_BYTES_H
#define LI2_SPAN_FAST_BYTES_H
#include <stddef.h>
#include <stdint.h>
#if !defined(LI2_SPAN_FAST_BYTES) || LI2_SPAN_FAST_BYTES != 1 || !defined(LI2_SCALAR_SPAN_TRACE) || LI2_SCALAR_SPAN_TRACE != 1
#error exact genuine-TRACE fast-byte profile required
#endif
/* Complete owned ranges only. C entry has DF clear; CLD establishes it locally
   too. Saved guest flags are separate. These instructions use no FP/SIMD state.
   Byte string operations retain the old forward-byte overlap/order semantics;
   zero length performs no memory access. No allocation, RAW or callback occurs. */
static inline void li2_span_bytes_copy(void *destination,const void *source,size_t length) {
    __asm__ volatile("cld; rep movsb" : "+D"(destination), "+S"(source), "+c"(length)
                     : : "memory","cc");
}
static inline void li2_span_bytes_zero(void *destination,size_t length) {
    __asm__ volatile("cld; rep stosb" : "+D"(destination), "+c"(length)
                     : "a"(0) : "memory","cc");
}
static inline int li2_span_bytes_equal(const void *left,const void *right,size_t length) {
    const unsigned char *a=left,*b=right;
    /* Same bounded alias/alignment-one integer comparison as LI2_FAST_EQUAL.
       Each load lies inside the requested range and one x86 page. Peel page
       ends bytewise so an early mismatch never causes a load from an otherwise
       untouched inaccessible next page. No suffix beyond length is read. */
    typedef uint64_t word __attribute__((__may_alias__,__aligned__(1)));
    _Static_assert(sizeof(word)==8 && __alignof__(word)==1,"bounded unaligned word");
    while(length>=sizeof(word)) {
        if(((uintptr_t)a&4095U)>4096U-sizeof(word) ||
           ((uintptr_t)b&4095U)>4096U-sizeof(word)) {
            if(*a++!=*b++)return 0;
            --length;continue;
        }
        if(*(const word *)(const void *)a!=*(const word *)(const void *)b)return 0;
        a+=sizeof(word);b+=sizeof(word);length-=sizeof(word);
    }
    for(size_t i=0;i<length;i++)if(a[i]!=b[i])return 0;
    return 1;
}
#endif
