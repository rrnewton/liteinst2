/* Fixture-only complete pure helper page. The actual emitted page plus halos
   must pass the unchanged native-policy checker before any app launch. */
#include <stddef.h>
#include <stdint.h>
#define PURE __attribute__((section(".li2_ua_pure"),noinline,used))
/* Full requested bytes only. Overlap preserves the original forward-byte
   behavior; disjoint ranges use unaligned, alias-anything words plus a tail. */
PURE void copy(void *v,const void *w,size_t n) {
    unsigned char *d=v;const unsigned char *s=w;
    uintptr_t a=(uintptr_t)v,b=(uintptr_t)w;
    if(n && (a<=b ? n<=b-a : n<=a-b)) {
        typedef uint64_t word __attribute__((__may_alias__,__aligned__(1)));
        _Static_assert(sizeof(word)==8 && __alignof__(word)==1,"bounded unaligned copy word");
        while(n>=sizeof(word)) {
            *(word *)(void *)d=*(const word *)(const void *)s;
            d+=sizeof(word);s+=sizeof(word);n-=sizeof(word);
        }
    }
    while(n--)*d++=*s++;
}
PURE int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
#ifdef LI2_FAST_EQUAL
    /* GCC's alias-anything, alignment-one integer type permits the same
       immutable byte ranges as the scalar path. Each load is wholly inside
       the requested range; neither alignment nor a readable suffix is needed.
       No vector/string instruction or application-state normalization is used. */
    typedef uint64_t word __attribute__((__may_alias__,__aligned__(1)));
    _Static_assert(sizeof(word)==8 && __alignof__(word)==1,"bounded unaligned word");
    while(n>=sizeof(word)) {
        if(*(const word *)(const void *)x!=*(const word *)(const void *)y)return 0;
        x+=sizeof(word);y+=sizeof(word);n-=sizeof(word);
    }
#endif
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
PURE void ua_data_pattern(unsigned char *p,size_t n) {
    for(size_t i=0;i<n;i++)p[i]=(unsigned char)(1+(i*17)%255);
}
PURE void ua_stack_pattern(unsigned char *p,size_t n) {
    for(size_t i=0;i<n;i++)p[i]=(unsigned char)(i*29+7);
}
