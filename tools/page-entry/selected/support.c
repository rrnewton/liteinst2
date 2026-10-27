#include "bridge.h"
void *memmove(void *d,const void *s,size_t n) {
    unsigned char *out=d;const unsigned char *in=s;
    if((uintptr_t)out<(uintptr_t)in)for(size_t i=0;i<n;i++)out[i]=in[i];
    else for(size_t i=n;i;i--)out[i-1]=in[i-1];
    return d;
}
int memcmp(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return x[i]<y[i]?-1:1;return 0;
}
int bcmp(const void *a,const void *b,size_t n) { return memcmp(a,b,n); }
