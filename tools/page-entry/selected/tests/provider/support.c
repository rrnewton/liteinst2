/* Freestanding support for the prototype link, not target libc. Compile with
   -fno-builtin -fno-tree-loop-distribute-patterns -mgeneral-regs-only. */
#include "../page-entry-selected-provider/decoder.h"

static long raw3(long n,long a,long b,long c) {
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
    return result;
}
_Noreturn void li2_decoder_abort(uint32_t reason) {
    char message[48]="LI2_DECODER_FATAL ";
    size_t used=18,count=0; char digits[10];
    do { digits[count++]=(char)('0'+reason%10);reason/=10; } while(reason);
    while(count) message[used++]=digits[--count];
    message[used++]='\n';
    (void)raw3(1,2,(long)message,(long)used);
    (void)raw3(231,125,0,0);
    __builtin_trap();
}
void *memcpy(void *out,const void *input,size_t length) {
    volatile unsigned char *d=out; const volatile unsigned char *s=input;
    for(size_t i=0;i<length;i++) d[i]=s[i];
    return out;
}
void *memset(void *out,int value,size_t length) {
    volatile unsigned char *d=out;
    for(size_t i=0;i<length;i++) d[i]=(unsigned char)value;
    return out;
}
void *memmove(void *out,const void *input,size_t length) {
    volatile unsigned char *d=out; const volatile unsigned char *s=input;
    if((uintptr_t)d<(uintptr_t)s) for(size_t i=0;i<length;i++) d[i]=s[i];
    else for(size_t i=length;i;i--) d[i-1]=s[i-1];
    return out;
}
int memcmp(const void *left,const void *right,size_t length) {
    const volatile unsigned char *a=left,*b=right;
    for(size_t i=0;i<length;i++) if(a[i]!=b[i]) return (int)a[i]-(int)b[i];
    return 0;
}
int bcmp(const void *left,const void *right,size_t length) { return memcmp(left,right,length); }
