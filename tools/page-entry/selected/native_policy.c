#include "native_policy.h"

/* These legacy opcode cores are invariant across 16/32/64-bit decoding.
   Prefixes can change validity, size or the selected operation; they cannot
   remove its core. Blocking the complete 0F C7 group includes every ModRM
   form of RDRAND/RDSEED/RDPID, including unavailable CPU features. */
static unsigned core(const unsigned char *p,size_t n) {
    if(n<2)return 0;
    if(p[0]==0xcd && p[1]==0x80)return LI2_NATIVE_BLOCK_SELECTED;
    if(p[0]==0xc7 && p[1]==0xf8)return LI2_NATIVE_BLOCK_TRANSACTION;
    if(p[0]==0xc6 && p[1]==0xf8)return LI2_NATIVE_BLOCK_TRANSACTION;
    if(p[0]!=0x0f)return 0;
    switch(p[1]) {
    case 0xa2: case 0x31: case 0x05: case 0x34: case 0xc7:
        return LI2_NATIVE_BLOCK_SELECTED;
    /* Whole groups deliberately include harmless operations: RDTSCP, PKRU,
       XSAVE restore, CET writes, user interrupts, enclave/VM/domain exits,
       RTM end, GETSEC, SYSRET/SYSEXIT and RSM cannot pass this profile. */
    case 0x01: case 0xae: case 0x07: case 0x35: case 0x37: case 0xaa:
        return LI2_NATIVE_BLOCK_STATE;
    case 0x38:
        if(n>=3 && (p[2]==0xf5 || p[2]==0xf6))return LI2_NATIVE_BLOCK_STATE;
        break;
    default: break;
    }
    return 0;
}
static int prefix(unsigned char b) {
    return (b>=0x40 && b<=0x4f) || b==0x66 || b==0x67 || b==0xf0 ||
        b==0xf2 || b==0xf3 || b==0x26 || b==0x2e || b==0x36 ||
        b==0x3e || b==0x64 || b==0x65;
}
/* D1 is Group-2 rotate/shift-by-one in every supported decode mode, including
   the redundant /6 SAL encoding. No D1 form permits LOCK or HLE. This proves
   only the absence of HLE for one prefix candidate, not instruction validity:
   an addressing SIB/displacement may still be incomplete. Keep an opcode and
   ModRM inside that candidate's 15-byte envelope before using this fact. */
static int lock_d1_nontransactional(const unsigned char *p,size_t n,
                                   size_t first,size_t opcode) {
    return opcode<n && n-opcode>=2 && opcode>=first && opcode-first<=13 &&
        p[opcode]==0xd1;
}
unsigned li2_native_policy(const unsigned char *bytes,size_t length) {
    unsigned result=0;
    for(size_t i=0;i<length;i++) {
        result|=core(bytes+i,length-i);
        /* HLE also has implicit-lock XCHG and release MOV encodings. Walk
           possible prefix runs in every mode, conservatively treating REX
           bytes as prefixes even where they would be legacy INC/DEC. */
        if(bytes[i]!=0xf2 && bytes[i]!=0xf3)continue;
        size_t j=i+1,limit=length-i<15?length:i+15;
        unsigned lock_after=0;
        for(;j<limit && prefix(bytes[j]);j++)
            if(bytes[j]==0xf0)lock_after=1;
        if(lock_after && !lock_d1_nontransactional(bytes,length,i,j))
            result|=LI2_NATIVE_BLOCK_TRANSACTION;
        if(j<limit && (bytes[j]==0x86 || bytes[j]==0x87 ||
           (bytes[i]==0xf3 && (bytes[j]==0x88 || bytes[j]==0x89 ||
                             bytes[j]==0xc6 || bytes[j]==0xc7))))
            result|=LI2_NATIVE_BLOCK_TRANSACTION;
        /* LOCK can precede the acquire/release prefix. */
        for(size_t k=i;k && i-k<14 && prefix(bytes[k-1]);k--)
            if(bytes[k-1]==0xf0 && !lock_d1_nontransactional(bytes,length,k-1,j))
                result|=LI2_NATIVE_BLOCK_TRANSACTION;
    }
    return result;
}
