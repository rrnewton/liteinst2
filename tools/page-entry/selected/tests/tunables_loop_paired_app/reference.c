/* An explicit original-instruction model, independent of all candidate APIs.
   Undefined AF/OF are returned as such, then retained from the actual native
   event by main.c. A future native/owner pair must compare their actual bits
   literally; this model is not permission to mask them from that comparison. */
#include "fixture.h"
#include <stddef.h>

const unsigned lp_entry[LP_CASES]={0,0,23,59,59,18,52};
/* Counts include the real initial E9 in BOTH histories and the genuine
   transparent cut jump for successful cases. A faulting read is not a step. */
const unsigned lp_steps[LP_CASES]={106,25,35,13,13,1,2};
const uintptr_t lp_source_page[LP_PLACEMENTS]={
    UINT64_C(0x4000000),UINT64_C(0x4000000),
    UINT64_C(0x700000000000),UINT64_C(0x700000000000)
};
/* Paired geometry: entry59 remains at offset4081
   in the first page, so unchanged cold {entry_page,next_page} binding can
   cover the entire88-byte interval. No runtime eligibility is widened. */
const unsigned lp_base_offset[LP_PLACEMENTS]={512,4022,512,4022};
const int32_t lp_predecessor_offset=-5;
const unsigned lp_backwards[LP_CASES][6]={
    {1,1,0,1,1,1},{0,0,1,0,0,0},{0,0,0,0,1,0},
    {0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0}
};
const unsigned lp_cuts[LP_CASES][2]={{0,1},{1,0},{0,1},{0,1},{0,1},{0,0},{0,0}};

void lp_inputs(unsigned mode,struct ua_live *s,unsigned char data[UA_DATA]) {
    /* All non-input memory remains a nonzero sentinel and must stay literal. */
    for(unsigned i=0;i<UA_DATA;i++)data[i]=(unsigned char)(1+(17U*i)%255U);
    for(unsigned i=0;i<16;i++)s->g[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    s->flags=UINT64_C(0xad7);
    for(unsigned row=0;row<5;row++) {
        unsigned p=512+128*row;
        data[p-8]=0;data[p]='a';data[p+1]='b';data[p+2]=0;
    }
    data[4096]='a';data[4097]='b';data[4098]='=';data[4099]=0;
    s->g[0]=LP_KEY;s->g[3]=LP_KEY;s->g[6]=LP_ROW;
    s->g[8]=LP_ROW-128;s->g[9]=30;
    if(mode==0) {
        data[512-8]=1;                 /* JNE26 -> 0. */
        data[512+128]=0;               /* JE35 -> 0. */
        data[512+256]='x';             /* JNE65 -> 0. */
        data[512+384+1]=0;             /* JNE86 -> 0. */
        /* Last row "ab": JNE81 ->56, then the genuine cut at88. */
    } else if(mode==1) {
        data[4096]=0;s->g[9]=35;       /* JE61 ->0, then JE12 ->-124. */
    } else if(mode==2) {
        s->g[8]=LP_ROW;
        s->g[9]=UINT64_C(0x89abcdef80000000);
        /* Genuine body entry23 after the flag-preserving E9; ZF=1 keeps JNE26 untaken. MOVSXD must
           discard the dirty upper32 and sign-extend bit31 into R10. */
    } else if(mode==3 || mode==4) {
        data[4097]='=';data[4098]=0;data[513]=0;
        s->g[1]=UINT64_C(0x123456789abcde61);
        s->g[2]=UINT64_C(0xfedcba9876543261);
        if(mode==3)s->flags&=~UINT64_C(0x10);
        /* First body TEST DL and CMP DL,CL must leave every upper bit intact.
           Modes3/4 differ only in the initial AF bit. */
    } else if(mode==5) {
        s->g[8]=LP_GUARD+8;            /* Actual CMP byte[R8-8],0 faults. */
    } else if(mode==6) {
        s->g[0]=LP_GUARD;              /* NOP52 cannot access; MOVZX56 faults. */
    }
}

void lp_model_init(struct lp_model *m,const struct ua_live *s,uintptr_t base,uintptr_t end,unsigned mode) {
    for(unsigned i=0;i<16;i++)m->g[i]=s->g[i];
    m->flags=s->flags;m->entry=base+lp_entry[mode];m->pc=base-5;m->base=base;m->endpoint=end;
    for(unsigned i=0;i<6;i++)m->backward[i]=0;
    m->cut[0]=m->cut[1]=0;
}
static unsigned parity(uint64_t x) {
    unsigned p=0;for(unsigned i=0;i<8;i++)p^=(unsigned)(x>>i)&1U;return p^1U;
}
static uint64_t arithmetic(uint64_t a,uint64_t b,unsigned bits,unsigned sub,uint64_t *f) {
    uint64_t mask=bits==64?UINT64_MAX:UINT64_C(255),sign=UINT64_C(1)<<(bits-1);
    a&=mask;b&=mask;uint64_t v=(sub?a-b:a+b)&mask;
    unsigned carry=sub?a<b:v<a;
    unsigned overflow=(unsigned)(((sub?(a^b):(a^b)^mask)&(a^v)&sign)!=0);
    uint64_t flags=carry|((uint64_t)parity(v)<<2)|((a^b^v)&0x10)|
        ((uint64_t)(v==0)<<6)|((uint64_t)((v&sign)!=0)<<7)|((uint64_t)overflow<<11);
    *f=(*f&~UINT64_C(0x8d5))|flags;return v;
}
static void test_byte(uint64_t a,uint64_t *f,uint64_t *undefined) {
    unsigned v=(unsigned)a&255U;
    *f=(*f&~UINT64_C(0x8c5))|((uint64_t)parity(v)<<2)|((uint64_t)(v==0)<<6)|((uint64_t)(v>>7)<<7);
    *undefined=0x10; /* AF is undefined, never normalized in retained state. */
}
static int byte_at(const unsigned char data[UA_DATA],uint64_t a,uint64_t *out) {
    if(a<LP_DATA || a-LP_DATA>=UA_DATA)return 0;
    *out=data[a-LP_DATA];return 1;
}
static uintptr_t branch(struct lp_model *m,unsigned take,unsigned next,unsigned to,unsigned slot) {
    if(take){m->backward[slot]++;return m->base+to;}
    return m->base+next;
}
int lp_advance(struct lp_model *m,const unsigned char data[UA_DATA],uint64_t *undefined) {
    uint64_t v=0;*undefined=0;
    if(m->pc==m->base-5){m->pc=m->entry;return 1;} /* Original E9, flags/GPR unchanged. */
    if(m->pc==m->base-124 || m->pc==m->base+88){m->pc=m->endpoint;return 1;}
    if(m->pc<m->base || m->pc>=m->base+88)return 0;
    unsigned off=(unsigned)(m->pc-m->base);
    switch(off) {
    case 0:m->g[9]=arithmetic(m->g[9],1,64,0,&m->flags);m->pc+=4;break;
    case 4:m->g[8]=arithmetic(m->g[8],UINT64_C(0xffffffffffffff80),64,1,&m->flags);m->pc+=4;break;
    case 8:(void)arithmetic(m->g[9],37,64,1,&m->flags);m->pc+=4;break;
    case 12:if(m->flags&0x40){m->cut[0]++;m->pc=m->base-124;}else m->pc+=6;break;
    case 18:if(!byte_at(data,m->g[8]-8,&v))return 0;(void)arithmetic(v,0,8,1,&m->flags);m->pc+=5;break;
    case 23:v=m->g[9]&UINT64_C(0xffffffff);
        m->g[10]=v|((v&UINT64_C(0x80000000))?UINT64_C(0xffffffff00000000):0);m->pc+=3;break;
    case 26:m->pc=branch(m,!(m->flags&0x40),28,0,0);break;
    case 28:if(!byte_at(data,m->g[8],&v))return 0;m->g[7]=v;m->pc+=4;break;
    case 32:test_byte(m->g[7],&m->flags,undefined);m->pc+=3;break;
    case 35:m->pc=branch(m,(m->flags&0x40)!=0,37,0,1);break;
    case 37:m->g[5]=m->g[9];m->pc+=3;break;
    case 40:m->g[6]=m->g[8];m->pc+=3;break;
    case 43:m->g[0]=m->g[3];m->pc+=3;break;
    case 46:m->g[1]=(uint32_t)m->g[7];m->pc+=2;break;
    case 48:v=m->g[5];m->g[5]<<=7;
        m->flags=(m->flags&~UINT64_C(0xc5))|((v>>57)&1)|((uint64_t)parity(m->g[5])<<2)|
            ((uint64_t)(m->g[5]==0)<<6)|((m->g[5]>>63)<<7);
        *undefined=0x810;m->pc+=4;break; /* AF/OF undefined for count7. */
    case 52:m->pc+=4;break; /* Canonical NOP has no address read, even guard RAX. */
    case 56:if(!byte_at(data,m->g[0],&v))return 0;m->g[2]=v;m->pc+=3;break;
    case 59:test_byte(m->g[2],&m->flags,undefined);m->pc+=2;break;
    case 61:m->pc=branch(m,(m->flags&0x40)!=0,63,0,2);break;
    case 63:(void)arithmetic(m->g[2],m->g[1],8,1,&m->flags);m->pc+=2;break;
    case 65:m->pc=branch(m,!(m->flags&0x40),67,0,3);break;
    case 67:if(!byte_at(data,m->g[6]+1,&v))return 0;m->g[1]=v;m->pc+=4;break;
    case 71:m->g[6]=arithmetic(m->g[6],1,64,0,&m->flags);m->pc+=4;break;
    case 75:m->g[0]=arithmetic(m->g[0],1,64,0,&m->flags);m->pc+=4;break;
    case 79:test_byte(m->g[1],&m->flags,undefined);m->pc+=2;break;
    case 81:m->pc=branch(m,!(m->flags&0x40),83,56,4);break;
    case 83:if(!byte_at(data,m->g[0],&v))return 0;(void)arithmetic(v,0x3d,8,1,&m->flags);m->pc+=3;break;
    case 86:if(!(m->flags&0x40))m->pc=branch(m,1,88,0,5);
        else {m->cut[1]++;m->pc+=2;}break;
    default:return 0;
    }
    return 1;
}
