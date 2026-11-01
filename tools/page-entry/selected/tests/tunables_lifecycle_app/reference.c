/* Independent literal original-instruction reference, not a decoder/chooser
   result. Expected instruction counts are static obligations until executed. */
#include "fixture.h"
const uintptr_t lc_source_page[LC_PLACEMENTS]={UINT64_C(0x4000000),UINT64_C(0x700000000000)};
const unsigned lc_entry[LC_CASES]={512,256},lc_steps[LC_CASES]={50,42};
const unsigned lc_a_back[LC_CASES]={3,2},lc_a_to_b[LC_CASES]={3,2};
const unsigned lc_base_offset=512,lc_b_offset=256,lc_cancel_offset=19,lc_c_offset=23,lc_stub_offset=29;
const int32_t lc_predecessor_offset=-5;
/* A0..18 is the loop. A19 is an unsupported m16 store; C starts at23.
   A's backward JE targets B before A in the same actual source pair. */
const unsigned char lc_a_template[35]={
    0x48,0x83,0xe9,0x01, 0x48,0x83,0xf9,0x02,
    0x0f,0x84,0xf2,0xfe,0xff,0xff, 0x48,0x85,0xc9, 0x75,0xed,
    0x66,0x89,0x4f,0x08, 0x49,0x83,0xea,0x01, 0x75,0xfa,
    0xff,0x25,0,0,0,0
};
const unsigned char lc_b_template[15]={
    0x4c,0x89,0x0f, 0x49,0x83,0xe9,0x01, 0x4c,0x89,0xc9,
    0xe9,0xf1,0x00,0x00,0x00
};
void lc_inputs(struct ua_live *s,unsigned char data[UA_DATA]) {
    for(unsigned i=0;i<UA_DATA;i++)data[i]=(unsigned char)(1+(17U*i)%255U);
    for(unsigned i=0;i<16;i++)s->g[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    s->g[1]=4;s->g[7]=LC_DATA;s->g[9]=5;s->g[10]=3;s->flags=UINT64_C(0xad7);
}
void lc_model_init(struct lc_model *m,const struct ua_live *s,const unsigned char data[UA_DATA],uintptr_t a,uintptr_t endpoint,unsigned mode) {
    for(unsigned i=0;i<16;i++)m->g[i]=s->g[i];
    for(unsigned i=0;i<UA_DATA;i++)m->data[i]=data[i];
    m->flags=s->flags;m->a=a;m->b=a-256;m->endpoint=endpoint;m->pc=(mode?m->b:m->a)-5;
    m->a_back=m->a_to_b=m->b_to_a=m->c_back=m->stores64=m->stores16=0;
}
static unsigned parity(uint64_t v) {
    unsigned p=0;for(unsigned i=0;i<8;i++)p^=(unsigned)(v>>i)&1U;return p^1U;
}
static uint64_t sub(uint64_t a,uint64_t b,uint64_t *f) {
    uint64_t v=a-b;
    *f=(*f&~UINT64_C(0x8d5))|(uint64_t)(a<b)|((uint64_t)parity(v)<<2)|((a^b^v)&0x10)|
        ((uint64_t)(v==0)<<6)|((v>>63)<<7)|(((a^b)&(a^v)&UINT64_C(0x8000000000000000))?UINT64_C(0x800):0);
    return v;
}
static int store(struct lc_model *m,uint64_t address,uint64_t value,unsigned width) {
    if(address<LC_DATA || address-LC_DATA>UA_DATA-width)return 0;
    for(unsigned i=0;i<width;i++)m->data[address-LC_DATA+i]=(unsigned char)(value>>(8*i));
    return 1;
}
int lc_advance(struct lc_model *m,uint64_t *undefined) {
    *undefined=0;
    if(m->pc==m->a-5){m->pc=m->a;return 1;}
    if(m->pc==m->b-5){m->pc=m->b;return 1;}
    if(m->pc==m->a+29){m->pc=m->endpoint;return 1;}
    if(m->pc>=m->b&&m->pc<m->b+15) {
        switch((unsigned)(m->pc-m->b)) {
        case 0:if(!store(m,m->g[7],m->g[9],8))return 0;++m->stores64;m->pc+=3;break;
        case 3:m->g[9]=sub(m->g[9],1,&m->flags);m->pc+=4;break;
        case 7:m->g[1]=m->g[9];m->pc+=3;break;
        case 10:++m->b_to_a;m->pc=m->a;break;
        default:return 0;
        }
        return 1;
    }
    if(m->pc<m->a||m->pc>=m->a+29)return 0;
    switch((unsigned)(m->pc-m->a)) {
    case 0:m->g[1]=sub(m->g[1],1,&m->flags);m->pc+=4;break;
    case 4:(void)sub(m->g[1],2,&m->flags);m->pc+=4;break;
    case 8:if(m->flags&0x40){++m->a_to_b;m->pc=m->b;}else m->pc+=6;break;
    case 14:m->flags=(m->flags&~UINT64_C(0x8c5))|((uint64_t)parity(m->g[1])<<2)|
        ((uint64_t)(m->g[1]==0)<<6)|((m->g[1]>>63)<<7);*undefined=0x10;m->pc+=3;break;
    case 17:if(!(m->flags&0x40)){++m->a_back;m->pc=m->a;}else m->pc+=2;break;
    case 19:if(!store(m,m->g[7]+8,m->g[1],2))return 0;++m->stores16;m->pc+=4;break;
    case 23:m->g[10]=sub(m->g[10],1,&m->flags);m->pc+=4;break;
    case 27:if(!(m->flags&0x40)){++m->c_back;m->pc=m->a+23;}else m->pc+=2;break;
    default:return 0;
    }
    return 1;
}
