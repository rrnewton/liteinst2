#include "model.h"
#include <string.h>
static uint64_t get(const unsigned char *p,unsigned n){uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;}
static unsigned parity(uint64_t x){unsigned n=0;for(unsigned i=0;i<8;i++)n+=(unsigned)(x>>i)&1;return !(n&1);}
static uint64_t flags_arithmetic(uint64_t old,uint64_t a,uint64_t b,unsigned bits,int add){
    uint64_t mask=bits==64?UINT64_MAX:255,sign=UINT64_C(1)<<(bits-1);a&=mask;b&=mask;
    uint64_t r=(add?a+b:a-b)&mask;
    unsigned carry=add?(bits==64?r<a:a+b>mask):a<b;
    unsigned overflow=(unsigned)(((add?~(a^b):(a^b))&(a^r)&sign)!=0);
    return(old&~LI2_AG_STATUS)|carry|((uint64_t)parity(r)<<2)|((a^b^r)&16)|((uint64_t)(!r)<<6)|((uint64_t)!!(r&sign)<<7)|((uint64_t)overflow<<11);
}
/* One byte-address space. Private spill writes and all subsequent reads
   alias by numeric address; no immutable stand-in for a guest operand. */
struct memory { unsigned char spill[32],guest[32];const struct li2_ag_plan *p;const struct model_input *in; };
static int byte(struct memory *m,uint64_t at,int write,unsigned char **out){
    if(at>=m->p->spill && at-m->p->spill<32){*out=m->spill+(at-m->p->spill);return 0;}
    if(at>=m->p->table.address && at-m->p->table.address<sizeof m->p->table){
        if(write)return 1;*out=(unsigned char *)&m->p->table+(at-m->p->table.address);return 0;
    }
    if(at<m->in->base || at-m->in->base>=32)return 1;
    unsigned i=(unsigned)(at-m->in->base);uint32_t bit=UINT32_C(1)<<i;
    if(!(m->in->readable&bit) || (write && !(m->in->writable&bit)))return 1;
    *out=m->guest+i;return 0;
}
static int load(struct memory *m,uint64_t at,uint64_t *out){
    unsigned char *p;*out=0;
    for(unsigned i=0;i<8;i++){if(at>UINT64_MAX-i || byte(m,at+i,0,&p))return 1;*out|=(uint64_t)*p<<(8*i);}return 0;
}
static int store(struct memory *m,uint64_t at,uint64_t value){
    unsigned char *p[8];
    for(unsigned i=0;i<8;i++)if(at>UINT64_MAX-i || byte(m,at+i,1,&p[i]))return 1;
    for(unsigned i=0;i<8;i++)*p[i]=(unsigned char)(value>>(8*i));return 0;
}
static void finish(struct memory *m,struct model_result *out){
    memcpy(out->memory,m->guest,32);for(unsigned i=0;i<4;i++)out->spill[i]=get(m->spill+8*i,8);
    for(unsigned i=0;i<8;i++){unsigned char *p;
        if(m->in->base<=UINT64_MAX-i && !byte(m,m->in->base+i,0,&p)){out->resolved[i]=*p;out->resolved_mask|=1U<<i;}
    }
}
static int operand(const unsigned char *b,unsigned n,unsigned *at,unsigned rex,const uint64_t r[16],uint64_t next,uint64_t *ea,unsigned *reg,unsigned *rm,int *memory){
    if(*at>=n)return 1;unsigned m=b[(*at)++],mod=m>>6;*reg=((m>>3)&7)|((rex&4)?8:0);*rm=(m&7)|((rex&1)?8:0);*memory=mod!=3;
    if(mod==3)return 0;
    uint64_t base=0,index=0;unsigned displacement=mod==1?1:mod==2?4:0;
    if((m&7)==4){
        if(*at>=n)return 1;unsigned s=b[(*at)++],ix=((s>>3)&7)|((rex&2)?8:0),br=(s&7)|((rex&1)?8:0);
        if(ix!=4)index=r[ix]<<(s>>6);
        if(mod==0 &&(s&7)==5)displacement=4;else base=r[br];
    }else if(mod==0 && (m&7)==5){base=next;displacement=4;}else base=r[*rm];
    if(displacement>n-*at)return 1;
    int64_t d=displacement==1?(int8_t)b[*at]:displacement==4?(int32_t)get(b+*at,4):0;*at+=displacement;
    *ea=base+index+(uint64_t)d;return 0;
}
int model_run(const struct li2_ag_plan *p,const uint64_t original[16],uint64_t initial_flags,const struct model_input *in,struct model_result *out){
    uint64_t r[16],spill[4],flags=initial_flags,committed_flags=initial_flags;
    struct memory memory={.p=p,.in=in};memcpy(memory.guest,in->bytes,32);memset(memory.spill,0xa5,32);
    memcpy(r,original,sizeof r);memset(out,0,sizeof *out);uint64_t pc=p->generated;
    while(++out->steps<=4096){
        if(pc==p->successor){finish(&memory,out);return out->writes==1 && !out->rejected?0:1;}
        if(pc<p->generated || pc-p->generated>=p->image_bytes)return 2;
        const struct li2_ag_boundary *map=0;for(unsigned i=0;i<p->boundaries;i++)if(p->boundary[i].offset==pc-p->generated){map=&p->boundary[i];break;}
        if(!map)return 3;
        for(unsigned i=0;i<4;i++)spill[i]=get(memory.spill+8*i,8);
        struct li2_ag_recovered recovered;
        if(li2_ag_recover(p,pc,r,flags,spill,&recovered) || !recovered.complete ||
           memcmp(recovered.gpr,original,sizeof r) || recovered.flags!=committed_flags ||
           recovered.original_pc!=(out->writes?p->original.tf.next_pc:p->original.tf.pc) ||
           (out->writes && recovered.phase!=LI2_AG_AFTER))return 4;
        ++out->recoveries;
        /* A fault's actual RF remains raw while the saved arithmetic state is recovered. */
        if(li2_ag_recover(p,pc,r,flags|UINT64_C(0x10000),spill,&recovered) || recovered.flags!=(committed_flags|UINT64_C(0x10000)))return 5;
        unsigned offset=(unsigned)(pc-p->generated),n=map->length,k=0;const unsigned char *b=p->image+offset;
        unsigned rex=0;if(b[0]>=0x40 && b[0]<=0x4f)rex=b[k++];unsigned op=b[k++];uint64_t next=pc+n;
        if(op==0x9f){r[0]=(r[0]&~UINT64_C(0xff00))|(((flags&0xd5)|2)<<8);}
        else if(op==0x9e){flags=(flags&~UINT64_C(0xd5))|((r[0]>>8)&0xd5);}
        else if(op==0x04){if(k>=n)return 6;unsigned imm=b[k++];flags=flags_arithmetic(flags,r[0]&255,imm,8,1);r[0]=(r[0]&~UINT64_C(255))|((r[0]+imm)&255);}
        else if(op==0xe9){if(n-k!=4)return 7;next+=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;}
        else if(op==0x0f){
            if(k>=n)return 8;unsigned second=b[k++];
            if(second==0x90){if(k>=n || b[k++]!=0xc0)return 9;r[0]=(r[0]&~UINT64_C(255))|((flags>>11)&1);}
            else if(second==0x0b){if(offset!=p->reject_offset || out->writes)return 10;out->rejected=1;finish(&memory,out);return k==n?0:11;}
            else if(second==0x83 || second==0x84 || second==0x86){
                if(n-k!=4)return 12;int take=second==0x83?!(flags&1):second==0x84?!!(flags&64):!!(flags&(1|64));
                if(take)next+=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
            }else return 13;
        }else if(op>=0xb8 && op<=0xbf){if(!(rex&8) || n-k!=8)return 14;r[op-0xb8+((rex&1)?8:0)]=get(b+k,8);k+=8;}
        else if(op==0x89 || op==0x8b || op==0x8d || op==0x3b || op==0x85 || op==0x01){
            uint64_t ea=0,v=0;unsigned reg=0,rm=0;int is_memory=0;
            if(operand(b,n,&k,rex,r,pc+n,&ea,&reg,&rm,&is_memory))return 15;
            unsigned width=rex&8?8:4;
            if(op==0x8d){if(!is_memory || width!=8)return 16;r[reg]=ea;}
            else if(op==0x85){if(is_memory)return 17;v=r[reg]&r[rm];flags=(flags&~LI2_AG_STATUS)|((uint64_t)parity(v)<<2)|((flags^16)&16)|((uint64_t)(!v)<<6)|((v>>63)<<7);}
            else if(op==0x3b){if(is_memory){if(load(&memory,ea,&v))return 18;}else v=r[rm];flags=flags_arithmetic(flags,r[reg],v,64,0);}
            else if(op==0x8b){if(!is_memory || load(&memory,ea,&v))return 19;r[reg]=v;}
            else{
                if(!is_memory)return 20;
                v=r[reg];
                if(op==0x01){
                    if(offset!=p->rmw_offset || out->writes || width!=8 || map->phase!=LI2_AG_RMW || memcmp(r,original,sizeof r) || flags!=initial_flags)return 22;
                    out->first=ea;uint64_t old;
                    if(load(&memory,ea,&old)){out->fault=1;finish(&memory,out);return 0;}
                    uint64_t result=old+v;
                    if(store(&memory,ea,result)){out->fault=2;finish(&memory,out);return 0;}
                    flags=flags_arithmetic(flags,old,v,64,1);committed_flags=flags;
                    out->value=result;out->flags=flags;out->width=8;++out->writes;
                }else{
                    if(op!=0x89 || width!=8 || ea<p->spill || ea-p->spill>24 || (ea&7) || store(&memory,ea,v))return 23;
                }
            }
        }else return 24;
        if(k!=n)return 25;pc=next;
    }
    return 26;
}
