#include "tests/persistent_direct_frontier/model.h"
#include "linked_loop_direct.h"
#include "linked_jmp_domain.h"
#include <string.h>
static uint64_t get(const unsigned char *p,unsigned n) {
    uint64_t out=0;for(unsigned i=0;i<n;i++)out|=(uint64_t)p[i]<<(i*8);return out;
}
static unsigned parity(uint64_t v) {
    unsigned n=0;for(unsigned i=0;i<8;i++)n+=(unsigned)(v>>i)&1;return !(n&1);
}
static uint64_t arithmetic(uint64_t flags,uint64_t a,uint64_t b,unsigned bits,int add) {
    uint64_t mask=bits==64?UINT64_MAX:255,sign=UINT64_C(1)<<(bits-1);
    a&=mask;b&=mask;uint64_t r=(add?a+b:a-b)&mask;
    unsigned carry=add?(bits==64?r<a:a+b>mask):a<b;
    unsigned overflow=!!((add?~(a^b):(a^b))&(a^r)&sign);
    return(flags&~LI2_MG_STATUS)|carry|((uint64_t)parity(r)<<2)|((a^b^r)&16)|
        ((uint64_t)(!r)<<6)|((uint64_t)!!(r&sign)<<7)|((uint64_t)overflow<<11);
}
/* Independent x86 predicate table; not li2_dd_arm or emitter branch metadata. */
int dd_model_taken(unsigned c,uint64_t flags) {
    unsigned o=!!(flags&0x800),s=!!(flags&0x80),z=!!(flags&0x40),p=!!(flags&4),b=!!(flags&1);
    const unsigned value[16]={o,!o,b,!b,z,!z,b||z,!b&&!z,s,!s,p,!p,s!=o,s==o,z||(s!=o),!z&&(s==o)};
    return c<16?(int)value[c]:-1;
}
static int load(const struct li2_dd_plan *p,const struct li2_jd_domain_directory *directory,const uint64_t spill[5],unsigned valid,
                unsigned cell_valid,uint64_t at,uint64_t *value,struct dd_model_result *out) {
    if(at>=p->spill && at-p->spill<=32 && !(at&7)) {
        unsigned index=(unsigned)((at-p->spill)/8);
        if(index==4?!cell_valid:!(valid&(1U<<index)))return 1;
        *value=spill[index];return 0;
    }
    if(at==p->binding.directory+8) {*value=directory->count;return 0;}
    if(at>=p->binding.directory+32) {
        uint64_t offset=at-p->binding.directory-32,index=offset/32;
        if(index>=directory->count || index>=LI2_JD_DOMAIN_HEADS)return 1;
        if(offset%32==0) {*value=directory->row[index].pc;++out->row_reads;return 0;}
        if(offset%32==8) {*value=directory->row[index].generated;return 0;}
    }
    return 1;
}
int dd_model_run(const struct li2_dd_plan *p,const struct li2_jd_domain_directory *directory,const uint64_t original[16],uint64_t original_flags,
                 struct dd_model_result *out) {
    uint64_t r[16],spill[5]={0xdead,0xbeef,0x1234,0x5678,UINT64_MAX},flags=original_flags,pc=p->generated;
    unsigned valid=0,cell_valid=0;memcpy(r,original,sizeof r);memset(out,0,sizeof *out);
    while(++out->steps<=2048) {
        if(pc<p->generated || pc-p->generated>=p->record.image_bytes)return 1;
        unsigned offset=(unsigned)(pc-p->generated);const struct li2_mg_boundary *m=0;
        for(unsigned i=0;i<p->record.boundaries;i++)if(p->record.boundary[i].offset==offset) {m=&p->record.boundary[i];out->visited|=UINT64_C(1)<<i;}
        if(!m || m->spill_valid!=valid || m->phase!=(cell_valid?LI2_DD_CELL_READY:LI2_DD_BEFORE))return 2;
        struct li2_dd_recovered recovered;
        if(li2_ld_recover(p,pc,r,flags,spill,&recovered) || !recovered.complete ||
           recovered.phase!=LI2_DD_BEFORE || recovered.original_pc!=p->original.decoded.pc ||
           memcmp(recovered.gpr,original,sizeof r) || recovered.flags!=original_flags)return 3;
        ++out->recoveries;
        if(li2_ld_recover(p,pc,r,flags|UINT64_C(0x10000),spill,&recovered) ||
           recovered.flags!=(original_flags|UINT64_C(0x10000)))return 4;
        const unsigned char *b=p->image+offset;unsigned n=m->length,k=0,rex=0;
        if(b[k]>=0x40 && b[k]<=0x4f)rex=b[k++];
        unsigned op=b[k++];uint64_t next=pc+n;
        if(op==0x9f)r[0]=(r[0]&~UINT64_C(0xff00))|(((flags&0xd5)|2)<<8);
        else if(op==0x9e)flags=(flags&~UINT64_C(0xd5))|((r[0]>>8)&0xd5);
        else if(op==0x04) {
            if(k>=n)return 5;unsigned imm=b[k++];
            flags=arithmetic(flags,r[0]&255,imm,8,1);r[0]=(r[0]&~UINT64_C(255))|((r[0]+imm)&255);
        } else if(op>=0xb8 && op<=0xbf) {
            if(!(rex&8) || n-k!=8)return 6;
            r[op-0xb8+((rex&1)?8:0)]=get(b+k,8);k+=8;
        } else if(op==0xe9) {
            if(n-k!=4)return 7;next+=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
            if(offset==p->record.miss_offset) {
                if(k!=n || next!=p->original.decoded.pc || cell_valid ||
                   memcmp(r,original,sizeof r) || flags!=original_flags)return 8;
                out->target=next;out->miss=1;return 0;
            }
            if(p->original.flow==LI2_REGION_JCC && p->original.external_mask!=3 && offset==6) {
                unsigned arm=dd_model_taken(p->original.condition,original_flags)?0:1;
                if((p->original.external_mask&(1U<<arm)) || next!=p->internal[arm] || k!=n || valid || cell_valid ||
                   memcmp(r,original,sizeof r) || flags!=original_flags)return 30;
                out->target=next;out->internal=1;return 0;
            }
        } else if(op==0x0f) {
            if(k>=n)return 9;unsigned second=b[k++];
            if(second==0x90) {
                if(k>=n || b[k++]!=0xc0)return 10;r[0]=(r[0]&~UINT64_C(255))|((flags>>11)&1);
            } else if(second>=0x80 && second<=0x8f) {
                if(n-k!=4)return 11;int take=dd_model_taken(second-0x80,flags);
                if(take)next+=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
            } else return 12;
        } else if(op==0x81 || op==0xc1) {
            if(!(rex&8) || k>=n)return 13;
            unsigned modrm=b[k++],operation=(modrm>>3)&7,reg=(modrm&7)+((rex&1)?8:0);
            if(modrm>>6!=3)return 14;
            if(op==0x81) {
                if(n-k!=4 || (operation!=0 && operation!=5 && operation!=7))return 15;
                uint64_t value=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
                flags=arithmetic(flags,r[reg],value,64,operation==0);
                if(operation==0)r[reg]+=value;else if(operation==5)r[reg]-=value;
            } else {
                if(operation!=4 || n-k!=1 || b[k]!=5)return 16;++k;
                uint64_t old=r[reg];r[reg]<<=5;
                /* OF/AF are undefined for this shift. Pick adversarial values;
                   the original six arithmetic bits must still reconstruct. */
                flags=(flags&~LI2_MG_STATUS)|((old>>(64-5))&1)|((uint64_t)parity(r[reg])<<2)|
                    ((flags^16)&16)|((uint64_t)!r[reg]<<6)|(r[reg]>>63<<7)|((flags^0x800)&0x800);
            }
        } else if(op==0x89 || op==0x8b || op==0x3b || op==0x03 || op==0xff) {
            if(k>=n)return 17;unsigned modrm=b[k++],mod=modrm>>6;
            unsigned reg=((modrm>>3)&7)+((rex&4)?8:0),rm=(modrm&7)+((rex&1)?8:0);
            int memory=mod!=3;uint64_t at=0,value=0;
            if(memory) {
                if(mod==0 && (modrm&7)==5) {
                    if(n-k!=4)return 18;at=pc+n+(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
                } else if(mod==1 && (modrm&7)!=4) {
                    if(n-k!=1)return 19;at=r[rm]+(uint64_t)(int64_t)(int8_t)b[k++];
                } else return 20;
            }
            if(op==0xff) {
                if(offset==p->record.miss_offset) {
                    if(p->record.version!=LI2_LD_VERSION || rex || modrm!=0x25 || !memory || n!=6 ||
                       at!=pc+6 || offset+14>p->record.image_bytes || cell_valid ||
                       memcmp(r,original,sizeof r) || flags!=original_flags || k!=n)return 31;
                    value=get(p->image+offset+6,8);
                    if(value!=p->original.decoded.pc)return 32;
                    out->target=value;out->miss=1;return 0;
                }
                if(rex || modrm!=0x25 || !memory || offset!=p->record.hit_offset ||
                   load(p,directory,spill,valid,cell_valid,at,&value,out) || at!=p->spill+32 ||
                   memcmp(r,original,sizeof r) || flags!=original_flags || k!=n)return 21;
                out->target=value;out->hit=1;return 0;
            }
            if(!(rex&8))return 22;
            if(op==0x89) {
                if(memory) {
                    if(at<p->spill || at-p->spill>32 || (at&7))return 23;
                    unsigned i=(unsigned)((at-p->spill)/8);spill[i]=r[reg];
                    if(i==4) { if(cell_valid)return 24;cell_valid=1;++out->cell_writes; }
                    else valid|=1U<<i;
                } else r[rm]=r[reg];
            } else if(op==0x8b) {
                if(!memory || load(p,directory,spill,valid,cell_valid,at,&value,out))return 25;r[reg]=value;
            } else {
                if(memory) { if(load(p,directory,spill,valid,cell_valid,at,&value,out))return 26; }
                else value=r[rm];
                flags=arithmetic(flags,r[reg],value,64,op==0x03);
                if(op==0x03)r[reg]+=value;
            }
        } else return 27;
        if(k!=n)return 28;pc=next;
    }
    return 29;
}
