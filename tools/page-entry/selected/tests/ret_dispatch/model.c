#include "model.h"
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
static int load(const struct li2_rd_plan *p,const struct li2_jd_domain_directory *directory,
                const struct li2_rd_window *window,const uint64_t spill[6],unsigned valid,
                unsigned cell_valid,unsigned target_valid,uint64_t at,uint64_t *value,
                struct rd_model_result *out) {
    if(at>=p->spill && at-p->spill<=40 && !(at&7)) {
        unsigned index=(unsigned)((at-p->spill)/8);
        if(index==5?!target_valid:index==4?!cell_valid:!(valid&(1U<<index)))return 1;
        *value=spill[index];return 0;
    }
    if(at==p->binding.window+24) {*value=window->first;return 0;}
    if(at==p->binding.window+32) {*value=window->end;return 0;}
    if(at==p->binding.directory+8) {*value=directory->count;return 0;}
    if(at>=p->binding.directory+32) {
        uint64_t offset=at-p->binding.directory-32,index=offset/32;
        if(index>=directory->count || index>=LI2_JD_DOMAIN_HEADS)return 1;
        if(offset%32==0) {*value=directory->row[index].pc;++out->row_reads;return 0;}
        if(offset%32==8) {*value=directory->row[index].generated;return 0;}
    }
    return 1;
}
static int recovered(const struct li2_rd_recovered *got,const uint64_t expected[16],
                     uint64_t flags,uint64_t pc,uint64_t rsp,uint64_t target,unsigned phase,unsigned loaded) {
    return !got->complete || got->phase!=phase || got->original_pc!=pc || got->original_rsp!=rsp ||
        got->target_valid!=loaded || got->target!=(loaded?target:0) || got->reserved ||
        memcmp(got->gpr,expected,16*sizeof(uint64_t)) || got->flags!=flags;
}
int rd_model_run(const struct li2_rd_plan *p,const struct li2_jd_domain_directory *directory,
                 const struct li2_rd_window *window,const uint64_t original[16],uint64_t original_flags,
                 uint64_t guest_word,unsigned readable,struct rd_model_result *out) {
    uint64_t r[16],words[6]={0xdead,0xbeef,0x1234,0x5678,UINT64_MAX,UINT64_MAX};
    uint64_t flags=original_flags,pc=p->generated,stack_word=guest_word;
    unsigned valid=0,cell_valid=0,target_valid=0,loaded=0,committed=0;
    memcpy(r,original,sizeof r);memset(out,0,sizeof *out);out->original_rsp=original[4];
    while(++out->steps<=2048) {
        if(pc<p->generated || pc-p->generated>=p->record.image_bytes)return 1;
        unsigned offset=(unsigned)(pc-p->generated);const struct li2_mg_boundary *m=0;
        for(unsigned i=0;i<p->record.boundaries;i++)if(p->record.boundary[i].offset==offset)m=&p->record.boundary[i];
        unsigned phase=committed?LI2_RD_COMMITTED:offset==p->record.commit_offset?LI2_RD_COMMIT:
            cell_valid?LI2_RD_CELL_READY:target_valid?LI2_RD_SAVED:loaded?LI2_RD_LOADED:
            offset==p->record.load_offset?LI2_RD_LOAD:LI2_RD_BEFORE;
        if(!m || m->spill_valid!=valid || m->phase!=phase)return 2;
        uint64_t expected[16];memcpy(expected,original,sizeof expected);if(committed)expected[4]+=8;
        struct li2_rd_recovered state;
        if(li2_rd_recover(p,pc,r,flags,words,&state) ||
           recovered(&state,expected,original_flags,p->original.decoded.pc,original[4],guest_word,phase,loaded))return 3;
        ++out->recoveries;
        /* Generated target is not recovery authority. Target bytes are ignored
           until initialized; afterward their exact saved value is required. */
        for(unsigned i=0;i<6;i++)if(i==4 || (i==5 && !target_valid) || (i<4 && !(m->dirty&(1U<<i)))) {
            uint64_t poison[6];memcpy(poison,words,sizeof poison);poison[i]^=UINT64_MAX;
            if(li2_rd_recover(p,pc,r,flags,poison,&state) ||
               recovered(&state,expected,original_flags,p->original.decoded.pc,original[4],guest_word,phase,loaded))return 4;
        }
        if(target_valid) {
            uint64_t poison[6];memcpy(poison,words,sizeof poison);poison[5]^=1;
            if(li2_rd_recover(p,pc,r,flags,poison,&state) ||
               recovered(&state,expected,original_flags,p->original.decoded.pc,original[4],guest_word^1,phase,loaded))return 43;
        }
        if(li2_rd_recover(p,pc,r,flags|UINT64_C(0x10000),words,&state) ||
           recovered(&state,expected,original_flags|UINT64_C(0x10000),p->original.decoded.pc,original[4],guest_word,phase,loaded))return 5;
        const unsigned char *b=p->image+offset;unsigned n=m->length,k=0,rex=0;
        if(b[k]>=0x40 && b[k]<=0x4f)rex=b[k++];
        unsigned op=b[k++];uint64_t next=pc+n;
        if(op==0x9f)r[0]=(r[0]&~UINT64_C(0xff00))|(((flags&0xd5)|2)<<8);
        else if(op==0x9e)flags=(flags&~UINT64_C(0xd5))|((r[0]>>8)&0xd5);
        else if(op==0x04) {
            if(k>=n)return 6;unsigned imm=b[k++];
            flags=arithmetic(flags,r[0]&255,imm,8,1);r[0]=(r[0]&~UINT64_C(255))|((r[0]+imm)&255);
        } else if(op>=0xb8 && op<=0xbf) {
            if(!(rex&8) || n-k!=8)return 7;
            r[op-0xb8+((rex&1)?8:0)]=get(b+k,8);k+=8;
        } else if(op==0xe9) {
            if(n-k!=4)return 8;next+=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
            if(k!=n || committed || cell_valid || out->stack_writes || memcmp(r,original,sizeof r) || flags!=original_flags)return 9;
            out->target=next;out->final_rsp=r[4];
            if(offset==p->record.miss_offset) {
                if(next!=p->original.decoded.pc || loaded || target_valid || out->load_attempts || out->guest_reads)return 10;
                out->before_miss=1;return 0;
            }
            if(offset!=p->record.loaded_miss_offset || next!=p->binding.loaded_miss ||
               !loaded || !target_valid || out->load_attempts!=1 || out->guest_reads!=1 || words[5]!=guest_word)return 11;
            if(li2_rd_recover_loaded_miss(p,next,r,flags,words,&state) ||
               recovered(&state,original,original_flags,p->original.decoded.pc,original[4],guest_word,LI2_RD_LOADED_MISS,1))return 12;
            uint64_t poison[6];memcpy(poison,words,sizeof poison);
            for(unsigned i=0;i<5;i++)poison[i]^=UINT64_MAX;
            if(li2_rd_recover_loaded_miss(p,next,r,flags,poison,&state) ||
               recovered(&state,original,original_flags,p->original.decoded.pc,original[4],guest_word,LI2_RD_LOADED_MISS,1))return 13;
            /* Changing the post-load guest word cannot affect the receipt. */
            if(stack_word!=~guest_word)return 14;
            out->loaded_target=state.target;out->loaded_miss=1;return 0;
        } else if(op==0x0f) {
            if(k>=n)return 15;unsigned second=b[k++];
            if(second==0x90) {
                if(k>=n || b[k++]!=0xc0)return 16;r[0]=(r[0]&~UINT64_C(255))|((flags>>11)&1);
            } else if(second==0x82 || second==0x84 || second==0x87) {
                if(n-k!=4)return 17;int take=second==0x82?!!(flags&1):second==0x84?!!(flags&64):!(flags&65);
                if(take)next+=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
            } else return 18;
        } else if(op==0x81 || op==0xc1) {
            if(!(rex&8) || k>=n)return 19;
            unsigned modrm=b[k++],operation=(modrm>>3)&7,reg=(modrm&7)+((rex&1)?8:0);
            if(modrm>>6!=3)return 20;
            if(op==0x81) {
                if(n-k!=4 || (operation!=0 && operation!=5 && operation!=7))return 21;
                uint64_t value=(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
                flags=arithmetic(flags,r[reg],value,64,operation==0);
                if(operation==0)r[reg]+=value;else if(operation==5)r[reg]-=value;
            } else {
                if(operation!=4 || n-k!=1 || b[k]!=5)return 22;++k;
                uint64_t old=r[reg];r[reg]<<=5;
                flags=(flags&~LI2_MG_STATUS)|((old>>(64-5))&1)|((uint64_t)parity(r[reg])<<2)|
                    ((flags^16)&16)|((uint64_t)!r[reg]<<6)|(r[reg]>>63<<7)|((flags^0x800)&0x800);
            }
        } else if(op==0x8d) {
            if(rex!=0x48 || n!=5 || b[k++]!=0x64 || b[k++]!=0x24 || b[k++]!=8 ||
               offset!=p->record.commit_offset || committed || !cell_valid || !target_valid ||
               !loaded || memcmp(r,original,sizeof r) || flags!=original_flags)return 23;
            r[4]+=8;committed=1;
        } else if(op==0x89 || op==0x8b || op==0x3b || op==0x03 || op==0xff) {
            if(k>=n)return 24;unsigned modrm=b[k++],mod=modrm>>6;
            unsigned reg=((modrm>>3)&7)+((rex&4)?8:0),rm=(modrm&7)+((rex&1)?8:0);
            int memory=mod!=3,guest=0;uint64_t at=0,value=0;
            if(memory) {
                if(mod==0 && (modrm&7)==5) {
                    if(n-k!=4)return 25;at=pc+n+(uint64_t)(int64_t)(int32_t)get(b+k,4);k+=4;
                } else if(mod==1 && (modrm&7)!=4) {
                    if(n-k!=1)return 26;at=r[rm]+(uint64_t)(int64_t)(int8_t)b[k++];
                } else if(mod==0 && (modrm&7)==4) {
                    if(rex!=0x48 || op!=0x8b || n-k!=1 || b[k++]!=0x24 ||
                       offset!=p->record.load_offset || loaded || target_valid || cell_valid ||
                       r[4]<window->first || r[4]>window->end)return 27;
                    at=r[4];guest=1;
                } else return 28;
            }
            if(op==0xff) {
                if(rex || !memory || k!=n || modrm!=0x25 || !committed ||
                   offset!=p->record.transfer_offset || at!=p->spill+32 ||
                   load(p,directory,window,words,valid,cell_valid,target_valid,at,&value,out))return 29;
                uint64_t expected[16];memcpy(expected,original,sizeof expected);expected[4]+=8;
                if(memcmp(r,expected,sizeof r) || flags!=original_flags || words[5]!=guest_word)return 30;
                out->target=value;out->loaded_target=words[5];out->final_rsp=r[4];out->hit=1;return 0;
            }
            if(!(rex&8))return 31;
            if(op==0x89) {
                if(memory) {
                    if(at<p->spill || at-p->spill>40 || (at&7))return 32;
                    unsigned i=(unsigned)((at-p->spill)/8);words[i]=r[reg];
                    if(i==4) { if(cell_valid || !target_valid)return 33;cell_valid=1;++out->cell_writes; }
                    else if(i==5) {if(target_valid || !loaded || words[i]!=guest_word)return 34;target_valid=1;++out->target_writes;}
                    else valid|=1U<<i;
                } else r[rm]=r[reg];
            } else if(op==0x8b) {
                if(!memory)return 35;
                if(guest) {
                    if(++out->load_attempts!=1 || at!=original[4])return 36;
                    if(!readable) {
                        if(out->guest_reads || loaded || target_valid || cell_valid || committed || out->stack_writes)return 37;
                        out->load_fault=1;out->final_rsp=r[4];return 0;
                    }
                    value=stack_word;stack_word=~stack_word;loaded=1;++out->guest_reads;
                } else if(load(p,directory,window,words,valid,cell_valid,target_valid,at,&value,out))return 38;
                r[reg]=value;
            } else {
                if(memory) {if(load(p,directory,window,words,valid,cell_valid,target_valid,at,&value,out))return 39;}
                else value=r[rm];
                flags=arithmetic(flags,r[reg],value,64,op==0x03);if(op==0x03)r[reg]+=value;
            }
        } else return 40;
        if(k!=n)return 41;pc=next;
    }
    return 42;
}
