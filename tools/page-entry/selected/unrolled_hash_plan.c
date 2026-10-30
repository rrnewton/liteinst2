#include "unrolled_hash.h"

static const unsigned char body[LI2_UNROLLED_HASH_BODY]={
    0x48,0x89,0xd8,0x48,0x83,0xc1,0x01,0x48,0xc1,0xe0,0x05,0x48,
    0x01,0xc3,0x48,0x01,0xd3,0x0f,0xb6,0x11,0x84,0xd2,0x75,0xe8
};
static const uint32_t codes[8]={282,249,381,8,8,2090,271,176};
static const unsigned char lengths[8]={3,4,4,3,3,3,2,2};
static const unsigned char offsets[8]={0,3,7,11,14,17,20,22};
static void zero(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
static int equal(const unsigned char *a,const unsigned char *b,size_t n) {
    for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;
    return 1;
}
static int window(uintptr_t pc,size_t n) {
    return n && n<=4096 && pc<=UINTPTR_MAX-n && (pc&4095U)<=4096U-n;
}
/* Unsigned differences avoid signed overflow at rel32 limits. */
static int displacement(uintptr_t next,uintptr_t target,uint32_t *out) {
    if(target>=next) {
        uintptr_t d=target-next;if(d>UINT32_C(0x7fffffff))return 0;
        *out=(uint32_t)d;
    } else {
        uintptr_t d=next-target;if(d>UINT32_C(0x80000000))return 0;
        *out=0U-(uint32_t)d;
    }
    return 1;
}
static void put32(unsigned char *p,uint32_t d) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(d>>(8*i));
}
static int same32(const unsigned char *p,uint32_t d) {
    for(unsigned i=0;i<4;i++)if(p[i]!=(unsigned char)(d>>(8*i)))return 0;
    return 1;
}
static int geometry(uintptr_t pc,uintptr_t entry) {
    if(!window(pc,LI2_UNROLLED_HASH_SOURCE) || !window(entry,LI2_UNROLLED_HASH_CODE))return 0;
    uint32_t d;
    for(unsigned i=0;i<LI2_UNROLLED_HASH_COPIES;i++)
        if(!displacement(entry+(i+1)*LI2_UNROLLED_HASH_STRIDE,pc+24,&d))return 0;
    return displacement(entry+LI2_UNROLLED_HASH_CODE,pc,&d);
}
static int row(const struct li2_decoded *d,uintptr_t pc,const unsigned char *s) {
    return d->abi_version==1 && !d->reserved && d->pc==pc && d->available==15 &&
        d->length && d->length<=15 && d->next_pc==pc+d->length &&
        equal(d->bytes,s,15) && !d->bytes[15];
}
static int instruction(const struct li2_decoded *d,unsigned i,uintptr_t pc,
                       const unsigned char *s) {
    return row(d,pc,s) && d->decode_status==LI2_VALID && d->code==codes[i] &&
        d->length==lengths[i] && d->kind==LI2_NONE && d->destination==16 &&
        !d->width_bits && d->step_disposition==(i?LI2_STEP_UNSUPPORTED:LI2_STEP_CANDIDATE);
}
static int guard(const struct li2_decoded *d,uintptr_t pc,const unsigned char *s) {
    return row(d,pc,s) && d->decode_status==LI2_VALID && d->code==281 &&
        d->length==2 && d->kind==LI2_NONE && d->destination==16 && !d->width_bits &&
        d->step_disposition==LI2_STEP_CANDIDATE && s[0]==0x89 && s[1]==0xdb;
}
static int shape(const struct li2_unrolled_hash_plan *p) {
    if(p->version!=1 || p->ready!=1 || p->decoder_calls!=9 || p->decoder_result ||
       !geometry(p->pc,p->entry) || p->stop!=p->pc+24 || !equal(p->source,body,24))return 0;
    for(unsigned i=0;i<8;i++)
        if(!instruction(&p->instructions[i],i,p->pc+offsets[i],p->source+offsets[i]))return 0;
    if(!guard(&p->guard,p->stop,p->source+24))return 0;
    uint32_t d;
    for(unsigned i=0;i<LI2_UNROLLED_HASH_COPIES;i++) {
        size_t at=i*LI2_UNROLLED_HASH_STRIDE;
        if(!equal(p->generated+at,body,22) || p->generated[at+22]!=0x0f ||
           p->generated[at+23]!=0x84 ||
           !displacement(p->entry+at+28,p->stop,&d) || !same32(p->generated+at+24,d))return 0;
    }
    return p->generated[1792]==0xe9 && displacement(p->entry+1797,p->pc,&d) &&
        same32(p->generated+1793,d);
}
int li2_unrolled_hash_plan_bytes(uintptr_t pc,const unsigned char *s,size_t n,
                                uintptr_t entry,struct li2_unrolled_hash_plan *out) {
    if(!out)return LI2_UNROLLED_HASH_ARGUMENT;
    zero(out,sizeof(*out));
    if(!s || n!=LI2_UNROLLED_HASH_SOURCE || !window(pc,n))return LI2_UNROLLED_HASH_ARGUMENT;
    out->version=1;out->pc=pc;out->stop=pc+24;out->entry=entry;
    for(size_t i=0;i<n;i++)out->source[i]=s[i];
    if(!equal(s,body,24) || s[24]!=0x89 || s[25]!=0xdb || !geometry(pc,entry))
        return LI2_UNROLLED_HASH_MISS;
    for(unsigned i=0;i<8;i++) {
        out->decoder_calls++;
        out->decoder_result=li2_decoder_decode(pc+offsets[i],s+offsets[i],15,&out->instructions[i]);
        if(out->decoder_result || !instruction(&out->instructions[i],i,pc+offsets[i],s+offsets[i]))
            return LI2_UNROLLED_HASH_DECODE;
    }
    out->decoder_calls++;
    out->decoder_result=li2_decoder_decode(out->stop,s+24,15,&out->guard);
    if(out->decoder_result || !guard(&out->guard,out->stop,s+24))return LI2_UNROLLED_HASH_DECODE;
    uint32_t d;
    for(unsigned i=0;i<LI2_UNROLLED_HASH_COPIES;i++) {
        size_t at=i*LI2_UNROLLED_HASH_STRIDE;
        for(unsigned j=0;j<22;j++)out->generated[at+j]=body[j];
        out->generated[at+22]=0x0f;out->generated[at+23]=0x84;
        if(!displacement(entry+at+28,out->stop,&d))return LI2_UNROLLED_HASH_SHAPE;
        put32(out->generated+at+24,d);
    }
    out->generated[1792]=0xe9;
    if(!displacement(entry+1797,pc,&d))return LI2_UNROLLED_HASH_SHAPE;
    put32(out->generated+1793,d);out->ready=1;
    if(!shape(out)){out->ready=0;return LI2_UNROLLED_HASH_SHAPE;}
    return LI2_UNROLLED_HASH_OK;
}
int li2_unrolled_hash_map_pc(const struct li2_unrolled_hash_plan *p,uintptr_t pc,
                           struct li2_unrolled_hash_pc *out) {
    if(!out)return LI2_UNROLLED_HASH_ARGUMENT;
    zero(out,sizeof(*out));
    if(!p)return LI2_UNROLLED_HASH_ARGUMENT;
    if(!shape(p))return LI2_UNROLLED_HASH_SHAPE;
    if(pc<p->entry || pc>=p->entry+LI2_UNROLLED_HASH_CODE)return LI2_UNROLLED_HASH_MISS;
    size_t at=pc-p->entry;
    unsigned copy,source,length,kind;
    if(at==1792) {
        copy=63;source=22;length=5;kind=LI2_UNROLLED_HASH_FINAL_HEAD_JMP;
    } else {
        copy=(unsigned)(at/LI2_UNROLLED_HASH_STRIDE);
        if(copy>=64)return LI2_UNROLLED_HASH_MISS;
        unsigned offset=(unsigned)(at%LI2_UNROLLED_HASH_STRIDE),index=0;
        while(index<8 && offsets[index]!=offset)index++;
        if(index==8)return LI2_UNROLLED_HASH_MISS;
        source=offset;length=index==7?6:lengths[index];
        kind=index==7?LI2_UNROLLED_HASH_SUBSTITUTED_JZ:LI2_UNROLLED_HASH_COPIED_INSTRUCTION;
    }
    out->version=1;out->copy_index=copy;out->source_offset=source;out->kind=kind;
    out->source_length=source==22?2:length;out->generated_length=length;
    out->original_pc=p->pc+source;out->generated_pc=pc;out->ready=1;
    return LI2_UNROLLED_HASH_OK;
}
