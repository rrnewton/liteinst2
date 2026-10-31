#include "linked_jmp_dispatch.h"
#if !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
#error "distinct resident register-JMP dispatch profile only"
#endif
static void zero(void *p,size_t n) { unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0; }
static void copy(void *p,const void *q,size_t n) { unsigned char *b=p;const unsigned char *a=q;for(size_t i=0;i<n;i++)b[i]=a[i]; }
static int same(const void *p,const void *q,size_t n) { const unsigned char *a=p,*b=q;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1; }
static int address(uint64_t p,size_t n) { return n && p<UINT64_C(0x800000000000) && n<=UINT64_C(0x800000000000)-p; }
static int apart(uint64_t a,size_t an,uint64_t b,size_t bn) { return a+an<=b || b+bn<=a; }
static void put32(unsigned char *p,uint32_t n) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i)); }
static void put64(unsigned char *p,uint64_t n) { for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(8*i)); }
static int disp(uint64_t next,uint64_t target,uint32_t *out) {
    if(target>=next) { uint64_t n=target-next;if(n>UINT32_C(0x7fffffff))return 0;*out=(uint32_t)n; }
    else { uint64_t n=next-target;if(n>UINT32_C(0x80000000))return 0;*out=0U-(uint32_t)n; }
    return 1;
}
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
static int describe(uintptr_t pc,const unsigned char *bytes,size_t n,struct li2_jd_descriptor *out) {
    if(!bytes || !n || n>15 || !address(pc,n))return LI2_JD_ARGUMENT;
    out->version=LI2_JD_VERSION;out->available=(uint32_t)n;
    unsigned prefix=bytes[0]==0x41?1U:0U,length=prefix+2U;
    if(n<length || bytes[prefix]!=0xff || bytes[prefix+1]<0xe0 || bytes[prefix+1]>0xe7)return LI2_JD_FORM;
    unsigned target=(bytes[prefix+1]&7U)+8U*prefix;
    struct li2_decoded expected={.pc=pc,.next_pc=pc+length,.abi_version=1,
        .decode_status=LI2_VALID,.code=765,.kind=LI2_NONE,.destination=16,
        .step_disposition=LI2_STEP_UNSUPPORTED,.available=(uint32_t)n,.length=length};
    copy(expected.bytes,bytes,n);
    struct li2_tf_classification tf={.pc=pc,.next_pc=pc+length,.abi_version=1,
        .policy=1,.code=765,.length=length,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_BRANCH};
    struct li2_write_registers regs={0};
    struct li2_write_footprint actual={0},wanted={.pc=pc,.next_pc=pc+length,
        .abi_version=1,.policy=LI2_WRITE_NONE,.code=765,.length=length};
    if(li2_decoder_decode(pc,bytes,n,&out->decoded) ||
       li2_decoder_tf_classify(pc,bytes,n,&out->tf) ||
       li2_decoder_write_footprint(pc,bytes,n,&regs,&actual))return LI2_JD_DECODER;
    if(!same(&expected,&out->decoded,sizeof expected) || !same(&tf,&out->tf,sizeof tf) ||
       !same(&actual,&wanted,sizeof actual))return LI2_JD_FORM;
    out->target=target;return 0;
}
#else
static int describe(uintptr_t pc,const unsigned char *bytes,size_t n,struct li2_jd_descriptor *out) {
    if(!bytes || !n || n>15 || !address(pc,n))return LI2_JD_ARGUMENT;
    out->version=1;out->available=(uint32_t)n;
    unsigned prefix=bytes[0]==0x41?1U:0U,length=prefix+2U;
    if(n<length || bytes[prefix]!=0xff || bytes[prefix+1]<0xe0 || bytes[prefix+1]>0xe7)return LI2_JD_FORM;
    unsigned target=(bytes[prefix+1]&7U)+8U*prefix;
    struct li2_decoded expected={.pc=pc,.next_pc=pc+length,.abi_version=1,
        .decode_status=LI2_VALID,.code=765,.kind=LI2_NONE,.destination=16,
        .step_disposition=LI2_STEP_UNSUPPORTED,.available=(uint32_t)n,.length=length};
    copy(expected.bytes,bytes,n);
    struct li2_tf_classification tf={.pc=pc,.next_pc=pc+length,.abi_version=1,
        .policy=1,.code=765,.length=length,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_BRANCH};
    struct li2_write_registers regs={0};
    struct li2_write_footprint actual={0},wanted={.pc=pc,.next_pc=pc+length,
        .abi_version=1,.policy=LI2_WRITE_NONE,.code=765,.length=length};
    if(li2_decoder_decode(pc,bytes,n,&out->decoded) ||
       li2_decoder_tf_classify(pc,bytes,n,&out->tf) ||
       li2_decoder_write_footprint(pc,bytes,n,&regs,&actual))return LI2_JD_DECODER;
    if(!same(&expected,&out->decoded,sizeof expected) || !same(&tf,&out->tf,sizeof tf) ||
       !same(&actual,&wanted,sizeof actual))return LI2_JD_FORM;
    out->target=target;return 0;
}
#endif
int li2_jd_describe(uintptr_t pc,const unsigned char *bytes,size_t n,struct li2_jd_descriptor *out) {
    if(!out)return LI2_JD_ARGUMENT;
    zero(out,sizeof *out);int e=describe(pc,bytes,n,out);out->refusal=(uint32_t)e;out->ready=e==0;return e;
}
struct writer { struct li2_jd_plan *p;unsigned valid,dirty,flags,phase;int error; };
static unsigned emit(struct writer *w,const unsigned char *b,unsigned n) {
    struct li2_jd_record *r=&w->p->record;unsigned at=r->image_bytes;
    if(w->error)return at;
    if(!n || n>15 || r->boundaries>=LI2_JD_BOUNDARIES || n>LI2_JD_SLOT_BYTES-at) { w->error=LI2_JD_CAPACITY;return at; }
    r->boundary[r->boundaries++]=(struct li2_mg_boundary){at,n,w->valid,w->dirty,w->flags,w->phase};
    copy(w->p->image+at,b,n);r->image_bytes+=n;return at;
}
static unsigned branch(struct writer *w,unsigned condition) {
    unsigned char b[6]={0x0f,(unsigned char)(0x80+condition),0,0,0,0};
    if(condition==16) { b[0]=0xe9;return emit(w,b,5); }
    return emit(w,b,6);
}
static void patch(struct writer *w,unsigned at,unsigned target) {
    if(w->error)return;
    unsigned n=w->p->image[at]==0xe9?5:6;uint32_t d;
    if(!disp(w->p->generated+at+n,w->p->generated+target,&d)) { w->error=LI2_JD_RELOCATION;return; }
    put32(w->p->image+at+n-4,d);
}
static void spill(struct writer *w,unsigned i,int load) {
    unsigned reg=w->p->record.scratch_regs[i];uint32_t d;
    unsigned char b[7]={(unsigned char)(0x48|((reg>>3)<<2)),(unsigned char)(load?0x8b:0x89),
        (unsigned char)(5|((reg&7)<<3)),0,0,0,0};
    if(!disp(w->p->generated+w->p->record.image_bytes+7,w->p->spill+8*i,&d)) { w->error=LI2_JD_RELOCATION;return; }
    put32(b+3,d);emit(w,b,7);
    if(load)w->dirty&=~(1U<<i);else w->valid|=1U<<i;
}
static void rr(struct writer *w,unsigned opcode,unsigned reg,unsigned rm) {
    unsigned char b[3]={(unsigned char)(0x48|((reg>>3)<<2)|(rm>>3)),(unsigned char)opcode,
        (unsigned char)(0xc0|((reg&7)<<3)|(rm&7))};emit(w,b,3);
}
static void immediate(struct writer *w,unsigned reg,unsigned operation,uint32_t value) {
    unsigned char b[7]={(unsigned char)(0x48|(reg>>3)),0x81,(unsigned char)(0xc0|(operation<<3)|(reg&7)),0,0,0,0};
    put32(b+3,value);emit(w,b,7);
}
static void absolute(struct writer *w,unsigned reg,uintptr_t value) {
    unsigned char b[10]={(unsigned char)(0x48|(reg>>3)),(unsigned char)(0xb8+(reg&7)),0,0,0,0,0,0,0,0};
    put64(b+2,value);emit(w,b,10);
}
static void restore(struct writer *w) {
    static const unsigned char add[]={0x04,0x7f},sahf[]={0x9e};
    emit(w,add,2);w->flags=LI2_MG_AH_PHYSICAL_OF;
    emit(w,sahf,1);w->flags=LI2_MG_PHYSICAL;
    for(unsigned i=1;i<4;i++)spill(w,i,1);
    spill(w,0,1);
}
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
static int binding(uintptr_t pc,size_t n,uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b) {
    if(!b || !b->heads || b->heads>LI2_JD_HEADS || b->head>=b->heads ||
       (b->rows&7) || (b->image[0]&4095) || (b->image[1]&4095) || (spill_at&7) ||
       !address(b->rows,(size_t)b->heads*sizeof(struct li2_span_decoded)) ||
       !address(b->image[0],LI2_JD_IMAGE_BYTES) || !address(b->image[1],LI2_JD_IMAGE_BYTES) ||
       !address(spill_at,40) || !address(pc,n) ||
       generated!=b->image[b->head/64]+(uintptr_t)(b->head%64)*512)return 0;
    size_t rows=(size_t)b->heads*sizeof(struct li2_span_decoded);
    if(!apart(b->image[0],LI2_JD_IMAGE_BYTES,b->image[1],LI2_JD_IMAGE_BYTES) ||
       !apart(b->rows,rows,spill_at,40) || !apart(pc,n,spill_at,40) || !apart(pc,n,b->rows,rows))return 0;
    for(unsigned i=0;i<2;i++)if(!apart(b->image[i],LI2_JD_IMAGE_BYTES,b->rows,rows) ||
        !apart(b->image[i],LI2_JD_IMAGE_BYTES,spill_at,40) || !apart(b->image[i],LI2_JD_IMAGE_BYTES,pc,n))return 0;
    if((b->directory&4095U) || !address(b->directory,LI2_JD_DOMAIN_BYTES) ||
       !apart(b->directory,LI2_JD_DOMAIN_BYTES,b->rows,rows) ||
       !apart(b->directory,LI2_JD_DOMAIN_BYTES,spill_at,40) ||
       !apart(b->directory,LI2_JD_DOMAIN_BYTES,pc,n))return 0;
    for(unsigned i=0;i<2;i++)if(!apart(b->directory,LI2_JD_DOMAIN_BYTES,b->image[i],LI2_JD_IMAGE_BYTES))return 0;
    return 1;
}
#else
static int binding(uintptr_t pc,size_t n,uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b) {
    if(!b || !b->heads || b->heads>LI2_JD_HEADS || b->head>=b->heads ||
       (b->rows&7) || (b->image[0]&4095) || (b->image[1]&4095) || (spill_at&7) ||
       !address(b->rows,(size_t)b->heads*sizeof(struct li2_span_decoded)) ||
       !address(b->image[0],LI2_JD_IMAGE_BYTES) || !address(b->image[1],LI2_JD_IMAGE_BYTES) ||
       !address(spill_at,40) || !address(pc,n) ||
       generated!=b->image[b->head/64]+(uintptr_t)(b->head%64)*512)return 0;
    size_t rows=(size_t)b->heads*sizeof(struct li2_span_decoded);
    if(!apart(b->image[0],LI2_JD_IMAGE_BYTES,b->image[1],LI2_JD_IMAGE_BYTES) ||
       !apart(b->rows,rows,spill_at,40) || !apart(pc,n,spill_at,40) || !apart(pc,n,b->rows,rows))return 0;
    for(unsigned i=0;i<2;i++)if(!apart(b->image[i],LI2_JD_IMAGE_BYTES,b->rows,rows) ||
        !apart(b->image[i],LI2_JD_IMAGE_BYTES,spill_at,40) || !apart(b->image[i],LI2_JD_IMAGE_BYTES,pc,n))return 0;
    return 1;
}
#endif
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
#include "linked_jmp_domain_emit.inc"
#else
static int build(uintptr_t pc,const unsigned char *bytes,size_t n,uintptr_t generated,uintptr_t spill_at,
                 const struct li2_jd_binding *b,struct li2_jd_plan *p) {
    if(!binding(pc,n,generated,spill_at,b))return LI2_JD_ARGUMENT;
    p->record.version=1;p->generated=generated;p->spill=spill_at;copy(&p->binding,b,sizeof *b);
    int e=li2_jd_describe(pc,bytes,n,&p->original);if(e)return e;
    unsigned blocked=(1U<<0)|(1U<<4)|(1U<<12)|(1U<<p->original.target);
    p->record.scratch_regs[0]=0;unsigned count=1;
    for(unsigned i=1;i<16 && count<4;i++)if(!(blocked&(1U<<i)))p->record.scratch_regs[count++]=i;
    if(count!=4)return LI2_JD_FORM;
    unsigned A=p->record.scratch_regs[1],E=p->record.scratch_regs[2],T=p->record.scratch_regs[3];
    struct writer w={.p=p};for(unsigned i=0;i<4;i++)spill(&w,i,0);
    /* RAX may itself be the target. Copy it after all four saves, before LAHF. */
    rr(&w,0x89,p->original.target,T);w.dirty|=8;
    static const unsigned char lahf[]={0x9f},seto[]={0x0f,0x90,0xc0};
    emit(&w,lahf,1);w.dirty|=1;w.flags=LI2_MG_AH_PHYSICAL_OF;
    emit(&w,seto,3);w.flags=LI2_MG_AH_AL;
    absolute(&w,A,b->rows);w.dirty|=2;absolute(&w,E,0);w.dirty|=4;
    unsigned loop=p->record.image_bytes;
    /* CMP T,[A+0]. A/E/T exclude RSP/R12, so this has no SIB ambiguity. */
    unsigned char cmp[4]={(unsigned char)(0x48|((T>>3)<<2)|(A>>3)),0x3b,
        (unsigned char)(0x40|((T&7)<<3)|(A&7)),0};emit(&w,cmp,4);
    unsigned found=branch(&w,4);
    immediate(&w,A,0,(uint32_t)sizeof(struct li2_span_decoded));
    immediate(&w,E,0,1);immediate(&w,E,7,b->heads);unsigned again=branch(&w,2);
    restore(&w);p->record.miss_offset=p->record.image_bytes;
    unsigned miss=branch(&w,16);uint32_t d;
    if(!disp(generated+miss+5,pc,&d))return LI2_JD_RELOCATION;
    put32(p->image+miss+1,d);
    unsigned hit=p->record.image_bytes;w.valid=15;w.dirty=15;w.flags=LI2_MG_AH_AL;w.phase=LI2_JD_BEFORE;
    immediate(&w,E,7,64);unsigned first=branch(&w,2);
    immediate(&w,E,5,64);absolute(&w,A,b->image[1]);unsigned join=branch(&w,16);
    unsigned bank0=p->record.image_bytes;absolute(&w,A,b->image[0]);
    unsigned common=p->record.image_bytes;
    unsigned char shl[4]={(unsigned char)(0x48|(E>>3)),0xc1,(unsigned char)(0xe0|(E&7)),9};emit(&w,shl,4);
    rr(&w,0x03,A,E);
    unsigned char cell[7]={(unsigned char)(0x48|((A>>3)<<2)),0x89,(unsigned char)(5|((A&7)<<3)),0,0,0,0};
    if(!disp(generated+p->record.image_bytes+7,spill_at+32,&d))return LI2_JD_RELOCATION;
    put32(cell+3,d);emit(&w,cell,7);w.phase=LI2_JD_CELL_READY;
    restore(&w);p->record.hit_offset=p->record.image_bytes;
    unsigned char jump[6]={0xff,0x25,0,0,0,0};
    if(!disp(generated+p->record.image_bytes+6,spill_at+32,&d))return LI2_JD_RELOCATION;
    put32(jump+2,d);emit(&w,jump,6);
    patch(&w,found,hit);patch(&w,again,loop);patch(&w,first,bank0);patch(&w,join,common);
    if(w.error)return w.error;
    for(unsigned i=0;i<p->record.boundaries;i++) {
        const struct li2_mg_boundary *m=&p->record.boundary[i];size_t available=p->record.image_bytes-m->offset;
        if(available>15)available=15;
        struct li2_decoded actual={0};
        if(li2_decoder_decode(generated+m->offset,p->image+m->offset,available,&actual) ||
           actual.abi_version!=1 || actual.decode_status!=LI2_VALID || actual.length!=m->length ||
           actual.next_pc!=generated+m->offset+m->length)return LI2_JD_DECODER;
    }
    p->record.ready=1;return 0;
}
#endif
int li2_jd_emit(uintptr_t pc,const unsigned char *bytes,size_t n,uintptr_t generated,uintptr_t spill_at,
                const struct li2_jd_binding *b,struct li2_jd_plan *out) {
    if(!out)return LI2_JD_ARGUMENT;
    zero(out,sizeof *out);int e=build(pc,bytes,n,generated,spill_at,b,out);
    out->record.result=(uint32_t)e;if(e)out->record.ready=0;return e;
}
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
int li2_jd_validate(const struct li2_jd_plan *p) {
    if(!p || p->record.version!=LI2_JD_VERSION || p->record.ready!=1 || p->record.result || p->record.reserved)return LI2_JD_CORRUPT;
    struct li2_jd_plan expected;
    int e=li2_jd_emit(p->original.decoded.pc,p->original.decoded.bytes,p->original.available,
        p->generated,p->spill,&p->binding,&expected);
    return e || !same(p,&expected,sizeof *p)?LI2_JD_CORRUPT:0;
}
#else
int li2_jd_validate(const struct li2_jd_plan *p) {
    if(!p || p->record.version!=1 || p->record.ready!=1 || p->record.result || p->record.reserved)return LI2_JD_CORRUPT;
    struct li2_jd_plan expected;
    int e=li2_jd_emit(p->original.decoded.pc,p->original.decoded.bytes,p->original.available,
        p->generated,p->spill,&p->binding,&expected);
    return e || !same(p,&expected,sizeof *p)?LI2_JD_CORRUPT:0;
}
#endif
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
int li2_jd_recover(const struct li2_jd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                   const uint64_t spill_words[4],struct li2_jd_recovered *out) {
    if(!out)return LI2_JD_ARGUMENT;
    zero(out,sizeof *out);
    if(!p || !raw || !spill_words || p->record.version!=LI2_JD_VERSION || p->record.ready!=1 || p->record.result ||
       !p->record.boundaries || p->record.boundaries>LI2_JD_BOUNDARIES || pc<p->generated)return LI2_JD_ARGUMENT;
    const struct li2_mg_boundary *m=0;
    for(unsigned i=0;i<p->record.boundaries;i++)if(pc-p->generated==p->record.boundary[i].offset) {
        if(m)return LI2_JD_CORRUPT;
        m=&p->record.boundary[i];
    }
    if(!m || m->spill_valid&~15U || m->dirty&~m->spill_valid || m->flags>LI2_MG_AH_AL ||
       m->phase>LI2_JD_CELL_READY || p->record.scratch_regs[0]!=0)return LI2_JD_CORRUPT;
    unsigned seen=0;
    for(unsigned i=0;i<4;i++) {
        unsigned reg=p->record.scratch_regs[i];
        if(reg>=16 || reg==4 || seen&(1U<<reg))return LI2_JD_CORRUPT;
        seen|=1U<<reg;
    }
    copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
    if(m->flags) {
        if(!(m->dirty&1))return LI2_JD_CORRUPT;
        uint64_t of=flags&UINT64_C(0x800);
        if(m->flags==LI2_MG_AH_AL) { if((raw[0]&255)>1)return LI2_JD_CORRUPT;of=(raw[0]&1)<<11; }
        out->flags=(flags&~LI2_MG_STATUS)|((raw[0]>>8)&UINT64_C(0xd5))|of;
    }
    for(unsigned i=0;i<4;i++)if(m->dirty&(1U<<i))out->gpr[p->record.scratch_regs[i]]=spill_words[i];
    out->phase=LI2_JD_BEFORE;out->original_pc=p->original.decoded.pc;out->complete=1;return 0;
}
#else
int li2_jd_recover(const struct li2_jd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                   const uint64_t spill_words[4],struct li2_jd_recovered *out) {
    if(!out)return LI2_JD_ARGUMENT;
    zero(out,sizeof *out);
    if(!p || !raw || !spill_words || p->record.version!=1 || p->record.ready!=1 || p->record.result ||
       !p->record.boundaries || p->record.boundaries>LI2_JD_BOUNDARIES || pc<p->generated)return LI2_JD_ARGUMENT;
    const struct li2_mg_boundary *m=0;
    for(unsigned i=0;i<p->record.boundaries;i++)if(pc-p->generated==p->record.boundary[i].offset) {
        if(m)return LI2_JD_CORRUPT;
        m=&p->record.boundary[i];
    }
    if(!m || m->spill_valid&~15U || m->dirty&~m->spill_valid || m->flags>LI2_MG_AH_AL ||
       m->phase>LI2_JD_CELL_READY || p->record.scratch_regs[0]!=0)return LI2_JD_CORRUPT;
    unsigned seen=0;
    for(unsigned i=0;i<4;i++) {
        unsigned reg=p->record.scratch_regs[i];
        if(reg>=16 || reg==4 || seen&(1U<<reg))return LI2_JD_CORRUPT;
        seen|=1U<<reg;
    }
    copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
    if(m->flags) {
        if(!(m->dirty&1))return LI2_JD_CORRUPT;
        uint64_t of=flags&UINT64_C(0x800);
        if(m->flags==LI2_MG_AH_AL) { if((raw[0]&255)>1)return LI2_JD_CORRUPT;of=(raw[0]&1)<<11; }
        out->flags=(flags&~LI2_MG_STATUS)|((raw[0]>>8)&UINT64_C(0xd5))|of;
    }
    for(unsigned i=0;i<4;i++)if(m->dirty&(1U<<i))out->gpr[p->record.scratch_regs[i]]=spill_words[i];
    out->phase=LI2_JD_BEFORE;out->original_pc=p->original.decoded.pc;out->complete=1;return 0;
}
#endif
