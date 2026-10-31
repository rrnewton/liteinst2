#include "linked_direct_dispatch.h"
#include "linked_rseq.h"
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

static uint32_t read_flags(unsigned c) {
    static const uint32_t mask[8]={0x800,1,0x40,0x41,0x80,4,0x880,0x8c0};
    return c<16?mask[c/2]:0;
}
int li2_dd_span(const struct li2_span_decoded *d,unsigned external,struct li2_dd_descriptor *out) {
    if(!out)return LI2_DD_ARGUMENT;
    zero(out,sizeof *out);
    if(!d)return LI2_DD_ARGUMENT;
    const struct li2_decoded *a=&d->decoded;
    if(a->abi_version!=1 || a->decode_status!=LI2_VALID || a->reserved || a->kind!=LI2_NONE ||
       !a->available || a->available>15 || !a->length || a->length>a->available ||
       !address(a->pc,a->available) || a->next_pc!=a->pc+a->length)return LI2_DD_FORM;
    for(unsigned i=a->available;i<16;i++)if(a->bytes[i])return LI2_DD_FORM;
    unsigned flow,condition,offset,count;
    if(a->length==2 && a->bytes[0]==0xeb) {flow=LI2_REGION_JMP;condition=16;offset=1;count=1;}
    else if(a->length==5 && a->bytes[0]==0xe9) {flow=LI2_REGION_JMP;condition=16;offset=1;count=4;}
    else if(a->length==2 && a->bytes[0]>=0x70 && a->bytes[0]<=0x7f) {
        flow=LI2_REGION_JCC;condition=a->bytes[0]&15;offset=1;count=1;
    } else if(a->length==6 && a->bytes[0]==0x0f && a->bytes[1]>=0x80 && a->bytes[1]<=0x8f) {
        flow=LI2_REGION_JCC;condition=a->bytes[1]&15;offset=2;count=4;
    } else return LI2_DD_FORM;
    if(!external || (external&~(flow==LI2_REGION_JCC?3U:1U)))return LI2_DD_FORM;
    uint32_t bits=0;for(unsigned i=0;i<count;i++)bits|=(uint32_t)a->bytes[offset+i]<<(8*i);
    int64_t delta=count==1?(bits&128?(int64_t)bits-256:(int64_t)bits):
        (bits&UINT32_C(0x80000000)?(int64_t)bits-INT64_C(4294967296):(int64_t)bits);
    if(delta<0 && (uint64_t)(-delta)>a->next_pc)return LI2_DD_FORM;
    uintptr_t target=a->next_pc+(uint64_t)delta;
    if(target>=UINT64_C(0x800000000000) && target<UINT64_C(0xffff800000000000))return LI2_DD_FORM;
    struct li2_span_decoded expected={0};expected.decoded=*a;
    expected.target=target;expected.version=1;expected.ready=1;expected.flow=flow;expected.condition=condition;
    expected.operand_count=1;expected.operands[0]=(struct li2_region_operand){target,LI2_REGION_BRANCH,0,64,LI2_REGION_READ,count*8,0};
    expected.flags_read=read_flags(condition);
    if(!same(d,&expected,sizeof expected))return LI2_DD_FORM;
    out->decoded=*a;out->target[0]=target;out->target[1]=flow==LI2_REGION_JCC?a->next_pc:0;
    out->version=LI2_DD_VERSION;out->ready=1;out->available=a->available;
    out->flow=flow;out->condition=condition;out->external_mask=external;return 0;
}
int li2_dd_describe(uintptr_t pc,const unsigned char *bytes,size_t n,unsigned external,struct li2_dd_descriptor *out) {
    if(!out)return LI2_DD_ARGUMENT;
    zero(out,sizeof *out);
    if(!bytes || !n || n>15 || !address(pc,n))return LI2_DD_ARGUMENT;
    struct li2_span_decoded d={0};struct li2_decoded actual={0};struct li2_write_footprint f={0};
    if(li2_decoder_span_describe(pc,bytes,n,&d) || li2_decoder_decode(pc,bytes,n,&actual) ||
       li2_decoder_link_none(pc,bytes,n,&f))return LI2_DD_DECODER;
    if(!same(&d.decoded,&actual,sizeof actual) || actual.pc!=pc || actual.available!=n ||
       !same(actual.bytes,bytes,n) || f.abi_version!=1 || f.policy!=LI2_WRITE_NONE || f.first || f.end ||
       f.pc!=pc || f.next_pc!=actual.next_pc || f.code!=actual.code || f.length!=actual.length)return LI2_DD_DECODER;
    return li2_dd_span(&d,external,out);
}
int li2_dd_arm(const struct li2_dd_descriptor *a,uint64_t flags) {
    if(!a || a->version!=LI2_DD_VERSION || a->ready!=1 || a->refusal || a->reserved ||
       !a->external_mask || (a->external_mask&~(a->flow==LI2_REGION_JCC?3U:1U)))return -1;
    if(a->flow==LI2_REGION_JMP)return a->condition==16?0:-1;
    if(a->flow!=LI2_REGION_JCC || a->condition>15)return -1;
    unsigned of=(flags>>11)&1,cf=flags&1,zf=(flags>>6)&1,sf=(flags>>7)&1,pf=(flags>>2)&1,taken;
    switch(a->condition/2) {
    case 0:taken=of;break;case 1:taken=cf;break;case 2:taken=zf;break;case 3:taken=cf|zf;break;
    case 4:taken=sf;break;case 5:taken=pf;break;case 6:taken=sf^of;break;default:taken=zf|(sf^of);break;
    }
    if(a->condition&1)taken^=1;
    return taken?0:1;
}
struct writer { struct li2_dd_plan *p;unsigned valid,dirty,flags,phase;int error; };
static unsigned emit(struct writer *w,const unsigned char *b,unsigned n) {
    struct li2_dd_record *r=&w->p->record;unsigned at=r->image_bytes;
    if(w->error)return at;
    if(!n || n>15 || r->boundaries>=LI2_DD_BOUNDARIES || n>LI2_DD_SLOT_BYTES-at) { w->error=LI2_DD_CAPACITY;return at; }
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
    if(!disp(w->p->generated+at+n,w->p->generated+target,&d)) { w->error=LI2_DD_RELOCATION;return; }
    put32(w->p->image+at+n-4,d);
}
static void spill(struct writer *w,unsigned i,int load) {
    unsigned reg=w->p->record.scratch_regs[i];uint32_t d;
    unsigned char b[7]={(unsigned char)(0x48|((reg>>3)<<2)),(unsigned char)(load?0x8b:0x89),
        (unsigned char)(5|((reg&7)<<3)),0,0,0,0};
    if(!disp(w->p->generated+w->p->record.image_bytes+7,w->p->spill+8*i,&d)) { w->error=LI2_DD_RELOCATION;return; }
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
static void domain_load(struct writer *w,unsigned target,unsigned base,unsigned offset) {
    unsigned char b[4]={(unsigned char)(0x48|((target>>3)<<2)|(base>>3)),0x8b,
        (unsigned char)(0x40|((target&7)<<3)|(base&7)),(unsigned char)offset};
    emit(w,b,4);
}

static int build(uintptr_t pc,const unsigned char *bytes,size_t n,unsigned external,
    uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b,const uintptr_t internal[2],
    struct li2_dd_plan *p) {
    if(!internal || !binding(pc,n,generated,spill_at,b))return LI2_DD_ARGUMENT;
    p->record.version=LI2_DD_VERSION;p->generated=generated;p->spill=spill_at;
    copy(&p->binding,b,sizeof *b);copy(p->internal,internal,sizeof p->internal);
    int e=li2_dd_describe(pc,bytes,n,external,&p->original);if(e)return e;
    unsigned arms=p->original.flow==LI2_REGION_JCC?2:1;
    for(unsigned i=0;i<2;i++) {
        if(i>=arms || (external&(1U<<i))) {if(internal[i])return LI2_DD_ARGUMENT;}
        else if(!address(internal[i],1) || (internal[i]!=generated && !apart(internal[i],1,generated,LI2_DD_SLOT_BYTES)) ||
                !apart(internal[i],1,spill_at,40) || !apart(internal[i],1,b->rows,b->heads*sizeof(struct li2_span_decoded)) ||
                !apart(internal[i],1,b->directory,LI2_JD_DOMAIN_BYTES))return LI2_DD_ARGUMENT;
    }
    /* Direct branches read no GPR: the fixed palette excludes RSP/R12. */
    for(unsigned i=0;i<4;i++)p->record.scratch_regs[i]=i;
    unsigned A=1,E=2,T=3;
    struct writer w={.p=p};
    if(arms==2 && external!=3) {
        /* The internal arm has no private effects at all. Both rows still
           recover the original branch-before, with the original flags. */
        unsigned which=external==1?0:1;
        unsigned selected=branch(&w,p->original.condition^(which?1U:0U));
        unsigned ordinary=branch(&w,16);uint32_t d;
        if(!disp(generated+ordinary+5,internal[which^1U],&d))return LI2_DD_RELOCATION;
        put32(p->image+ordinary+1,d);patch(&w,selected,p->record.image_bytes);
    }
    for(unsigned i=0;i<4;i++)spill(&w,i,0);
    if(arms==2 && external==3) {
        unsigned taken=branch(&w,p->original.condition);
        absolute(&w,T,p->original.target[1]);w.dirty|=8;
        unsigned join=branch(&w,16),yes=p->record.image_bytes;
        w.valid=15;w.dirty=0;w.flags=LI2_MG_PHYSICAL;w.phase=LI2_DD_BEFORE;
        absolute(&w,T,p->original.target[0]);w.dirty|=8;
        patch(&w,taken,yes);patch(&w,join,p->record.image_bytes);
    } else {
        absolute(&w,T,p->original.target[external==2?1:0]);w.dirty|=8;
    }
    static const unsigned char lahf[]={0x9f},seto[]={0x0f,0x90,0xc0};
    emit(&w,lahf,1);w.dirty|=1;w.flags=LI2_MG_AH_PHYSICAL_OF;
    emit(&w,seto,3);w.flags=LI2_MG_AH_AL;
    absolute(&w,A,b->directory);w.dirty|=2;
    domain_load(&w,E,A,8);w.dirty|=4;
    immediate(&w,E,7,1);unsigned empty=branch(&w,2);
    immediate(&w,E,7,LI2_JD_DOMAIN_HEADS);unsigned excess=branch(&w,7);
    immediate(&w,A,0,32);
    unsigned char shl[4]={(unsigned char)(0x48|(E>>3)),0xc1,(unsigned char)(0xe0|(E&7)),5};
    emit(&w,shl,4);rr(&w,0x03,E,A); /* E is the one-past-last row address. */
    unsigned loop=p->record.image_bytes;
    unsigned char cmp[4]={(unsigned char)(0x48|((T>>3)<<2)|(A>>3)),0x3b,
        (unsigned char)(0x40|((T&7)<<3)|(A&7)),0};emit(&w,cmp,4);
    unsigned found=branch(&w,4);
    immediate(&w,A,0,32);rr(&w,0x3b,A,E);unsigned again=branch(&w,2);
    unsigned rejected=p->record.image_bytes;
    restore(&w);p->record.miss_offset=p->record.image_bytes;
    unsigned miss=branch(&w,16);uint32_t d;
    if(!disp(generated+miss+5,pc,&d))return LI2_DD_RELOCATION;
    put32(p->image+miss+1,d);
    unsigned hit=p->record.image_bytes;
    w.valid=15;w.dirty=15;w.flags=LI2_MG_AH_AL;w.phase=LI2_DD_BEFORE;
    domain_load(&w,A,A,8);
    unsigned char cell[7]={(unsigned char)(0x48|((A>>3)<<2)),0x89,(unsigned char)(5|((A&7)<<3)),0,0,0,0};
    if(!disp(generated+p->record.image_bytes+7,spill_at+32,&d))return LI2_DD_RELOCATION;
    put32(cell+3,d);emit(&w,cell,7);w.phase=LI2_DD_CELL_READY;
    restore(&w);p->record.hit_offset=p->record.image_bytes;
    unsigned char jump[6]={0xff,0x25,0,0,0,0};
    if(!disp(generated+p->record.image_bytes+6,spill_at+32,&d))return LI2_DD_RELOCATION;
    put32(jump+2,d);emit(&w,jump,6);
    patch(&w,empty,rejected);patch(&w,excess,rejected);patch(&w,found,hit);patch(&w,again,loop);
    if(w.error)return w.error;
    for(unsigned i=0;i<p->record.boundaries;i++) {
        const struct li2_mg_boundary *m=&p->record.boundary[i];size_t available=p->record.image_bytes-m->offset;
        if(available>15)available=15;
        struct li2_decoded actual={0};
        if(li2_decoder_decode(generated+m->offset,p->image+m->offset,available,&actual) ||
           actual.abi_version!=1 || actual.decode_status!=LI2_VALID || actual.length!=m->length ||
           actual.next_pc!=generated+m->offset+m->length)return LI2_DD_DECODER;
    }
    p->record.ready=1;return 0;
}

int li2_dd_emit(uintptr_t pc,const unsigned char *bytes,size_t n,unsigned external,
    uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b,const uintptr_t internal[2],
    struct li2_dd_plan *out) {
    if(!out)return LI2_DD_ARGUMENT;
    zero(out,sizeof *out);int e=build(pc,bytes,n,external,generated,spill_at,b,internal,out);
    out->record.result=(uint32_t)e;if(e)out->record.ready=0;return e;
}
int li2_dd_validate(const struct li2_dd_plan *p) {
    if(!p || p->record.version!=LI2_DD_VERSION || p->record.ready!=1 || p->record.result || p->record.reserved)return LI2_DD_CORRUPT;
    struct li2_dd_plan expected;
    int e=li2_dd_emit(p->original.decoded.pc,p->original.decoded.bytes,p->original.available,p->original.external_mask,
        p->generated,p->spill,&p->binding,p->internal,&expected);
    return e || !same(p,&expected,sizeof *p)?LI2_DD_CORRUPT:0;
}
int li2_dd_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                   const uint64_t spill_words[4],struct li2_dd_recovered *out) {
    if(!out)return LI2_DD_ARGUMENT;
    zero(out,sizeof *out);
    if(!p || !raw || !spill_words || p->record.version!=LI2_DD_VERSION || p->record.ready!=1 || p->record.result ||
       !p->record.boundaries || p->record.boundaries>LI2_DD_BOUNDARIES || pc<p->generated)return LI2_DD_ARGUMENT;
    const struct li2_mg_boundary *m=0;
    for(unsigned i=0;i<p->record.boundaries;i++)if(pc-p->generated==p->record.boundary[i].offset) {
        if(m)return LI2_DD_CORRUPT;
        m=&p->record.boundary[i];
    }
    if(!m || m->spill_valid&~15U || m->dirty&~m->spill_valid || m->flags>LI2_MG_AH_AL ||
       m->phase>LI2_DD_CELL_READY || p->record.scratch_regs[0]!=0)return LI2_DD_CORRUPT;
    unsigned seen=0;
    for(unsigned i=0;i<4;i++) {
        unsigned reg=p->record.scratch_regs[i];
        if(reg>=16 || reg==4 || seen&(1U<<reg))return LI2_DD_CORRUPT;
        seen|=1U<<reg;
    }
    copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
    if(m->flags) {
        if(!(m->dirty&1))return LI2_DD_CORRUPT;
        uint64_t of=flags&UINT64_C(0x800);
        if(m->flags==LI2_MG_AH_AL) { if((raw[0]&255)>1)return LI2_DD_CORRUPT;of=(raw[0]&1)<<11; }
        out->flags=(flags&~LI2_MG_STATUS)|((raw[0]>>8)&UINT64_C(0xd5))|of;
    }
    for(unsigned i=0;i<4;i++)if(m->dirty&(1U<<i))out->gpr[p->record.scratch_regs[i]]=spill_words[i];
    out->phase=LI2_DD_BEFORE;out->original_pc=p->original.decoded.pc;out->complete=1;return 0;
}
