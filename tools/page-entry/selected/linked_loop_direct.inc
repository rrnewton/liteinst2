/* LOOP-only DIRECT miss transfer. The old public emitter, validator and
   recovery bodies remain unchanged in the including translation unit. */
#include "linked_loop_direct.h"

static int ld_far_build(uintptr_t pc,const unsigned char *bytes,size_t n,unsigned external,
    uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b,const uintptr_t internal[2],
    struct li2_dd_plan *p) {
    if(!internal || !binding(pc,n,generated,spill_at,b))return LI2_DD_ARGUMENT;
    p->record.version=LI2_LD_VERSION;p->generated=generated;p->spill=spill_at;
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
    /* The target is immutable image data, not an instruction boundary. All
       GPRs and flags have already been restored at the six-byte JMP. */
    uint32_t d;
    if(disp(generated+p->record.miss_offset+5,pc,&d))return LI2_DD_ARGUMENT;
    static const unsigned char far_jump[6]={0xff,0x25,0,0,0,0};
    emit(&w,far_jump,sizeof far_jump);
    if(w.error || p->record.image_bytes>LI2_DD_SLOT_BYTES-8 ||
       (generated&4095U)+p->record.image_bytes+8>4096U)return LI2_DD_CAPACITY;
    put64(p->image+p->record.image_bytes,pc);p->record.image_bytes+=8;
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


/* A successful old image stays version1, byte for byte. Only the actual old
   emitter's precise original-PC E9 displacement failure can choose version2. */
int li2_ld_emit(uintptr_t pc,const unsigned char *bytes,size_t n,unsigned external,
    uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b,const uintptr_t internal[2],
    struct li2_dd_plan *out) {
    int e=li2_dd_emit(pc,bytes,n,external,generated,spill_at,b,internal,out);
    if(e!=LI2_DD_RELOCATION || !out || out->record.version!=LI2_DD_VERSION ||
       out->record.ready || out->record.result!=LI2_DD_RELOCATION ||
       !out->record.miss_offset || out->record.miss_offset>LI2_DD_SLOT_BYTES-5 || !out->record.boundaries ||
       out->record.boundaries>LI2_DD_BOUNDARIES ||
       out->record.image_bytes!=out->record.miss_offset+5)return e;
    const struct li2_mg_boundary *m=&out->record.boundary[out->record.boundaries-1];
    const unsigned char *jump=out->image+out->record.miss_offset;uint32_t delta;
    if(m->offset!=out->record.miss_offset || m->length!=5 || m->spill_valid!=15 ||
       m->dirty || m->flags!=LI2_MG_PHYSICAL || m->phase!=LI2_DD_BEFORE ||
       jump[0]!=0xe9 || jump[1]!=0x90 || jump[2] || jump[3] || jump[4] ||
       disp(generated+m->offset+5,pc,&delta))return e;
    zero(out,sizeof *out);e=ld_far_build(pc,bytes,n,external,generated,spill_at,b,internal,out);
    out->record.result=(uint32_t)e;if(e)out->record.ready=0;return e;
}
int li2_ld_validate(const struct li2_dd_plan *p) {
    if(!p)return LI2_DD_CORRUPT;
    if(p->record.version==LI2_DD_VERSION)return li2_dd_validate(p);
    if(p->record.version!=LI2_LD_VERSION || p->record.ready!=1 || p->record.result || p->record.reserved)
        return LI2_DD_CORRUPT;
    struct li2_dd_plan expected;
    int e=li2_ld_emit(p->original.decoded.pc,p->original.decoded.bytes,p->original.available,p->original.external_mask,
        p->generated,p->spill,&p->binding,p->internal,&expected);
    return e || !same(p,&expected,sizeof *p)?LI2_DD_CORRUPT:0;
}

static int ld_far_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                   const uint64_t spill_words[4],struct li2_dd_recovered *out) {
    if(!out)return LI2_DD_ARGUMENT;
    zero(out,sizeof *out);
    if(!p || !raw || !spill_words || p->record.version!=LI2_LD_VERSION || p->record.ready!=1 || p->record.result ||
       !p->record.boundaries || p->record.boundaries>LI2_DD_BOUNDARIES || pc<p->generated)return LI2_DD_ARGUMENT;
    /* Even an invented row cannot make any target-literal byte recoverable.
       The real RX page supplies this exact immutable data; no target cell or
       guest memory is read during decoder-free recovery. */
    unsigned miss=p->record.miss_offset;
    if(miss>LI2_DD_SLOT_BYTES-14 || p->record.image_bytes>LI2_DD_SLOT_BYTES ||
       miss+14>p->record.image_bytes || (p->generated&4095U)+miss+14>4096U ||
       p->image[miss]!=0xff || p->image[miss+1]!=0x25 ||
       p->image[miss+2] || p->image[miss+3] || p->image[miss+4] || p->image[miss+5])return LI2_DD_CORRUPT;
    for(unsigned i=0;i<8;i++)if(p->image[miss+6+i]!=(unsigned char)(p->original.decoded.pc>>(8*i)))return LI2_DD_CORRUPT;
    if(pc-p->generated>=miss+6 && pc-p->generated<miss+14)return LI2_DD_CORRUPT;
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

int li2_ld_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                   const uint64_t spill_words[4],struct li2_dd_recovered *out) {
    if(p && p->record.version==LI2_DD_VERSION)return li2_dd_recover(p,pc,raw,flags,spill_words,out);
    return ld_far_recover(p,pc,raw,flags,spill_words,out);
}
