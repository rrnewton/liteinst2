/* Same original 16-register grammar and scratch/flags protocol. The new
   immutable directory supplies exact generated PCs rather than deriving a
   target from one certificate's row index. No guest-stack scratch is used. */
static void domain_load(struct writer *w,unsigned target,unsigned base,unsigned offset) {
    unsigned char b[4]={(unsigned char)(0x48|((target>>3)<<2)|(base>>3)),0x8b,
        (unsigned char)(0x40|((target&7)<<3)|(base&7)),(unsigned char)offset};
    emit(w,b,4);
}
static int build(uintptr_t pc,const unsigned char *bytes,size_t n,uintptr_t generated,uintptr_t spill_at,
                 const struct li2_jd_binding *b,struct li2_jd_plan *p) {
    if(!binding(pc,n,generated,spill_at,b))return LI2_JD_ARGUMENT;
    p->record.version=LI2_JD_VERSION;p->generated=generated;p->spill=spill_at;copy(&p->binding,b,sizeof *b);
    int e=li2_jd_describe(pc,bytes,n,&p->original);if(e)return e;
    unsigned blocked=(1U<<0)|(1U<<4)|(1U<<12)|(1U<<p->original.target);
    p->record.scratch_regs[0]=0;unsigned count=1;
    for(unsigned i=1;i<16 && count<4;i++)if(!(blocked&(1U<<i)))p->record.scratch_regs[count++]=i;
    if(count!=4)return LI2_JD_FORM;
    unsigned A=p->record.scratch_regs[1],E=p->record.scratch_regs[2],T=p->record.scratch_regs[3];
    struct writer w={.p=p};for(unsigned i=0;i<4;i++)spill(&w,i,0);
    rr(&w,0x89,p->original.target,T);w.dirty|=8;
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
    if(!disp(generated+miss+5,pc,&d))return LI2_JD_RELOCATION;
    put32(p->image+miss+1,d);
    unsigned hit=p->record.image_bytes;
    w.valid=15;w.dirty=15;w.flags=LI2_MG_AH_AL;w.phase=LI2_JD_BEFORE;
    domain_load(&w,A,A,8);
    unsigned char cell[7]={(unsigned char)(0x48|((A>>3)<<2)),0x89,(unsigned char)(5|((A&7)<<3)),0,0,0,0};
    if(!disp(generated+p->record.image_bytes+7,spill_at+32,&d))return LI2_JD_RELOCATION;
    put32(cell+3,d);emit(&w,cell,7);w.phase=LI2_JD_CELL_READY;
    restore(&w);p->record.hit_offset=p->record.image_bytes;
    unsigned char jump[6]={0xff,0x25,0,0,0,0};
    if(!disp(generated+p->record.image_bytes+6,spill_at+32,&d))return LI2_JD_RELOCATION;
    put32(jump+2,d);emit(&w,jump,6);
    patch(&w,empty,rejected);patch(&w,excess,rejected);patch(&w,found,hit);patch(&w,again,loop);
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
