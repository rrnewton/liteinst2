/* Separate byte-only guard implementation. Every common writer/table/spill/
   restore helper above remains the original implementation; old public APIs
   are untouched. A byte store changes only the exact descriptor, interval
   width and immediate extent used to form LEA, never the guarded state flow. */
#include "linked_byte_mov_guard.h"

int li2_bmg_interval_allowed(const struct li2_mg_table *t,uint64_t first,unsigned width){
    if(width!=1 || li2_mg_table_validate(t))return -LI2_MG_ARGUMENT;
    if(first>UINT64_MAX-width)return 0;
    uint64_t end=first+width,p=t->root;unsigned visits=0;
    while(p){
        if(++visits>8 || p<node_address(t,0) || (p-node_address(t,0))%32)return -LI2_MG_CORRUPT;
        uint64_t i=(p-node_address(t,0))/32;if(i>=t->count)return -LI2_MG_CORRUPT;
        const struct li2_mg_node *n=&t->node[i];
        if(end<=n->first)p=n->left;else if(first>=n->end)p=n->right;else return 0;
    }
    return 1;
}

static int bmg_build(uintptr_t pc,const unsigned char *bytes,size_t length,uintptr_t generated,uintptr_t spill_at,uintptr_t successor,
                 const struct li2_mg_table *table,struct li2_mg_plan *p){
    int e;uint32_t d;
    if(!bytes || !length || length>15 || !address(pc,length) || !address(generated,LI2_MG_CODE_BYTES) ||
       !address(spill_at,32) || (spill_at&7) || !address(successor,1) || !table || li2_mg_table_validate(table) ||
       !apart(generated,LI2_MG_CODE_BYTES,spill_at,32) || !apart(generated,LI2_MG_CODE_BYTES,table->address,sizeof *table) ||
       !apart(spill_at,32,table->address,sizeof *table) || !apart(pc,length,generated,LI2_MG_CODE_BYTES) ||
       !apart(pc,length,spill_at,32) || !apart(pc,length,table->address,sizeof *table) ||
       !apart(successor,1,generated,LI2_MG_CODE_BYTES))return LI2_MG_ARGUMENT;
    p->version=LI2_BMG_VERSION;p->generated=generated;p->spill=spill_at;p->successor=successor;copy(&p->table,table,sizeof *table);
    e=(int)li2_decoder_byte_mov_store(pc,bytes,length,&p->original);if(e)return LI2_MG_DECODER;
    const struct li2_mg_store *s=&p->original;
    if(s->version!=LI2_BMG_VERSION || s->ready!=1 || s->refusal || s->reserved || s->available!=length ||
       s->tf.abi_version!=1 || s->tf.policy!=1 || s->tf.pc!=pc || !s->tf.length || s->tf.length>length ||
       s->tf.next_pc!=pc+s->tf.length || s->width_bytes!=1 ||
       !same(s->bytes,bytes,length) || s->base>16 || s->index>16 || s->source_reg>16)return LI2_MG_FORM;
    if((s->source_kind==1 && (s->source_reg>=16 || s->immediate)) ||
       (s->source_kind==2 && (s->source_reg!=16 || s->immediate>255)) ||
       (s->source_kind!=1 && s->source_kind!=2) ||
       s->tf.code!=(s->source_kind==2?LI2_BMG_IMMEDIATE_CODE:LI2_BMG_REGISTER_CODE))return LI2_MG_FORM;
    unsigned blocked=(1U<<0)|(1U<<4)|(1U<<12);
    if(s->base<16)blocked|=1U<<s->base;
    if(s->index<16)blocked|=1U<<s->index;
    if(s->source_reg<16)blocked|=1U<<s->source_reg;
    p->scratch_regs[0]=0;unsigned count=1;
    for(unsigned i=1;i<16 && count<4;i++)if(!(blocked&(1U<<i)))p->scratch_regs[count++]=i;
    if(count!=4)return LI2_MG_FORM;
    unsigned A=p->scratch_regs[1],E=p->scratch_regs[2],T=p->scratch_regs[3];
    struct writer w={.p=p};for(unsigned i=0;i<4;i++)spill(&w,i,0);
    /* Compute the actual EA while every operand, including RAX and RSP, is original. */
    unsigned end=s->tf.length-(s->source_kind==2?1U:0U);
    if(s->modrm_offset!=s->opcode_offset+1 || s->opcode_offset>1 || end<=s->modrm_offset || end-s->modrm_offset>6)return LI2_MG_FORM;
    unsigned char ea[15]={0};unsigned en=2+end-s->modrm_offset;
    ea[0]=(unsigned char)(0x48|((A>>3)<<2)|(s->opcode_offset?s->bytes[0]&3:0));ea[1]=0x8d;
    copy(ea+2,s->bytes+s->modrm_offset,end-s->modrm_offset);ea[2]=(unsigned char)((ea[2]&0xc7)|((A&7)<<3));
    if(s->rip_relative){unsigned at=2+s->displacement_offset-s->modrm_offset;
        if(s->displacement_bytes!=4 || at+4>en || !disp(generated+p->image_bytes+en,s->rip_target,&d))return LI2_MG_RELOCATION;
        put32(ea+at,d);}
    emit(&w,ea,en);w.dirty|=2;
    static const unsigned char lahf[]={0x9f},seto[]={0x0f,0x90,0xc0};emit(&w,lahf,1);w.dirty|=1;w.flags=LI2_MG_AH_PHYSICAL_OF;
    emit(&w,seto,3);w.flags=LI2_MG_AH_AL;
    unsigned char root[10]={(unsigned char)(0x48|(T>>3)),(unsigned char)(0xb8+(T&7)),0,0,0,0,0,0,0,0};put64(root+2,table->root);emit(&w,root,10);w.dirty|=8;
    memory(&w,0x8d,E,A,s->width_bytes);w.dirty|=4;
    rr(&w,0x3b,E,A);unsigned overflow=branch(&w,6); /* JBE: checked complete interval. */
    unsigned loop=p->image_bytes;rr(&w,0x85,T,T);unsigned accept_branch=branch(&w,4);
    memory(&w,0x3b,E,T,0);unsigned left_branch=branch(&w,6);
    memory(&w,0x3b,A,T,8);unsigned right_branch=branch(&w,3);unsigned reject_branch=branch(&w,16);
    unsigned left=p->image_bytes;memory(&w,0x8b,T,T,16);unsigned left_back=branch(&w,16);
    unsigned right=p->image_bytes;memory(&w,0x8b,T,T,24);unsigned right_back=branch(&w,16);
    unsigned accept=p->image_bytes;restore(&w);p->store_offset=p->image_bytes;w.phase=LI2_MG_STORE;
    unsigned char store[15];copy(store,s->bytes,s->tf.length);
    if(s->rip_relative){if(!disp(generated+p->image_bytes+s->tf.length,s->rip_target,&d))return LI2_MG_RELOCATION;put32(store+s->displacement_offset,d);}
    emit(&w,store,s->tf.length);w.phase=LI2_MG_AFTER;
    unsigned follow=branch(&w,16);if(!disp(generated+follow+5,successor,&d))return LI2_MG_RELOCATION;put32(p->image+follow+1,d);
    unsigned reject=p->image_bytes;w.valid=15;w.dirty=15;w.flags=LI2_MG_AH_AL;w.phase=LI2_MG_BEFORE;restore(&w);
    p->reject_offset=p->image_bytes;w.phase=LI2_MG_REJECT;static const unsigned char ud2[]={0x0f,0x0b};emit(&w,ud2,2);
    patch(&w,overflow,reject);patch(&w,accept_branch,accept);patch(&w,left_branch,left);patch(&w,right_branch,right);patch(&w,reject_branch,reject);patch(&w,left_back,loop);patch(&w,right_back,loop);
    if(w.error)return w.error;
    /* Every recovery boundary is also an actual decoder boundary. Trusted
       guard instructions are not silently put in the old NONE guest domain. */
    for(unsigned i=0;i<p->boundaries;i++){
        const struct li2_mg_boundary *m=&p->boundary[i];size_t n=p->image_bytes-m->offset;if(n>15)n=15;
        struct li2_decoded actual={0};e=(int)li2_decoder_decode(generated+m->offset,p->image+m->offset,n,&actual);
        if(e || actual.abi_version!=1 || actual.decode_status!=LI2_VALID || actual.length!=m->length || actual.next_pc!=generated+m->offset+m->length)return LI2_MG_DECODER;
    }
    p->ready=1;return 0;
}
int li2_bmg_emit(uintptr_t pc,const unsigned char *bytes,size_t length,uintptr_t generated,uintptr_t spill_at,uintptr_t successor,const struct li2_mg_table *table,struct li2_mg_plan *out){
    if(!out)return LI2_MG_ARGUMENT;
    zero(out,sizeof *out);
    int e=bmg_build(pc,bytes,length,generated,spill_at,successor,table,out);out->result=(uint32_t)e;if(e)out->ready=0;return e;
}
int li2_bmg_validate(const struct li2_mg_plan *p){
    if(!p || p->version!=LI2_BMG_VERSION || p->ready!=1 || p->result || p->reserved)return LI2_MG_CORRUPT;
    struct li2_mg_plan expected;int e=li2_bmg_emit(p->original.tf.pc,p->original.bytes,p->original.available,p->generated,p->spill,p->successor,&p->table,&expected);
    return e || !same(p,&expected,sizeof *p)?LI2_MG_CORRUPT:0;
}
int li2_bmg_recover(const struct li2_mg_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,const uint64_t spill_words[4],struct li2_mg_recovered *out){
    if(!out)return LI2_MG_ARGUMENT;
    zero(out,sizeof *out);
    if(!p || !raw || !spill_words || p->version!=LI2_BMG_VERSION || p->ready!=1 || p->result || !p->boundaries || p->boundaries>LI2_MG_BOUNDARIES || pc<p->generated)return LI2_MG_ARGUMENT;
    const struct li2_mg_boundary *m=0;for(unsigned i=0;i<p->boundaries;i++)if(pc-p->generated==p->boundary[i].offset){m=&p->boundary[i];break;}
    if(!m || m->spill_valid&~15U || m->dirty&~m->spill_valid || m->flags>LI2_MG_AH_AL || m->phase>LI2_MG_REJECT || p->scratch_regs[0]!=0)return LI2_MG_CORRUPT;
    unsigned seen=0;for(unsigned i=0;i<4;i++){unsigned r=p->scratch_regs[i];if(r>=16 || r==4 || seen&(1U<<r))return LI2_MG_CORRUPT;seen|=1U<<r;}
    copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
    if(m->flags){
        if(!(m->dirty&1))return LI2_MG_CORRUPT;
        uint64_t of=flags&UINT64_C(0x800);
        if(m->flags==LI2_MG_AH_AL){if((raw[0]&255)>1)return LI2_MG_CORRUPT;of=(raw[0]&1)<<11;}
        out->flags=(flags&~LI2_MG_STATUS)|((raw[0]>>8)&UINT64_C(0xd5))|of;
    }
    for(unsigned i=0;i<4;i++)if(m->dirty&(1U<<i))out->gpr[p->scratch_regs[i]]=spill_words[i];
    out->phase=m->phase;out->original_pc=m->phase==LI2_MG_AFTER?p->original.tf.next_pc:p->original.tf.pc;
    out->complete=1;return 0;
}
