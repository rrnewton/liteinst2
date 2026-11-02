/* Additive component. The entire old oracle runs first, with its exact counts
   and assertions. New expected descriptors are literal encoding models; the
   generic72-byte decode header is the only reused decoder output. */
#define main old_mov_main
#include "../linked_mov_guard/metadata.c"
#undef main
#include "loop_scalar_decode.h"
#include "bmg_model.h"
#include <sys/mman.h>
static unsigned byte_rows,byte_models,byte_refusals,byte_corruptions,byte_edges;
static unsigned imul_rows,imul_refusals,scalar_legacy;
static uint64_t recovered_rows,interior_refusals;
static void unchanged(void){struct li2_decoder_stats s;assert(!li2_decoder_stats(&s)&&!memcmp(&s,&initial,sizeof s));}

/* Independent byte encoding and whole expected144-byte row. base16 is RIP;
   base17 is the absolute no-base/no-index SIB. GPR forms use disp8 -16. */
static unsigned byte_encode(unsigned char b[15],int imm,unsigned src,unsigned base,
                            unsigned index,unsigned scale,uint64_t target,unsigned value,
                            struct li2_mg_store *want){
    memset(b,0,15);memset(want,0,sizeof *want);
    unsigned rex=0x40|(!imm&&src>=8?4:0)|(index<16&&index>=8?2:0)|(base<16&&base>=8?1:0),n=0;
    if(rex!=0x40||(!imm&&src>=4&&src<8))b[n++]=(unsigned char)rex;
    unsigned op=n;b[n++]=(unsigned char)(imm?0xc6:0x88);unsigned reg=imm?0:src&7,d,dn;
    if(base==16){b[n++]=(unsigned char)((reg<<3)|5);d=n;dn=4;n+=4;
        int64_t delta=(int64_t)target-(int64_t)(PC+n+(unsigned)imm);assert(delta>=INT32_MIN&&delta<=INT32_MAX);put32(b+d,(uint32_t)delta);
    }else if(base==17){b[n++]=(unsigned char)((reg<<3)|4);b[n++]=0x25;d=n;dn=4;put32(b+n,(uint32_t)target);n+=4;
    }else if(index<16||(base&7)==4){b[n++]=(unsigned char)(0x40|(reg<<3)|4);b[n++]=(unsigned char)((scale<<6)|((index<16?index&7:4)<<3)|(base&7));d=n;dn=1;b[n++]=0xf0;
    }else{b[n++]=(unsigned char)(0x40|(reg<<3)|(base&7));d=n;dn=1;b[n++]=0xf0;}
    if(imm)b[n++]=(unsigned char)value;
    *want=(struct li2_mg_store){.tf={PC,PC+n,1,1,imm?401:279,n,1,1},
        .displacement=base==16?target:base==17?target:UINT64_MAX-15,
        .rip_target=base==16?target:0,.immediate=imm?value:0,.version=2,.ready=1,
        .available=n,.width_bytes=1,.source_kind=imm?2:1,.source_reg=imm?16:src,
        .base=base<16?base:16,.index=index,.scale=1U<<scale,.rip_relative=base==16,
        .displacement_offset=d,.displacement_bytes=dn,.modrm_offset=op+1,.opcode_offset=op};
    memcpy(want->bytes,b,n);return n;
}
static void byte_run(const struct li2_mg_plan *p,const uint64_t r[16],uint64_t flags,uint64_t ea,uint64_t value,int good){
    struct bmg_model_result out;assert(!bmg_model_run(p,r,flags,&out));
    assert(out.rejected==(unsigned)!good&&out.writes==(unsigned)good);
    if(good)assert(out.first==ea&&out.width==1&&out.value==(uint8_t)value);
    assert(out.recoveries&&out.steps<=128);recovered_rows+=out.recoveries;byte_models++;
}
static void byte_specimen(int imm,unsigned src,unsigned base,unsigned index,unsigned scale,unsigned value){
    uint64_t ea=base==17?0x10000:0x70000000;
    if(base<16&&base==index)ea=(1U+(1U<<scale))*UINT64_C(0x10000000)-16;
    unsigned char b[15];struct li2_mg_store want,got,old;
    unsigned n=byte_encode(b,imm,src,base,index,scale,ea,value,&want);
    memset(&got,0xa5,sizeof got);assert(!li2_decoder_byte_mov_store(PC,b,n,&got)&&!memcmp(&got,&want,sizeof got));
    assert(!li2_decoder_mov_store(PC,b,n,&old)&&old.version==1&&!old.ready&&old.refusal);
    struct li2_mg_plan p,q;assert(!li2_bmg_emit(PC,b,n,CODE,SPILL,NEXT,&table,&p)&&!li2_bmg_validate(&p));
    assert(p.version==2&&p.ready==1&&!p.result&&p.boundaries==37&&p.image_bytes<=196&&!memcmp(&p.original,&want,sizeof want));
    assert(li2_mg_emit(PC,b,n,CODE,SPILL,NEXT,&table,&q)==LI2_MG_FORM&&!q.ready);
    assert(li2_mg_validate(&p)==LI2_MG_CORRUPT);
    uint64_t r[16];registers(r,base,index,scale,ea);struct li2_write_registers wr={0};memcpy(wr.gpr,r,sizeof r);
    struct li2_write_footprint f,w={.pc=PC,.next_pc=PC+n,.first=ea,.end=ea+1,.abi_version=1,.policy=2,.code=imm?401:279,.length=n};
    assert(!li2_decoder_write_footprint(PC,b,n,&wr,&f)&&!memcmp(&f,&w,sizeof f));
    byte_run(&p,r,status(byte_rows&63),ea,imm?value:r[src],permitted(ea,1));
    for(unsigned at=0;at<p.image_bytes;at++){
        unsigned j=0;while(j<p.boundaries&&p.boundary[j].offset!=at)j++;
        if(j==p.boundaries){struct li2_mg_recovered x,z={0};uint64_t spill[4]={0};memset(&x,0xa5,sizeof x);
            assert(li2_bmg_recover(&p,CODE+at,r,status(0),spill,&x)==LI2_MG_CORRUPT&&!memcmp(&x,&z,sizeof x));interior_refusals++;}
    }
    byte_rows++;unchanged();
}
static void byte_edges_and_flags(void){
    for(unsigned imm=0;imm<2;imm++){
        unsigned char b[15];struct li2_mg_store want;unsigned n=byte_encode(b,(int)imm,0,7,16,0,0,0xcc,&want);struct li2_mg_plan p;
        assert(!li2_bmg_emit(PC,b,n,CODE,SPILL,NEXT,&table,&p));
        const uint64_t a[]={ranges[0].first-1,ranges[0].first,ranges[0].end-1,ranges[0].end,UINT64_MAX,0x70000000};
        for(unsigned j=0;j<6;j++)for(unsigned f=0;f<64;f++){
            uint64_t r[16];registers(r,7,16,0,a[j]);byte_run(&p,r,status(f),a[j],imm?0xcc:r[0],permitted(a[j],1));
        }
    }
    for(unsigned i=0;i<sizeof ranges/sizeof ranges[0];i++){
        const uint64_t a[]={ranges[i].first-1,ranges[i].first,ranges[i].end-1,ranges[i].end};
        for(unsigned j=0;j<4;j++){assert(li2_bmg_interval_allowed(&table,a[j],1)==permitted(a[j],1));byte_edges++;}
    }
    assert(!li2_bmg_interval_allowed(&table,UINT64_MAX,1));byte_edges++;
    for(unsigned w=0;w<9;w++)if(w!=1){assert(li2_bmg_interval_allowed(&table,0x70000000,w)==-LI2_MG_ARGUMENT);byte_edges++;}
    struct li2_mg_range ranges8[LI2_MG_RANGES];struct li2_mg_table t;
    for(unsigned i=0;i<LI2_MG_RANGES;i++)ranges8[i]=(struct li2_mg_range){UINT64_C(0x50000000)+32*i,UINT64_C(0x50000008)+32*i};
    assert(!li2_mg_table_build(ranges8,LI2_MG_RANGES,TABLE,&t)&&t.count==131&&t.height==8);
    for(unsigned i=0;i<LI2_MG_RANGES;i++){
        assert(li2_bmg_interval_allowed(&t,ranges8[i].first-1,1)==1);
        assert(li2_bmg_interval_allowed(&t,ranges8[i].first,1)==0);
        assert(li2_bmg_interval_allowed(&t,ranges8[i].end,1)==1);byte_edges+=3;
    }
    unsigned char b[15];struct li2_mg_store want;unsigned n=byte_encode(b,1,0,7,16,0,0,0xcc,&want);struct li2_mg_plan p;
    assert(!li2_bmg_emit(PC,b,n,CODE,SPILL,NEXT,&t,&p)&&!li2_bmg_validate(&p));
    const uint64_t a[]={ranges8[0].first-1,ranges8[0].first,ranges8[130].first,ranges8[130].end};
    for(unsigned j=0;j<4;j++){uint64_t r[16];registers(r,7,16,0,a[j]);byte_run(&p,r,status(63-j),a[j],0xcc,j==0||j==3);}
}
static void byte_address_forms(void){
    static const struct form{unsigned n;unsigned char b[10];unsigned imm,src,base,index,scale,d,dn;int64_t displacement;unsigned value;} items[]={
        {2,{0x88,0x07},0,0,7,16,1,0,0,0,0},
        {7,{0xc6,0x85,0x00,0x01,0x00,0x00,0x80},1,16,5,16,1,2,4,256,128},
        {8,{0x47,0x88,0xbc,0xcc,0x00,0xff,0xff,0xff},0,15,12,9,8,4,4,-256,0},
        {9,{0x42,0xc6,0x04,0x8d,0x00,0x00,0x01,0x00,0xff},1,16,16,9,4,4,4,65536,255},
        {4,{0x40,0x88,0x34,0x24},0,6,4,16,1,0,0,0,0},
        {4,{0x41,0xc6,0x00,0xcc},1,16,8,16,1,0,0,0,204}
    };
    for(unsigned i=0;i<sizeof items/sizeof items[0];i++){
        const struct form *a=&items[i];unsigned op=a->b[0]>=0x40&&a->b[0]<=0x4f;
        struct li2_mg_store want={.tf={PC,PC+a->n,1,1,a->imm?401:279,a->n,1,1},.displacement=(uint64_t)a->displacement,
            .immediate=a->value,.version=2,.ready=1,.available=a->n,.width_bytes=1,.source_kind=a->imm?2:1,.source_reg=a->src,
            .base=a->base,.index=a->index,.scale=a->scale,.displacement_offset=a->d,.displacement_bytes=a->dn,.modrm_offset=op+1,.opcode_offset=op},got,old;
        memcpy(want.bytes,a->b,a->n);assert(!li2_decoder_byte_mov_store(PC,a->b,a->n,&got)&&!memcmp(&got,&want,sizeof got));
        assert(!li2_decoder_mov_store(PC,a->b,a->n,&old)&&old.version==1&&!old.ready&&old.refusal);
        struct li2_mg_plan p;assert(!li2_bmg_emit(PC,a->b,a->n,CODE,SPILL,NEXT,&table,&p)&&!li2_bmg_validate(&p)&&!memcmp(&p.original,&want,sizeof want));
        uint64_t r[16];for(unsigned k=0;k<16;k++)r[k]=UINT64_C(0x1234000000000000)+0x101*k;
        if(a->index<16)r[a->index]=3;if(a->base<16)r[a->base]=UINT64_C(0x70000000)-(uint64_t)a->displacement-(a->index<16?r[a->index]*a->scale:0);
        uint64_t ea=(a->base<16?r[a->base]:0)+(a->index<16?r[a->index]*a->scale:0)+(uint64_t)a->displacement;
        byte_run(&p,r,status(i),ea,a->imm?a->value:r[a->src],permitted(ea,1));byte_rows++;unchanged();
    }
}
static void byte_controls(void){
    static const struct{unsigned n;unsigned char b[10];} bad[]={
        {2,{0x88,0xe0}},{2,{0x88,0x20}},{2,{0x88,0x28}},{2,{0x88,0x30}},{2,{0x88,0x38}},
        {3,{0x66,0x88,0x00}},{3,{0x67,0x88,0x00}},{3,{0x64,0x88,0x00}},{3,{0x65,0x88,0x00}},
        {3,{0xf0,0x88,0x00}},{3,{0xf2,0x88,0x00}},{3,{0xf3,0x88,0x00}},{3,{0x48,0x88,0x00}},
        {3,{0x40,0x88,0x00}},{3,{0x42,0x88,0x00}},{7,{0x41,0x88,0x05,0,0,0,0}},
        {4,{0x40,0xc6,0x00,1}},{4,{0x44,0xc6,0x00,1}},{3,{0xc6,0x08,1}},{3,{0xc6,0xc0,1}},
        {2,{0xc6,0x00}},{1,{0x88}},{4,{0x40,0x40,0x88,0x20}},
        {2,{0x89,0x00}},{3,{0x48,0x89,0x00}},{6,{0xc7,0x00,1,0,0,0}},{7,{0x48,0xc7,0x00,1,0,0,0}}
    };
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){
        struct li2_mg_store d;struct li2_mg_plan p;
        assert(!li2_decoder_byte_mov_store(PC,bad[i].b,bad[i].n,&d)&&d.version==2&&!d.ready&&d.refusal);
        assert(li2_bmg_emit(PC,bad[i].b,bad[i].n,CODE,SPILL,NEXT,&table,&p)==LI2_MG_FORM&&!p.ready);byte_refusals++;
    }
    unsigned char b[15];struct li2_mg_store want;unsigned n=byte_encode(b,0,0,7,16,0,0,0,&want);struct li2_mg_plan p,q;
    assert(!li2_bmg_emit(PC,b,n,CODE,SPILL,NEXT,&table,&p));
    const size_t fields[]={offsetof(struct li2_mg_plan,version),offsetof(struct li2_mg_plan,ready),offsetof(struct li2_mg_plan,result),
        offsetof(struct li2_mg_plan,store_offset),offsetof(struct li2_mg_plan,reject_offset),offsetof(struct li2_mg_plan,scratch_regs),
        offsetof(struct li2_mg_plan,original)+offsetof(struct li2_mg_store,width_bytes),offsetof(struct li2_mg_plan,original)+offsetof(struct li2_mg_store,source_reg),
        offsetof(struct li2_mg_plan,original)+offsetof(struct li2_mg_store,bytes),offsetof(struct li2_mg_plan,table)+offsetof(struct li2_mg_table,root),
        offsetof(struct li2_mg_plan,boundary),offsetof(struct li2_mg_plan,boundary)+8,offsetof(struct li2_mg_plan,boundary)+12,
        offsetof(struct li2_mg_plan,boundary)+16,offsetof(struct li2_mg_plan,boundary)+20,offsetof(struct li2_mg_plan,image)};
    for(unsigned i=0;i<sizeof fields/sizeof fields[0];i++){q=p;((unsigned char *)&q)[fields[i]]^=1;assert(li2_bmg_validate(&q)==LI2_MG_CORRUPT);byte_corruptions++;}
    q=p;q.image[p.image_bytes]=1;assert(li2_bmg_validate(&q)==LI2_MG_CORRUPT);byte_corruptions++;
    assert(li2_bmg_emit(PC,b,n,CODE,UINT64_C(0x200000000),NEXT,&table,&q)==LI2_MG_RELOCATION&&!q.ready);byte_refusals++;
    assert(li2_bmg_emit(PC,b,n,CODE,SPILL,UINT64_C(0x200000000),&table,&q)==LI2_MG_RELOCATION&&!q.ready);byte_refusals++;
    n=byte_encode(b,1,0,16,16,0,0x70000000,0xcc,&want);
    assert(li2_bmg_emit(PC,b,n,UINT64_C(0x200000000),UINT64_C(0x200002000),UINT64_C(0x200001000),&table,&q)==LI2_MG_RELOCATION&&!q.ready);byte_refusals++;
    unchanged();
}
static struct li2_region_operand imul_reg(unsigned r,unsigned a){return(struct li2_region_operand){.kind=1,.reg=r,.width_bits=64,.access=a};}
static void imul_reject(const unsigned char *b,unsigned n){
    struct li2_span_decoded got,want={0};struct li2_write_footprint f,w={0};
    assert(!li2_decoder_loop_scalar_describe(PC,b,n,&got)&&!got.ready&&got.refusal&&got.version==3);
    assert(!li2_decoder_decode(PC,b,n,&want.decoded));want.version=3;want.refusal=got.refusal;
    assert(!memcmp(&got,&want,sizeof got));w=(struct li2_write_footprint){.pc=want.decoded.pc,.next_pc=want.decoded.next_pc,.abi_version=1,.code=want.decoded.code,.length=want.decoded.length};
    assert(!li2_decoder_loop_scalar_none(PC,b,n,&f)&&!memcmp(&f,&w,sizeof f));imul_refusals++;unchanged();
}
static void imul_descriptors(void){
    for(unsigned dst=0;dst<16;dst++)for(unsigned src=0;src<16;src++){
        unsigned char b[]={0x48|(dst>=8?4:0)|(src>=8?1:0),0x0f,0xaf,0xc0|((dst&7)<<3)|(src&7)};
        if(dst==4){imul_reject(b,4);continue;}
        struct li2_span_decoded want={.version=3,.ready=1,.condition=16,.operand_count=2,.register_count=2,
            .gpr_read=(1U<<dst)|(1U<<src),.gpr_write=1U<<dst,.flags_written=1|2048,.flags_undefined=4|16|64|128},got,old;
        assert(!li2_decoder_decode(PC,b,4,&want.decoded)&&want.decoded.decode_status==LI2_VALID&&want.decoded.code==2072&&want.decoded.length==4);
        want.operands[0]=imul_reg(dst,3);want.operands[1]=imul_reg(src,1);
        want.registers[0]=(struct li2_region_register){dst,64,3,0};want.registers[1]=(struct li2_region_register){src,64,1,0};
        assert(!li2_decoder_loop_scalar_describe(PC,b,4,&got)&&!memcmp(&got,&want,sizeof got));
        assert(!li2_decoder_scalar_read_describe(PC,b,4,&old)&&old.version==2&&!old.ready&&old.refusal);
        assert(!li2_decoder_span_describe(PC,b,4,&old)&&old.version==1&&!old.ready&&old.refusal);
        struct li2_write_footprint f,w={.pc=PC,.next_pc=PC+4,.abi_version=1,.policy=1,.code=2072,.length=4};
        assert(!li2_decoder_loop_scalar_none(PC,b,4,&f)&&!memcmp(&f,&w,sizeof f));
        assert(!li2_decoder_scalar_read_none(PC,b,4,&f)&&!f.policy&&!f.first&&!f.end);imul_rows++;unchanged();
    }
    static const struct{unsigned n;unsigned char b[8];} bad[]={
        {3,{0x0f,0xaf,0xc6}},{4,{0x66,0x0f,0xaf,0xc6}},{5,{0x66,0x48,0x0f,0xaf,0xc6}},
        {4,{0x4a,0x0f,0xaf,0xc6}},{5,{0x48,0x48,0x0f,0xaf,0xc6}},{5,{0xf0,0x48,0x0f,0xaf,0xc6}},
        {5,{0xf3,0x48,0x0f,0xaf,0xc6}},{5,{0x64,0x48,0x0f,0xaf,0xc6}},{5,{0x67,0x48,0x0f,0xaf,0xc6}},
        {4,{0x48,0x0f,0xaf,0x06}},{4,{0x48,0x6b,0xc6,2}},{3,{0x48,0xf7,0xee}},{3,{0x48,0x0f,0xaf}}
    };for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++)imul_reject(bad[i].b,bad[i].n);
    static const struct{unsigned n;unsigned char b[8];} legacy[]={
        {3,{0x48,0x89,0xd8}},{4,{0x48,0x83,0xc0,1}},{3,{0x48,0x8b,0x03}},{2,{0x75,0xfe}},
        {2,{0x3c,0x7f}},{3,{0x48,0x63,0xc0}},{3,{0x40,0x84,0xe4}},{3,{0x80,0x38,0x3d}},{3,{0x0f,0x1f,0}}
    };for(unsigned i=0;i<sizeof legacy/sizeof legacy[0];i++){
        struct li2_span_decoded a,b;struct li2_write_footprint x,y;
        assert(!li2_decoder_scalar_read_describe(PC,legacy[i].b,legacy[i].n,&a)&&a.ready);
        assert(!li2_decoder_loop_scalar_describe(PC,legacy[i].b,legacy[i].n,&b));a.version=3;assert(!memcmp(&a,&b,sizeof a));
        assert(!li2_decoder_scalar_read_none(PC,legacy[i].b,legacy[i].n,&x)&&!li2_decoder_loop_scalar_none(PC,legacy[i].b,legacy[i].n,&y)&&!memcmp(&x,&y,sizeof x));scalar_legacy++;
    }
    unsigned char *m=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(m!=MAP_FAILED&&!mprotect(m+4096,4096,PROT_NONE));
    const unsigned char mul[]={0x48,0x0f,0xaf,0xc6};for(unsigned n=1;n<4;n++){memcpy(m+4096-n,mul,n);imul_reject(m+4096-n,n);}assert(!munmap(m,8192));
}
int main(void){
    assert(!old_mov_main());
    for(unsigned base=0;base<16;base++)for(unsigned src=0;src<16;src++)byte_specimen(0,src,base,16,0,0);
    for(unsigned base=0;base<16;base++)for(unsigned v=0;v<4;v++)byte_specimen(1,0,base,16,0,(unsigned[]){0,1,0x80,0xff}[v]);
    for(unsigned ix=0;ix<16;ix++)if(ix!=4)for(unsigned scale=0;scale<4;scale++)byte_specimen(0,15,7,ix,scale,0);
    for(unsigned imm=0;imm<2;imm++)for(unsigned base=16;base<=17;base++)byte_specimen((int)imm,9,base,16,0,0xcc);
    byte_address_forms();byte_edges_and_flags();byte_controls();imul_descriptors();unchanged();
    assert(byte_rows==390&&byte_models==1162&&byte_refusals==30&&byte_corruptions==17&&byte_edges==426);
    assert(imul_rows==240&&imul_refusals==32&&scalar_legacy==9&&recovered_rows&&interior_refusals);
    printf("{\"schema\":1,\"descriptor_version\":3,\"byte_guard_version\":2,\"byte_descriptors\":390,\"byte_models\":1162,\"byte_refusals\":30,\"byte_corruptions\":17,\"interval_edges\":426,\"imul_descriptors\":240,\"imul_refusals\":32,\"scalar_legacy\":9,\"recovery_checks\":%llu,\"interior_refusals\":%llu,\"postseal_equal\":1,\"instruction_execution\":0,\"owner_execution\":0}\n",(unsigned long long)recovered_rows,(unsigned long long)interior_refusals);
    return 0;
}
