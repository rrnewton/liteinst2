/* Source/byte-model component: no emitted application instruction executes. */
#include "linked_add_guard.h"
#include "write_footprint.h"
#include "model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_decoder_stats initial;
static unsigned descriptors,models,refusals,corruptions,edge_checks;
static const uint64_t PC=UINT64_C(0x400100),CODE=UINT64_C(0x10000000),SPILL=UINT64_C(0x10002000),TABLE=UINT64_C(0x10004000),NEXT=UINT64_C(0x10001000);
static const struct li2_mg_range ranges[]={
    {UINT64_C(0x70001008),UINT64_C(0x70001010)}, /* actual shape of cs publication word */
    {UINT64_C(0x400000),UINT64_C(0x402000)},
    {UINT64_C(0x10000000),UINT64_C(0x10001000)},
    {UINT64_C(0x10002000),UINT64_C(0x10003000)},
    {UINT64_C(0x10004000),UINT64_C(0x10006000)},
    {UINT64_C(0x60000000),UINT64_C(0x60001000)}
};
static struct li2_mg_table table;
static void put32(unsigned char *b,uint32_t x){for(unsigned i=0;i<4;i++)b[i]=(unsigned char)(x>>(i*8));}
static uint64_t status(unsigned n){static const unsigned bit[]={0,2,4,6,7,11};uint64_t f=UINT64_C(0x202)|((uint64_t)(n&1)<<10)|((uint64_t)(n&2)<<20);for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bit[i];return f;}
static int permitted(uint64_t a,unsigned width){
    if(a>UINT64_MAX-width)return 0;
    for(unsigned i=0;i<sizeof ranges/sizeof ranges[0];i++)if(a<ranges[i].end && ranges[i].first<a+width)return 0;
    return 1;
}
/* Independent specimen constructor: disp8 except RIP/absolute disp32.
   index==16 means absent; base==16 means RIP, base==17 absolute SIB. */
static unsigned encode(unsigned char b[15],unsigned source,unsigned base,unsigned index,unsigned scale,uint64_t target){
    memset(b,0,15);unsigned rex=0x48|(source>=8?4:0)|(index<16 && index>=8?2:0)|(base<16 && base>=8?1:0),n=0;
    b[n++]=(unsigned char)rex;b[n++]=0x01;unsigned reg=source&7;
    if(base==16){b[n++]=(unsigned char)((reg<<3)|5);unsigned d=n;n+=4;
        int64_t delta=(int64_t)target-(int64_t)(PC+n);assert(delta>=INT32_MIN && delta<=INT32_MAX);put32(b+d,(uint32_t)delta);return n;}
    if(base==17){b[n++]=(unsigned char)((reg<<3)|4);b[n++]=0x25;put32(b+n,(uint32_t)target);n+=4;}
    else if(index<16 || (base&7)==4){
        b[n++]=(unsigned char)(0x40|(reg<<3)|4);b[n++]=(unsigned char)((scale<<6)|((index<16?index&7:4)<<3)|(base&7));b[n++]=0xf0;
    }else{b[n++]=(unsigned char)(0x40|(reg<<3)|(base&7));b[n++]=0xf0;}return n;
}
static void put64(unsigned char *b,uint64_t x){for(unsigned i=0;i<8;i++)b[i]=(unsigned char)(x>>(8*i));}
static uint64_t get64(const unsigned char *b){uint64_t x=0;for(unsigned i=0;i<8;i++)x|=(uint64_t)b[i]<<(8*i);return x;}
static void run_expected(const struct li2_ag_plan *p,const uint64_t regs[16],uint64_t flags,uint64_t target,uint64_t old,int good){
    struct model_input in={.base=target,.readable=UINT32_MAX,.writable=UINT32_MAX};
    for(unsigned i=0;i<32;i++)in.bytes[i]=(unsigned char)(i*7+3);put64(in.bytes,old);
    struct model_result out;assert(!model_run(p,regs,flags,&in,&out));
    assert(out.rejected==(unsigned)!good && out.writes==(unsigned)good && !out.fault);
    if(good){assert(out.first==target && out.width==8 && out.value==old+regs[p->original.source_reg]);
        assert(get64(out.memory)==out.value && !memcmp(out.memory+8,in.bytes+8,24));
        assert((out.flags&~LI2_AG_STATUS)==(flags&~LI2_AG_STATUS));}
    else {
        /* External backing remains untouched; for a numeric private alias it
           is NOT the target. Observe the actual resolved bytes separately. */
        assert(!memcmp(out.memory,in.bytes,32));
        if(target>=SPILL && target-SPILL<=24){
            for(unsigned i=0;i<4;i++)assert(out.spill[i]==regs[p->scratch_regs[i]]);
            unsigned char saved[32];for(unsigned i=0;i<4;i++)put64(saved+8*i,out.spill[i]);
            assert(out.resolved_mask==255 && !memcmp(out.resolved,saved+(target-SPILL),8));
        }else if(target==TABLE)assert(out.resolved_mask==255 && !memcmp(out.resolved,&p->table,8));
    }
    assert(out.recoveries && out.steps<=128);++models;
}
static void run(const struct li2_ag_plan *p,const uint64_t regs[16],uint64_t flags,uint64_t target,uint64_t old){
    run_expected(p,regs,flags,target,old,permitted(target,8));
}
static void registers(uint64_t r[16],unsigned base,unsigned index,unsigned scale,uint64_t target){
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234000000000000)+UINT64_C(0x100010001)*i;
    if(base<16 && base==index){
        unsigned factor=1U+(1U<<scale);assert((target+16)%factor==0);r[base]=(target+16)/factor;
    }else{
        if(index<16)r[index]=3;
        if(base<16)r[base]=target+16-(index<16?(r[index]<<scale):0);
    }
}
static void specimen(unsigned source,unsigned base,unsigned index,unsigned scale){
    unsigned char bytes[15];uint64_t target=base==17?UINT64_C(0x10000):UINT64_C(0x70000000);
    if(base<16 && base==index)target=(1U+(1U<<scale))*UINT64_C(0x10000000)-16;
    unsigned n=encode(bytes,source,base,index,scale,target);struct li2_ag_plan p;
    assert(!li2_ag_emit(PC,bytes,n,CODE,SPILL,NEXT,&table,&p));assert(!li2_ag_validate(&p));
    assert(p.boundaries==37 && p.image_bytes<=196);
    const struct li2_ag_descriptor *s=&p.original;
    assert(s->tf.code==8 && s->tf.length==n && s->tf.next_pc==PC+n && s->tf.policy==1);
    assert(s->width_bytes==8 && s->memory_access==LI2_AG_READ_WRITE && s->source_reg==source && s->flags_written==LI2_AG_STATUS);
    assert(s->base==(base<16?base:16) && s->index==index && s->scale==(1U<<scale) && s->rip_relative==(unsigned)(base==16));
    if(base==16)assert(s->rip_target==target);else if(base==17)assert(s->displacement==target);else assert(s->displacement==UINT64_MAX-15);
    uint64_t r[16];registers(r,base,index,scale,target);
    struct li2_write_registers regs={0};memcpy(regs.gpr,r,sizeof r);struct li2_write_footprint footprint={0};
    assert(!li2_decoder_write_footprint(PC,bytes,n,&regs,&footprint) && footprint.policy==LI2_WRITE_RANGE && footprint.first==target && footprint.end==target+8 && footprint.code==8);
    run(&p,r,status(descriptors&63),target,UINT64_C(0x7fffffffffffffff));++descriptors;
}
static void flag_edges(void){
    unsigned char b[15];unsigned n=encode(b,0,7,16,0,0);struct li2_ag_plan p;
    assert(!li2_ag_emit(PC,b,n,CODE,SPILL,NEXT,&table,&p));
    uint64_t L=ranges[0].first,U=ranges[0].end;
    const uint64_t targets[]={L-8,L-7,L-1,L,U-1,U,U+1,ranges[5].first,UINT64_MAX-3,UINT64_C(0x70000000)};
    for(unsigned j=0;j<10;j++)for(unsigned f=0;f<64;f++){
        uint64_t r[16];registers(r,7,16,0,targets[j]);run(&p,r,status(f),targets[j],UINT64_MAX);
    }
    const uint64_t v[]={0,1,15,16,UINT64_MAX,UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000001)};
    for(unsigned a=0;a<8;a++)for(unsigned s=0;s<8;s++)for(unsigned f=0;f<64;f++){
        uint64_t r[16];registers(r,7,16,0,targets[9]);r[0]=v[s];run(&p,r,status(f),targets[9],v[a]);
    }
    /* These numeric aliases are rejected before any ADD read/write; modeled
       private saves still really update that same shared address space. */
    const uint64_t alias[]={SPILL,SPILL+7,TABLE,PC};
    for(unsigned i=0;i<4;i++){uint64_t r[16];registers(r,7,16,0,alias[i]);run(&p,r,status(63),alias[i],123);}
    /* Synthetic read/write faults preserve before-state; actual split-page
       fault effects are compared separately by the native component. */
    for(unsigned mode=0;mode<3;mode++){
        uint64_t r[16];registers(r,7,16,0,targets[9]);struct model_input in={.base=targets[9],.readable=mode?UINT32_MAX:0,.writable=mode==2?15:0};
        memset(in.bytes,0x5a,32);struct model_result out;assert(!model_run(&p,r,status(63),&in,&out));
        assert(out.fault==(mode?2U:1U) && !out.writes && !out.rejected && !memcmp(out.memory,in.bytes,32));++models;
    }
    const unsigned char actual[]={0x4d,0x01,0x75,0x00};
    assert(!li2_ag_emit(0x10021,actual,sizeof actual,CODE,SPILL,NEXT,&table,&p));
    uint64_t r[16];registers(r,13,16,0,targets[9]-16);r[13]=targets[9];r[14]=1;
    run(&p,r,status(63),targets[9],UINT64_MAX);++descriptors;
}
static void tables(void){
    for(unsigned i=0;i<sizeof ranges/sizeof ranges[0];i++)for(unsigned w=4;w<=8;w+=4){
        const uint64_t a[]={ranges[i].first-w,ranges[i].first-w+1,ranges[i].first,ranges[i].end-1,ranges[i].end,ranges[i].end+1};
        for(unsigned j=0;j<6;j++){assert(li2_mg_interval_allowed(&table,a[j],w)==permitted(a[j],w));++edge_checks;}
    }
    struct li2_mg_range full[LI2_MG_RANGES];struct li2_mg_table t;
    for(unsigned i=0;i<LI2_MG_RANGES;i++)full[i]=(struct li2_mg_range){UINT64_C(0x50000000)+32*i,UINT64_C(0x50000000)+32*i+8};
    assert(!li2_mg_table_build(full,LI2_MG_RANGES,TABLE,&t) && t.count==131 && t.height==8 && !li2_mg_table_validate(&t));
    for(unsigned i=0;i<LI2_MG_RANGES;i++){assert(!li2_mg_interval_allowed(&t,full[i].first,4));assert(li2_mg_interval_allowed(&t,full[i].first-4,4)==1);assert(li2_mg_interval_allowed(&t,full[i].end,8)==1);edge_checks+=3;}
    /* Exercise the actual emitted traversal at maximum tree height as well
       as the independent complete interval census above. */
    {
        unsigned char b[15];unsigned n=encode(b,0,7,16,0,0);struct li2_ag_plan p;
        assert(!li2_ag_emit(PC,b,n,CODE,SPILL,NEXT,&t,&p) && !li2_ag_validate(&p));
        const uint64_t a[]={full[0].first-8,full[0].first,full[130].first,full[130].end};
        for(unsigned j=0;j<4;j++){
            int good=1;for(unsigned k=0;k<LI2_MG_RANGES;k++)if(a[j]<full[k].end && full[k].first<a[j]+8)good=0;
            uint64_t r[16];registers(r,7,16,0,a[j]);run_expected(&p,r,status(63-j),a[j],17,good);
        }
    }
    const struct li2_mg_range overlap[]={{100,200},{150,250},{250,300},{301,400}};
    assert(!li2_mg_table_build(overlap,4,TABLE,&t) && t.count==2 && t.node[0].first==100 && t.node[0].end==300 && t.node[1].first==301);
    assert(li2_mg_table_validate(&t)==0);t.node[0].end=301;assert(li2_mg_table_validate(&t)==LI2_MG_CORRUPT);++corruptions;
    t=table;t.node[0].left=t.root;assert(li2_mg_table_validate(&t)==LI2_MG_CORRUPT);++corruptions;
    t=table;t.height++;assert(li2_mg_table_validate(&t)==LI2_MG_CORRUPT);++corruptions;
    t=table;t.node[t.count].end=1;assert(li2_mg_table_validate(&t)==LI2_MG_CORRUPT);++corruptions;
}
static void controls(void){
    const struct{unsigned n;unsigned char b[8];} bad[]={
        {3,{0x48,0x01,0xc0}},{3,{0x48,0x03,0x07}},{2,{0x01,0x07}},{4,{0x66,0x48,0x01,0x07}},
        {4,{0xf0,0x48,0x01,0x07}},{4,{0x64,0x48,0x01,0x07}},{4,{0x65,0x48,0x01,0x07}},{4,{0x67,0x48,0x01,0x07}},
        {4,{0x48,0x48,0x01,0x07}},{3,{0x48,0x89,0x07}},{1,{0x01}},{3,{0xc5,0xf9,0x7f}},
        {4,{0x48,0x83,0x07,0x20}},{7,{0x48,0x81,0x07,1,0,0,0}},
        {4,{0xf3,0x48,0x01,0x07}},{4,{0xf2,0x48,0x01,0x07}},
        {8,{0x48,0x83,0x85,0x48,0xff,0xff,0xff,0x20}}
    };
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){struct li2_ag_plan p;int e=li2_ag_emit(PC,bad[i].b,bad[i].n,CODE,SPILL,NEXT,&table,&p);assert(e==LI2_AG_FORM && !p.ready);++refusals;}
    const unsigned char b[]={0x48,0x01,0x47,0xf0};struct li2_ag_plan p,q;assert(!li2_ag_emit(PC,b,sizeof b,CODE,SPILL,NEXT,&table,&p));
    const size_t at[]={offsetof(struct li2_ag_plan,version),offsetof(struct li2_ag_plan,rmw_offset),offsetof(struct li2_ag_plan,reject_offset),
        offsetof(struct li2_ag_plan,scratch_regs),offsetof(struct li2_ag_plan,original)+offsetof(struct li2_ag_descriptor,source_reg),
        offsetof(struct li2_ag_plan,original)+offsetof(struct li2_ag_descriptor,flags_written),
        offsetof(struct li2_ag_plan,original)+offsetof(struct li2_ag_descriptor,memory_access),
        offsetof(struct li2_ag_plan,original)+offsetof(struct li2_ag_descriptor,bytes),offsetof(struct li2_ag_plan,table)+offsetof(struct li2_mg_table,root),
        offsetof(struct li2_ag_plan,boundary),offsetof(struct li2_ag_plan,boundary)+8,offsetof(struct li2_ag_plan,boundary)+12,
        offsetof(struct li2_ag_plan,boundary)+16,offsetof(struct li2_ag_plan,boundary)+20,offsetof(struct li2_ag_plan,image)};
    for(unsigned i=0;i<sizeof at/sizeof at[0];i++){q=p;((unsigned char *)&q)[at[i]]^=1;assert(li2_ag_validate(&q)==LI2_AG_CORRUPT);++corruptions;}
    for(unsigned i=0;i<p.boundaries;i++)if(p.boundary[i].phase==LI2_AG_AFTER){q=p;q.boundary[i].phase=LI2_AG_BEFORE;assert(li2_ag_validate(&q)==LI2_AG_CORRUPT);++corruptions;break;}
    q=p;q.image[p.image_bytes]=1;assert(li2_ag_validate(&q)==LI2_AG_CORRUPT);++corruptions;
    assert(li2_ag_emit(PC,b,sizeof b,CODE,UINT64_C(0x200000000),NEXT,&table,&q)==LI2_AG_RELOCATION && !q.ready);++refusals;
    assert(li2_ag_emit(PC,b,sizeof b,CODE,CODE+16,NEXT,&table,&q)==LI2_AG_ARGUMENT && !q.ready);++refusals;
    unsigned char rip[]={0x48,0x01,0x05,0,0,0,0};put32(rip+3,(uint32_t)(UINT64_C(0x70000000)-PC-sizeof rip));
    assert(li2_ag_emit(PC,rip,sizeof rip,UINT64_C(0x200000000),UINT64_C(0x200002000),UINT64_C(0x200001000),&table,&q)==LI2_AG_RELOCATION && !q.ready);++refusals;
}
int main(void){
    assert(!li2_decoder_initialize(arena,sizeof arena,&initial) && initial.phase==2 && !initial.first_fatal_reason);
    assert(!li2_mg_table_build(ranges,sizeof ranges/sizeof ranges[0],TABLE,&table));
    for(unsigned base=0;base<16;base++)for(unsigned source=0;source<16;source++)specimen(source,base,16,0);
    for(unsigned ix=0;ix<16;ix++)if(ix!=4)for(unsigned scale=0;scale<4;scale++)specimen(15,7,ix,scale);
    for(unsigned source=0;source<16;source++)for(unsigned base=16;base<=17;base++)specimen(source,base,16,0);
    flag_edges();tables();controls();struct li2_decoder_stats final;assert(!li2_decoder_stats(&final) && !memcmp(&initial,&final,sizeof final));
    assert(descriptors==349 && models==5096 && refusals==20 && corruptions==21 && edge_checks==465);
    printf("{\"schema\":1,\"add_codes\":1,\"descriptors\":349,\"byte_models\":5096,\"refusals\":20,\"corruptions\":21,\"interval_edges\":465,\"max_tree_height\":8,\"postseal_equal\":1,\"emitted_instruction_execution\":0}\n");return 0;
}
