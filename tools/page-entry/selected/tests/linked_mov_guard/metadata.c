/* Source/byte-model component: no emitted application instruction executes. */
#include "linked_mov_guard.h"
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
static unsigned encode(unsigned char b[15],unsigned width,int immediate,unsigned source,unsigned base,unsigned index,unsigned scale,uint64_t target,uint32_t value){
    memset(b,0,15);unsigned rex=0x40|(width==8?8:0)|(!immediate && source>=8?4:0)|(index<16 && index>=8?2:0)|(base<16 && base>=8?1:0),n=0;
    if(rex!=0x40)b[n++]=(unsigned char)rex;b[n++]=(unsigned char)(immediate?0xc7:0x89);
    unsigned reg=immediate?0:source&7;
    if(base==16){b[n++]=(unsigned char)((reg<<3)|5);unsigned d=n;n+=4;if(immediate)n+=4;
        int64_t delta=(int64_t)target-(int64_t)(PC+n);assert(delta>=INT32_MIN && delta<=INT32_MAX);put32(b+d,(uint32_t)delta);if(immediate)put32(b+n-4,value);return n;}
    if(base==17){b[n++]=(unsigned char)((reg<<3)|4);b[n++]=0x25;put32(b+n,(uint32_t)target);n+=4;}
    else if(index<16 || (base&7)==4){
        b[n++]=(unsigned char)(0x40|(reg<<3)|4);b[n++]=(unsigned char)((scale<<6)|((index<16?index&7:4)<<3)|(base&7));b[n++]=0xf0;
    }else{b[n++]=(unsigned char)(0x40|(reg<<3)|(base&7));b[n++]=0xf0;}
    if(immediate){put32(b+n,value);n+=4;}return n;
}
static void run_expected(const struct li2_mg_plan *p,const uint64_t regs[16],uint64_t flags,uint64_t target,uint64_t value,int good){
    struct model_result out;assert(!model_run(p,regs,flags,&out));
    assert(out.rejected==(unsigned)!good && out.writes==(unsigned)good);
    if(good)assert(out.first==target && out.width==p->original.width_bytes && out.value==value);
    assert(out.recoveries && out.steps<=128);++models;
}
static void run(const struct li2_mg_plan *p,const uint64_t regs[16],uint64_t flags,uint64_t target,uint64_t value){
    run_expected(p,regs,flags,target,value,permitted(target,p->original.width_bytes));
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
static void specimen(unsigned width,int immediate,unsigned source,unsigned base,unsigned index,unsigned scale,uint32_t value){
    unsigned char bytes[15];uint64_t target=base==17?UINT64_C(0x10000):UINT64_C(0x70000000);
    if(base<16 && base==index)target=(1U+(1U<<scale))*UINT64_C(0x10000000)-16;
    unsigned n=encode(bytes,width,immediate,source,base,index,scale,target,value);struct li2_mg_plan p;
    assert(!li2_mg_emit(PC,bytes,n,CODE,SPILL,NEXT,&table,&p));assert(!li2_mg_validate(&p));
    assert(p.boundaries==37 && p.image_bytes<=196);
    const struct li2_mg_store *s=&p.original;
    unsigned code=immediate?(width==8?405:404):(width==8?282:281);
    assert(s->tf.code==code && s->tf.length==n && s->tf.next_pc==PC+n && s->tf.policy==1);
    assert(s->width_bytes==width && s->source_kind==(unsigned)(immediate?2:1) && s->source_reg==(immediate?16:source));
    assert(s->base==(base<16?base:16) && s->index==index && s->scale==(1U<<scale) && s->rip_relative==(unsigned)(base==16));
    if(base==16)assert(s->rip_target==target);else if(base==17)assert(s->displacement==target);else assert(s->displacement==UINT64_MAX-15);
    uint64_t r[16];registers(r,base,index,scale,target);
    struct li2_write_registers regs={0};memcpy(regs.gpr,r,sizeof r);struct li2_write_footprint footprint={0};
    assert(!li2_decoder_write_footprint(PC,bytes,n,&regs,&footprint) && footprint.policy==LI2_WRITE_RANGE && footprint.first==target && footprint.end==target+width && footprint.code==code);
    uint64_t expected=immediate?(width==8?(uint64_t)(int64_t)(int32_t)value:value):(width==8?r[source]:(uint32_t)r[source]);
    assert(s->immediate==(immediate?expected:0));run(&p,r,status(descriptors&63),target,expected);++descriptors;
}
static void flag_edges(void){
    for(unsigned width=4;width<=8;width+=4)for(unsigned immediate=0;immediate<2;immediate++){
        unsigned char b[15];unsigned n=encode(b,width,(int)immediate,0,7,16,0,0,UINT32_C(0x80000001));struct li2_mg_plan p;
        assert(!li2_mg_emit(PC,b,n,CODE,SPILL,NEXT,&table,&p));
        uint64_t L=ranges[0].first,U=ranges[0].end;
        const uint64_t targets[]={L-width,L-width+1,L-1,L,U-1,U,U+1,ranges[5].first,UINT64_MAX-3,UINT64_C(0x70000000)};
        for(unsigned j=0;j<10;j++)for(unsigned f=0;f<64;f++){
            uint64_t r[16];registers(r,7,16,0,targets[j]);uint64_t v=immediate?(width==8?UINT64_C(0xffffffff80000001):UINT64_C(0x80000001)):(width==8?r[0]:(uint32_t)r[0]);
            run(&p,r,status(f),targets[j],v);
        }
    }
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
    for(unsigned w=4;w<=8;w+=4){
        unsigned char b[15];unsigned n=encode(b,w,0,0,7,16,0,0,0);struct li2_mg_plan p;
        assert(!li2_mg_emit(PC,b,n,CODE,SPILL,NEXT,&t,&p) && !li2_mg_validate(&p));
        const uint64_t a[]={full[0].first-w,full[0].first,full[130].first,full[130].end};
        for(unsigned j=0;j<4;j++){
            int good=1;for(unsigned k=0;k<LI2_MG_RANGES;k++)if(a[j]<full[k].end && full[k].first<a[j]+w)good=0;
            uint64_t r[16];registers(r,7,16,0,a[j]);run_expected(&p,r,status(63-j),a[j],w==4?(uint32_t)r[0]:r[0],good);
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
        {2,{0x89,0xc0}},{3,{0x48,0x8b,0x07}},{2,{0x88,0x07}},{3,{0x66,0x89,0x07}},
        {3,{0xf0,0x89,0x07}},{3,{0x64,0x89,0x07}},{3,{0x65,0x89,0x07}},{3,{0x67,0x89,0x07}},
        {4,{0x48,0x48,0x89,0x07}},{3,{0x48,0x01,0x07}},{1,{0x89}},{3,{0xc5,0xf9,0x7f}}
    };
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){struct li2_mg_plan p;int e=li2_mg_emit(PC,bad[i].b,bad[i].n,CODE,SPILL,NEXT,&table,&p);assert(e==LI2_MG_FORM && !p.ready);++refusals;}
    const unsigned char b[]={0x48,0x89,0x47,0xf0};struct li2_mg_plan p,q;assert(!li2_mg_emit(PC,b,sizeof b,CODE,SPILL,NEXT,&table,&p));
    const size_t at[]={offsetof(struct li2_mg_plan,version),offsetof(struct li2_mg_plan,store_offset),offsetof(struct li2_mg_plan,reject_offset),
        offsetof(struct li2_mg_plan,scratch_regs),offsetof(struct li2_mg_plan,original)+offsetof(struct li2_mg_store,source_reg),
        offsetof(struct li2_mg_plan,original)+offsetof(struct li2_mg_store,bytes),offsetof(struct li2_mg_plan,table)+offsetof(struct li2_mg_table,root),
        offsetof(struct li2_mg_plan,boundary),offsetof(struct li2_mg_plan,boundary)+8,offsetof(struct li2_mg_plan,boundary)+12,
        offsetof(struct li2_mg_plan,boundary)+16,offsetof(struct li2_mg_plan,boundary)+20,offsetof(struct li2_mg_plan,image)};
    for(unsigned i=0;i<sizeof at/sizeof at[0];i++){q=p;((unsigned char *)&q)[at[i]]^=1;assert(li2_mg_validate(&q)==LI2_MG_CORRUPT);++corruptions;}
    for(unsigned i=0;i<p.boundaries;i++)if(p.boundary[i].phase==LI2_MG_AFTER){q=p;q.boundary[i].phase=LI2_MG_BEFORE;assert(li2_mg_validate(&q)==LI2_MG_CORRUPT);++corruptions;break;}
    q=p;q.image[p.image_bytes]=1;assert(li2_mg_validate(&q)==LI2_MG_CORRUPT);++corruptions;
    assert(li2_mg_emit(PC,b,sizeof b,CODE,UINT64_C(0x200000000),NEXT,&table,&q)==LI2_MG_RELOCATION && !q.ready);++refusals;
    assert(li2_mg_emit(PC,b,sizeof b,CODE,CODE+16,NEXT,&table,&q)==LI2_MG_ARGUMENT && !q.ready);++refusals;
    unsigned char rip[]={0x48,0x89,0x05,0,0,0,0};put32(rip+3,(uint32_t)(UINT64_C(0x70000000)-PC-sizeof rip));
    assert(li2_mg_emit(PC,rip,sizeof rip,UINT64_C(0x200000000),UINT64_C(0x200002000),UINT64_C(0x200001000),&table,&q)==LI2_MG_RELOCATION && !q.ready);++refusals;
}
int main(void){
    assert(!li2_decoder_initialize(arena,sizeof arena,&initial) && initial.phase==2 && !initial.first_fatal_reason);
    assert(!li2_mg_table_build(ranges,sizeof ranges/sizeof ranges[0],TABLE,&table));
    for(unsigned w=4;w<=8;w+=4)for(unsigned base=0;base<16;base++)for(unsigned source=0;source<16;source++)specimen(w,0,source,base,16,0,0);
    for(unsigned w=4;w<=8;w+=4)for(unsigned base=0;base<16;base++)for(unsigned v=0;v<2;v++)specimen(w,1,0,base,16,0,v?UINT32_C(0x80000001):UINT32_C(0x12345678));
    for(unsigned w=4;w<=8;w+=4)for(unsigned ix=0;ix<16;ix++)if(ix!=4)for(unsigned scale=0;scale<4;scale++)specimen(w,0,15,7,ix,scale,0);
    for(unsigned w=4;w<=8;w+=4)for(unsigned imm=0;imm<2;imm++)for(unsigned base=16;base<=17;base++)specimen(w,(int)imm,9,base,16,0,UINT32_C(0x80000001));
    flag_edges();tables();controls();struct li2_decoder_stats final;assert(!li2_decoder_stats(&final) && !memcmp(&initial,&final,sizeof final));
    assert(descriptors==704 && models==3272 && refusals==15 && corruptions==19 && edge_checks==465);
    printf("{\"schema\":1,\"store_codes\":4,\"descriptors\":704,\"byte_models\":3272,\"refusals\":15,\"corruptions\":19,\"interval_edges\":465,\"max_tree_height\":8,\"postseal_equal\":1,\"emitted_instruction_execution\":0}\n");return 0;
}
