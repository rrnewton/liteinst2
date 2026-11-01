/* Independent fixed E8 image/rows and actual decoder/graph/byte-model component.
   Supplied numeric bindings do not prove live owner or mapping custody. */
#include "persistent_group_compact.h"
#include "tests/call_dispatch/model.h"
#include "tests/ret_dispatch/model.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#if !defined(LI2_PERSISTENT_DIRECT_CALL) || LI2_PERSISTENT_DIRECT_CALL != 1
#error "explicit direct E8 component required"
#endif
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_cd_plan plan,good;
static struct li2_pg_plan full,scratch;
static struct li2_pg_compact compact,rebuilt,bad;
static struct li2_mg_table table;
static struct li2_jd_domain_directory directory;
static unsigned char source[2][4096];
static uintptr_t pages[2];
static struct li2_pg_layout layout;
static unsigned descriptors,images,models,forms,corruptions,recovery_controls,interiors,descriptor_controls;
static unsigned plans,pairs,boundary_misses,lookup_misses,refusals,graph_corruptions;
static const unsigned char image_template[255]={
    0x48,0x89,0x05,0x00,0x00,0x00,0x00,0x48,0x89,0x0d,0x00,0x00,0x00,0x00,0x48,0x89,
    0x15,0x00,0x00,0x00,0x00,0x48,0x89,0x1d,0x00,0x00,0x00,0x00,0x48,0xbb,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x9f,0x0f,0x90,0xc0,0x48,0xb9,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x48,0x8b,0x51,0x18,0x48,0x81,0xc2,0x08,0x00,0x00,0x00,0x48,
    0x3b,0xe2,0x0f,0x82,0x00,0x00,0x00,0x00,0x48,0x8b,0x51,0x20,0x48,0x3b,0xe2,0x0f,
    0x87,0x00,0x00,0x00,0x00,0x48,0xb9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,
    0x8b,0x51,0x08,0x48,0x81,0xfa,0x01,0x00,0x00,0x00,0x0f,0x82,0x00,0x00,0x00,0x00,
    0x48,0x81,0xfa,0x00,0x01,0x00,0x00,0x0f,0x87,0x00,0x00,0x00,0x00,0x48,0x81,0xc1,
    0x20,0x00,0x00,0x00,0x48,0xc1,0xe2,0x05,0x48,0x03,0xd1,0x48,0x3b,0x59,0x00,0x0f,
    0x84,0x00,0x00,0x00,0x00,0x48,0x81,0xc1,0x20,0x00,0x00,0x00,0x48,0x3b,0xca,0x0f,
    0x82,0x00,0x00,0x00,0x00,0x04,0x7f,0x9e,0x48,0x8b,0x0d,0x00,0x00,0x00,0x00,0x48,
    0x8b,0x15,0x00,0x00,0x00,0x00,0x48,0x8b,0x1d,0x00,0x00,0x00,0x00,0x48,0x8b,0x05,
    0x00,0x00,0x00,0x00,0xe9,0x00,0x00,0x00,0x00,0x48,0x8b,0x49,0x08,0x48,0x89,0x0d,
    0x00,0x00,0x00,0x00,0x04,0x7f,0x9e,0x48,0x8b,0x0d,0x00,0x00,0x00,0x00,0x48,0x8b,
    0x15,0x00,0x00,0x00,0x00,0x48,0x8b,0x1d,0x00,0x00,0x00,0x00,0x48,0x8b,0x05,0x00,
    0x00,0x00,0x00,0xff,0x35,0x00,0x00,0x00,0x00,0xff,0x25,0x00,0x00,0x00,0x00,
};
static const struct li2_mg_boundary expected_rows[46]={
    {0,7,0,0,0,0},
    {7,7,1,0,0,0},
    {14,7,3,0,0,0},
    {21,7,7,0,0,0},
    {28,10,15,0,0,0},
    {38,1,15,8,0,0},
    {39,3,15,9,1,0},
    {42,10,15,9,2,0},
    {52,4,15,11,2,0},
    {56,7,15,15,2,0},
    {63,3,15,15,2,0},
    {66,6,15,15,2,0},
    {72,4,15,15,2,0},
    {76,3,15,15,2,0},
    {79,6,15,15,2,0},
    {85,10,15,15,2,0},
    {95,4,15,15,2,0},
    {99,7,15,15,2,0},
    {106,6,15,15,2,0},
    {112,7,15,15,2,0},
    {119,6,15,15,2,0},
    {125,7,15,15,2,0},
    {132,4,15,15,2,0},
    {136,3,15,15,2,0},
    {139,4,15,15,2,0},
    {143,6,15,15,2,0},
    {149,7,15,15,2,0},
    {156,3,15,15,2,0},
    {159,6,15,15,2,0},
    {165,2,15,15,2,0},
    {167,1,15,15,1,0},
    {168,7,15,15,0,0},
    {175,7,15,13,0,0},
    {182,7,15,9,0,0},
    {189,7,15,1,0,0},
    {196,5,15,0,0,0},
    {201,4,15,15,2,0},
    {205,7,15,15,2,0},
    {212,2,15,15,2,1},
    {214,1,15,15,1,1},
    {215,7,15,15,0,1},
    {222,7,15,13,0,1},
    {229,7,15,9,0,1},
    {236,7,15,1,0,1},
    {243,6,15,0,0,2},
    {249,6,15,0,0,3},
};
static uint64_t get(const unsigned char *p,unsigned n) {
    uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static void put32(unsigned char *p,uint32_t v) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));
}
static void put64(unsigned char *p,uint64_t v) {
    for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));
}
static void rel(unsigned char *p,uint64_t next,uint64_t target) {
    uint64_t distance=target>=next?target-next:next-target;
    assert(distance<=(target>=next?UINT64_C(0x7fffffff):UINT64_C(0x80000000)));
    put32(p,target>=next?(uint32_t)distance:0U-(uint32_t)distance);
}
static uint64_t immediate(const struct li2_cd_plan *p) {
    return p->original.decoded.pc+5+(uint64_t)(int64_t)(int32_t)get(p->original.decoded.bytes+1,4);
}
static void seal(const struct li2_cd_plan *p) {
    unsigned char expected[512]={0};memcpy(expected,image_template,sizeof image_template);
    const unsigned offsets[]={0,7,14,21,168,175,182,189,215,222,229,236};
    const unsigned slots[]={0,1,2,3,1,2,3,0,1,2,3,0};
    for(unsigned i=0;i<12;i++)rel(expected+offsets[i]+3,p->generated+offsets[i]+7,p->spill+8*slots[i]);
    put64(expected+30,immediate(p));put64(expected+44,p->binding.window);put64(expected+87,p->binding.directory);
    const unsigned branches[]={66,79,106,119,143,159},targets[]={165,165,165,165,201,139};
    for(unsigned i=0;i<6;i++)rel(expected+branches[i]+2,p->generated+branches[i]+6,p->generated+targets[i]);
    rel(expected+197,p->generated+201,p->original.decoded.pc);
    rel(expected+208,p->generated+212,p->spill+32);
    rel(expected+245,p->generated+249,p->generated+504);
    rel(expected+251,p->generated+255,p->spill+32);put64(expected+504,p->original.decoded.pc+5);
    struct li2_cd_record record={.version=1,.ready=1,.image_bytes=255,.boundaries=46,
        .push_offset=243,.transfer_offset=249,.miss_offset=196,.literal_offset=504,.scratch_regs={0,1,2,3}};
    memcpy(record.boundary,expected_rows,sizeof expected_rows);
    assert(!memcmp(&record,&p->record,sizeof record) && !memcmp(expected,p->image,sizeof expected));
    for(unsigned i=0;i<46;i++) {
        const struct li2_mg_boundary *m=&expected_rows[i];struct li2_decoded d;
        assert(!li2_decoder_decode(p->generated+m->offset,p->image+m->offset,m->length,&d) &&
            d.decode_status==LI2_VALID && d.length==m->length && d.next_pc==p->generated+m->offset+m->length);
    }
    assert(!li2_cd_validate(p));++images;
}
static uint64_t flags(unsigned n,unsigned df) {
    static const unsigned bits[]={0,2,4,6,7,11};uint64_t f=0x202|((uint64_t)df<<10);
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bits[i];return f;
}
static void registers(uint64_t r[16]) {
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234567800000000)+0x101*i;
    r[4]=0x60000100;
}
static void directory_value(unsigned count,uint64_t target,unsigned hit) {
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=73;directory.count=count;
    for(unsigned i=0;i<count && i<LI2_JD_DOMAIN_HEADS;i++)directory.row[i]=(struct li2_jd_domain_row){
        .pc=0x500200+0x1000*i,.generated=0x20000000+512*i,.generation=91+i/128,.slot=i/128,.head=i%128};
    if(hit && count && count<=LI2_JD_DOMAIN_HEADS)directory.row[count-1].pc=target;
}
static struct cd_model_result model(const struct li2_cd_plan *p,const uint64_t r[16],uint64_t f,
                                    const struct li2_cd_window *w) {
    struct cd_model_result result;assert(!cd_model_run(p,&directory,w,r,f,&result));
    unsigned row=LI2_JD_DOMAIN_HEADS;
    if(directory.count && directory.count<=LI2_JD_DOMAIN_HEADS && r[4]>=w->first+8 && r[4]<=w->end)
        for(unsigned i=0;i<directory.count;i++)if(directory.row[i].pc==immediate(p)) {row=i;break;}
    if(row<LI2_JD_DOMAIN_HEADS)assert(result.hit && !result.miss && result.stack_writes==1 &&
        result.cell_writes==1 && result.row_reads==row+1 && result.stack_address==r[4]-8 &&
        result.return_word==p->original.decoded.next_pc && result.target==directory.row[row].generated);
    else {
        assert(result.miss && !result.hit && !result.stack_writes && !result.cell_writes &&
            !result.stack_address && !result.return_word && result.target==p->original.decoded.pc);
        assert(result.row_reads==((!directory.count || directory.count>256 || r[4]<w->first+8 || r[4]>w->end)?0:directory.count));
    }
    assert(result.steps==result.recoveries && result.steps<=2048);++models;return result;
}
static void standalone(void) {
    const uint32_t deltas[]={0,1,UINT32_MAX,UINT32_C(0x7fffffff),UINT32_C(0x80000000)};
    for(unsigned high=0;high<2;high++)for(unsigned k=0;k<5;k++) {
        uintptr_t shift=high?UINT64_C(0x500000000000):0,pc=shift+0x90000200;
        struct li2_cd_binding b={.rows=shift+0xc0000000,.image={shift+0xa0000000,shift+0xa0008000},
            .heads=1,.directory=shift+0xd0000000,.window=shift+0xd0010000};
        unsigned char bytes[15];memset(bytes,0xcc,sizeof bytes);bytes[0]=0xe8;put32(bytes+1,deltas[k]);
        assert(!li2_cd_emit(pc,bytes,15,b.image[0],shift+0xa0012000,&b,&plan));
        struct li2_cd_descriptor expected={.decoded={.pc=pc,.next_pc=pc+5,.abi_version=1,
            .decode_status=LI2_VALID,.code=693,.kind=LI2_NONE,.destination=16,
            .step_disposition=LI2_STEP_UNSUPPORTED,.available=15,.length=5},
            .tf={.pc=pc,.next_pc=pc+5,.abi_version=1,.policy=1,.code=693,.length=5,
                .flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_CALL},.version=1,.ready=1,.available=15,.target=16};
        memcpy(expected.decoded.bytes,bytes,15);assert(!memcmp(&plan.original,&expected,sizeof expected));
        uintptr_t target;assert(!li2_cd_direct_target(&plan.original,&target) && target==immediate(&plan));
        ++descriptors;seal(&plan);if(!high && !k)good=plan;
        for(unsigned df=0;df<2;df++)for(unsigned f=0;f<64;f++)for(unsigned hit=0;hit<2;hit++) {
            uint64_t r[16];registers(r);directory_value(4,target,hit);
            struct li2_cd_window w={.version=1,.owner=0x72000000,.serial=73,.first=r[4]-256,.end=r[4]+256};
            model(&plan,r,flags(f,df),&w);
        }
    }
    struct li2_cd_window w={.version=1,.owner=0x72000000,.serial=73,.first=0x60000000,.end=0x60000200};
    const uint64_t positions[]={w.first+8,w.end,w.first+7,w.end+1,0,UINT64_C(0x800000000000)};
    const unsigned counts[]={0,1,256,257};
    for(unsigned k=0;k<4;k++)for(unsigned j=0;j<6;j++) {
        uint64_t r[16];registers(r);r[4]=positions[j];directory_value(counts[k],immediate(&good),1);
        model(&good,r,flags(j,1),&w);
    }
}
static void bad_material(void) {
    unsigned char b[15]={0xe8,0,0,0,0};struct li2_cd_descriptor d;
    for(unsigned n=1;n<5;n++) {assert(li2_cd_describe(0x400200,b,n,&d)==LI2_CD_FORM && !d.ready);++forms;}
    const unsigned prefixes[]={0x66,0x48,0xf2,0x2e,0x67};
    for(unsigned i=0;i<5;i++) {unsigned char v[15]={0};v[0]=(unsigned char)prefixes[i];v[1]=0xe8;
        assert(li2_cd_describe(0x400200,v,15,&d)==LI2_CD_FORM && !d.ready);++forms;}
    const uintptr_t pc[]={0x1000,UINT64_C(0x7ffffffffff6),UINT64_C(0x7ffffffffffb)};
    const uint32_t delta[]={UINT32_C(0x80000000),UINT32_C(0x7fffffff),0};
    for(unsigned i=0;i<3;i++) {put32(b+1,delta[i]);assert(li2_cd_describe(pc[i],b,5,&d)==LI2_CD_FORM && !d.ready);++forms;}
    put32(b+1,UINT32_C(0x80000000));uintptr_t target=1;
    assert(!li2_cd_describe(0x7ffffffb,b,5,&d) && !li2_cd_direct_target(&d,&target) && !target);++descriptors;
    for(unsigned i=0;i<512;i++) {plan=good;plan.image[i]^=1;assert(li2_cd_validate(&plan)==LI2_CD_CORRUPT);++corruptions;}
    for(unsigned i=0;i<32;i++) {
        uint64_t r[16],spill[5]={0xdead,0xbeef,0,UINT64_MAX,0};registers(r);r[i%16]^=UINT64_C(0xfedcba9876543210);
        r[4]=0x600000f8;spill[4]=i?UINT64_MAX:0;struct li2_cd_recovered recovered;
        assert(!li2_cd_recover(&good,good.generated+249,r,0xed7,spill,&recovered) && recovered.complete &&
            recovered.phase==LI2_CD_COMMITTED && recovered.original_pc==immediate(&good) &&
            recovered.original_rsp==r[4]+8 && recovered.return_pc==good.original.decoded.next_pc &&
            recovered.flags==0xed7 && !memcmp(recovered.gpr,r,sizeof r));++recovery_controls;
    }
    for(unsigned i=0;i<8;i++) {
        struct li2_cd_plan bad=good;uintptr_t value=UINTPTR_MAX;
        if(i==0)bad.original.reserved[0]=1;
        if(i==1)bad.original.decoded.bytes[0]=0xff;
        if(i==2)bad.original.available=4;
        if(i==3)bad.original.decoded.available=14;
        if(i==4)bad.original.decoded.code=759;
        if(i==5)bad.original.tf.next_pc++;
        if(i==6)bad.original.target=17;
        if(i==7)bad.original.decoded.bytes[15]=1;
        uint64_t r[16],spill[4]={0};registers(r);struct li2_cd_recovered out;
        assert(li2_cd_direct_target(&bad.original,&value)==LI2_CD_CORRUPT && value==UINTPTR_MAX &&
            li2_cd_recover(&bad,bad.generated+249,r,0x202,spill,&out)==LI2_CD_CORRUPT && !out.complete);
        ++descriptor_controls;
    }
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned j=0;j<46;j++)found|=expected_rows[j].offset==offset;
        if(!found) {uint64_t r[16],spill[4]={0};registers(r);struct li2_cd_recovered out;
            assert(li2_cd_recover(&good,good.generated+offset,r,0x202,spill,&out)==LI2_CD_CORRUPT && !out.complete);++interiors;}
    }
}
static uintptr_t pc(unsigned at) {assert(at<8192);return pages[at/4096]+at%4096;}
static void put(unsigned at,const unsigned char *bytes,unsigned n) {
    assert(at<=8192 && n<=8192-at);for(unsigned i=0;i<n;i++)source[(at+i)/4096][(at+i)%4096]=bytes[i];
}
static void geometry(uintptr_t shift,unsigned gap) {
    pages[0]=shift+0x400000;pages[1]=pages[0]+(gap?0x3000:0x1000);
    layout=(struct li2_pg_layout){.generated={shift+0x10000000,shift+0x10008000},
        .stubs=shift+0x10010000,.slots=shift+0x10011000,.spill=shift+0x10012000,
        .directory=shift+0x70000000,.window=shift+0x70010000,.ret_miss=shift+0x70010040};
    uintptr_t proof=shift+0x30000000;
    struct li2_mg_range ranges[]={{pages[0],pages[0]+4096},{pages[1],pages[1]+4096},
        {layout.generated[0],layout.spill+4096},{proof,proof+0x100000},
        {layout.directory,layout.directory+LI2_JD_DOMAIN_BYTES},{layout.window,layout.window+4096}};
    assert(!li2_mg_table_build(ranges,6,proof+offsetof(struct li2_pg_compact,table),&table));
    memset(source,0xcc,sizeof source);
}
static void call(unsigned at,uint64_t target) {
    unsigned char b[5]={0xe8};rel(b+1,pc(at)+5,target);put(at,b,5);
}
static void jump(unsigned at,uint64_t target) {
    unsigned char b[5]={0xe9};rel(b+1,pc(at)+5,target);put(at,b,5);
}
static void prove(unsigned root,unsigned heads,unsigned exits,unsigned links) {
    struct li2_pg_miss miss,empty={.version=9};
    assert(!li2_pg_plan_pages(pages,source,pc(root),&layout,&table,&full,&miss) &&
        !memcmp(&miss,&empty,sizeof miss) && full.version==9 && full.ready==1 && !full.result &&
        full.heads==heads && full.exits==exits && full.links==links &&
        !memcmp(full.source,source,sizeof source) && !memcmp(full.page,pages,sizeof pages));
    assert(!li2_pg_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_pg_compact_build(&full,&scratch,&compact) && compact.version==9 &&
        !li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=73;directory.count=heads;
    unsigned calls=0;
    for(unsigned i=0;i<heads;i++) {
        for(unsigned j=0;j<i;j++)assert(full.original[j].decoded.pc!=full.original[i].decoded.pc);
        directory.row[i]=(struct li2_jd_domain_row){.pc=full.original[i].decoded.pc,
            .generated=layout.generated[i/64]+512*(i%64),.generation=91,.slot=0,.head=i};
        if(full.head[i].kind==LI2_PG_CALL) {
            struct li2_cd_plan c;assert(!li2_pg_compact_call(&compact,i/64,i%64,&c) &&
                !memcmp(&c,&full.guard[i].call,sizeof c) && !full.head[i].successor_count &&
                !full.head[i].successors[0] && !full.head[i].successors[1]);seal(&c);++calls;
            unsigned count=0;
            for(unsigned j=0;j<exits;j++)if(full.exit_pc[j]==c.original.decoded.pc) {
                assert(!memcmp(&full.frontier[j],&full.original[i],sizeof full.frontier[j]));++count;
            }
            assert(count==1);
        }
    }
    assert(calls==full.stores);++plans;
}
static void reject(unsigned root,int result,unsigned reason,uint64_t detail) {
    struct li2_pg_miss miss;assert(li2_pg_plan_pages(pages,source,pc(root),&layout,&table,&full,&miss)==result &&
        !full.ready && full.result==(unsigned)result && miss.reason==reason && miss.detail==detail &&
        li2_pg_miss_valid(&full,&miss,result));++refusals;
}
static void paired(unsigned return_head,unsigned outside) {
    struct li2_cd_plan c;struct li2_rd_plan r;
    assert(!li2_pg_compact_call(&compact,0,0,&c) && !li2_pg_compact_ret(&compact,0,1,&r));
    uint64_t gpr[16];registers(gpr);const uint64_t before=gpr[4];
    struct li2_cd_window cw={.version=1,.owner=0x72000000,.serial=73,.first=before-256,.end=before+256};
    struct cd_model_result co=model(&c,gpr,0xed7,&cw);
    assert(co.hit && co.target==directory.row[1].generated);gpr[4]=co.stack_address;
    struct li2_rd_window rw={.version=1,.owner=cw.owner,.serial=cw.serial,.first=cw.first,.end=cw.end};
    struct rd_model_result ro;assert(!rd_model_run(&r,&directory,&rw,gpr,0xed7,co.return_word,1,&ro));
    assert(ro.guest_reads==1 && ro.load_attempts==1 && ro.target_writes==1 && !ro.stack_writes &&
        !ro.load_fault && !ro.before_miss && ro.original_rsp==before-8 && ro.loaded_target==co.return_word);
    if(outside) {assert(ro.loaded_miss && !ro.hit && !ro.cell_writes && ro.final_rsp==before-8 &&
        ro.target==r.binding.loaded_miss);++boundary_misses;}
    else {assert(ro.hit && !ro.loaded_miss && ro.cell_writes==1 && ro.final_rsp==before &&
        ro.target==directory.row[return_head].generated);++pairs;}
}
static void lookup_miss(void) {
    struct li2_cd_plan c;assert(!li2_pg_compact_call(&compact,0,0,&c));uint64_t r[16];registers(r);
    struct li2_cd_window w={.version=1,.owner=0x72000000,.serial=73,.first=r[4]-256,.end=r[4]+256};
    struct cd_model_result out=model(&c,r,0xed7,&w);
    assert(out.miss && !out.hit && !out.stack_writes && !out.cell_writes);++lookup_misses;
}
static void graphs(void) {
    for(unsigned where=0;where<3;where++) {
        geometry(where==1?UINT64_C(0x500000000000):0,0);unsigned at=where==2?4093:0x200;
        call(at,pc(0x300));put(0x300,(const unsigned char *)"\xc3",1);
        put(at+5,(const unsigned char *)"\x48\x83\xc0\x01\xff\x23",6);
        prove(at,3,3,0);assert(full.original[1].decoded.pc==pc(0x300) &&
            full.original[2].decoded.pc==pc(at+5) && full.source_bytes==10 &&
            full.source_mask==(where==2?3U:1U) && full.exit_pc[0]==pc(at) && full.exit_pc[1]==pc(0x300));paired(2,0);
    }
    geometry(0,0);call(0x300,pc(0x100));put(0x100,(const unsigned char *)"\xc3",1);
    put(0x305,(const unsigned char *)"\x48\x83\xc0\x01\xff\x23",6);prove(0x300,3,3,0);paired(2,0);
    for(unsigned gap=0;gap<2;gap++) {
        geometry(0,gap);unsigned at=(gap?4096:8192)-5;call(at,pc(0x300));put(0x300,(const unsigned char *)"\xc3",1);
        prove(at,2,2,0);assert(full.original[0].decoded.available==5 && full.original[0].decoded.next_pc==pc(at)+5);
        for(unsigned i=0;i<2;i++)assert(pc(at)+5<pages[i] || pc(at)+5-pages[i]>=4096);paired(0,1);
    }
    geometry(0,0);call(0x200,pages[1]+0x2000);put(0x205,(const unsigned char *)"\xc3",1);
    prove(0x200,2,2,0);assert(full.source_mask==1 && full.source_bytes==6);lookup_miss();
    geometry(0,0);call(0x200,pc(0x205));put(0x205,(const unsigned char *)"\xc3",1);
    prove(0x200,2,2,0);paired(1,0);
    geometry(0,0);call(0x200,pc(0x200));put(0x205,(const unsigned char *)"\xc3",1);prove(0x200,2,2,0);
    struct li2_cd_plan c;assert(!li2_pg_compact_call(&compact,0,0,&c));uint64_t gpr[16];registers(gpr);
    struct li2_cd_window w={.version=1,.owner=0x72000000,.serial=73,.first=gpr[4]-256,.end=gpr[4]+256};
    struct cd_model_result out=model(&c,gpr,0xed7,&w);assert(out.hit && out.target==directory.row[0].generated);
    geometry(0,0);call(0x200,pc(0x300));put(0x300,(const unsigned char *)"\xff\x23",2);
    put(0x205,(const unsigned char *)"\xc3",1);prove(0x200,2,3,0);lookup_miss();
    geometry(0,0);put(8190,(const unsigned char *)"\xe8\x00",2);reject(8190,LI2_PG_BOUNDARY,LI2_PGD_SOURCE_TRUNCATED,2);
    geometry(0,0);call(0x200,pc(8191));put(8191,(const unsigned char *)"\x0f",1);
    reject(0x200,LI2_PG_BOUNDARY,LI2_PGD_SOURCE_TRUNCATED,1);
    geometry(0,0);call(8186,pc(0x300));put(0x300,(const unsigned char *)"\xc3",1);put(8191,(const unsigned char *)"\x0f",1);
    reject(8186,LI2_PG_BOUNDARY,LI2_PGD_SOURCE_TRUNCATED,1);
    geometry(0,0);call(0x200,pc(0x201));reject(0x200,LI2_PG_GRAPH,LI2_PGD_SOURCE_OVERLAP,pc(0x201));
    geometry(0,0);put(0x200,(const unsigned char *)"\xe8\x00\x00\x00\x80",5);
    reject(0x200,LI2_PG_MISS,LI2_PGD_ROOT_UNSUPPORTED,LI2_REGION_UNSUPPORTED);
    for(unsigned n=8;n<=9;n++) {
        geometry(0,0);for(unsigned i=0;i<n;i++)call(0x200+5*i,pages[1]+0x2000);
        jump(0x200+5*n,pc(0x200));
        if(n==8)prove(0x200,9,8,0);else reject(0x200,LI2_PG_GRAPH,LI2_PGD_EXIT_LIMIT,8);
    }
    for(unsigned n=125;n<=126;n++) {
        geometry(0,0);call(0x200,pc(0x100));put(0x100,(const unsigned char *)"\xc3",1);
        for(unsigned i=0;i<n;i++)put(0x205+4*i,(const unsigned char *)"\x48\x83\xc0\x01",4);
        put(0x205+4*n,(const unsigned char *)"\xc3",1);
        if(n==125)prove(0x200,128,3,1);else reject(0x200,LI2_PG_GRAPH,LI2_PGD_HEAD_LIMIT,128);
    }
}
static void corrupt_graph(void) {
    geometry(0,0);call(0x200,pc(0x300));put(0x300,(const unsigned char *)"\xc3",1);
    put(0x205,(const unsigned char *)"\x48\x83\xc0\x01\xff\x23",6);prove(0x200,3,3,0);
    for(unsigned i=0;i<12;i++) {
        bad=compact;
        if(i==0)bad.version=8;
        if(i==1)bad.original[0].decoded.bytes[1]^=1;
        if(i==2)bad.instruction[0].call.target=0;
        if(i==3)bad.instruction[0].call.decoded.code=759;
        if(i==4)bad.instruction[0].call.tf.code=759;
        if(i==5)bad.image[0][30]^=1;
        if(i==6)bad.image[0][504]^=1;
        if(i==7)bad.image[0][255]=1;
        if(i==8)bad.guard[0].call.boundary[4].dirty=1;
        if(i==9)bad.head[0].successor_count=1;
        if(i==10)bad.head[1].source_offset++;
        if(i==11)bad.head[2].source_offset++;
        assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++graph_corruptions;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    standalone();bad_material();graphs();corrupt_graph();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(descriptors==11 && images==30 && models==2594 && forms==12 && corruptions==512 &&
        recovery_controls==32 && interiors==466 && plans==13 && pairs==5 && boundary_misses==2 &&
        lookup_misses==2 && refusals==7 && graph_corruptions==12 && descriptor_controls==8);
    printf("direct-call descriptors=%u images=%u models=%u forms=%u corruptions=%u recovery_controls=%u interiors=%u plans=%u pairs=%u boundary_misses=%u lookup_misses=%u refusals=%u graph_corruptions=%u descriptor_controls=%u\n",
        descriptors,images,models,forms,corruptions,recovery_controls,interiors,plans,pairs,boundary_misses,lookup_misses,refusals,graph_corruptions,descriptor_controls);
    return 0;
}
