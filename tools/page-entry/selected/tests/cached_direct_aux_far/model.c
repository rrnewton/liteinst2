/* Actual LD-AUX API plus the existing independent far-DIRECT byte model.
   Model outcomes confer no executable lease or native owner authority. */
#include "linked_loop_direct.h"
#include "tests/persistent_direct_frontier/model.h"
#include "model.h"
#include <assert.h>
#include <string.h>
static const struct li2_dd_aux_plan *active;
static uint64_t decoded,recovered;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *d) {
    ++decoded;return __real_li2_decoder_decode(pc,b,n,d);
}
uint64_t far_aux_decoder_calls(void) {return decoded;}
int __real_li2_ld_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_ld_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t raw[16],
    uint64_t flags,const uint64_t spill[4],struct li2_dd_recovered *out) {
    if(!active || p!=&active->value)return __real_li2_ld_recover(p,pc,raw,flags,spill,out);
    uint64_t before=decoded;int e=li2_ld_aux_recover(active,pc,raw,flags,spill,out);
    assert(decoded==before);++recovered;return e;
}
static uint64_t flags_for(unsigned n) {
    const unsigned bit[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bit[i];return f;
}
static void bytes(uintptr_t pc,uintptr_t target,unsigned char b[5]) {
    int64_t delta=(int64_t)target-(int64_t)(pc+5);
    assert(delta>=INT32_MIN && delta<=INT32_MAX);uint32_t v=(uint32_t)delta;
    b[0]=0xe9;for(unsigned i=0;i<4;i++)b[i+1]=(unsigned char)(v>>(8*i));
}
void far_aux_models(struct model_counts *out) {
    memset(out,0,sizeof *out);struct li2_dd_aux_plan p,old,bad;
    for(unsigned direction=0;direction<2;direction++)for(unsigned slot=0;slot<8;slot++) {
        uintptr_t low=0x10000000,high=UINT64_C(0x700000000000);
        uintptr_t code=direction?high:low,pc=(direction?low:high)+0xffa,root=pc-0xdfa;
        struct li2_dd_aux_binding b={.owner={.rows=code+0x20000,
            .image={code+0x30000,code+0x38000},.heads=1,.head=0,.directory=code+0x50000},
            .code=code,.spill=code+0x10000,.slot=slot};
        unsigned char source[5];bytes(pc,root,source);
        assert(li2_dd_aux_emit(pc,source,5,&b,&old)==LI2_DD_RELOCATION &&
            !old.ready && old.result==LI2_DD_RELOCATION && old.version==1 &&
            old.value.record.version==1 && !old.value.record.ready &&
            old.value.record.image_bytes==old.value.record.miss_offset+5 &&
            !memcmp(old.value.image+old.value.record.miss_offset,"\xe9\x90\0\0\0",5));
        assert(!li2_ld_aux_emit(pc,source,5,&b,&p) && !li2_ld_aux_validate(&p) &&
            p.version==2 && p.ready==1 && !p.result && p.value.record.version==2 &&
            p.value.record.ready==1 && p.value.record.image_bytes==215 &&
            p.value.record.boundaries==37 && p.value.record.miss_offset==153 &&
            p.value.record.hit_offset==209 && p.value.original.target[0]==root &&
            li2_dd_aux_validate(&p)==LI2_DD_CORRUPT && li2_ld_validate(&p.value)==LI2_DD_CORRUPT);
        unsigned at=p.value.record.miss_offset;
        assert(!memcmp(p.value.image+at,"\xff\x25\0\0\0\0",6));
        for(unsigned i=0;i<8;i++)assert(p.value.image[at+6+i]==(unsigned char)(pc>>(8*i)));
        ++out->far_adapters;active=&p;uint64_t visited=0;
        for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<4;mode++) {
            struct li2_jd_domain_directory d={.version=1,.serial=17};
            if(mode<2) {
                d.count=2;d.row[0]=(struct li2_jd_domain_row){root+1,code+0x30200,7,0,0};
                d.row[1]=(struct li2_jd_domain_row){mode?root+2:root,code+0x30000,9,1,0};
            } else d.count=mode==2?0:LI2_JD_DOMAIN_HEADS+1;
            uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=UINT64_C(0x1234567800000000)+0x101*i;
            struct dd_model_result got;assert(!dd_model_run(&p.value,&d,raw,flags_for(f),&got));
            assert(got.steps==got.recoveries && got.steps && !got.internal);
            if(!mode)assert(got.hit && !got.miss && got.target==code+0x30000 && got.cell_writes==1 && got.row_reads==2);
            else assert(got.miss && !got.hit && got.target==pc && !got.cell_writes && got.row_reads==(mode==1?2U:0U));
            visited|=got.visited;out->steps+=got.steps;++out->models;
        }
        assert(visited==((UINT64_C(1)<<37)-1));active=0;
        uint64_t raw[16]={0},spill[4]={0},before=decoded;struct li2_dd_recovered got,zero={0};
        for(unsigned offset=0;offset<512;offset++) {
            unsigned boundary=0;for(unsigned j=0;j<p.value.record.boundaries;j++)
                boundary|=p.value.record.boundary[j].offset==offset;
            if(boundary)continue;
            memset(&got,0xa5,sizeof got);
            assert(li2_ld_aux_recover(&p,p.value.generated+offset,raw,flags_for(63),spill,&got)==LI2_DD_CORRUPT &&
                !memcmp(&got,&zero,sizeof got));++out->nonboundary_refusals;
            if(offset>=at+6 && offset<at+14)++out->literal_refusals;
        }
        assert(decoded==before);
        /* A representable original-PC displacement keeps the complete old value. */
        uintptr_t near=code+0x90ffa;bytes(near,near-0xdfa,source);
        assert(!li2_dd_aux_emit(near,source,5,&b,&old) && !li2_ld_aux_emit(near,source,5,&b,&bad) &&
            !memcmp(&old,&bad,sizeof old));++out->near_equivalences;
    }
    /* Every byte of one complete far auxiliary value remains authenticated. */
    for(size_t i=0;i<sizeof p;i++) {
        bad=p;((unsigned char *)&bad)[i]^=1;
        assert(li2_ld_aux_validate(&bad)==LI2_DD_CORRUPT);++out->mutations;
    }
    for(unsigned which=0;which<4;which++) {
        bad=p;
        if(which==0)bad.version=1;if(which==1)bad.value.record.version=1;
        if(which==2)bad.binding.slot^=1;if(which==3)bad.value.original.decoded.bytes[0]=0xeb;
        struct li2_dd_recovered got,zero={0};uint64_t raw[16]={0},spill[4]={0},before=decoded;
        memset(&got,0xa5,sizeof got);
        assert(li2_ld_aux_recover(&bad,bad.value.generated,raw,flags_for(63),spill,&got)==LI2_DD_CORRUPT &&
            !memcmp(&got,&zero,sizeof got) && decoded==before);++out->refusals;
    }
    out->recoveries=recovered;
    assert(out->models==4096 && out->recoveries==2*out->steps && out->far_adapters==16 &&
        out->near_equivalences==16 && out->mutations==2368 && out->literal_refusals==128 &&
        out->nonboundary_refusals==16*(512-37) && out->refusals==4);
}
