/* Real shared decoder/emitter/recovery plus the unchanged independent DIRECT
   byte model. No generated code, runtime lease, source permission or claim is
   executed or established by this component test. */
#include "linked_direct_dispatch.h"
#include "model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct li2_dd_aux_plan example,bad;
static const struct li2_dd_aux_plan *active;
static uint64_t decoded,models,steps,recoveries,mutations,refusals;
static unsigned nested;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *d) {
    ++decoded;return __real_li2_decoder_decode(pc,b,n,d);
}
int __real_li2_dd_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_dd_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    if(!active || p!=&active->value || nested)return __real_li2_dd_recover(p,pc,raw,flags,spill,out);
    uint64_t before=decoded;nested=1;
    int e=li2_dd_aux_recover(active,pc,raw,flags,spill,out);nested=0;
    assert(decoded==before);++recoveries;return e;
}
static uint64_t flags_for(unsigned n) {
    static const unsigned bit[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((n>>i)&1)<<bit[i];return f;
}
static const struct li2_dd_aux_binding placement={
    .owner={.rows=0x17000000,.image={0x10000000,0x10008000},.heads=1,.head=0,.directory=0x30000000},
    .code=0x18000000,.spill=0x18010000};
static const uintptr_t source_pc=0x410ffa,root_pc=0x410200;
static void branch_bytes(unsigned char b[5]) {
    int64_t delta=(int64_t)root_pc-(int64_t)(source_pc+5);
    assert(delta>=INT32_MIN && delta<=INT32_MAX);uint32_t v=(uint32_t)delta;
    b[0]=0xe9;for(unsigned i=0;i<4;i++)b[i+1]=(unsigned char)(v>>(8*i));
}
static void accepted(void) {
    unsigned char bytes[5];branch_bytes(bytes);
    for(unsigned slot=0;slot<LI2_DD_AUX_SLOTS;slot++) {
        struct li2_dd_aux_binding b=placement;b.slot=slot;
        assert(!li2_dd_aux_emit(source_pc,bytes,sizeof bytes,&b,&example) &&
            !li2_dd_aux_validate(&example) && example.ready==1 && !example.result &&
            example.value.generated==b.code+(uintptr_t)slot*LI2_DD_SLOT_BYTES &&
            example.value.spill==b.spill+(uintptr_t)slot*LI2_DD_AUX_SPILL_STRIDE &&
            example.value.original.target[0]==root_pc && example.value.record.boundaries==37 &&
            example.value.record.image_bytes==206 &&
            !memcmp(&example.value.binding,&placement.owner,sizeof placement.owner));
        /* The ordinary validator must refuse auxiliary placement. A genuine
           ordinary binding at the same address emits the identical image and
           recovery rows; only its actual owner binding value differs. */
        assert(li2_dd_validate(&example.value)==LI2_DD_CORRUPT);
        struct li2_jd_binding ordinary=placement.owner;
        ordinary.image[0]=b.code;ordinary.image[1]=b.code+LI2_JD_IMAGE_BYTES;
        ordinary.heads=LI2_DD_AUX_SLOTS;ordinary.head=slot;
        struct li2_dd_plan normal;const uintptr_t internal[2]={0,0};
        assert(!li2_dd_emit(source_pc,bytes,5,1,example.value.generated,example.value.spill,
            &ordinary,internal,&normal) && !li2_dd_validate(&normal));
        normal.binding=example.value.binding;
        assert(!memcmp(&normal,&example.value,sizeof normal));
        active=&example;uint64_t visited=0;
        for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<4;mode++) {
            struct li2_jd_domain_directory d={.version=1,.serial=17};
            if(mode<2) {
                d.count=2;d.row[0]=(struct li2_jd_domain_row){root_pc+1,0x10000200,7,0,0};
                d.row[1]=(struct li2_jd_domain_row){mode?root_pc+2:root_pc,0x10000000,9,1,0};
            } else d.count=mode==2?0:LI2_JD_DOMAIN_HEADS+1;
            uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=UINT64_C(0x1234567800000000)+0x101*i;
            struct dd_model_result out;assert(!dd_model_run(&example.value,&d,raw,flags_for(f),&out));
            assert(out.steps==out.recoveries && out.steps && !out.internal);
            if(!mode)assert(out.hit==1 && !out.miss && out.target==0x10000000 &&
                out.cell_writes==1 && out.row_reads==2);
            else assert(out.miss==1 && !out.hit && out.target==source_pc && !out.cell_writes &&
                out.row_reads==(mode==1?2U:0U));
            visited|=out.visited;steps+=out.steps;++models;
        }
        assert(visited==((UINT64_C(1)<<example.value.record.boundaries)-1));active=0;
    }
    assert(models==LI2_DD_AUX_SLOTS*64U*4U && recoveries==2*steps);
}
static void refuse_binding(struct li2_dd_aux_binding b) {
    unsigned char bytes[5];branch_bytes(bytes);
    assert(li2_dd_aux_emit(source_pc,bytes,5,&b,&bad)==LI2_DD_ARGUMENT &&
        bad.ready==0 && bad.result==LI2_DD_ARGUMENT && !bad.value.record.ready &&
        li2_dd_aux_validate(&bad)==LI2_DD_CORRUPT);++refusals;
}
static void geometry(void) {
    struct li2_dd_aux_binding b=placement;
    b.reserved=1;refuse_binding(b);b=placement;b.slot=LI2_DD_AUX_SLOTS;refuse_binding(b);
    b=placement;b.slot=UINT32_MAX;refuse_binding(b);
    b=placement;b.code++;refuse_binding(b);b=placement;b.spill++;refuse_binding(b);
    b=placement;b.code=UINT64_C(0x800000000000);refuse_binding(b);
    b=placement;b.spill=UINT64_C(0x800000000000);refuse_binding(b);
    b=placement;b.spill=b.code;refuse_binding(b);
    for(unsigned i=0;i<2;i++)for(unsigned k=0;k<2;k++) {
        b=placement;if(i)b.spill=b.owner.image[k];else b.code=b.owner.image[k];refuse_binding(b);
    }
    for(unsigned i=0;i<2;i++)for(unsigned k=0;k<3;k++) {
        b=placement;uintptr_t at=k==0?source_pc&~(uintptr_t)4095:k==1?b.owner.rows:b.owner.directory;
        if(i)b.spill=at;else b.code=at;refuse_binding(b);
    }
    b=placement;b.owner.heads=0;refuse_binding(b);
    b=placement;b.owner.heads=LI2_JD_HEADS+1;refuse_binding(b);
    b=placement;b.owner.head=1;refuse_binding(b);
    b=placement;b.owner.rows++;refuse_binding(b);
    b=placement;b.owner.image[1]=b.owner.image[0];refuse_binding(b);
    b=placement;b.owner.directory++;refuse_binding(b);
    assert(refusals==24);
    unsigned char bytes[6];branch_bytes(bytes);bytes[5]=0x90;
    for(unsigned n=0;n<=6;n++)if(n!=5) {
        assert(li2_dd_aux_emit(source_pc,bytes,n,&placement,&bad)==LI2_DD_FORM && !bad.ready);++refusals;
    }
    bytes[0]=0xeb;assert(li2_dd_aux_emit(source_pc,bytes,5,&placement,&bad)==LI2_DD_FORM);++refusals;
    branch_bytes(bytes);
    assert(li2_dd_aux_emit((source_pc&~(uintptr_t)4095)+4092,bytes,5,&placement,&bad)==LI2_DD_ARGUMENT);++refusals;
    assert(li2_dd_aux_emit(source_pc,0,5,&placement,&bad)==LI2_DD_ARGUMENT);++refusals;
    assert(li2_dd_aux_emit(source_pc,bytes,5,0,&bad)==LI2_DD_ARGUMENT);++refusals;
    assert(li2_dd_aux_emit(source_pc,bytes,5,&placement,0)==LI2_DD_ARGUMENT);++refusals;
    b=placement;b.code=UINT64_C(0x4000000000);b.spill=b.code+0x10000;
    assert(li2_dd_aux_emit(source_pc,bytes,5,&b,&bad)==LI2_DD_RELOCATION &&
        !bad.ready && bad.result==LI2_DD_RELOCATION);++refusals;
    assert(refusals==36);
}
static void whole_value(void) {
    for(size_t i=0;i<sizeof example;i++) {
        bad=example;((unsigned char *)&bad)[i]^=1;
        assert(li2_dd_aux_validate(&bad)==LI2_DD_CORRUPT);++mutations;
    }
    assert(mutations==sizeof example);
    uint64_t raw[16]={0},spill[4]={0};struct li2_dd_recovered out,zero={0};
    uint64_t before=decoded;
    for(unsigned offset=0;offset<LI2_DD_SLOT_BYTES;offset++) {
        unsigned boundary=0;for(unsigned j=0;j<example.value.record.boundaries;j++)
            boundary|=example.value.record.boundary[j].offset==offset;
        if(boundary)continue;
        memset(&out,0xa5,sizeof out);
        assert(li2_dd_aux_recover(&example,example.value.generated+offset,raw,flags_for(63),spill,&out) &&
            !memcmp(&out,&zero,sizeof out));++refusals;
    }
    bad=example;bad.binding.slot^=1;memset(&out,0xa5,sizeof out);
    assert(li2_dd_aux_recover(&bad,example.value.generated,raw,0,spill,&out)==LI2_DD_CORRUPT &&
        !memcmp(&out,&zero,sizeof out));++refusals;
    assert(decoded==before);
}
int main(void) {
    accepted();geometry();whole_value();
    printf("{\"profile\":\"cached_direct_aux_component\",\"models\":%llu,\"steps\":%llu,"
        "\"recoveries\":%llu,\"whole_byte_mutations\":%llu,\"refusals\":%llu,"
        "\"runtime_authority\":false,\"native_credit\":false}\n",
        (unsigned long long)models,(unsigned long long)steps,(unsigned long long)recoveries,
        (unsigned long long)mutations,(unsigned long long)refusals);
    return 0;
}
