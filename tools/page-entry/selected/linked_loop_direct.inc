/* LOOP-only typed selection. The public fallback, validation and recovery
   dispatch stay exact; DD owns the one image and recovery implementation. */
#include "linked_loop_direct.h"

static int ld_far_build(uintptr_t pc,const unsigned char *bytes,size_t n,unsigned external,
    uintptr_t generated,uintptr_t spill_at,const struct li2_jd_binding *b,const uintptr_t internal[2],
    struct li2_dd_plan *p) {
    return build(pc,bytes,n,external,generated,spill_at,b,internal,0,LI2_LD_VERSION,1,p);
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
    return recover(p,pc,raw,flags,spill_words,LI2_LD_VERSION,1,out);
}

int li2_ld_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                   const uint64_t spill_words[4],struct li2_dd_recovered *out) {
    if(p && p->record.version==LI2_DD_VERSION)return li2_dd_recover(p,pc,raw,flags,spill_words,out);
    return ld_far_recover(p,pc,raw,flags,spill_words,out);
}
