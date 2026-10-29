/* Fixed former Code1720 register neighbors. Supplied tuples are not
   relabelled genuine native before-state; the new family owns native coverage. */
#ifndef VPE_PROMOTED_INDICES
#error exact old table indices are required
#endif
#ifndef VPE_FIRST_ENCODING
#error exact fixed family encoding offset is required
#endif
struct vpe_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct { uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vpe_promotion_row rows[4]; } vpe_promotions;
_Static_assert(sizeof(struct vpe_promotion_row)==288&&sizeof(vpe_promotions)==1216,"whole supplied register promotion record");
static const unsigned vpe_indices[]={VPE_PROMOTED_INDICES};
static const unsigned char vpe_bytes[5][6]={
    {0x62,0xf1,0x75,0x40,0x74,0xc7},
    {0x62,0xb1,0x75,0x40,0x74,0xc0},
    {0x62,0xb1,0x75,0x40,0x74,0xc9},
    {0x62,0xb1,0x7d,0x40,0x74,0xc8},
    {0x62,0xb1,0x75,0x41,0x74,0xc8},
};
static unsigned vpe_is_promoted(size_t index) {
    for(size_t i=0;i<sizeof(vpe_indices)/sizeof(vpe_indices[0]);i++)if(index==vpe_indices[i])return 1;
    return 0;
}
static void vpe_promote(size_t index,const unsigned char *bytes,size_t n,
                        uint32_t classified,const struct li2_tf_classification *value) {
    size_t at=(size_t)vpe_promotions.attempted,count=sizeof(vpe_indices)/sizeof(vpe_indices[0]);
    need(((count==1&&VPE_FIRST_ENCODING==0)||(count==4&&VPE_FIRST_ENCODING==1))&&
         at<count&&index==vpe_indices[at]&&n==6&&!memcmp(bytes,vpe_bytes[at+VPE_FIRST_ENCODING],6),1370);
    struct vpe_promotion_row *r=&vpe_promotions.rows[at];++vpe_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1720&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->next_pc==0x1006&&value->length==6,1371);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==1720&&r->footprint.length==6&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1006&&!r->footprint.first&&!r->footprint.end,1372);
    r->complete=1;++vpe_promotions.completed;
}
static void vpe_promotions_complete(void) {
    size_t n=sizeof(vpe_indices)/sizeof(vpe_indices[0]);
    need(vpe_promotions.attempted==n&&vpe_promotions.completed==n,1373);
    vpe_promotions.magic=UINT64_C(0x315052455056324c);vpe_promotions.version=1;vpe_promotions.bytes=sizeof(vpe_promotions);
}
