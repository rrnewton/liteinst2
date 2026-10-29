/* Every promoted old byte remains an exact typed/query control. The input
   GPR tuple is supplied, never relabelled an actual native before-state. */
#ifndef VTN_PROMOTED_INDICES
#error VTN_PROMOTED_INDICES must name the exact fixed old catalog rows
#endif
struct vtn_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vtn_promotion_row rows[11];
} vtn_promotions;
_Static_assert(sizeof(struct vtn_promotion_row)==288&&sizeof(vtn_promotions)==3232,
               "complete supplied Code2791 promotion records");
static const unsigned vtn_promoted_indices[]={VTN_PROMOTED_INDICES};
static const unsigned char vtn_promoted_bytes[10][6]={
    {0x62,0xb2,0x76,0x40,0x26,0xc9},
    {0x62,0xb2,0x76,0x40,0x26,0xf9},
    {0x62,0xb2,0x76,0x40,0x26,0xc0},
    {0x62,0xb2,0x76,0x40,0x26,0xc2},
    {0x62,0xb2,0x7e,0x40,0x26,0xc1},
    {0x62,0xb2,0x6e,0x40,0x26,0xc1},
    {0x62,0xf2,0x76,0x40,0x26,0xc1},
    {0x62,0xb2,0x76,0x48,0x26,0xc1},
    {0x62,0xb2,0x76,0x41,0x26,0xc1},
    {0x62,0xb2,0x76,0x47,0x26,0xc1},
};
static unsigned vtn_is_promoted(size_t index) {
    for(size_t i=0;i<sizeof(vtn_promoted_indices)/sizeof(vtn_promoted_indices[0]);i++)
        if(index==vtn_promoted_indices[i])return 1;
    return 0;
}
static void vtn_promote(size_t index,const unsigned char *bytes,size_t n,
                        uint32_t classified,const struct li2_tf_classification *value) {
    size_t at=(size_t)vtn_promotions.attempted;
    size_t count=sizeof(vtn_promoted_indices)/sizeof(vtn_promoted_indices[0]);
    need(count>=10&&count<=11&&at<count&&index==vtn_promoted_indices[at]&&n==6&&
         !memcmp(bytes,vtn_promoted_bytes[at==10?8:at],6),1280);
    struct vtn_promotion_row *r=&vtn_promotions.rows[at];++vtn_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==2791&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1281);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==2791&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&!r->footprint.first&&!r->footprint.end,1282);
    r->complete=1;++vtn_promotions.completed;
}
static void vtn_promotions_complete(void) {
    size_t count=sizeof(vtn_promoted_indices)/sizeof(vtn_promoted_indices[0]);
    need((count==10||count==11)&&vtn_promotions.attempted==count&&vtn_promotions.completed==count,1283);
    vtn_promotions.magic=UINT64_C(0x31504d4e5456324c);vtn_promotions.version=1;
    vtn_promotions.bytes=sizeof(vtn_promotions);
}
