/* Five exact old neighbors are positive typed controls, separately exercised natively.
   The query inputs here are supplied tuples, not native before-state frames. */
struct vpcm_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vpcm_promotion_row rows[5];
} vpcm_promotions;
_Static_assert(sizeof(struct vpcm_promotion_row)==288&&sizeof(vpcm_promotions)==1504,
               "complete supplied promotion records");
static const unsigned vpcm_promoted_rows[5]={33,34,39,40,41};
static const unsigned char vpcm_promoted_bytes[5][6]={
    {0x62,0xf1,0x75,0x40,0x74,0x0f},{0x62,0xf1,0x75,0x40,0x74,0x3f},
    {0x62,0xf1,0x75,0x48,0x74,0x07},{0x62,0xf1,0x7d,0x40,0x74,0x07},
    {0x62,0xf1,0x6d,0x40,0x74,0x07},
};
static unsigned vpcm_is_promoted(size_t index) {
    for(unsigned i=0;i<5;i++)if(index==vpcm_promoted_rows[i])return 1;
    return 0;
}
static void vpcm_promote(size_t index,const unsigned char *bytes,size_t n,
                         uint32_t classified,const struct li2_tf_classification *value) {
    unsigned at=(unsigned)vpcm_promotions.attempted;
    need(at<5&&index==vpcm_promoted_rows[at]&&n==6&&!memcmp(bytes,vpcm_promoted_bytes[at],6),1250);
    struct vpcm_promotion_row *r=&vpcm_promotions.rows[at];++vpcm_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1720&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1251);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==1720&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&!r->footprint.first&&!r->footprint.end,1252);
    r->complete=1;++vpcm_promotions.completed;
}
static void vpcm_promotions_complete(void) {
    need(vpcm_promotions.attempted==5&&vpcm_promotions.completed==5,1253);
    vpcm_promotions.magic=UINT64_C(0x31504d435056324c);vpcm_promotions.version=1;
    vpcm_promotions.bytes=sizeof(vpcm_promotions);
}
