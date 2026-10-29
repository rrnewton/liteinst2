/* Fixed former Code3676 register neighbors. Supplied tuples are not
   relabelled genuine native before-state; the new family owns native coverage. */
struct bmi_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct { uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct bmi_promotion_row rows[2]; } bmi_promotions;
_Static_assert(sizeof(struct bmi_promotion_row)==288&&sizeof(bmi_promotions)==640,"whole supplied register promotion record");
static const unsigned bmi_indices[]={15,16};
static const unsigned char bmi_bytes[2][5]={
    {0xc4,0xe2,0xc0,0xf3,0xd6},{0xc4,0xe2,0xc8,0xf3,0xd7},
};
static unsigned bmi_is_promoted(size_t index) {
    for(size_t i=0;i<sizeof(bmi_indices)/sizeof(bmi_indices[0]);i++)if(index==bmi_indices[i])return 1;
    return 0;
}
static void bmi_promote(size_t index,const unsigned char *bytes,size_t n,
                        uint32_t classified,const struct li2_tf_classification *value) {
    size_t at=(size_t)bmi_promotions.attempted,count=sizeof(bmi_indices)/sizeof(bmi_indices[0]);
    need(count==2&&
         at<count&&index==bmi_indices[at]&&n==5&&!memcmp(bytes,bmi_bytes[at],5),1370);
    struct bmi_promotion_row *r=&bmi_promotions.rows[at];++bmi_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==3676&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_INTEGER&&
         value->pc==0x1000&&value->next_pc==0x1005&&value->length==5,1371);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==3676&&r->footprint.length==5&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1005&&!r->footprint.first&&!r->footprint.end,1372);
    r->complete=1;++bmi_promotions.completed;
}
static void bmi_promotions_complete(void) {
    size_t n=sizeof(bmi_indices)/sizeof(bmi_indices[0]);
    need(bmi_promotions.attempted==n&&bmi_promotions.completed==n,1373);
    bmi_promotions.magic=UINT64_C(0x3150524d4950324c);bmi_promotions.version=1;bmi_promotions.bytes=sizeof(bmi_promotions);
}
