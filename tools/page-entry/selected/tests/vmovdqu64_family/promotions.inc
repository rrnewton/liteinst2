/* Seven exact old neighbors are positive typed controls, separately exercised natively.
   The query inputs here are supplied tuples, not native before-state frames. */
struct vm64_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vm64_promotion_row rows[7];
} vm64_promotions;
_Static_assert(sizeof(struct vm64_promotion_row)==288&&sizeof(vm64_promotions)==2080,
               "complete supplied promotion records");
static const unsigned vm64_promoted_rows[7]={0,1,2,3,4,5,6};
static const unsigned char vm64_promoted_bytes[7][6]={
    {0x62,0xf1,0xfe,0x48,0x6f,0x0f},
    {0x62,0x71,0xfe,0x48,0x6f,0x0f},
    {0x62,0x61,0xfe,0x48,0x6f,0x0f},
    {0x62,0xc1,0xfe,0x48,0x6f,0x0f},
    {0x62,0xe1,0xfe,0x48,0x6f,0x0e},
    {0x62,0xe1,0xfe,0x48,0x6f,0x17},
    {0x62,0xe1,0xfe,0x48,0x6f,0xcf},
};
static unsigned vm64_is_promoted(size_t index) {
    for(unsigned i=0;i<7;i++)if(index==vm64_promoted_rows[i])return 1;
    return 0;
}
static void vm64_promote(size_t index,const unsigned char *bytes,size_t n,
                         uint32_t classified,const struct li2_tf_classification *value) {
    unsigned at=(unsigned)vm64_promotions.attempted;
    need(at<7&&index==vm64_promoted_rows[at]&&n==6&&!memcmp(bytes,vm64_promoted_bytes[at],6),1250);
    struct vm64_promotion_row *r=&vm64_promotions.rows[at];++vm64_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1605&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1251);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==1605&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&!r->footprint.first&&!r->footprint.end,1252);
    r->complete=1;++vm64_promotions.completed;
}
static void vm64_promotions_complete(void) {
    need(vm64_promotions.attempted==7&&vm64_promotions.completed==7,1253);
    vm64_promotions.magic=UINT64_C(0x31504d343656324c);vm64_promotions.version=1;
    vm64_promotions.bytes=sizeof(vm64_promotions);
}
