/* The original index20 KMOVD bytes are now one mandatory typed/NONE control.
   Inputs here are supplied tuples; native coverage is a separate full-state pair. */
struct kd32_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct kd32_promotion_row rows[1];
} kd32_promotions;
_Static_assert(sizeof(struct kd32_promotion_row)==288&&sizeof(kd32_promotions)==352,
               "complete supplied Code1932 promotion record");
static unsigned kd32_is_promoted(size_t index) {return index==20;}
static void kd32_promote(size_t index,const unsigned char *bytes,size_t n,
                          uint32_t classified,const struct li2_tf_classification *value) {
    static const unsigned char literal[4]={0xc5,0xfb,0x93,0xf0};
    need(!kd32_promotions.attempted&&index==20&&n==4&&!memcmp(bytes,literal,4),1280);
    struct kd32_promotion_row *r=&kd32_promotions.rows[0];++kd32_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1932&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1281);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==1932&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&!r->footprint.first&&!r->footprint.end,1282);
    r->complete=1;++kd32_promotions.completed;
}
static void kd32_promotions_complete(void) {
    need(kd32_promotions.attempted==1&&kd32_promotions.completed==1,1283);
    kd32_promotions.magic=UINT64_C(0x31504d444b56324c);kd32_promotions.version=1;
    kd32_promotions.bytes=sizeof(kd32_promotions);
}
