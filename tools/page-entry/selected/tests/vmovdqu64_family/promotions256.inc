/* The original index12 vl256 bytes are now one mandatory typed/NONE control.
   Inputs here are supplied tuples; native coverage is a separate full-state pair. */
struct vm256_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vm256_promotion_row rows[1];
} vm256_promotions;
_Static_assert(sizeof(struct vm256_promotion_row)==288&&sizeof(vm256_promotions)==352,
               "complete supplied Code1604 promotion record");
static unsigned vm256_is_promoted(size_t index) {return index==12;}
static void vm256_promote(size_t index,const unsigned char *bytes,size_t n,
                          uint32_t classified,const struct li2_tf_classification *value) {
    static const unsigned char literal[6]={0x62,0xe1,0xfe,0x28,0x6f,0x0f};
    need(!vm256_promotions.attempted&&index==12&&n==6&&!memcmp(bytes,literal,6),1280);
    struct vm256_promotion_row *r=&vm256_promotions.rows[0];++vm256_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1604&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1281);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==1604&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&!r->footprint.first&&!r->footprint.end,1282);
    r->complete=1;++vm256_promotions.completed;
}
static void vm256_promotions_complete(void) {
    need(vm256_promotions.attempted==1&&vm256_promotions.completed==1,1283);
    vm256_promotions.magic=UINT64_C(0x31504d363256324c);vm256_promotions.version=1;
    vm256_promotions.bytes=sizeof(vm256_promotions);
}
