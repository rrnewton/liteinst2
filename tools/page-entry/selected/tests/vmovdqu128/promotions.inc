/* Twelve formerly refused bytes remain explicit typed positive controls.
   These supplied register tuples are not native before-state observations. */
struct v128_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct v128_promotion_row rows[12];
} v128_promotions;
_Static_assert(sizeof(struct v128_promotion_row)==288&&sizeof(v128_promotions)==3520,
               "complete supplied promotion records");
static const unsigned v128_promoted_rows[12]={66,67,68,69,70,71,72,79,80,81,82,83};
static unsigned v128_is_promoted(size_t index) {
    for(unsigned i=0;i<12;i++)if(index==v128_promoted_rows[i])return 1;
    return 0;
}
static void v128_promote(size_t index,const unsigned char *bytes,size_t n,
                         uint32_t classified,const struct li2_tf_classification *value) {
    need(v128_promotions.attempted<12&&index==v128_promoted_rows[v128_promotions.attempted]&&n<=16,1250);
    struct v128_promotion_row *r=&v128_promotions.rows[v128_promotions.attempted++];
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1598&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1251);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_NONE&&
         r->footprint.code==1598&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&!r->footprint.first&&!r->footprint.end,1252);
    r->complete=1;++v128_promotions.completed;
}
static void v128_promotions_complete(void) {
    need(v128_promotions.attempted==12&&v128_promotions.completed==12,1253);
    v128_promotions.magic=UINT64_C(0x31504d383231564c);v128_promotions.version=1;
    v128_promotions.bytes=sizeof(v128_promotions);
}
