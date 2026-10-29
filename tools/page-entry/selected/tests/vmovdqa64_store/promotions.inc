/* The original index10 store bytes are now one mandatory typed/RANGE64 control.
   Inputs here are supplied tuples; native coverage is a separate full-state pair. */
struct vqa_store_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vqa_store_promotion_row rows[1];
} vqa_store_promotions;
_Static_assert(sizeof(struct vqa_store_promotion_row)==288&&sizeof(vqa_store_promotions)==352,
               "complete supplied Code1838 promotion record");
static unsigned vqa_store_is_promoted(size_t index) {return index==10;}
static void vqa_store_promote(size_t index,const unsigned char *bytes,size_t n,
                          uint32_t classified,const struct li2_tf_classification *value) {
    static const unsigned char literal[6]={0x62,0xe1,0xfd,0x48,0x7f,0x0f};
    need(!vqa_store_promotions.attempted&&index==10&&n==6&&!memcmp(bytes,literal,6),1280);
    struct vqa_store_promotion_row *r=&vqa_store_promotions.rows[0];++vqa_store_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1838&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1281);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_RANGE&&
         r->footprint.code==1838&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&r->footprint.first==r->before.gpr[7]&&r->footprint.end==r->before.gpr[7]+64,1282);
    r->complete=1;++vqa_store_promotions.completed;
}
static void vqa_store_promotions_complete(void) {
    need(vqa_store_promotions.attempted==1&&vqa_store_promotions.completed==1,1283);
    vqa_store_promotions.magic=UINT64_C(0x31504d415156324c);vqa_store_promotions.version=1;
    vqa_store_promotions.bytes=sizeof(vqa_store_promotions);
}
