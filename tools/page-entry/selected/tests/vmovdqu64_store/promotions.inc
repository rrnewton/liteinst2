/* Original retained Code1847 bytes are mandatory typed/RANGE64 controls.
   Inputs here are supplied tuples; native coverage is a separate full-state pair. */
#ifndef VDQ_STORE_PROMOTED_INDICES
#error VDQ_STORE_PROMOTED_INDICES must bind the complete original row set
#endif
static const uint64_t vdq_store_indices[]={VDQ_STORE_PROMOTED_INDICES};
#define VDQ_STORE_PROMOTION_COUNT (sizeof(vdq_store_indices)/sizeof(vdq_store_indices[0]))
_Static_assert(VDQ_STORE_PROMOTION_COUNT==1||VDQ_STORE_PROMOTION_COUNT==2,"one or two exact original tables");
struct vdq_store_promotion_row {
    uint64_t index,attempted,class_result,query_result,complete;
    unsigned char bytes[16];
    struct li2_tf_classification classification;
    struct li2_write_registers before;
    struct li2_write_footprint footprint;
};
static struct {
    uint64_t magic,version,bytes,attempted,completed,reserved[3];
    struct vdq_store_promotion_row rows[VDQ_STORE_PROMOTION_COUNT];
} vdq_store_promotions;
_Static_assert(sizeof(struct vdq_store_promotion_row)==288&&sizeof(vdq_store_promotions)==64+288*VDQ_STORE_PROMOTION_COUNT,
               "complete supplied Code1847 promotion record");
static unsigned vdq_store_is_promoted(size_t index) {
    for(size_t i=0;i<VDQ_STORE_PROMOTION_COUNT;i++)if(index==vdq_store_indices[i])return 1;
    return 0;
}
static void vdq_store_promote(size_t index,const unsigned char *bytes,size_t n,
                          uint32_t classified,const struct li2_tf_classification *value) {
    static const unsigned char literal[6]={0x62,0xe1,0xfe,0x48,0x7f,0x0f};
    size_t slot=0;while(slot<VDQ_STORE_PROMOTION_COUNT&&vdq_store_indices[slot]!=index)++slot;
    need(slot<VDQ_STORE_PROMOTION_COUNT&&n==6&&!memcmp(bytes,literal,6),1280);
    struct vdq_store_promotion_row *r=&vdq_store_promotions.rows[slot];
    need(!r->attempted&&!r->complete,1280);++vdq_store_promotions.attempted;
    r->index=index;r->attempted=1;r->class_result=classified;
    memcpy(r->bytes,bytes,n);r->classification=*value;
    need(!classified&&value->abi_version==1&&value->policy==1&&value->code==1847&&
         value->flow==LI2_TF_FALLTHROUGH&&value->family==LI2_TF_SIMD&&
         value->pc==0x1000&&value->length==n&&value->next_pc==0x1000+n,1281);
    for(unsigned i=0;i<16;i++)r->before.gpr[i]=UINT64_C(0x1234000)+16*i;
    r->query_result=li2_decoder_write_footprint(0x1000,bytes,n,&r->before,&r->footprint);
    need(!r->query_result&&r->footprint.abi_version==1&&r->footprint.policy==LI2_WRITE_RANGE&&
         r->footprint.code==1847&&r->footprint.length==n&&r->footprint.pc==0x1000&&
         r->footprint.next_pc==0x1000+n&&r->footprint.first==r->before.gpr[7]&&r->footprint.end==r->before.gpr[7]+64,1282);
    r->complete=1;++vdq_store_promotions.completed;
}
static void vdq_store_promotions_complete(void) {
    need(vdq_store_indices[0]==16&&(VDQ_STORE_PROMOTION_COUNT==1||vdq_store_indices[1]==5)&&
         vdq_store_promotions.attempted==VDQ_STORE_PROMOTION_COUNT&&
         vdq_store_promotions.completed==VDQ_STORE_PROMOTION_COUNT,1283);
    for(size_t i=0;i<VDQ_STORE_PROMOTION_COUNT;i++)need(vdq_store_promotions.rows[i].attempted==1&&
        vdq_store_promotions.rows[i].complete==1&&vdq_store_promotions.rows[i].index==vdq_store_indices[i],1284);
    vdq_store_promotions.magic=UINT64_C(0x31504d445156324c);vdq_store_promotions.version=1;
    vdq_store_promotions.bytes=sizeof(vdq_store_promotions);
}
