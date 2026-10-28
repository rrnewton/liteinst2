/* Exact supplied-byte promotions. Old rows stay in their original arrays.
   A valid classification alone is insufficient: every promoted row also needs
   the separately typed zero-write footprint. Callers retain exact counts. */
#include "write_footprint.h"
static unsigned vbr_promoted;
static void vbr_promote(const struct vpb_refusal *v,unsigned index) {
    static const unsigned char exact[4][6]={
        {0x62,0xe2,0x7d,0x48,0x7a,0xc0},{0x62,0xe2,0x7d,0x48,0x7a,0xce},
        {0x62,0xf2,0x7d,0x48,0x7a,0xc6},{0x62,0xc2,0x7d,0x48,0x7a,0xc6}};
    need(index<4&&v->n==6&&!memcmp(v->b,exact[index],6)&&
         !result.decoder_result&&refused_last.abi_version==1&&
         refused_last.pc==0x1000&&refused_last.next_pc==0x1006&&
         refused_last.policy==1&&refused_last.flow==LI2_TF_FALLTHROUGH&&
         refused_last.family==LI2_TF_SIMD&&refused_last.code==3210&&refused_last.length==6,1194);
    struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
    need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
         footprint.abi_version==1&&footprint.policy==LI2_WRITE_NONE&&
         footprint.code==3210&&footprint.length==6&&footprint.pc==0x1000&&
         footprint.next_pc==0x1006&&!footprint.first&&!footprint.end,1195);
    ++vbr_promoted;
}
