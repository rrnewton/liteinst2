/* Exact supplied-byte promotions. Old rows stay in their original arrays.
   A valid classification alone is insufficient: every promoted row also needs
   the separately typed zero-write footprint. Callers retain exact counts. */
#include "write_footprint.h"
static unsigned kmr_promoted;
static void kmr_promote(const struct vpb_refusal *v,unsigned index) {
    static const unsigned char exact[7][5]={
        {0xc4,0xe1,0xfb,0x93,0xc0},{0xc4,0xe1,0xfb,0x93,0xf8},
        {0xc4,0x61,0xfb,0x93,0xf0},{0xc4,0xe1,0xfb,0x93,0xf1},
        {0xc4,0xe1,0xfb,0x93,0xf7},{0xc4,0xe1,0xfb,0x93,0xc9},
        {0xc4,0xe1,0xfb,0x93,0xc2}};
    need(index<7&&v->n==5&&!memcmp(v->b,exact[index],5)&&
         !result.decoder_result&&refused_last.abi_version==1&&
         refused_last.pc==0x1000&&refused_last.next_pc==0x1005&&
         refused_last.policy==1&&refused_last.flow==LI2_TF_FALLTHROUGH&&
         refused_last.family==LI2_TF_SIMD&&refused_last.code==1933&&refused_last.length==5,1194);
    struct li2_write_registers registers={0};struct li2_write_footprint footprint={0};
    need(!li2_decoder_write_footprint(0x1000,v->b,v->n,&registers,&footprint)&&
         footprint.abi_version==1&&footprint.policy==LI2_WRITE_NONE&&
         footprint.code==1933&&footprint.length==5&&footprint.pc==0x1000&&
         footprint.next_pc==0x1005&&!footprint.first&&!footprint.end,1195);
    ++kmr_promoted;
}
