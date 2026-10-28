/* Supplied-byte controls only; call after real decoder initialization. These
   exercise the shared entry decision, never create a mapping/entry permit. */
#include "tf_entry_route.h"
#include "tf_owner.h"
struct route_case { unsigned char bytes[8];size_t length;unsigned route,policy; };
int li2_trace_route_controls(size_t *failed) {
    static const struct route_case cases[]={
        {{0x48,0x01,0xc8},3,LI2_TF_ENTRY_PLAIN,1}, /* ADD RAX,RCX */
        {{0x48,0x8b,0x06},3,LI2_TF_ENTRY_PLAIN,1}, /* MOV RAX,[RSI] */
        {{0xe8,0,0,0,0},5,LI2_TF_ENTRY_PLAIN,1}, /* original near CALL */
        {{0xc3},1,LI2_TF_ENTRY_PLAIN,1},
        {{0x66,0x90},2,LI2_TF_ENTRY_PLAIN,1},
        {{0x0f,0x01,0xd0},3,LI2_TF_ENTRY_XGETBV,1},
        {{0xf3,0x48,0x0f,0x1e,0xc8},5,LI2_TF_ENTRY_RDSSPQ,1},
        {{0xf2,0xff,0x25,0,0,0,0},7,LI2_TF_ENTRY_BND,1},
        {{0xff,0x25,0,0,0,0},6,LI2_TF_ENTRY_PLAIN,1},
        {{0x0f,0xa2},2,LI2_TF_ENTRY_UNKNOWN,0},
        {{0x48,0x0f,0xc7,0xf0},4,LI2_TF_ENTRY_UNKNOWN,0},
        {{0x0f,0x05},2,LI2_TF_ENTRY_UNKNOWN,0},
        {{0xf3,0x48,0xab},3,LI2_TF_ENTRY_UNKNOWN,0},
        {{0x0f,0x0b},2,LI2_TF_ENTRY_UNKNOWN,0},
        /* A plain Code alone cannot grant entry: actual classifier must also
           reject this unqualified prefix, as the chain preparation does. */
        {{0x2e,0x48,0x01,0xc8},4,LI2_TF_ENTRY_PLAIN,0}
    };
    if(!failed)return 0;
    *failed=SIZE_MAX;
    for(size_t i=0;i<sizeof cases/sizeof cases[0];i++) {
        const struct route_case *r=&cases[i];struct li2_decoded d={0};struct li2_tf_classification c={0};
        if(li2_decoder_decode(0x1000,r->bytes,r->length,&d) ||
           li2_decoder_tf_classify(0x1000,r->bytes,r->length,&c) ||
           li2_tf_entry_route(&d)!=r->route || c.policy!=r->policy){*failed=i;return 0;}
    }
    return 1;
}
