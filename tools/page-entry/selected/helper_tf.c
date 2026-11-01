#include "helper_tf.h"

struct helper_form { struct li2_decoded decoded; uint32_t family,width,displacement; };
static int helper_same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
/* Exact Code numbers are from the bound iced-x86 1.21 enum. Every candidate
   is re-decoded by that actual sealed provider before any description escapes.
   No prefixes, WAIT byte, alternate addressing, K extension or other widths. */
static int helper_literal(const struct li2_decoded *held,struct helper_form *out) {
    if(!held || !out || !held->available || held->available>15 ||
       held->pc>UINTPTR_MAX-held->available)return LI2_HT_ARGUMENT;
    const unsigned char *b=held->bytes;size_t n=held->available;
    uint32_t code=0,length=0,family=0,width=0,displacement=0;
    if(n>=6 && b[0]==0x8f && b[1]==0x05) {
        code=298;length=6;family=LI2_TF_STACK;width=8;displacement=2;
    } else if(n>=6 && b[0]==0x8c && (b[1]&0xc7)==0x05 && (b[1]&0x38)<0x30) {
        code=288;length=6;family=LI2_TF_INTEGER;width=2;displacement=2;
    } else if(n>=6 && b[0]==0xd9 && b[1]==0x3d) {
        code=520;length=6;family=LI2_HELPER_TF_X87;width=2;displacement=2;
    } else if(n>=6 && b[0]==0xdd && b[1]==0x3d) {
        code=615;length=6;family=LI2_HELPER_TF_X87;width=2;displacement=2;
    } else if(n>=2 && b[0]==0xdb && b[1]==0xe3) {
        code=582;length=2;family=LI2_HELPER_TF_X87;
    } else if(n>=2 && b[0]==0xd9 && (b[1]==0xe8 || b[1]==0xeb)) {
        code=b[1]==0xe8?530:533;length=2;family=LI2_HELPER_TF_X87;
    } else if(n>=6 && b[0]==0xd9 && b[1]==0x2d) {
        code=515;length=6;family=LI2_HELPER_TF_X87;
    } else if(n>=9 && b[0]==0xc4 && b[1]==0xe1 && b[2]==0xf8 &&
              (b[3]==0x90 || b[3]==0x91) && (b[4]&0xc7)==0x05) {
        code=b[3]==0x90?1919:1923;length=9;family=LI2_TF_SIMD;
        if(b[3]==0x91){width=8;displacement=5;}
    } else return LI2_HT_FORM;
    *out=(struct helper_form){.decoded={.pc=held->pc,.next_pc=held->pc+length,
        .abi_version=1,.decode_status=LI2_VALID,.code=code,.kind=LI2_NONE,
        .destination=16,.step_disposition=LI2_STEP_UNSUPPORTED,
        .available=(uint32_t)n,.length=length},.family=family,
        .width=width,.displacement=displacement};
    for(size_t i=0;i<n;i++)out->decoded.bytes[i]=b[i];
    return 0;
}
static int helper_describe(const struct li2_decoded *held,struct helper_form *out) {
    int e=helper_literal(held,out);if(e)return e;
    struct li2_decoded actual={0};
    if(li2_decoder_decode(held->pc,held->bytes,held->available,&actual))return LI2_HT_DECODER;
    if(!helper_same(&actual,&out->decoded,sizeof actual) ||
       !helper_same(held,&actual,sizeof actual))return LI2_HT_IDENTITY;
    return 0;
}
int li2_helper_tf_classify(const struct li2_decoded *held,struct li2_tf_classification *out) {
    if(!out)return LI2_HT_ARGUMENT;
    *out=(struct li2_tf_classification){0};
    struct helper_form form;int e=helper_describe(held,&form);if(e)return e;
    *out=(struct li2_tf_classification){.pc=form.decoded.pc,.next_pc=form.decoded.next_pc,
        .abi_version=1,.policy=1,.code=form.decoded.code,.length=form.decoded.length,
        .flow=LI2_TF_FALLTHROUGH,.family=form.family};
    return 0;
}
int li2_helper_tf_entry(const struct li2_decoded *held) {
    struct li2_tf_classification c={0};int e=li2_helper_tf_classify(held,&c);
    if(e)return e;
    return c.policy==1 && c.flow==LI2_TF_FALLTHROUGH &&
        (c.family==LI2_TF_INTEGER || c.family==LI2_TF_STACK ||
         c.family==LI2_TF_SIMD || c.family==LI2_HELPER_TF_X87)?0:LI2_HT_IDENTITY;
}
int li2_helper_tf_write(const struct li2_decoded *held,const struct li2_write_registers *regs,
                        struct li2_write_footprint *out) {
    if(!out)return LI2_HT_ARGUMENT;
    *out=(struct li2_write_footprint){0};
    if(!regs)return LI2_HT_ARGUMENT;
    struct helper_form form;int e=helper_describe(held,&form);if(e)return e;
    struct li2_write_footprint f={.pc=form.decoded.pc,.next_pc=form.decoded.next_pc,
        .abi_version=1,.policy=LI2_WRITE_NONE,.code=form.decoded.code,.length=form.decoded.length};
    /* NONE describes no application-memory write, never a successful read or
       an unchanged FP/mask result. FNINIT and FNST* retain no-WAIT semantics.
       FLD1/FLDPI/FLDCW and all memory faults remain actual CPU effects at the
       original PC. POP writes its complete RIP-relative destination; its
       implicit stack read/RSP increment is not a store, and cannot change EA. */
    if(form.width) {
        f.policy=LI2_WRITE_UNSUPPORTED;
        const unsigned char *d=form.decoded.bytes+form.displacement;
        uint32_t bits=(uint32_t)d[0]|(uint32_t)d[1]<<8|(uint32_t)d[2]<<16|(uint32_t)d[3]<<24;
        uint64_t first;
        if(bits&UINT32_C(0x80000000)) {
            uint64_t magnitude=(uint64_t)(~bits)+1;
            if(f.next_pc<magnitude){*out=f;return 0;}
            first=f.next_pc-magnitude;
        } else {
            if(f.next_pc>UINT64_MAX-bits){*out=f;return 0;}
            first=f.next_pc+bits;
        }
        if(first<=UINT64_MAX-form.width) {
            f.first=first;f.end=first+form.width;f.policy=LI2_WRITE_RANGE;
        }
    }
    *out=f;return 0;
}
