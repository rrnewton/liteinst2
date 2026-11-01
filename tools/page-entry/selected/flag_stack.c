#include "flag_stack.h"
#include "tf_owner.h"
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int literal(uintptr_t pc,const unsigned char *bytes,size_t n,
                   struct li2_fs_descriptor *out) {
    if(!bytes || !out || !n || n>15 || pc>UINTPTR_MAX-n)return LI2_FS_ARGUMENT;
    if(bytes[0]!=0x9c && bytes[0]!=0x9d)return LI2_FS_FORM;
    *out=(struct li2_fs_descriptor){.decoded={.pc=pc,.next_pc=pc+1,
        .abi_version=1,.decode_status=LI2_VALID,.code=bytes[0]==0x9c?317:320,
        .kind=LI2_NONE,.destination=16,.step_disposition=bytes[0]==0x9c?
            LI2_STEP_FLAGS_OBSERVED:LI2_STEP_FLAGS_RESTORED,
        .available=(uint32_t)n,.length=1},.version=LI2_FS_VERSION,
        .operation=bytes[0]==0x9c?LI2_FS_PUSHFQ:LI2_FS_POPFQ};
    for(size_t i=0;i<n;i++)out->decoded.bytes[i]=bytes[i];
    return 0;
}
int li2_fs_describe(uintptr_t pc,const unsigned char *bytes,size_t n,
                    struct li2_fs_descriptor *out) {
    if(!out)return LI2_FS_ARGUMENT;
    *out=(struct li2_fs_descriptor){0};
    struct li2_fs_descriptor expected;
    int e=literal(pc,bytes,n,&expected);if(e)return e;
    struct li2_decoded actual={0};struct li2_tf_classification tf={0};
    if(li2_decoder_decode(pc,bytes,n,&actual) ||
       li2_decoder_tf_classify(pc,bytes,n,&tf))return LI2_FS_DECODER;
    const struct li2_tf_classification refused={.pc=pc,.next_pc=pc+1,
        .abi_version=1,.code=expected.decoded.code,.length=1};
    if(!same(&actual,&expected.decoded,sizeof actual) ||
       !same(&tf,&refused,sizeof tf))return LI2_FS_FORM;
    *out=expected;return 0;
}
int li2_fs_validate(const struct li2_fs_descriptor *d) {
    if(!d)return LI2_FS_ARGUMENT;
    struct li2_fs_descriptor expected;
    int e=literal(d->decoded.pc,d->decoded.bytes,d->decoded.available,&expected);
    return e || !same(d,&expected,sizeof expected)?LI2_FS_CORRUPT:0;
}
int li2_fs_emit(const struct li2_fs_descriptor *d,unsigned char out[LI2_FS_IMAGE_BYTES]) {
    if(!out)return LI2_FS_ARGUMENT;
    int e=li2_fs_validate(d);if(e)return e;
    unsigned char image[LI2_FS_IMAGE_BYTES]={0,0xff,0x25,1,0,0,0,0xcc};
    image[0]=d->decoded.bytes[0];
    for(unsigned i=0;i<8;i++)image[8+i]=(unsigned char)(d->decoded.next_pc>>(8*i));
    for(unsigned i=0;i<LI2_FS_IMAGE_BYTES;i++)out[i]=image[i];
    return 0;
}
int li2_fs_write(const struct li2_fs_descriptor *d,uint64_t rsp,
                 struct li2_write_footprint *out) {
    if(!out)return LI2_FS_ARGUMENT;
    int e=li2_fs_validate(d);if(e)return e;
    struct li2_write_footprint f={.pc=d->decoded.pc,.next_pc=d->decoded.next_pc,
        .abi_version=1,.policy=LI2_WRITE_NONE,.code=d->decoded.code,.length=1};
    if(d->operation==LI2_FS_PUSHFQ) {
        f.policy=LI2_WRITE_UNSUPPORTED;
        if(rsp>=8){f.first=rsp-8;f.end=rsp;f.policy=LI2_WRITE_RANGE;}
    }
    *out=f;return 0;
}
