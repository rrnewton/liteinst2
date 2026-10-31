#define _GNU_SOURCE
#include "../../capture_rle.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Actual codec, synthetic immutable snapshots and write results. No runtime
   permissions, owner, signal chronology or native admission are established. */
_Alignas(64) static unsigned char raw_store[LI2_CAPTURE_RLE_LIMIT+32],body_store[LI2_CAPTURE_RLE_LIMIT+32];
static unsigned char written[LI2_CAPTURE_RLE_LIMIT+32],decoded[LI2_CAPTURE_RLE_LIMIT];
static unsigned char *const raw=raw_store+16,*const body=body_store+16;
struct output {size_t at,calls,chunk,fail_call;long failure;};
static long put(void *context,const void *p,size_t n) {
    struct output *o=context;++o->calls;
    if(o->calls==o->fail_call)return o->failure;
    size_t k=o->chunk && o->chunk<n?o->chunk:n;
    assert(k<=LI2_CAPTURE_RLE_LIMIT-o->at);memcpy(written+o->at,p,k);o->at+=k;
    return (long)k;
}
static uint64_t u64(const unsigned char *p) {
    uint64_t n=0;for(unsigned i=0;i<8;i++)n|=(uint64_t)p[i]<<(8*i);return n;
}
static uint32_t u32(const unsigned char *p) {
    uint32_t n=0;for(unsigned i=0;i<4;i++)n|=(uint32_t)p[i]<<(8*i);return n;
}
static void expand(size_t body_bytes,size_t n) {
    size_t at=64,used=0;
    while(at<body_bytes) {
        assert(body_bytes-at>=5);unsigned tag=body[at];size_t k=u32(body+at+1);at+=5;
        assert(k && k<=n-used);
        if(tag==0) {assert(k<=65536 && k<=body_bytes-at);memcpy(decoded+used,body+at,k);at+=k;}
        else {assert(tag==1 && k>=8 && at<body_bytes);memset(decoded+used,body[at++],k);}
        used+=k;
    }
    assert(at==body_bytes && used==n && !memcmp(decoded,raw,n));
}
static void sentinels(void) {
    for(unsigned i=0;i<16;i++) {
        assert(raw_store[i]==0x6a && raw_store[LI2_CAPTURE_RLE_LIMIT+16+i]==0x6a);
        assert(body_store[i]==0x7b && body_store[LI2_CAPTURE_RLE_LIMIT+16+i]==0x7b);
    }
}
int main(int argc,char **argv) {
    assert(argc==2);
    memset(raw_store,0x6a,sizeof raw_store);memset(body_store,0x7b,sizeof body_store);
    const size_t lengths[]={1,7,8,9,127,128,129,65535,65536,65537};
    unsigned roundtrips=0;
    for(unsigned kind=0;kind<4;kind++)for(unsigned i=0;i<sizeof lengths/sizeof *lengths;i++) {
        size_t n=lengths[i],bytes=0;
        for(size_t j=0;j<n;j++)raw[j]=(unsigned char)(kind==0?0:kind==1?j%256:kind==2?(j/8)%2:j%9?0x90:0x42);
        assert(li2_capture_rle_prepare(raw,n,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes)==LI2_CAPTURE_RLE_OK);
        for(size_t j=0;j<n;j++)assert(raw[j]==(unsigned char)(kind==0?0:kind==1?j%256:kind==2?(j/8)%2:j%9?0x90:0x42));
        assert(bytes+64<LI2_CAPTURE_RLE_LIMIT);
        assert(u64(body)==LI2_CAPTURE_RLE_MAGIC && u64(body+24)==n && u64(body+32)==bytes-64);
        expand(bytes,n);sentinels();++roundtrips;
    }
    /* Incompressible input at the exact strict output boundary, not a larger
       configurable cap. The next byte must refuse before writing output. */
    size_t n=LI2_CAPTURE_RLE_LIMIT-128-5*64-1,bytes=0;
    for(size_t i=0;i<=n;i++)raw[i]=(unsigned char)(i%251);
    assert(li2_capture_rle_prepare(raw,n,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes)==0 && bytes+64==LI2_CAPTURE_RLE_LIMIT-1);
    expand(bytes,n);memset(body,0x7b,LI2_CAPTURE_RLE_LIMIT);bytes=123;
    assert(li2_capture_rle_prepare(raw,n+1,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes)==LI2_CAPTURE_RLE_CAPACITY && !bytes);
    for(size_t i=0;i<LI2_CAPTURE_RLE_LIMIT;i++)assert(body[i]==0x7b);
    sentinels();
    unsigned arguments=0;
#define ARG(rawp,n_,version,out,cap,result) do {assert(li2_capture_rle_prepare(rawp,n_,version,out,cap,result)==LI2_CAPTURE_RLE_ARGUMENT);++arguments;}while(0)
    ARG(raw,0,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes);
    ARG(0,8,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes);
    ARG(raw,8,0,body,LI2_CAPTURE_RLE_LIMIT,&bytes);
    ARG(raw,8,17,body,63,&bytes);
    ARG(raw,8,17,raw,LI2_CAPTURE_RLE_LIMIT,&bytes);
    ARG(raw,8,17,body,LI2_CAPTURE_RLE_LIMIT,(size_t *)(void *)raw);
    ARG(raw,8,17,body,LI2_CAPTURE_RLE_LIMIT,(size_t *)(void *)body);
    ARG(raw,8,17,body,LI2_CAPTURE_RLE_LIMIT,0);
    ARG((const void *)(UINTPTR_MAX-3),8,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes);
    ARG(raw,(size_t)UINT32_MAX+1,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes);
    ARG(raw,8,17,body,LI2_CAPTURE_RLE_LIMIT+1,&bytes);
    _Alignas(64) unsigned char result_space[64];
    ARG(raw,8,17,body,LI2_CAPTURE_RLE_LIMIT,(size_t *)(void *)(result_space+1));
#undef ARG
    /* This exact vector is consumed by the independent Python decoder. */
    n=1024;for(size_t i=0;i<n;i++)raw[i]=(unsigned char)(i%31<9?i%251:0x90);
    assert(!li2_capture_rle_prepare(raw,n,17,body,LI2_CAPTURE_RLE_LIMIT,&bytes) && bytes==730);
    struct output o={0};assert(!li2_capture_rle_write(body,bytes,n,17,0,0,put,&o));
    assert(o.calls==2 && o.at==bytes+64 && u64(written+bytes)==LI2_CAPTURE_RLE_END &&
        u64(written+bytes+16)==bytes && u64(written+bytes+24)==bytes &&
        u64(written+bytes+32)==1 && u64(written+bytes+40)==bytes);
    FILE *file=fopen(argv[1],"wbx");assert(file);
    assert(fwrite(written,1,o.at,file)==o.at && !fclose(file));
    /* Body/footer accounting and every failure leave a real partial stream. */
    o=(struct output){.chunk=bytes-1};
    assert(!li2_capture_rle_write(body,bytes,n,17,0,0,put,&o));
    assert(o.calls==3 && o.at==bytes+64 && u64(written+bytes+32)==2 && u64(written+bytes+40)==1);
    o=(struct output){.fail_call=1,.failure=0};
    assert(li2_capture_rle_write(body,bytes,n,17,0,0,put,&o)==LI2_CAPTURE_RLE_WRITE && o.calls==1 && !o.at);
    o=(struct output){.fail_call=1,.failure=-1};
    assert(li2_capture_rle_write(body,bytes,n,17,0,0,put,&o)==LI2_CAPTURE_RLE_WRITE && o.calls==1 && !o.at);
    o=(struct output){.fail_call=1,.failure=(long)bytes+1};
    assert(li2_capture_rle_write(body,bytes,n,17,0,0,put,&o)==LI2_CAPTURE_RLE_WRITE && o.calls==1 && !o.at);
    o=(struct output){.chunk=1};
    assert(li2_capture_rle_write(body,bytes,n,17,0,0,put,&o)==LI2_CAPTURE_RLE_WRITE && o.calls==64 && o.at==64);
    o=(struct output){.fail_call=2,.failure=0};
    assert(li2_capture_rle_write(body,bytes,n,17,0,0,put,&o)==LI2_CAPTURE_RLE_WRITE && o.calls==2 && o.at==bytes);
    o=(struct output){0};
    assert(li2_capture_rle_write(body,bytes,n,18,0,0,put,&o)==LI2_CAPTURE_RLE_ARGUMENT && !o.calls && !o.at);
    sentinels();assert(roundtrips==40 && arguments==12);
    puts("{\"scope\":\"capture_codec_only\",\"roundtrips\":40,\"strict_cap_cases\":2,\"argument_refusals\":12,\"write_cases\":8,\"cross_language_vectors\":1,\"vector_stream_bytes\":794,\"native_qualification\":false}");
    return 0;
}
