#include "capture_rle.h"

static int cr_span(const void *p,size_t n) {
    return p && n && (uintptr_t)p<=UINTPTR_MAX-n;
}
static int cr_overlap(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y?y-x<an:x-y<bn;
}
static void cr_u32(unsigned char *p,uint32_t v) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));
}
static void cr_u64(unsigned char *p,uint64_t v) {
    for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));
}
static uint64_t cr_get64(const unsigned char *p) {
    uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static size_t cr_run(const unsigned char *p,size_t n) {
    size_t k=1;while(k<n && p[k]==p[0])++k;return k;
}
/* Count and emit use the same canonical greedy partition. Every read is
   inside [raw,raw+n); long runs may be scanned twice, never quadratically. */
static int cr_walk(const unsigned char *raw,size_t n,unsigned char *out,
    size_t limit,size_t *used) {
    size_t at=0,bytes=0;
    while(at<n) {
        size_t begin=at,count=cr_run(raw+at,n-at);unsigned tag;
        if(count>=LI2_CAPTURE_RLE_RUN) { tag=1;at+=count; }
        else {
            tag=0;at+=count;
            while(at<n && at-begin<LI2_CAPTURE_RLE_LITERAL) {
                count=cr_run(raw+at,n-at);
                if(count>=LI2_CAPTURE_RLE_RUN)break;
                size_t room=LI2_CAPTURE_RLE_LITERAL-(at-begin);
                at+=count<room?count:room;
            }
            count=at-begin;
        }
        size_t payload=tag?1:count;
        if(bytes>limit || limit-bytes<5 || payload>limit-bytes-5)
            return LI2_CAPTURE_RLE_CAPACITY;
        if(out) {
            out[bytes]=(unsigned char)tag;cr_u32(out+bytes+1,(uint32_t)count);
            if(tag)out[bytes+5]=raw[begin];
            else for(size_t i=0;i<count;i++)out[bytes+5+i]=raw[begin+i];
        }
        bytes+=5+payload;
    }
    *used=bytes;return LI2_CAPTURE_RLE_OK;
}
int li2_capture_rle_prepare(const void *raw,size_t n,uint64_t schema,void *body,
    size_t capacity,size_t *body_bytes) {
    if(!schema || n>UINT32_MAX || !cr_span(raw,n) || capacity<LI2_CAPTURE_RLE_HEADER ||
       capacity>LI2_CAPTURE_RLE_LIMIT || !cr_span(body,capacity) ||
       !cr_span(body_bytes,sizeof *body_bytes) ||
       (uintptr_t)body_bytes%_Alignof(size_t) ||
       cr_overlap(raw,n,body,capacity) || cr_overlap(raw,n,body_bytes,sizeof *body_bytes) ||
       cr_overlap(body,capacity,body_bytes,sizeof *body_bytes))return LI2_CAPTURE_RLE_ARGUMENT;
    *body_bytes=0;
    size_t limit=capacity-LI2_CAPTURE_RLE_HEADER;
    const size_t payload_cap=LI2_CAPTURE_RLE_LIMIT-LI2_CAPTURE_RLE_HEADER-LI2_CAPTURE_RLE_FOOTER-1;
    if(limit>payload_cap)limit=payload_cap;
    size_t counted=0,written=0;
    int result=cr_walk(raw,n,0,limit,&counted);
    if(result)return result; /* No output bytes written on a count refusal. */
    result=cr_walk(raw,n,(unsigned char *)body+LI2_CAPTURE_RLE_HEADER,limit,&written);
    if(result || written!=counted)return LI2_CAPTURE_RLE_CHANGED;
    const uint64_t h[8]={LI2_CAPTURE_RLE_MAGIC,LI2_CAPTURE_RLE_VERSION,schema,n,counted,
        LI2_CAPTURE_RLE_HEADER,LI2_CAPTURE_RLE_FOOTER,0};
    for(unsigned i=0;i<8;i++)cr_u64((unsigned char *)body+8*i,h[i]);
    *body_bytes=LI2_CAPTURE_RLE_HEADER+counted;return LI2_CAPTURE_RLE_OK;
}
int li2_capture_rle_write(const void *body,size_t n,size_t raw_bytes,uint64_t schema,
    uint64_t status,uint64_t code,li2_capture_rle_write_fn write_fn,void *context) {
    if(!schema || !raw_bytes || raw_bytes>UINT32_MAX || !write_fn ||
       n<LI2_CAPTURE_RLE_HEADER || n>=LI2_CAPTURE_RLE_LIMIT-LI2_CAPTURE_RLE_FOOTER || !cr_span(body,n))
        return LI2_CAPTURE_RLE_ARGUMENT;
    const unsigned char *p=body;
    const uint64_t h[8]={LI2_CAPTURE_RLE_MAGIC,LI2_CAPTURE_RLE_VERSION,schema,raw_bytes,
        n-LI2_CAPTURE_RLE_HEADER,LI2_CAPTURE_RLE_HEADER,LI2_CAPTURE_RLE_FOOTER,0};
    for(unsigned i=0;i<8;i++)if(cr_get64(p+8*i)!=h[i])return LI2_CAPTURE_RLE_ARGUMENT;
    size_t at=0;uint64_t calls=0;long result=0;
    while(at<n && calls<64) {
        ++calls;result=write_fn(context,p+at,n-at);
        if(result<=0 || (size_t)result>n-at)return LI2_CAPTURE_RLE_WRITE;
        at+=(size_t)result;
    }
    if(at!=n)return LI2_CAPTURE_RLE_WRITE;
    const uint64_t f[8]={LI2_CAPTURE_RLE_END,LI2_CAPTURE_RLE_VERSION,n,at,calls,(uint64_t)result,status,code};
    unsigned char footer[LI2_CAPTURE_RLE_FOOTER];
    for(unsigned i=0;i<8;i++)cr_u64(footer+8*i,f[i]);
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=write_fn(context,footer+at,sizeof footer-at);
        if(result<=0 || (size_t)result>sizeof footer-at)return LI2_CAPTURE_RLE_WRITE;
        at+=(size_t)result;
    }
    return at==sizeof footer?LI2_CAPTURE_RLE_OK:LI2_CAPTURE_RLE_WRITE;
}
