#include "../../region_decode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Descriptive metadata only. Never executes supplied bytes or grants an owner
 * permission. The enclosing qualifier binds this exact production archive,
 * request file, process limits and complete response before using any row. */
enum { CAPACITY=70 };
struct request_row { uint64_t pc; uint32_t available,reserved; unsigned char bytes[16]; };
struct request { uint64_t magic,version,count,row_bytes; struct request_row rows[CAPACITY]; };
struct response_row { struct request_row request; uint32_t result,reserved; struct li2_region_decoded decoded; };
struct response { uint64_t magic,version,count,row_bytes;
    struct li2_decoder_stats before,after; struct response_row rows[CAPACITY]; };
static _Alignas(4096) unsigned char arena[16*1024*1024];
static struct request input;
static struct response output;
_Static_assert(sizeof(struct request_row)==32,"request ABI");
_Static_assert(offsetof(struct request,rows)==32,"request header ABI");
_Static_assert(sizeof(struct response_row)==344,"response ABI");
_Static_assert(offsetof(struct response,rows)==128,"response header ABI");
static void need(int ok) { if(!ok)exit(125); }
static int canonical(uint64_t n) {
    return n<=UINT64_C(0x00007fffffffffff)||n>=UINT64_C(0xffff800000000000);
}
int main(int argc,char **argv) {
    need(argc==2);FILE *f=fopen(argv[1],"rb");need(f!=NULL);
    need(fread(&input,1,32,f)==32);
    need(input.magic==UINT64_C(0x315152534c49324c)&&input.version==1&&
        input.count<=CAPACITY&&input.row_bytes==sizeof(struct request_row));
    need(fread(input.rows,sizeof(struct request_row),(size_t)input.count,f)==input.count);
    need(fgetc(f)==EOF&&!ferror(f));need(fclose(f)==0);
    need(li2_decoder_initialize(arena,sizeof arena,&output.before)==LI2_OK);
    need(output.before.abi_version==1&&output.before.phase==2&&
        !output.before.first_fatal_reason&&!output.before.reserved&&
        output.before.arena_bytes==sizeof arena&&output.before.retained_high_water>0&&
        output.before.retained_high_water<=sizeof arena&&output.before.allocation_calls>0);
    output.magic=UINT64_C(0x315352534c49324c);output.version=1;
    output.count=input.count;output.row_bytes=sizeof(struct response_row);
    for(size_t i=0;i<input.count;i++) {
        const struct request_row *q=&input.rows[i];struct response_row *r=&output.rows[i];
        need(q->available>=1&&q->available<=15&&!q->reserved&&canonical(q->pc)&&
            q->pc<=UINT64_MAX-q->available&&canonical(q->pc+q->available));
        for(size_t j=q->available;j<sizeof q->bytes;j++)need(q->bytes[j]==0);
        for(size_t j=0;j<i;j++)need(memcmp(q,&input.rows[j],sizeof *q)!=0);
        memcpy(&r->request,q,sizeof *q);
        r->result=li2_decoder_region_describe(q->pc,q->bytes,q->available,&r->decoded);
        need(r->result==LI2_OK);
        struct li2_decoder_stats now;need(li2_decoder_stats(&now)==LI2_OK);
        need(memcmp(&now,&output.before,sizeof now)==0);
    }
    need(li2_decoder_stats(&output.after)==LI2_OK);
    need(memcmp(&output.before,&output.after,sizeof output.before)==0);
    size_t n=offsetof(struct response,rows)+(size_t)input.count*sizeof(struct response_row);
    need(fwrite(&output,1,n,stdout)==n);need(fflush(stdout)==0);return 0;
}
