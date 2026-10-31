/* Actual lifecycle TU; scripted syscall results are component inputs, not
   kernel observations. Every reference call forces the original raw parser.
   The separate maintained/differential native gates remain mandatory. */
#include "lifecycle_loader.c"
#define LI2_SPAN_FAST_BYTES 1
#define LI2_SCALAR_SPAN_TRACE 1
#include "span_fast_bytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if LI2_MAPS_PARSE_MEMO_TEST != 1 || LI2_MAPS_DIFFERENTIAL != 1
#error "exact actual-TU memo/differential component required"
#endif
/* Exact bridge wrappers over the unchanged bounded helpers. */
void copy(void *v,const void *w,size_t n) { li2_span_bytes_copy(v,w,n); }
int equal(const void *v,const void *w,size_t n) { return li2_span_bytes_equal(v,w,n); }
enum { OPEN_ERROR=1, READ_ERROR=2, CLOSE_ERROR=3 };
struct script { const unsigned char *input;size_t length,chunk;unsigned error; };
struct call { long args[7],result; };
struct result {
    int returned;struct check_error error;struct li2_fetch_map_progress progress;
    size_t count,calls;struct map_row table[MAP_ROWS];struct call call[512];
};
static struct script script;
static size_t offset,call_count,read_count;
static unsigned io_phase;
static struct call calls[512];
static struct result reference,actual;
static struct maps_parse_memo seed;
static unsigned char input[MAP_BYTES+1];
static unsigned cases,byte_changes,io_failures,state_controls,differential_controls;
static void need(int condition,unsigned code) {
    if(!condition){fprintf(stderr,"maps parse memo control %u case %u\n",code,cases);exit(1);}
}
static _Noreturn void fatal(unsigned code,long detail) {
    (void)detail;need(0,10000+code);__builtin_unreachable();
}
static int protected_none(uintptr_t p,size_t n){(void)p;(void)n;return 0;}
static long supplied(long n,long a,long b,long c,long d,long e,long f) {
    need(call_count<512,1);struct call *out=&calls[call_count++];
    const long args[7]={n,a,b,c,d,e,f};memcpy(out->args,args,sizeof args);
    long result;
    if(n==SYS_openat) {
        need(!io_phase && a==AT_FDCWD && !strcmp((const char *)b,"/proc/self/maps") &&
             c==(O_RDONLY|O_CLOEXEC) && !d && !e && !f,2);
        result=script.error==OPEN_ERROR?-ENOENT:19;io_phase=result<0?4:1;
    } else if(n==SYS_read) {
        need(io_phase==1 && a==19 && (uintptr_t)b==(uintptr_t)maps_bytes+offset &&
             c==(long)(MAP_BYTES-offset) && !d && !e && !f,3);++read_count;
        if(script.error==READ_ERROR && read_count==2)result=-EIO;
        else {
            size_t nbytes=script.length-offset;
            if(nbytes>script.chunk)nbytes=script.chunk;
            if(nbytes>(size_t)c)nbytes=(size_t)c;
            memcpy((void *)b,script.input+offset,nbytes);offset+=nbytes;result=(long)nbytes;
            if(!nbytes)io_phase=2;
        }
    } else {
        need(n==SYS_close && (io_phase==1 || io_phase==2) && a==19 &&
             !b && !c && !d && !e && !f,4);
        result=script.error==CLOSE_ERROR?-EIO:0;io_phase=3;
    }
    out->result=result;return result;
}
static long tracked(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(supplied,n,a,b,c,d,e,f);
}
static void initial(void) {
    memset(rows,0xa5,sizeof rows);row_count=5;
    memset(maps_bytes,0xc3,sizeof maps_bytes);
}
static void run(struct result *out,struct script s,unsigned view) {
    script=s;offset=call_count=read_count=0;io_phase=0;
    memset(calls,0,sizeof calls);memset(out,0,sizeof *out);
    out->returned=view?read_maps_checked(&out->error,&out->progress):
                       read_maps_fresh(&out->error,&out->progress);
    out->count=row_count;out->calls=call_count;
    memcpy(out->table,rows,sizeof rows);memcpy(out->call,calls,sizeof calls);
}
static void same(void) {
    need(reference.returned==actual.returned &&
         !memcmp(&reference.error,&actual.error,sizeof actual.error) &&
         !memcmp(&reference.progress,&actual.progress,sizeof actual.progress) &&
         reference.count==actual.count && reference.calls==actual.calls &&
         !memcmp(reference.table,actual.table,sizeof actual.table) &&
         !memcmp(reference.call,actual.call,sizeof actual.call),10);
}
static void equivalence(struct script s,int expected,unsigned hit) {
    struct maps_parse_memo *saved=&seed;
    /* The preserved cache was produced by an actual complete successful parse.
       Only the reference's valid flag is cleared to force the old grammar. */
    maps_parse_memo.valid=0;initial();
    uint64_t before=maps_parse_memo_hits;
    run(&reference,s,0);
    need(maps_parse_memo_hits==before && !maps_parse_memo.busy &&
         (expected<0 || reference.returned==expected),11);
    maps_parse_memo=*saved;initial();before=maps_parse_memo_hits;
    run(&actual,s,0);same();++cases;
    need(maps_parse_memo_hits-before==hit && !maps_parse_memo.busy,12);
    if(actual.returned && !s.error && actual.returned!=105)
        need(!maps_parse_memo.valid,13);
    /* Capacity/read/open/close refusal precedes the parser hook: preserve the
       complete previous successful cache, while still returning the error. */
    if(s.error || actual.returned==105)
        need(!memcmp(&maps_parse_memo,saved,sizeof maps_parse_memo),16);
}
static void seed_input(const unsigned char *s,size_t n) {
    maps_parse_memo.valid=0;initial();run(&actual,(struct script){s,n,4096,0},0);
    need(!actual.returned && maps_parse_memo.valid==1 && !maps_parse_memo.busy &&
         maps_parse_memo.bytes==n && maps_parse_memo.count==row_count,14);
    seed=maps_parse_memo;
}
static const unsigned char one[]="1000-3000 rw-p 00000000 00:00 0 [stack with spaces]\n";
static void grammar(void) {
    const size_t n=sizeof one-1;seed_input(one,n);
    equivalence((struct script){one,n,4096,0},0,1);
    equivalence((struct script){one,n,1,0},0,1);
    /* Every input byte participates, even ignored pathname/spacing. */
    for(size_t i=0;i<n;i++) {
        memcpy(input,one,n);input[i]^=1;
        equivalence((struct script){input,n,7,0},-1,0);++byte_changes;
    }
    equivalence((struct script){one,n-1,4096,0},108,0);
    static const unsigned char other[]="1000-3000 rw-p 00000000 00:00 0 [other with spaces]\n";
    equivalence((struct script){other,sizeof other-1,4096,0},0,0);
    static const struct {const char *text;unsigned error;} bad[]={
        {"g000-3000 rw-p 0 00:00 0\n",101},
        {"10000000000000000-3000 rw-p 0 00:00 0\n",102},
        {"-3000 rw-p 0 00:00 0\n",103},
        {"1001-3000 rw-p 0 00:00 0\n",109},
        {"1000-3000 rq-p 0 00:00 0\n",110},
        {"1000-3000 rw-p 0 00:00 18446744073709551616\n",111},
        {"1000-3000 rw-p 0 00:00 \n",112},
        {"1000-3000 rw-p 0 00:00 0\n2000-4000 rw-p 0 00:00 0\n",112},
    };
    for(size_t i=0;i<sizeof bad/sizeof bad[0];i++)
        equivalence((struct script){(const unsigned char *)bad[i].text,strlen(bad[i].text),4096,0},(int)bad[i].error,0);
    for(unsigned error=OPEN_ERROR;error<=CLOSE_ERROR;error++) {
        equivalence((struct script){one,n,7,error},error==OPEN_ERROR?104:error==READ_ERROR?106:107,0);
        ++io_failures;
    }
    seed_input(one,0);equivalence((struct script){one,0,4096,0},0,1);
    /* Full accepted row count, then exact old one-row overflow refusal. */
    size_t length=0;
    for(unsigned i=0;i<=MAP_ROWS;i++) {
        int got=snprintf((char *)input+length,sizeof input-length,
            "%lx-%lx r--p 0 00:00 0\n",(unsigned long)(2*i+1)*PAGE,(unsigned long)(2*i+2)*PAGE);
        need(got>0 && (size_t)got<sizeof input-length,15);length+=(size_t)got;
        if(i==MAP_ROWS-1) {
            seed_input(input,length);equivalence((struct script){input,length,4096,0},0,1);
        }
    }
    equivalence((struct script){input,length,4096,0},108,0);
    /* MAP_BYTES-1 is accepted; exactly filling MAP_BYTES still refuses before
       an EOF read. Long ignored pathname bytes still require full equality. */
    static const unsigned char prefix[]="1000-3000 rw-p 0 00:00 0 ";
    memset(input,'x',MAP_BYTES);memcpy(input,prefix,sizeof prefix-1);input[MAP_BYTES-2]='\n';
    seed_input(input,MAP_BYTES-1);equivalence((struct script){input,MAP_BYTES-1,4096,0},0,1);
    input[MAP_BYTES-2]='x';input[MAP_BYTES-1]='\n';
    equivalence((struct script){input,MAP_BYTES,4096,0},105,0);
}
static void state(void) {
    const struct script s={one,sizeof one-1,4096,0};seed_input(one,sizeof one-1);
    maps_parse_memo.busy=1;initial();run(&actual,s,0);
    need(actual.returned==LI2_FETCH_BUSY && actual.error.code==LI2_FETCH_BUSY &&
         actual.progress.opened==1 && actual.progress.closed==1 && !actual.progress.rows &&
         maps_parse_memo.busy==1 && maps_parse_memo.valid==1 && row_count==5,20);
    maps_parse_memo.busy=0;++state_controls;
    for(unsigned i=0;i<3;i++) {
        maps_parse_memo=seed;
        if(!i)maps_parse_memo.valid=2;
        else if(i==1)maps_parse_memo.bytes=MAP_BYTES+1;
        else maps_parse_memo.count=MAP_ROWS+1;
        initial();run(&actual,s,0);
        need(actual.returned==LI2_FETCH_STATE && actual.error.code==LI2_FETCH_STATE &&
             !maps_parse_memo.valid && !maps_parse_memo.busy,21);++state_controls;
    }
    maps_parse_memo=seed;maps_parse_memo.valid=0;
    memset(maps_parse_memo.raw,0x5a,sizeof maps_parse_memo.raw);
    initial();uint64_t h=maps_parse_memo_hits;run(&actual,s,0);
    need(!actual.returned && maps_parse_memo_hits==h && maps_parse_memo.valid==1 &&
         !maps_parse_memo.busy && row_count==1 && rows[0].first==0x1000 &&
         rows[0].end==0x3000 && equal(rows,maps_parse_memo.raw,sizeof rows[0]),22);
    ++state_controls;
}
static void differential(void) {
    static const unsigned char split[]=
        "1000-2000 rw-p 0 00:00 0 [stack]\n2000-3000 rw-p 0 00:00 0\n";
    const struct script s={split,sizeof split-1,4096,0};
    memset(&mv,0,sizeof mv);memset(&maps_stats,0,sizeof maps_stats);
    mv.enabled=mv.differential=1;active=1;maps_stats.active=1;maps_stats.handler_id=1;
    mv_stack_anchor=0x1800;mv_stack_retired=mv_stack_pending=0;maps_parse_memo.valid=0;
    run(&actual,s,1);
    need(!actual.returned && row_count==1 && maps_parse_memo.count==2 &&
         mv_stack_first==0x1000 && mv_stack_end==0x2000 && maps_stats.acquisitions==1,30);
    ++differential_controls;
    uint64_t h=maps_parse_memo_hits;run(&actual,s,1);
    need(!actual.returned && maps_parse_memo_hits==h+1 && row_count==1 &&
         maps_parse_memo.count==2 && mv_stack_end==0x2000 && mv.comparisons==1 &&
         mv.hits==1 && maps_stats.reuses==1 && maps_stats.fresh_calls==2 &&
         maps_stats.acquisitions==2 && actual.progress.observation.acquisition_id==2 &&
         actual.progress.observation.io_performed==1 &&
         actual.progress.observation.kind==LI2_MAPS_VERIFIED && actual.calls==4 &&
         actual.progress.opened==1 && actual.progress.closed==1,31);
    ++differential_controls;
    rows[0].prot^=PROT_EXEC;h=maps_parse_memo_hits;run(&actual,s,1);
    need(actual.returned==LI2_FETCH_STATE && maps_parse_memo_hits==h+1 &&
         mv.comparisons==2 && mv.mismatches==1 && mv.poisoned==1 &&
         maps_stats.fresh_calls==3 && maps_stats.acquisitions==3,32);++differential_controls;
    h=maps_parse_memo_hits;run(&actual,s,1);
    need(actual.returned==LI2_FETCH_STATE && !actual.calls && maps_parse_memo_hits==h &&
         mv.comparisons==2 && mv.mismatches==1 && mv.poisoned==1,33);++differential_controls;
}
int main(void) {
    hooks=(struct li2_lifecycle_hooks){tracked,fatal,protected_none};
    grammar();state();differential();
    printf("{\"version\":1,\"cases\":%u,\"byte_changes\":%u,\"io_failures\":%u,"
           "\"state_controls\":%u,\"differential_controls\":%u}\n",
           cases,byte_changes,io_failures,state_controls,differential_controls);
    return 0;
}
