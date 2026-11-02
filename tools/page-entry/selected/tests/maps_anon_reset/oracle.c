/* Whole actual lifecycle TU and real mmap calls. Supplied state/return
   controls are identified below; none is a guest or owner qualification. */
#include "lifecycle_loader.c"
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if LI2_MAPS_MAINTAINED != 1
#error "the reset fixture requires the maintained view"
#endif
static uintptr_t arena;
static int file=-1;
static unsigned positives,refusals,row_refusals,issuing,injection,mmap_calls;
static struct map_row saved_rows[MAP_ROWS],bad_rows[MAP_ROWS];
static unsigned char file_bytes[3*PAGE];
enum {
    ALTER_PROT=1,ALTER_FLAGS,ALTER_BACKING,ALTER_OFFSET,ALTER_ADDRESS,
    ALTER_EXTENT,ALTER_RETURN,PARTIAL_ERROR,ALTER_HANDLER,ALTER_EPOCH
};
static void need(int,unsigned);
static long kernel_body(long n,long a,long b,long c,long d,long e,long f) {
    errno=0;long r=syscall(n,a,b,c,d,e,f);return r==-1?-errno:r;
}
static void cleanup(void) {
    if(arena) {
        if(kernel_body(SYS_munmap,(long)arena,192*PAGE,0,0,0,0))_Exit(124);
        arena=0;
    }
    if(file>=0) {
        if(kernel_body(SYS_close,file,0,0,0,0,0))_Exit(124);
        file=-1;
    }
}
static void need(int yes,unsigned code) {
    if(!yes) {
        cleanup();fprintf(stderr,"anonymous reset fixture failure %u\n",code);_Exit(124);
    }
}
static _Noreturn void fatal(unsigned code,long detail) {
    (void)detail;need(0,10000+code);__builtin_unreachable();
}
static int protected_owned(uintptr_t p,size_t n) {
    return arena && p>=arena && p-arena<160*PAGE && n && n<=160*PAGE-(p-arena);
}
static long kernel(long n,long a,long b,long c,long d,long e,long f) {
    if(n==SYS_mmap) {
        /* Actual pre-kernel gate, including invalid input and changed tuples. */
        need(!maps_stats.valid && mv_depth,10);++mmap_calls;
        if(issuing && injection==PARTIAL_ERROR) {
            /* Named supplied return after an ACTUAL partial mapping change.
               This is not a claim that Linux mmap partially failed. */
            need(!kernel_body(SYS_munmap,a,PAGE,0,0,0,0),11);return -ENOMEM;
        }
    }
    long r=kernel_body(n,a,b,c,d,e,f);
    if(issuing && n==SYS_mmap) {
        if(injection==ALTER_RETURN && r==a)return r+PAGE;
        if(injection==ALTER_HANDLER)++maps_stats.handler_id;
        if(injection==ALTER_EPOCH)li2_maps_view_unexplained();
    }
    return r;
}
static long tracked(long n,long a,long b,long c,long d,long e,long f) {
    if(issuing && n==SYS_mmap) {
        switch(injection) {
        case ALTER_PROT:c=PROT_READ|PROT_WRITE;break;
        case ALTER_FLAGS:d=MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED;break;
        case ALTER_BACKING:d=MAP_PRIVATE|MAP_FIXED;e=file;break;
        case ALTER_OFFSET:f=PAGE;break;
        case ALTER_ADDRESS:a+=PAGE;break;
        case ALTER_EXTENT:b+=PAGE;break;
        default:break;
        }
    }
    return li2_maps_raw(kernel,n,a,b,c,d,e,f);
}
static long nested(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(tracked,n,a,b,c,d,e,f);
}
static void query(unsigned hit,unsigned code) {
    if(!maps_stats.active)need(!li2_maps_phase_begin(),code);
    struct li2_maps_view_stats old=mv;
    uint64_t acquisitions=maps_stats.acquisitions;
    struct check_error e={0};struct li2_fetch_map_progress p={0};
    need(!read_maps_checked(&e,&p) && !e.code && !e.detail && row_count &&
         row_count<=MAP_ROWS && maps_stats.valid==1 && !maps_stats.poisoned &&
         !mv.poisoned && !mv.mismatches && !mv_depth,code+1);
    need(mv.queries==old.queries+1 && mv.hits==old.hits+hit &&
         mv.refreshes==old.refreshes+!hit,code+2);
    need(p.rows==row_count && p.observation.mutation_epoch==maps_stats.mutation_epoch &&
         p.observation.acquisition_id==maps_stats.acquisitions &&
         p.observation.handler_id==maps_stats.handler_id,code+3);
#ifdef LI2_MAPS_DIFFERENTIAL
    need(mv.comparisons==old.comparisons+hit &&
         maps_stats.acquisitions==acquisitions+1 && p.observation.io_performed==1 &&
         p.observation.kind==(hit?LI2_MAPS_VERIFIED:LI2_MAPS_FRESH),code+4);
#else
    need(mv.comparisons==old.comparisons && maps_stats.acquisitions==acquisitions+!hit &&
         p.observation.io_performed==!hit &&
         p.observation.kind==(hit?LI2_MAPS_PROJECTED:LI2_MAPS_FRESH),code+4);
#endif
}
static void anonymous(uintptr_t first,size_t bytes,unsigned code) {
    for(size_t i=0;i<bytes;i++)need(!*(const volatile unsigned char *)(first+i),code);
    for(size_t i=0;i<bytes;i+=PAGE) {
        const struct map_row *r=mapping(first+i);
        need(r && r->private==1 && r->prot==PROT_READ && !r->offset &&
             !r->major && !r->minor && !r->inode,code+1);
    }
}
static void projected(uintptr_t first,size_t bytes,unsigned code) {
    uint64_t epoch=maps_stats.mutation_epoch,invalidations=mv.invalidations,updates=mv.updates;
    unsigned calls=mmap_calls;issuing=1;
    long result=li2_maps_view_anon_reset(first,bytes);
    issuing=0;
    need(result==(long)first && maps_stats.valid==1 && !mv_depth &&
         maps_stats.mutation_epoch==epoch+1 && mv.invalidations==invalidations+1 &&
         mv.updates==updates && mmap_calls==calls+1,code);
    query(1,code+1);anonymous(first,bytes,code+6);++positives;
}
static void refused(uintptr_t first,size_t bytes,unsigned fault,long expected,unsigned code) {
    uint64_t updates=mv.updates;unsigned calls=mmap_calls;
    injection=fault;issuing=1;long result=li2_maps_view_anon_reset(first,bytes);
    issuing=0;injection=0;
    need(result==expected && !maps_stats.valid && !mv_depth &&
         mv.updates==updates && mmap_calls==calls+1,code);
    query(0,code+1);++refusals;
}
static void row_controls(void) {
    /* These six table-only failures separately exercise the actual rows helper.
       The kernel map is never replaced by these supplied table descriptions. */
    for(unsigned mode=0;mode<6;mode++) {
        size_t old_count=row_count;struct li2_fetch_map_progress receipt=mv_receipt;
        memcpy(saved_rows,rows,sizeof rows);li2_maps_view_require_fresh();
        memset(rows,0,sizeof rows);
        row_count=1;
        rows[0]=(struct map_row){.first=PAGE,.end=4*PAGE,.prot=PROT_READ,.private=1};
        if(mode==0) {
            row_count=2;rows[0].end=2*PAGE;
            rows[1]=(struct map_row){.first=3*PAGE,.end=4*PAGE,.prot=PROT_READ,.private=1};
        } else if(mode==1) {
            row_count=MAP_ROWS;
            for(size_t i=1;i<row_count;i++)
                rows[i]=(struct map_row){.first=(i*2+4)*PAGE,.end=(i*2+5)*PAGE,
                                        .prot=PROT_READ,.private=1};
        } else if(mode==2) {
            rows[0].inode=1;rows[0].major=1;rows[0].offset=UINT64_MAX-PAGE;
        } else if(mode==3) {
            row_count=2;
            rows[1]=(struct map_row){.first=3*PAGE,.end=5*PAGE,.prot=PROT_READ,.private=1};
        } else if(mode==4)rows[0].offset=1;
        else rows[0].prot=8;
        size_t bad_count=row_count;memcpy(bad_rows,rows,sizeof rows);
        need(!mv_anon_rows(2*PAGE,PAGE) && row_count==bad_count &&
             !memcmp(rows,bad_rows,sizeof rows) && !memcmp(&mv_receipt,&receipt,sizeof receipt) &&
             !maps_stats.valid,300+mode*10);
        memcpy(rows,saved_rows,sizeof rows);row_count=old_count;
        query(0,301+mode*10);++row_refusals;
    }
}
int main(void) {
    uintptr_t anchor=(uintptr_t)&anchor;
    hooks=(struct li2_lifecycle_hooks){.raw=tracked,.fail=fatal,.protected_range=protected_owned};
    active=1;li2_maps_view_stack(anchor);
    need(!li2_maps_view_enable() && !li2_maps_phase_begin(),1);query(0,20);
    long p=tracked(SYS_mmap,0,192*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(!kernel_error(p) && p>0,30);arena=(uintptr_t)p;query(0,31);
    file=(int)tracked(SYS_memfd_create,(long)"li2-anonymous-reset",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    memset(file_bytes,0x5a,sizeof file_bytes);
    need(file>=0 && !tracked(SYS_ftruncate,file,sizeof file_bytes,0,0,0,0) &&
         tracked(SYS_pwrite64,file,(long)file_bytes,sizeof file_bytes,0,0,0)==(long)sizeof file_bytes &&
         !tracked(SYS_fcntl,file,F_ADD_SEALS,SEALS,0,0,0),40);
    need(tracked(SYS_mmap,(long)arena,3*PAGE,PROT_READ,MAP_PRIVATE|MAP_FIXED,file,0)==(long)arena &&
         tracked(SYS_mmap,(long)(arena+128*PAGE),PAGE,PROT_READ,MAP_PRIVATE|MAP_FIXED,file,PAGE)==
             (long)(arena+128*PAGE),41);query(0,42);
    struct map_row identity=*mapping(arena);
    need(identity.inode && identity.offset==0,47);
    projected(arena+PAGE,PAGE,50);
    const struct map_row *left=mapping(arena),*right=mapping(arena+2*PAGE),*alias=mapping(arena+128*PAGE);
    need(left && right && alias && left->inode==identity.inode && right->inode==identity.inode &&
         alias->inode==identity.inode && left->offset==0 && right->offset==2*PAGE &&
         alias->offset==PAGE && *(const volatile unsigned char *)arena==0x5a &&
         *(const volatile unsigned char *)(arena+2*PAGE)==0x5a &&
         *(const volatile unsigned char *)(arena+128*PAGE)==0x5a,59);
    projected(arena,3*PAGE,60);
    need(mapping(arena)==mapping(arena+2*PAGE),69);
    hooks.raw=nested;projected(arena+PAGE,PAGE,70);hooks.raw=tracked;
    need(mapping(arena)==mapping(arena+2*PAGE),79);
    projected(arena+8*PAGE,17*PAGE,80);projected(arena+32*PAGE,89*PAGE,90);
    need(mapping(arena+128*PAGE)->inode==identity.inode &&
         *(const volatile unsigned char *)(arena+128*PAGE)==0x5a,99);
    row_controls();

    /* An ordinary gateway call never acquires the new typed projection. */
    need(tracked(SYS_mmap,(long)arena,PAGE,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==
         (long)arena && !maps_stats.valid,100);query(0,101);++refusals;
    li2_maps_view_require_fresh();refused(arena,PAGE,0,(long)arena,110);
    li2_maps_phase_end();refused(arena,PAGE,0,(long)arena,120);
    tx.guard=1;issuing=1;long guarded=li2_maps_view_anon_reset(arena,PAGE);issuing=0;
    need(guarded==(long)arena && !maps_stats.valid && !mv_depth,130);
    tx.guard=0;query(0,131);++refusals;
    for(unsigned fault=ALTER_PROT;fault<=ALTER_EPOCH;fault++) {
        long expected=(long)arena;
        if(fault==ALTER_ADDRESS || fault==ALTER_RETURN)expected+=PAGE;
        if(fault==PARTIAL_ERROR)expected=-ENOMEM;
        refused(arena,PAGE,fault,expected,140+fault*10);
        if(fault==ALTER_PROT)need(mapping(arena)->prot==(PROT_READ|PROT_WRITE),145+fault*10);
        if(fault==ALTER_FLAGS)need(mapping(arena)->private==0,145+fault*10);
        if(fault==ALTER_BACKING)need(mapping(arena)->inode==identity.inode,145+fault*10);
        if(fault==PARTIAL_ERROR)need(!mapping(arena),145+fault*10);
    }
    refused(arena,0,0,-EINVAL,250);
    refused(arena+1,PAGE,0,-EINVAL,260);
    refused(arena,PAGE+1,0,(long)arena,270);
    refused(arena+180*PAGE,PAGE,0,(long)(arena+180*PAGE),280);
    need(!tracked(SYS_munmap,(long)(arena+PAGE),PAGE,0,0,0,0),370);query(0,371);
    refused(arena,2*PAGE,0,(long)arena,380);anonymous(arena,2*PAGE,386);
    /* Supplied old stack bounds overlap real arena memory, never the host
       stack. The original retirement predicate must prevent projection. */
    mv_stack_first=arena+4*PAGE;mv_stack_end=arena+5*PAGE;mv_stack_pending=0;
    refused(arena+4*PAGE,PAGE,0,(long)(arena+4*PAGE),390);
    need(mv_stack_retired && positives==5 && refusals==20 && row_refusals==6,399);
    cleanup();
    printf("{\"version\":1,\"differential\":%u,\"positives\":5,\"fallback_controls\":20,"
           "\"row_refusals\":6,\"guest_executions\":0}\n",
#ifdef LI2_MAPS_DIFFERENTIAL
           1U
#else
           0U
#endif
    );
    return 0;
}

