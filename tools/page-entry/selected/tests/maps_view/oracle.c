/* Whole actual TU; real mappings. Boundaries are supplied, not signal credit. */
#include "lifecycle_loader.c"
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#if LI2_MAPS_MAINTAINED != 1 || LI2_MAPS_DIFFERENTIAL != 1
#error "this fixture requires the exact maintained differential profile"
#endif
static uintptr_t ranges[4];
static size_t extents[4];
static int file=-1;
static unsigned mode,cases,partial_errno,alias_refusals,nested_updates,stack_growth;
static unsigned syscall_stack_growth,stack_split_retired,mismatch_refusal,poison_refusal,cleanup_maps,cleanup_fds;
static unsigned disabled_refusal,anchor_fallback,persona_control,persona_calls;
static struct li2_maps_view_stats final;
static long kernel(long n,long a,long b,long c,long d,long e,long f) {
    /* Named supplied-return control only; never attributed to the kernel. */
    if(persona_control && n==SYS_personality) {++persona_calls;return READ_IMPLIES_EXEC;}
    errno=0;long r=syscall(n,a,b,c,d,e,f);return r==-1?-errno:r;
}
static long tracked(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(kernel,n,a,b,c,d,e,f);
}
static long nested(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(tracked,n,a,b,c,d,e,f);
}
static void cleanup(void) {
    /* Real terminal cleanup, including poisoned prefixes; no resumed query. */
    for(unsigned i=0;i<4;i++)if(ranges[i]) {
        if(kernel(SYS_munmap,(long)ranges[i],(long)extents[i],0,0,0,0))_Exit(124);
        ranges[i]=0;++cleanup_maps;
    }
    if(file>=0) {if(kernel(SYS_close,file,0,0,0,0,0))_Exit(124);file=-1;++cleanup_fds;}
}
static void need(int yes,unsigned code) {
    if(!yes){cleanup();fprintf(stderr,"maps-view fixture failure %u mode %u\n",code,mode);_Exit(124);}
}
static _Noreturn void fatal(unsigned code,long detail) {
    (void)detail;need(0,10000+code);__builtin_unreachable();
}
static int protected_none(uintptr_t p,size_t n) {(void)p;(void)n;return 0;}
static struct li2_maps_view_stats stats(void) {
    struct li2_maps_view_stats s={0};li2_maps_view_snapshot(&s);return s;
}
static struct li2_maps_view_stats query(unsigned code) {
    struct check_error e={0};struct li2_fetch_map_progress p;
    need(!read_maps_checked(&e,&p) && !e.code && !e.detail && row_count && row_count<=MAP_ROWS,code);
    struct li2_maps_view_stats s=stats();
    need(s.enabled==1 && s.differential==1 && !s.poisoned && !s.reserved && !s.mismatches &&
         p.fd>=0 && p.opened==1 && p.closed==1 && p.close_started==1 &&
         !p.close_result && !p.last_read && p.bytes && p.rows==row_count &&
         p.observation.io_performed==1,code+1);
    struct li2_maps_stats observed={0};li2_maps_stats_read(&observed);
    need(observed.valid==1 && !observed.poisoned && !observed.reserved &&
         p.observation.acquisition_id==observed.acquisitions &&
         p.observation.mutation_epoch==observed.mutation_epoch,code+3);
    if(mv_stack_retired)need(observed.active==1 && observed.handler_id &&
         p.observation.kind==LI2_MAPS_FRESH && p.observation.io_performed==1 &&
         p.observation.handler_id==observed.handler_id,code+4);
    return s;
}
static void hit(unsigned code) {
    struct li2_maps_view_stats a=stats(),b=query(code);
    need(b.queries==a.queries+1 && b.hits==a.hits+1 && b.comparisons==a.comparisons+1,code+2);
}
static void refreshed(unsigned code) {
    struct li2_maps_view_stats a=stats(),b=query(code);
    need(b.queries==a.queries+1 && b.refreshes==a.refreshes+1 && b.hits==a.hits,code+2);
}
static void permission(uintptr_t p,unsigned prot,unsigned code) {
    const struct map_row *r=mapping(p);
    need(r && r->private==1 && r->prot==prot && r->first<=p && p<r->end,code);
}
static uintptr_t mapped(unsigned slot,size_t bytes,unsigned prot,int fd,uint64_t offset) {
    need(slot<4 && !ranges[slot],20);
    long r=tracked(SYS_mmap,0,(long)bytes,prot,MAP_PRIVATE|(fd<0?MAP_ANONYMOUS:0),fd,(long)offset);
    need(!kernel_error(r) && r>0,21);ranges[slot]=(uintptr_t)r;extents[slot]=bytes;return ranges[slot];
}
static void unmapped(unsigned slot) {
    need(slot<4 && ranges[slot] && !tracked(SYS_munmap,(long)ranges[slot],(long)extents[slot],0,0,0,0),22);
    ranges[slot]=0;++cleanup_maps;
}
static void protect_page(uintptr_t p,size_t n,unsigned prot,unsigned code) {
    struct li2_maps_view_stats a=stats();
    need(!tracked(SYS_mprotect,(long)p,(long)n,prot,0,0,0),code);
    struct li2_maps_view_stats b=stats();
    need(b.updates==a.updates+1 && b.mismatches==a.mismatches && !b.poisoned,code+1);
    hit(code+2);
}
static void alias(int expected,unsigned code) {
    struct check_error e={0};uintptr_t p=ranges[1];
    int r=alias_check_checked(0,PAGE,PAGE,PROT_READ|PROT_EXEC,p,p+PAGE,&e);
    need(r==expected && e.code==(unsigned)expected && !e.detail,code);
    if(expected)++alias_refusals;
}
__attribute__((noinline)) static void grow_stack(size_t n) {
    volatile unsigned char *p=__builtin_alloca(n);
    p[0]=0x5a;__asm__ volatile(""::"r"(p):"memory");
}
static void positive(uintptr_t anchor) {
    uintptr_t a=mapped(0,3*PAGE,PROT_NONE,-1,0);refreshed(100);hit(104);++cases;
    protect_page(a+PAGE,PAGE,PROT_READ,110);
    permission(a,PROT_NONE,115);permission(a+PAGE,PROT_READ,116);permission(a+2*PAGE,PROT_NONE,117);
    const struct map_row *middle=mapping(a+PAGE);
    need(middle->first==a+PAGE && middle->end==a+2*PAGE,118);
    protect_page(a,3*PAGE,PROT_READ,120);
    need(mapping(a)==mapping(a+2*PAGE),125);++cases;
    struct li2_maps_view_stats s=stats();
    need(!nested(SYS_mprotect,(long)a,PAGE,PROT_READ|PROT_WRITE,0,0,0),130);
    need(stats().updates==s.updates+1,131);nested_updates=1;
    hit(132);permission(a,PROT_READ|PROT_WRITE,135);
    protect_page(a,PAGE,PROT_READ,136);++cases;
    /* Partial mprotect before ENOMEM must not preserve stale permissions. */
    need(!tracked(SYS_munmap,(long)(a+PAGE),PAGE,0,0,0,0),142);refreshed(143);
    need(!mapping(a+PAGE),146);s=stats();
    long r=tracked(SYS_mprotect,(long)a,3*PAGE,PROT_READ|PROT_WRITE,0,0,0);
    need(r==-ENOMEM && stats().updates==s.updates,147);partial_errno=ENOMEM;
    refreshed(148);permission(a,PROT_READ|PROT_WRITE,151);
    need(!mapping(a+PAGE),152);permission(a+2*PAGE,PROT_READ,153);++cases;
    file=(int)tracked(SYS_memfd_create,(long)"li2-maps-view",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    need(file>=0 && !tracked(SYS_ftruncate,file,3*PAGE,0,0,0,0) &&
         !tracked(SYS_fcntl,file,F_ADD_SEALS,SEALS,0,0,0) &&
         tracked(SYS_fcntl,file,F_GET_SEALS,0,0,0,0)==SEALS,160);
    uintptr_t f=mapped(1,PAGE,PROT_READ,file,PAGE);refreshed(161);
    const struct map_row *fr=mapping(f);need(fr && fr->offset==PAGE && fr->inode,164);
    object_count=1;objects[0].major=fr->major;objects[0].minor=fr->minor;objects[0].inode=fr->inode;
    alias(0,165);
    uintptr_t w=mapped(2,PAGE,PROT_READ|PROT_WRITE,file,PAGE);refreshed(166);
    alias(119,169);hit(170);alias(119,173);
    protect_page(w,PAGE,PROT_READ,174);alias(0,179);
    unmapped(2);refreshed(180);alias(0,183);++cases;
    s=stats();li2_maps_view_unexplained();
    need(stats().unexplained==s.unexplained+1,190);refreshed(191);++cases;
    /* A supplied boundary needs exactly one stable actual-stack probe. */
    s=stats();li2_maps_event_boundary();need(!li2_maps_phase_begin(),200);hit(201);
    need(stats().stack_probes==s.stack_probes+1,204);hit(205);
    need(stats().stack_probes==s.stack_probes+1,208);++cases;
    const struct map_row *sr=mapping(anchor);need(sr && sr->first<=anchor && sr->end>anchor,210);
    uintptr_t old_bottom=sr->first;
    size_t amount=anchor-old_bottom+3*PAGE;
    need(amount>=3*PAGE && amount<=1024*1024,211);s=stats();
    grow_stack(amount);
    li2_maps_event_boundary();need(!li2_maps_phase_begin(),212);refreshed(213);
    sr=mapping(anchor);need(sr && sr->first<old_bottom && stats().stack_probes==s.stack_probes+1 &&
                            stats().unexplained==s.unexplained+1,216);
    stack_growth=1;++cases;
    /* Actual copy_to_user growth: no user touch or event before the query. */
    old_bottom=sr->first;s=stats();uintptr_t dest=old_bottom-PAGE;
    need(tracked(SYS_pread64,file,(long)dest,1,0,0,0)==1,217);
    refreshed(230);sr=mapping(anchor);
    need(sr && sr->first<old_bottom && sr->first<=dest &&
         stats().stack_probes==s.stack_probes+1 && stats().unexplained==s.unexplained+1 &&
         *(const volatile unsigned char *)dest==0,233);
    syscall_stack_growth=1;++cases;
    /* Grow, then split below the last observed bottom before any map consumer.
       The pre-unmap probe must retire, rather than lose a grow-down fragment. */
    old_bottom=sr->first;s=stats();amount=anchor-old_bottom+3*PAGE;
    need(amount<=1024*1024,234);grow_stack(amount);
    li2_maps_event_boundary();need(!li2_maps_phase_begin(),235);
    need(!tracked(SYS_munmap,(long)(old_bottom-PAGE),PAGE,0,0,0,0),236);
    refreshed(237);need(!mapping(old_bottom-PAGE) && mapping(old_bottom-2*PAGE) &&
         mapping(anchor) && stats().stack_probes==s.stack_probes+1 &&
         stats().unexplained==s.unexplained+1,240);
    refreshed(241);stack_split_retired=1;++cases;
    /* Stack mprotect also leaves reuse retired. */
    need(!tracked(SYS_mprotect,(long)(anchor&~(PAGE-1)),PAGE,PROT_READ|PROT_WRITE,0,0,0),218);
    refreshed(220);refreshed(224);++cases;
    unmapped(0);unmapped(1);refreshed(228);++cases;
}
static void negative(void) {
    uintptr_t a=mapped(0,PAGE,PROT_READ,-1,0);refreshed(300);hit(304);++cases;
    /* Real untracked mutation: require mismatch then persistent poison. */
    if(mode==1)need(!kernel(SYS_mprotect,(long)a,PAGE,PROT_READ|PROT_WRITE,0,0,0),310);
    else {
        long r=kernel(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        need(!kernel_error(r) && r>0,311);ranges[1]=(uintptr_t)r;extents[1]=PAGE;
    }
    struct li2_maps_view_stats s=stats();struct check_error e={0};struct li2_fetch_map_progress p;
    need(read_maps_checked(&e,&p)==LI2_FETCH_STATE && e.code==LI2_FETCH_STATE,312);
    struct li2_maps_view_stats t=stats();
    need(t.mismatches==s.mismatches+1 && t.poisoned==1 && t.enabled==1 && t.differential==1 && !t.reserved,313);
    mismatch_refusal=1;e=(struct check_error){0};
    need(read_maps_checked(&e,&p)==LI2_FETCH_STATE && e.code==LI2_FETCH_STATE &&
         stats().poisoned==1 && stats().mismatches==t.mismatches,314);
    poison_refusal=1;++cases;
}
int main(int argc,char **argv) {
    need(argc==2 && argv[1][0]>='0' && argv[1][0]<='5' && !argv[1][1],1);
    mode=(unsigned)(argv[1][0]-'0');
    uintptr_t anchor=(uintptr_t)&argc;
    hooks=(struct li2_lifecycle_hooks){tracked,fatal,protected_none};active=1;
    /* Real disabled bootstrap parser. */
    struct check_error e={0};struct li2_fetch_map_progress p;
    need(!read_maps_checked(&e,&p) && !e.code && p.opened==1 && p.closed==1 &&
         p.observation.io_performed==1 && row_count,2);
    if(mode==3 || mode==4) {
        if(mode==4){li2_maps_view_stack(anchor);persona_control=1;}
        need(li2_maps_view_enable()==LI2_FETCH_STATE && !stats().enabled && !stats().poisoned,3);
        need(persona_calls==(mode==4),4);disabled_refusal=1;cases=1;
    } else {
        if(mode==5) {
            long r=tracked(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
            need(!kernel_error(r) && r>0,7);ranges[0]=(uintptr_t)r;extents[0]=PAGE;anchor=(uintptr_t)r;
        }
        li2_maps_view_stack(anchor);need(!li2_maps_view_enable(),8);
        li2_maps_event_boundary();need(!li2_maps_phase_begin(),9);query(10);
        if(!mode)positive(anchor);
        else if(mode<3)negative();
        else {refreshed(320);refreshed(324);need(!stats().hits,328);anchor_fallback=1;cases=1;}
    }
    final=stats();li2_maps_phase_end();cleanup();
    printf("{\"version\":1,\"mode\":%u,\"cases\":%u,\"partial_errno\":%u,"
           "\"alias_refusals\":%u,\"nested_updates\":%u,\"stack_growth\":%u,\"syscall_stack_growth\":%u,\"stack_split_retired\":%u,"
           "\"mismatch_refusal\":%u,\"poison_refusal\":%u,\"cleanup_maps\":%u,\"cleanup_fds\":%u,"
           "\"disabled_refusal\":%u,\"anchor_fallback\":%u,\"persona_calls\":%u,\"stats\":[%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u]}\n",
           mode,cases,partial_errno,alias_refusals,nested_updates,stack_growth,syscall_stack_growth,stack_split_retired,mismatch_refusal,
           poison_refusal,cleanup_maps,cleanup_fds,disabled_refusal,anchor_fallback,persona_calls,final.queries,final.hits,final.refreshes,final.updates,
           final.invalidations,final.comparisons,final.mismatches,final.unexplained,final.stack_probes,
           final.enabled,final.differential,final.poisoned,final.reserved);
    return mode && mode!=5?125:0;
}
