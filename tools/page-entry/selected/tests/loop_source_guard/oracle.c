/* Actual loader TU, supplied metadata only. No source instruction, kernel
   mapping, owner receipt, publication, native frame or qualification credit.
   Build only after the reviewed anonymous-source implementation is installed. */
#include "lifecycle_loader.c"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if LI2_PERSISTENT_LOOP_RUNTIME != 1 || LI2_PERSISTENT_LOOP_PLAN != 1
#error "the actual LOOP release profile is required"
#endif
_Static_assert(offsetof(struct li2_fetch_backing,retained_fd)==0,"backing first member");
_Static_assert(sizeof(struct li2_fetch_backing)==176,"reviewed backing extent");
enum { LG_PAGE=0x100000 };
static unsigned lg_checks,lg_raw_calls;
static void lg_expect(int yes,const char *where,unsigned line) {
    ++lg_checks;
    if(!yes) {fprintf(stderr,"loop source guard failure %s:%u\n",where,line);_Exit(124);}
}
#define LG_CHECK(x) lg_expect(!!(x),__func__,__LINE__)
static _Noreturn void lg_die(unsigned code,long detail) {
    fprintf(stderr,"unexpected loader failure %u/%ld\n",code,detail);_Exit(125);
}
static long lg_no_raw(long n,long a,long b,long c,long d,long e,long f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;++lg_raw_calls;lg_die(999,n);
}
static struct li2_fetch_page lg_page(unsigned i) {
    const struct owned_page *p=&records[i];const struct map_row *r=&rows[i];
    return (struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=p->actual,
        .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,.vma_minor=r->minor,
        .vma_inode=r->inode,.vma_offset=r->offset};
}
static __attribute__((noinline)) void lg_setup(unsigned kind) {
    memset(records,0,3*sizeof *records);memset(rows,0,3*sizeof *rows);
    memset(objects,0,sizeof *objects);memset(&fetch,0,sizeof fetch);
    memset(&pg_source,0,sizeof pg_source);memset(&tx,0,sizeof tx);
    used=2;row_count=2;object_count=1;active=1;
    objects[0].major=8;objects[0].minor=1;objects[0].inode=91;
    for(unsigned i=0;i<2;i++) {
        uintptr_t address=LG_PAGE+(uintptr_t)i*PAGE;
        records[i]=(struct owned_page){.address=address,.allocation=7+i,.generation=11+i,
            .offset=(uint64_t)i*PAGE,.initial_extent=kind==SEALED?2*PAGE:0,
            .backing=kind,.object=kind==SEALED?0:OBJECTS,
            .logical=PROT_READ|PROT_EXEC,.actual=PROT_READ,.live=1};
        rows[i]=(struct map_row){.first=address,.end=address+PAGE,.offset=(uint64_t)i*PAGE,
            .major=kind==SEALED?8:0,.minor=kind==SEALED?1:0,.inode=kind==SEALED?91:0,
            .prot=PROT_READ,.private=1};
    }
    fetch.pc=LG_PAGE+512;fetch.requested=15;fetch.page_count=1;
    fetch.original[0]=records[0];fetch.pages[0]=lg_page(0);
    hooks.raw=lg_no_raw;hooks.fail=lg_die;
}
static __attribute__((noinline)) void lg_classes(void) {
    for(unsigned kind=SEALED;kind<=ANONYMOUS;kind++) {
        lg_setup(kind);struct owned_page p=records[0];struct li2_fetch_page q=lg_page(0);
        LG_CHECK(pgs_loop_owned_class(&p)==kind);LG_CHECK(pgs_loop_page_class(&q)==kind);
        LG_CHECK(!pgs_loop_owned_class(0));LG_CHECK(!pgs_loop_page_class(0));
        p.backing=0;q.backing=0;LG_CHECK(!pgs_loop_owned_class(&p));LG_CHECK(!pgs_loop_page_class(&q));
        p.backing=3;q.backing=3;LG_CHECK(!pgs_loop_owned_class(&p));LG_CHECK(!pgs_loop_page_class(&q));
        p=records[0];q=lg_page(0);p.object=OBJECTS+1;q.object=OBJECTS+1;
        LG_CHECK(!pgs_loop_owned_class(&p));LG_CHECK(!pgs_loop_page_class(&q));
        p=records[0];q=lg_page(0);object_count=OBJECTS+1;
        LG_CHECK(!pgs_loop_owned_class(&p));LG_CHECK(!pgs_loop_page_class(&q));
        object_count=1;LG_CHECK(pgs_loop_owned_class(&p)==kind);LG_CHECK(pgs_loop_page_class(&q)==kind);
    }
    lg_setup(ANONYMOUS);
    for(unsigned i=0;i<5;i++) {
        struct owned_page p=records[0];struct li2_fetch_page q=lg_page(0);
        if(i==0) {p.object=0;q.object=0;} /* loader-replacement subtype remains refused */
        if(i==1) {p.initial_extent=PAGE;q.initial_extent=PAGE;}
        if(i==2)q.vma_major=1;
        if(i==3)q.vma_minor=1;
        if(i==4)q.vma_inode=1;
        if(i<2)LG_CHECK(!pgs_loop_owned_class(&p));
        LG_CHECK(!pgs_loop_page_class(&q));
    }
    lg_setup(SEALED);records[0].object=1;fetch.pages[0].object=1;
    LG_CHECK(!pgs_loop_owned_class(&records[0]));LG_CHECK(!pgs_loop_page_class(&fetch.pages[0]));
}
static __attribute__((noinline)) void lg_backing(void) {
    lg_setup(ANONYMOUS);struct li2_fetch_page p=lg_page(0),q=lg_page(1);
    struct li2_fetch_backing a,b;
    memset(&a,0xa5,sizeof a);memset(&b,0xa5,sizeof b);
    LG_CHECK(fetch_backing_check(&records[0],&a)==0);
    LG_CHECK(fetch_backing_check(&records[1],&b)==0);
    LG_CHECK(pgs_loop_anonymous_backing(&a));LG_CHECK(pgs_loop_anonymous_backing(&b));
    LG_CHECK(pgs_loop_backing_equal(&p,&a,&q,&b));
    LG_CHECK(!pgs_loop_anonymous_backing(0));
    LG_CHECK(!pgs_loop_backing_equal(&p,0,&q,&b));LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,0));
    for(unsigned side=0;side<2;side++)for(size_t i=0;i<sizeof a;i++) {
        unsigned char *raw=side?(void *)&b:(void *)&a;
        raw[i]^=1;LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,&b));
        raw[i]^=1;LG_CHECK(pgs_loop_backing_equal(&p,&a,&q,&b));
    }
    q.backing=SEALED;q.object=0;LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,&b));
    q=p;q.backing=3;LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,&b));
    lg_setup(SEALED);p=lg_page(0);q=lg_page(1);
    a=(struct li2_fetch_backing){.retained_fd=7,.seals=SEALS,.seals_observed=1,.stat_observed=1,
        .stat={.st_dev=8,.st_ino=91,.st_size=2*PAGE,.st_mode=0100500}};
    b=a;LG_CHECK(pgs_loop_backing_equal(&p,&a,&q,&b));
    for(unsigned side=0;side<2;side++)for(unsigned i=0;i<9;i++) {
        struct li2_fetch_backing saved=side?b:a,*changed=side?&b:&a;
        switch(i) {
        case 0:changed->retained_fd=-1;break;case 1:changed->seals=0;break;
        case 2:changed->stat_result=1;break;case 3:changed->seals_observed=0;break;
        case 4:changed->stat_observed=0;break;case 5:changed->stat.st_dev++;break;
        case 6:changed->stat.st_ino++;break;case 7:changed->stat.st_size++;break;
        case 8:changed->stat.st_mode^=1;break;
        }
        LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,&b));
        *changed=saved;LG_CHECK(pgs_loop_backing_equal(&p,&a,&q,&b));
    }
    q.backing=ANONYMOUS;q.object=OBJECTS;q.initial_extent=0;
    q.vma_major=0;q.vma_minor=0;q.vma_inode=0;
    LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,&b));
    p=q;LG_CHECK(!pgs_loop_backing_equal(&p,&a,&q,&b));
}
static __attribute__((noinline)) void lg_maps(void) {
    for(unsigned kind=SEALED;kind<=ANONYMOUS;kind++) {
        lg_setup(kind);struct check_error e={0};
        LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==0 && !e.code);
        e=(struct check_error){0};LG_CHECK(pgs_loop_page_check(&records[0],0,&e)==113);
        for(unsigned i=0;i<5;i++) {
            lg_setup(kind);
            switch(i) {case 0:rows[0].private=0;break;case 1:rows[0].end--;break;
            case 2:rows[0].major++;break;case 3:rows[0].minor++;break;case 4:rows[0].inode++;break;}
            e=(struct check_error){0};
            LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==(i<2?113:kind==SEALED?114:115));
        }
        lg_setup(kind);e=(struct check_error){0};records[0].object=OBJECTS+1;
        LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==LI2_FETCH_BACKING);
        lg_setup(kind);e=(struct check_error){0};
        LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==0 && !e.code);
    }
    lg_setup(SEALED);rows[0].offset++;struct check_error e={0};
    LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==114);
    lg_setup(SEALED);rows[0].first-=PAGE;rows[0].offset=UINT64_MAX;
    e=(struct check_error){0};LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==114);
    lg_setup(SEALED);row_count=3;rows[2]=rows[0];rows[2].first=LG_PAGE+4*PAGE;
    rows[2].end=rows[2].first+PAGE;rows[2].prot=PROT_READ|PROT_WRITE;
    e=(struct check_error){0};LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==119);
    rows[2].prot=PROT_READ;e=(struct check_error){0};
    LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==0);
    rows[2].prot=PROT_READ|PROT_WRITE;rows[2].offset=4*PAGE;e=(struct check_error){0};
    LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==0);
    lg_setup(ANONYMOUS);row_count=3;rows[2]=rows[0];rows[2].first=LG_PAGE+4*PAGE;
    rows[2].end=rows[2].first+PAGE;rows[2].prot=PROT_READ|PROT_WRITE;e=(struct check_error){0};
    /* Unrelated private anonymous RW memory is not an alias of this source. */
    LG_CHECK(pgs_loop_page_check(&records[0],&rows[0],&e)==0);
    LG_CHECK(pgs_page(0,LG_PAGE)==0);
}
static __attribute__((noinline)) void lg_geometry(void) {
    for(unsigned kind=SEALED;kind<=ANONYMOUS;kind++) {
        lg_setup(kind);LG_CHECK(pgs_loop_geometry());
        fetch.pc=LG_PAGE+PAGE-15;LG_CHECK(pgs_loop_geometry());
        for(unsigned i=0;i<10;i++) {
            lg_setup(kind);
            switch(i) {case 0:fetch.page_count=0;break;case 1:fetch.page_count=2;break;
            case 2:fetch.requested=14;break;case 3:fetch.requested=16;break;
            case 4:fetch.pc=LG_PAGE-1;break;case 5:fetch.pc=LG_PAGE+PAGE-14;break;
            case 6:fetch.pages[0].address++;fetch.original[0].address++;break;
            case 7:fetch.pages[0].address=UINT64_C(1)<<47;fetch.original[0].address=UINT64_C(1)<<47;
                fetch.pc=(UINT64_C(1)<<47)+512;break;
            case 8:fetch.pages[0].logical=PROT_READ;break;case 9:fetch.pages[0].closed_prot|=PROT_EXEC;break;}
            LG_CHECK(!pgs_loop_geometry());
        }
        lg_setup(kind);LG_CHECK(pgs_loop_geometry());
    }
    for(unsigned i=0;i<23;i++) {
        lg_setup(ANONYMOUS);
        switch(i) {
        case 0:fetch.original[0].live=0;break;case 1:fetch.original[0].allocation=0;break;
        case 2:fetch.original[0].generation=0;break;case 3:fetch.original[0].admitted=1;break;
        case 4:fetch.original[0].object=0;break;case 5:fetch.original[0].initial_extent=PAGE;break;
        case 6:fetch.original[0].backing=0;break;case 7:fetch.pages[0].address+=PAGE;break;
        case 8:fetch.pages[0].allocation++;break;case 9:fetch.pages[0].generation++;break;
        case 10:fetch.pages[0].offset++;break;case 11:fetch.pages[0].initial_extent=PAGE;break;
        case 12:fetch.pages[0].object=0;break;case 13:fetch.pages[0].backing=SEALED;break;
        case 14:fetch.pages[0].vma_major=1;break;case 15:fetch.pages[0].vma_minor=1;break;
        case 16:fetch.pages[0].vma_inode=1;break;case 17:fetch.original[0].logical=PROT_READ;break;
        case 18:fetch.original[0].actual|=PROT_EXEC;break;case 19:fetch.pages[0].logical|=PROT_WRITE;break;
        case 20:fetch.pages[0].closed_prot|=PROT_WRITE;break;case 21:object_count=OBJECTS+1;break;
        case 22:fetch.original[0].backing=3;break;
        }
        LG_CHECK(!pgs_loop_geometry());
    }
    lg_setup(ANONYMOUS);fetch.original[0].offset=7*PAGE;fetch.pages[0].offset=7*PAGE;
    LG_CHECK(pgs_loop_geometry()); /* real offset is not restricted to fixture offset zero */
}
static __attribute__((noinline)) void lg_advisories(void) {
    const uintptr_t pages[2]={LG_PAGE,LG_PAGE+PAGE};
    for(unsigned kind=SEALED;kind<=ANONYMOUS;kind++) {
        lg_setup(kind);LG_CHECK(li2_pg_source_pair_advisory(LG_PAGE+512)==1);
        LG_CHECK(li2_pgs_source_pair_advisory(LG_PAGE+512,pages)==1);
        LG_CHECK(li2_pg_source_pair_advisory(LG_PAGE+PAGE-15)==1);
        LG_CHECK(li2_pgs_source_pair_advisory(LG_PAGE+2*PAGE-15,pages)==1);
        for(unsigned j=0;j<2;j++)for(unsigned i=0;i<12;i++) {
            lg_setup(kind);struct owned_page *p=&records[j];
            switch(i) {case 0:p->live=0;break;case 1:p->allocation=0;break;
            case 2:p->generation=0;break;case 3:p->admitted=1;break;
            case 4:p->backing=0;break;case 5:p->backing=3;break;
            case 6:p->object=OBJECTS+1;break;case 7:p->logical=PROT_READ;break;
            case 8:p->logical|=PROT_WRITE;break;case 9:p->actual|=PROT_WRITE;break;
            case 10:p->actual|=PROT_EXEC;break;case 11:p->address+=4*PAGE;break;}
            LG_CHECK(!li2_pg_source_pair_advisory(LG_PAGE+512));
            LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+512,pages));
        }
        for(unsigned i=0;i<4;i++) {
            lg_setup(kind);
            switch(i) {case 0:active=0;break;case 1:tx.guard=1;break;
            case 2:used=RECORDS+1;break;case 3:object_count=OBJECTS+1;break;}
            LG_CHECK(!li2_pg_source_pair_advisory(LG_PAGE+512));
            LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+512,pages));
        }
        lg_setup(kind);LG_CHECK(li2_pg_source_pair_advisory(LG_PAGE+512)==1);
        LG_CHECK(li2_pgs_source_pair_advisory(LG_PAGE+512,pages)==1);
    }
    lg_setup(ANONYMOUS);
    for(unsigned j=0;j<2;j++)for(unsigned i=0;i<2;i++) {
        lg_setup(ANONYMOUS);if(i)records[j].initial_extent=PAGE;else records[j].object=0;
        LG_CHECK(!li2_pg_source_pair_advisory(LG_PAGE+512));
        LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+512,pages));
    }
    lg_setup(ANONYMOUS);LG_CHECK(!li2_pg_source_pair_advisory(LG_PAGE+PAGE-14));
    LG_CHECK(!li2_pg_source_pair_advisory(UINT64_C(1)<<47));
    LG_CHECK(!li2_pg_source_pair_advisory((UINT64_C(1)<<47)-PAGE));
    LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+512,0));
    LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE-1,pages));
    LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+PAGE-14,pages));
    LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+2*PAGE-14,pages));
    for(unsigned i=0;i<5;i++) {
        uintptr_t bad[2]={pages[0],pages[1]};
        switch(i) {case 0:bad[1]=bad[0];break;case 1:bad[0]=pages[1];bad[1]=pages[0];break;
        case 2:bad[0]++;break;case 3:bad[1]++;break;case 4:bad[1]=UINT64_C(1)<<47;break;}
        LG_CHECK(!li2_pgs_source_pair_advisory(LG_PAGE+512,bad));
    }
}
static __attribute__((noinline)) void lg_full_page(void) {
    for(unsigned j=0;j<2;j++) {
        lg_setup(ANONYMOUS);LG_CHECK(pgs_page(j,records[j].address)==0);
        LG_CHECK(!memcmp(&pg_source.original[j],&records[j],sizeof records[j]));
        struct li2_fetch_page expected=lg_page(j);
        LG_CHECK(!memcmp(&pg_source.p.source.key.page[j].identity,&expected,sizeof expected));
        LG_CHECK(pgs_loop_anonymous_backing(&pg_source.p.source.key.page[j].backing));
        LG_CHECK(pg_source.p.pages_copied==j+1 && !pg_source.p.first_error);
        for(unsigned i=0;i<22;i++) {
            lg_setup(ANONYMOUS);struct owned_page *p=&records[j];struct map_row *r=&rows[j];
            unsigned expected_error=LI2_FETCH_PAGE;
            switch(i) {case 0:p->live=0;break;case 1:p->allocation=0;break;
            case 2:p->generation=0;break;case 3:p->admitted=1;break;
            case 4:p->backing=0;break;case 5:p->backing=3;break;
            case 6:p->object=0;break;case 7:p->initial_extent=PAGE;break;
            case 8:p->logical=PROT_READ;break;case 9:p->logical|=PROT_WRITE;break;
            case 10:p->actual|=PROT_EXEC;break;case 11:p->actual|=PROT_WRITE;break;
            case 12:r->private=0;expected_error=113;break;case 13:r->end--;expected_error=113;break;
            case 14:r->major=1;expected_error=115;break;case 15:r->minor=1;expected_error=115;break;
            case 16:r->inode=1;expected_error=115;break;case 17:r->prot|=PROT_EXEC;break;
            case 18:r->prot|=PROT_WRITE;break;case 19:r->first++;expected_error=113;break;
            case 20:object_count=OBJECTS+1;break;case 21:p->object=OBJECTS+1;break;}
            LG_CHECK(pgs_page(j,LG_PAGE+(uintptr_t)j*PAGE)==(int)expected_error);
            LG_CHECK(pg_source.p.first_error==expected_error && !pg_source.p.pages_copied);
        }
        lg_setup(ANONYMOUS);LG_CHECK(pgs_page(j,records[j].address)==0);
    }
}
int main(void) {
    lg_classes();lg_backing();lg_maps();lg_geometry();lg_advisories();lg_full_page();
    LG_CHECK(lg_checks==1109 && lg_raw_calls==0);
    printf("{\"status\":\"component_passed\",\"checks\":%u,\"backing_bytes\":%zu,"
           "\"raw_calls\":%u,\"native_executed\":false,\"qualification\":false}\n",
           lg_checks,sizeof(struct li2_fetch_backing),lg_raw_calls);
    return 0;
}
