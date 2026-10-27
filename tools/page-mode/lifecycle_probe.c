#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "lifecycle.h"
#define PAGE 4096UL
static void (*snapshot)(struct li2_lifecycle_counts *);
static int (*page_view)(uintptr_t,struct li2_lifecycle_page_view *);
static int instrumented;
static struct li2_lifecycle_counts state(void) {
    struct li2_lifecycle_counts out={0}; if (snapshot) snapshot(&out); return out;
}
static struct li2_lifecycle_page_view page(void *address) {
    struct li2_lifecycle_page_view out={0};
    if (instrumented) assert(page_view((uintptr_t)address,&out));
    return out;
}
static void code(unsigned char *p,unsigned char value) {
    /* mov eax,imm32; ret: deliberately unchanged between modes. */
    const unsigned char bytes[]={0xb8,value,0,0,0,0xc3};
    memcpy(p,bytes,sizeof(bytes));
}
static int call(void *p) { return ((int (*)(void))p)(); }
static void library(const char *fd_text) {
    char path[96]; int n=snprintf(path,sizeof(path),"/proc/self/fd/%s",fd_text);
    assert(n>0 && (size_t)n<sizeof(path));
    uint64_t prior_generation=0;
    for (unsigned turn=0;turn<2;turn++) {
        void *handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
        if (!handle) { fprintf(stderr,"dlopen: %s\n",dlerror()); abort(); }
        int (*f)(int)=(int (*)(int))dlsym(handle,"lifecycle_value"); assert(f);
        struct li2_lifecycle_page_view before=page((void *)f);
        if (instrumented) {
            assert(before.logical==(PROT_READ|PROT_EXEC) && before.actual==PROT_READ && !before.admitted);
            assert(before.generation>prior_generation);
        }
        struct li2_lifecycle_counts first=state();
        assert(f(11)==40);
        struct li2_lifecycle_counts second=state();
        struct li2_lifecycle_page_view after=page((void *)f);
        if (instrumented) {
            assert(second.admissions==first.admissions+1 && after.admitted && before.generation==after.generation);
            assert(after.actual==(PROT_READ|PROT_EXEC));
        }
        for (unsigned i=0;i<100;i++) assert(f((int)i)==(int)i*3+7);
        if (instrumented) assert(state().admissions==second.admissions);
        prior_generation=after.generation;
        assert(!dlclose(handle));
        if (instrumented) assert(!page_view((uintptr_t)f,&after));
    }
    puts("sealed_dlopen=40,40");
}
static void jit(void) {
    unsigned char *p=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
    code(p,17); assert(!mprotect(p,PAGE,PROT_READ|PROT_EXEC));
    struct li2_lifecycle_page_view first=page(p); assert(call(p)==17);
    assert(!mprotect(p,PAGE,PROT_READ|PROT_WRITE));
    struct li2_lifecycle_page_view write=page(p);
    if (instrumented) assert(write.generation>first.generation && write.logical==(PROT_READ|PROT_WRITE) && !write.admitted);
    code(p,29); assert(!mprotect(p,PAGE,PROT_READ|PROT_EXEC));
    struct li2_lifecycle_page_view second=page(p); assert(call(p)==29);
    if (instrumented) assert(second.generation>write.generation && second.actual==PROT_READ && !second.admitted);
    assert(!munmap(p,PAGE));
    struct li2_lifecycle_page_view absent;
    if (instrumented) assert(!page_view((uintptr_t)p,&absent));
    void *reused=mmap(p,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(reused==p); code(p,41); assert(!mprotect(p,PAGE,PROT_READ|PROT_EXEC));
    struct li2_lifecycle_page_view third=page(p); assert(call(p)==41);
    if (instrumented) assert(third.allocation!=first.allocation && third.generation>second.generation);
    assert(!munmap(p,PAGE)); puts("jit_generations=17,29,41");
}
static void cross_page(void) {
    unsigned char *p=mmap(0,2*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
    /* The first MOV fetch crosses a page; neither page has been executed. */
    code(p+PAGE-2,53); assert(!mprotect(p,2*PAGE,PROT_READ|PROT_EXEC));
    struct li2_lifecycle_counts before=state(); assert(call(p+PAGE-2)==53);
    if (instrumented) assert(state().admissions==before.admissions+2);
    assert(!munmap(p,2*PAGE));
    p=mmap(0,2*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
    /* CALL ends at page boundary; its return PC is in the other pending page. */
    code(p,67); p[PAGE-5]=0xe8;
    int32_t displacement=-(int32_t)PAGE; memcpy(p+PAGE-4,&displacement,4); p[PAGE]=0xc3;
    assert(!mprotect(p,2*PAGE,PROT_READ|PROT_EXEC));
    before=state(); assert(call(p+PAGE-5)==67);
    if (instrumented) assert(state().admissions==before.admissions+2);
    assert(!munmap(p,2*PAGE)); puts("cross_page=53,67");
}
static void sealed_slice(const char *fd_text) {
    int fd=atoi(fd_text);
    unsigned char *p=mmap(0,3*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0); assert(p!=MAP_FAILED);
    assert(!mprotect(p+PAGE,PAGE,PROT_READ|PROT_EXEC));
    struct li2_lifecycle_page_view middle=page(p+PAGE);
    if (instrumented) assert(middle.logical==(PROT_READ|PROT_EXEC) && middle.actual==PROT_READ);
    assert(!mprotect(p+PAGE,PAGE,PROT_READ|PROT_WRITE));
    assert(!munmap(p,3*PAGE)); puts("sealed_partial_vma=rx,rw");
}
static void partial(int request_rx) {
    unsigned char *p=mmap(0,3*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
    code(p,71); code(p+2*PAGE,73);
    assert(!mprotect(p,3*PAGE,PROT_READ|PROT_EXEC));
    assert(call(p)==71); /* actual admitted first, pending third */
    assert(!munmap(p+PAGE,PAGE));
    if (request_rx) assert(!mprotect(p,PAGE,PROT_READ|PROT_WRITE));
    struct li2_lifecycle_page_view before=page(p+2*PAGE);
    errno=0; int result=mprotect(p,3*PAGE,request_rx?(PROT_READ|PROT_EXEC):PROT_READ); int error=errno;
    assert(result==-1 && error==ENOMEM);
    struct li2_lifecycle_page_view left=page(p),right=page(p+2*PAGE);
    if (instrumented) {
        assert(left.logical==(unsigned)(request_rx?(PROT_READ|PROT_EXEC):PROT_READ));
        assert(right.logical==(PROT_READ|PROT_EXEC) && right.actual==PROT_READ && !right.admitted);
        assert(right.generation>before.generation);
        if (request_rx) assert(left.actual==PROT_READ && !left.admitted);
        else assert(left.actual==PROT_READ && !left.admitted);
    }
    assert(call(p+2*PAGE)==73);
    if (request_rx) assert(call(p)==71);
    assert(!munmap(p,3*PAGE));
    printf("partial_%s=ENOMEM,73\n",request_rx?"rx":"r");
}
static void negative(const char *which,const char *fd_text) {
    int fd=atoi(fd_text);
    if (!strcmp(which,"wx")) (void)mmap(0,PAGE,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    else if (!strcmp(which,"shared")) (void)mmap(0,PAGE,PROT_READ|PROT_EXEC,MAP_SHARED,fd,0);
    else if (!strcmp(which,"unsealed")) {
        int other=open("/proc/self/exe",O_RDONLY); assert(other>=0); (void)mmap(0,PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,other,0);
    } else if (!strcmp(which,"alias")) {
        assert(mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0)!=MAP_FAILED);
        (void)mmap(0,PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0);
    } else if (!strcmp(which,"partial_alias")) {
        unsigned char *p=mmap(0,3*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
        assert(!munmap(p,3*PAGE));
        assert(mmap(p,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,0)==p);
        assert(mmap(p+2*PAGE,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,0)==p+2*PAGE);
        /* Genuine first-page RX effect, ENOMEM at the hole, untouched RW alias. */
        (void)mprotect(p,3*PAGE,PROT_READ|PROT_EXEC);
    } else if (!strcmp(which,"protected")) {
        void *own=dlsym(RTLD_DEFAULT,"li2_dynamic_lifecycle_snapshot"); assert(own);
        (void)mprotect((void *)((uintptr_t)own&~(PAGE-1)),PAGE,PROT_READ|PROT_WRITE);
    } else if (!strcmp(which,"unknown")) {
        char local; (void)mprotect((void *)((uintptr_t)&local&~(PAGE-1)),PAGE,PROT_READ|PROT_EXEC);
    } else if (!strcmp(which,"thread")) (void)syscall(SYS_clone,0,0,0,0,0);
    else if (!strcmp(which,"stale")) {
        void *p=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
        code(p,1); assert(!mprotect(p,PAGE,PROT_READ|PROT_EXEC)); assert(call(p)==1);
        assert(!mprotect(p,PAGE,PROT_READ|PROT_WRITE)); (void)call(p);
    } else if (!strcmp(which,"brk_hole")) {
        uintptr_t old=(uintptr_t)syscall(SYS_brk,0);
        assert(old && old<=UINTPTR_MAX-4*PAGE);
        uintptr_t aligned=(old+PAGE-1)&~(PAGE-1),end=aligned+3*PAGE;
        assert((uintptr_t)syscall(SYS_brk,end)==end);
        unsigned char *hole=(void *)(aligned+PAGE);
        assert(!munmap(hole,PAGE));
        assert(mmap(hole,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==hole);
        code(hole,83); assert(!mprotect(hole,PAGE,PROT_READ|PROT_EXEC));
        assert(call(hole)==83);
        /* Must refuse before the genuine shrink can remove the live owner. */
        (void)syscall(SYS_brk,old);
    } else if (!strcmp(which,"post_effect")) {
        void *p=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
        code(p,97); (void)mprotect(p,PAGE,PROT_READ|PROT_EXEC);
    } else if (!strcmp(which,"capacity")) {
        for (unsigned i=0;i<8193;i++) {
            void *p=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
            assert(!munmap(p,PAGE));
        }
    } else abort();
    /* The accepted negative profile must refuse before this application point. */
    _exit(99);
}
static int fd_same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_mode==b->st_mode && a->st_rdev==b->st_rdev && a->st_size==b->st_size;
}
static int held_duplicate(int source,unsigned first,unsigned end) {
    struct stat original;assert(!fstat(source,&original));int found=-1;
    for(unsigned fd=first;fd<end;fd++) {
        errno=0;long flags=syscall(SYS_fcntl,fd,F_GETFD,0);
        if(flags==-1) { assert(errno==EBADF);continue; }
        assert(flags>=0);struct stat actual;assert(!fstat((int)fd,&actual));
        if(flags==FD_CLOEXEC && fd_same(&actual,&original)) { assert(found==-1);found=(int)fd; }
    }
    assert(found>=0);return found;
}
static void fd_marker(const char *prefix,const char *name) {
    char line[96];int n=snprintf(line,sizeof(line),"%s%s\n",prefix,name);
    assert(n>0 && (size_t)n<sizeof(line) && syscall(SYS_write,1,line,n)==n);
}
static void fd_control(const char *name,int source) {
    int fd=-1;struct stat original;assert(!fstat(source,&original) && S_ISREG(original.st_mode) && original.st_size>0);
    if(!strcmp(name,"fd_report_highbits")) {
        if(!instrumented) {
            errno=0;assert(syscall(SYS_fcntl,100,F_GETFD,0)==-1 && errno==EBADF);
            assert(syscall(SYS_fcntl,2,F_DUPFD_CLOEXEC,100)==100);
        }
        fd=held_duplicate(2,100,200);
    } else if(!strcmp(name,"fd_retained_highbits")) {
        if(!instrumented) {
            errno=0;assert(syscall(SYS_fcntl,200,F_GETFD,0)==-1 && errno==EBADF);
            assert(syscall(SYS_fcntl,source,F_DUPFD_CLOEXEC,200)==200);
        }
        fd=held_duplicate(source,200,234);
    } else {
        assert(!strcmp(name,"fd_ordinary_highbits"));
        fd=(int)syscall(SYS_fcntl,source,F_DUPFD_CLOEXEC,300);assert(fd>=300);
        struct stat actual;assert(!fstat(fd,&actual) && fd_same(&original,&actual));
    }
    struct stat before;assert(!fstat(fd,&before) && syscall(SYS_fcntl,fd,F_GETFD,0)>=0);
    fd_marker("ATTEMPT ",name);
    assert(syscall(SYS_close,(long)((1ULL<<32)|(unsigned)fd))==0);
    errno=0;assert(syscall(SYS_fcntl,fd,F_GETFD,0)==-1 && errno==EBADF);
    fd_marker("NATIVE_OK ",name);
}
int main(int argc,char **argv) {
    assert(argc==3);
    snapshot=(void (*)(struct li2_lifecycle_counts *))dlsym(RTLD_DEFAULT,"li2_dynamic_lifecycle_snapshot");
    page_view=(int (*)(uintptr_t,struct li2_lifecycle_page_view *))dlsym(RTLD_DEFAULT,"li2_dynamic_lifecycle_page");
    instrumented=snapshot!=0;
    if (instrumented) assert(page_view && state().enabled);
    if (!strcmp(argv[1],"fd_report_highbits") || !strcmp(argv[1],"fd_retained_highbits") || !strcmp(argv[1],"fd_ordinary_highbits")) {
        fd_control(argv[1],atoi(argv[2]));return 0;
    }
    if (strcmp(argv[1],"positive")) { negative(argv[1],argv[2]); return 99; }
    library(argv[2]); sealed_slice(argv[2]); jit(); cross_page(); partial(0); partial(1);
    /* Kernel errors that require no supported mutation remain genuine. */
    errno=0; assert(mmap(0,0,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)==MAP_FAILED && errno==EINVAL);
    errno=0; assert(mprotect((void *)1,PAGE,PROT_READ)==-1 && errno==EINVAL);
    puts("kernel_errors=EINVAL,EINVAL");
    return 0;
}
