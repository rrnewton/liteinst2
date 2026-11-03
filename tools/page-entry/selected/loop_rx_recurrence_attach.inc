/* One protected shared writer, initialized before guest/handler execution. */
#include <sys/personality.h>
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif
#include "counter_environment.inc"
struct li2_lrc_bank *li2_lrc_bank;
/* Retained by the recipe link root; read from this actual ELF, no inferior. */
const uint64_t li2_lrc_layout[]={
    sizeof(struct li2_lrc_bank),offsetof(struct li2_lrc_bank,tail),sizeof(struct li2_lrc_row),
    sizeof(struct li2_pg_source_key),offsetof(struct li2_lrc_row,source),
    offsetof(struct li2_lrc_row,registry),offsetof(struct li2_lrc_row,heads),
    sizeof(struct li2_fetch_page),sizeof(struct li2_fetch_backing),sizeof(struct li2_pg_source_page),
    offsetof(struct li2_fetch_backing,seals),offsetof(struct li2_fetch_backing,stat_result),
    offsetof(struct li2_fetch_backing,stat),offsetof(struct li2_fetch_backing,seals_observed),
    offsetof(struct li2_fetch_backing,stat_observed),offsetof(struct stat,st_dev),
    offsetof(struct stat,st_ino),offsetof(struct stat,st_mode),offsetof(struct stat,st_size),
    offsetof(struct li2_pg_source_key,entry),offsetof(struct li2_pg_source_key,page),
    offsetof(struct li2_pg_source_page,bytes),
    offsetof(struct li2_fetch_page,address),
    offsetof(struct li2_fetch_page,allocation),
    offsetof(struct li2_fetch_page,generation),
    offsetof(struct li2_fetch_page,offset),
    offsetof(struct li2_fetch_page,initial_extent),
    offsetof(struct li2_fetch_page,backing),
    offsetof(struct li2_fetch_page,object),
    offsetof(struct li2_fetch_page,logical),
    offsetof(struct li2_fetch_page,closed_prot),
    offsetof(struct li2_fetch_page,vma_first),
    offsetof(struct li2_fetch_page,vma_end),
    offsetof(struct li2_fetch_page,vma_major),
    offsetof(struct li2_fetch_page,vma_minor),
    offsetof(struct li2_fetch_page,vma_inode),
    offsetof(struct li2_fetch_page,vma_offset)
};

static void lrc_attach(void) {
    checked(!li2_lrc_bank,3390,4);
    uint64_t number=pgc_environment_number("LI2_LOOP_RX_RECURRENCE_FD=");
    uint64_t nonce=pgc_environment_number("LI2_LOOP_RX_RECURRENCE_NONCE=");
    checked(number>2 && number<=0x7fffffffU,3390,5);int fd=(int)number;
    long flags=raw(SYS_fcntl,fd,F_GETFL,0,0,0,0);
    long descriptor=raw(SYS_fcntl,fd,F_GETFD,0,0,0,0);
    long seals=raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);
    struct stat st;
    checked(flags>=0 && (flags&O_ACCMODE)==O_RDWR && descriptor==0 && seals==6 &&
        !raw(SYS_fstat,fd,(long)&st,0,0,0,0) && S_ISREG(st.st_mode) &&
        (st.st_mode&07777)==0600 && st.st_nlink==0 && st.st_size==LI2_LRC_STORAGE,3390,6);
    long pid=raw(SYS_getpid,0,0,0,0,0,0),tid=raw(SYS_gettid,0,0,0,0,0,0);
    long parent=raw(SYS_getppid,0,0,0,0,0,0);
    checked(pid>0 && pid==tid && parent>0,3390,7);
    long personality=raw(SYS_personality,0xffffffffUL,0,0,0,0,0);
    checked(personality>=0 && !(personality&READ_IMPLIES_EXEC),3390,15);
    long mapped=raw(SYS_mmap,0,LI2_LRC_STORAGE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    checked(mapped>0 && !((uintptr_t)mapped&(PAGE-1)) &&
        (uintptr_t)mapped<=UINTPTR_MAX-LI2_LRC_STORAGE,3390,8);
    struct li2_lrc_bank *p=(void *)(uintptr_t)mapped;
    const uint64_t expected[8]={LI2_LRC_MAGIC,LI2_LRC_VERSION,LI2_LRC_BYTES,
        LI2_LRC_STORAGE,nonce,(uint64_t)parent,(uint64_t)st.st_dev,(uint64_t)st.st_ino};
    checked(equal(p->header,expected,sizeof expected),3390,9);
    const unsigned char *bytes=(const void *)p;
    for(size_t i=sizeof expected;i<LI2_LRC_STORAGE;i++)checked(!bytes[i],3390,10);
    protect((uintptr_t)p,LI2_LRC_STORAGE);
    checked(!raw(SYS_fcntl,fd,F_ADD_SEALS,F_SEAL_FUTURE_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL,0,0,0) &&
        raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)==23,3390,11);
    checked(!raw(SYS_close,fd,0,0,0,0,0),3390,12);
    p->header[8]=(uint64_t)pid;p->header[9]=(uint64_t)tid;
    p->header[10]=6;p->header[11]=23;p->header[12]=(uintptr_t)p;
    p->header[13]=1;p->header[14]=1;li2_lrc_bank=p;
    __atomic_store_n(&p->header[15],1,__ATOMIC_RELEASE);
}
