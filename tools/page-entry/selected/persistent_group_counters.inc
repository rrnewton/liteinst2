/* Bootstrap only: one inherited memfd, one shared target writer, no guest FD.
   All RAW calls precede the complete old maps-prefix transfer. */
#include <sys/personality.h>
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif
static struct li2_pgc_record pgc_bootstrap;
struct li2_pgc_record *li2_pgc_current=&pgc_bootstrap;
static uint64_t pgc_environment_number(const char *key) {
    const char *const *env=bridge_environment();const char *value=0;
    for(size_t i=0;env[i];i++) {
        size_t j=0;while(key[j] && key[j]==env[i][j])j++;
        if(!key[j]){checked(!value,3390,1);value=env[i]+j;}
    }
    checked(value && *value && *value!='0',3390,2);uint64_t n=0;
    while(*value){checked(*value>='0' && *value<='9' && n<=(UINT64_MAX-(*value-'0'))/10,3390,3);
        n=n*10+(unsigned)(*value++-'0');}
    return n;
}
static void pgc_attach(void) {
    checked(li2_pgc_current==&pgc_bootstrap,3390,4);
    uint64_t number=pgc_environment_number("LI2_GROUP_COUNTER_FD=");
    uint64_t nonce=pgc_environment_number("LI2_GROUP_COUNTER_NONCE=");
    checked(number>2 && number<=0x7fffffffU,3390,5);int fd=(int)number;
    long flags=raw(SYS_fcntl,fd,F_GETFL,0,0,0,0);
    long descriptor=raw(SYS_fcntl,fd,F_GETFD,0,0,0,0);
    long seals=raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);
    struct stat st;
    checked(flags>=0 && (flags&O_ACCMODE)==O_RDWR && descriptor==0 &&
        seals==LI2_PGC_INITIAL_SEALS && !raw(SYS_fstat,fd,(long)&st,0,0,0,0) &&
        S_ISREG(st.st_mode) && (st.st_mode&07777)==0600 && st.st_nlink==0 &&
        st.st_size==LI2_PGC_PAGE,3390,6);
    long pid=raw(SYS_getpid,0,0,0,0,0,0),tid=raw(SYS_gettid,0,0,0,0,0,0);
    long parent=raw(SYS_getppid,0,0,0,0,0,0);
    checked(pid>0 && pid==tid && parent>0,3390,7);
    long personality=raw(SYS_personality,0xffffffffUL,0,0,0,0,0);
    checked(personality>=0 && !(personality&READ_IMPLIES_EXEC),3390,15);
    long mapped=raw(SYS_mmap,0,LI2_PGC_PAGE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    checked(mapped>0 && ((uintptr_t)mapped&(LI2_PGC_PAGE-1))==0 &&
        (uintptr_t)mapped<=UINTPTR_MAX-LI2_PGC_PAGE,3390,8);
    struct li2_pgc_record *p=(void *)(uintptr_t)mapped;
    const uint64_t expected[8]={LI2_PGC_MAGIC,2,LI2_PGC_BYTES,LI2_PGC_PAGE,nonce,
        (uint64_t)parent,(uint64_t)st.st_dev,(uint64_t)st.st_ino};
    checked(equal(p->header,expected,sizeof expected),3390,9);
    const unsigned char *bytes=(const void *)p;
    for(size_t i=sizeof expected;i<LI2_PGC_PAGE;i++)checked(!bytes[i],3390,10);
    protect((uintptr_t)p,LI2_PGC_PAGE);
    checked(!raw(SYS_fcntl,fd,F_ADD_SEALS,F_SEAL_FUTURE_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL,0,0,0) &&
        raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)==LI2_PGC_FINAL_SEALS,3390,11);
    checked(!raw(SYS_close,fd,0,0,0,0,0),3390,12);
    p->header[8]=(uint64_t)pid;p->header[9]=(uint64_t)tid;
    p->header[10]=LI2_PGC_INITIAL_SEALS;p->header[11]=LI2_PGC_FINAL_SEALS;
    p->header[12]=(uintptr_t)p;p->header[13]=1;p->header[14]=1;
    /* No RAW, handlers, SUD, or guest execution may intervene in this switch.
       Earlier linked/group/native ingress is zero; maps includes all bootstrap RAWs. */
    for(size_t i=0;i<sizeof pgc_bootstrap;i++)checked(!((const unsigned char *)&pgc_bootstrap)[i],3390,13);
    checked(li2_pgc_bind_maps(&p->maps,&p->view),3390,14);
    li2_pgc_current=p;
    __atomic_store_n(&p->header[15],1,__ATOMIC_RELEASE);
}
