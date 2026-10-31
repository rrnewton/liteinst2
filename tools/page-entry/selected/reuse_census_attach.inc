/* Bootstrap only; the ABI2 counter backing is unchanged. */
static struct li2_rcc_wire *rcc_wire;
static void rcc_attach(void) {
    checked(!rcc_wire,3391,0);
    uint64_t number=pgc_environment_number("LI2_REUSE_CENSUS_FD=");
    uint64_t nonce=pgc_environment_number("LI2_REUSE_CENSUS_NONCE=");
    checked(number>2 && number<=0x7fffffffU,3391,1);int fd=(int)number;
    long flags=raw(SYS_fcntl,fd,F_GETFL,0,0,0,0),descriptor=raw(SYS_fcntl,fd,F_GETFD,0,0,0,0);
    struct stat st;long seals=raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);
    checked(flags>=0 && (flags&O_ACCMODE)==O_RDWR && descriptor==0 && seals==6 &&
        !raw(SYS_fstat,fd,(long)&st,0,0,0,0) && S_ISREG(st.st_mode) &&
        (st.st_mode&07777)==0600 && !st.st_nlink && st.st_size==LI2_RCC_BYTES,3391,2);
    long pid=raw(SYS_getpid,0,0,0,0,0,0),tid=raw(SYS_gettid,0,0,0,0,0,0),parent=raw(SYS_getppid,0,0,0,0,0,0);
    checked(pid>0 && pid==tid && parent>0,3391,3);
    long mapped=raw(SYS_mmap,0,LI2_RCC_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    checked(mapped>0 && !((uintptr_t)mapped&4095U) && (uintptr_t)mapped<=(UINT64_C(1)<<47)-LI2_RCC_BYTES,3391,4);
    struct li2_rcc_wire *p=(void *)(uintptr_t)mapped;
    const uint64_t expected[8]={LI2_RCC_MAGIC,1,LI2_RCC_BYTES,4096,nonce,(uint64_t)parent,(uint64_t)st.st_dev,(uint64_t)st.st_ino};
    checked(equal(p->header,expected,sizeof expected),3391,5);
    const unsigned char *bytes=(const void *)p;
    for(size_t i=sizeof expected;i<LI2_RCC_BYTES;i++)checked(!bytes[i],3391,6);
    protect((uintptr_t)p,LI2_RCC_BYTES);
    checked(!raw(SYS_fcntl,fd,F_ADD_SEALS,F_SEAL_FUTURE_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL,0,0,0) &&
        raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)==23,3391,7);
    checked(!raw(SYS_close,fd,0,0,0,0,0),3391,8);
    p->header[8]=(uint64_t)pid;p->header[9]=(uint64_t)tid;p->header[10]=6;p->header[11]=23;
    p->header[12]=(uintptr_t)p;p->header[13]=1;p->header[14]=1;
    p->header[24]=LI2_RCC_PAGES;p->header[25]=LI2_RCC_KEYS;p->header[26]=LI2_RCC_GRAPHS;
    p->header[27]=LI2_RCC_REGISTRIES;p->header[28]=LI2_RCC_ATTEMPTS;p->header[29]=2;
    rcc_wire=p;__atomic_store_n(&p->header[15],1,__ATOMIC_RELEASE);
}
