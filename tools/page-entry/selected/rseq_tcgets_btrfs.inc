/* Opt-in normal-open btrfs capture FD1. Included only after the original
   ready/word_zero/same_data helpers. Every syscall uses the ordinary raw maps
   gateway, with a fresh pure zero/owner check before and after each query. */
#include <limits.h>
#include <linux/magic.h>
static struct li2_tcgets_state tcgets;
static const char tcgets_empty[]="",tcgets_mount_path[]="/proc/self/mountinfo";
const struct li2_tcgets_state *li2_rseq_tcgets_snapshot(void) { return &tcgets; }
static int tcgets_bad(long detail) {
    if(!tcgets.first_error){tcgets.first_error=state.first_error?state.first_error:LI2_RSEQ_UNSUPPORTED;tcgets.first_detail=detail;}
    tcgets.phase=LI2_TCGETS_FAILED;
    return bad(LI2_RSEQ_UNSUPPORTED,SYS_ioctl); /* old1207/detail16 stays exact */
}
static int tcgets_safe(void) {
    if(ready() || li2_lifecycle_fetch_interlock())return 0;
    if(!state.registered)return tcgets.phase==LI2_TCGETS_BINDING && !state.held && state.phase==LI2_RSEQ_IDLE;
    if(!state.held || state.phase!=LI2_RSEQ_ACTIVE || !state.tls_complete ||
       state.pid<=0 || state.pid!=state.tid || state.length!=32 || !state.epoch ||
       (state.address&31) || state.address>UINTPTR_MAX-32 ||
       state.page!=(state.address&~(RSEQ_PAGE-1)) || !state.data.complete || state.data.error ||
       state.data.address!=state.address || state.data.page!=state.page ||
       state.data.pid!=state.pid || state.data.tid!=state.tid ||
       !state.data.allocation || !state.data.generation)return 0;
    return !word_zero();
}
static int tcgets_query(long n,long a,long b,long c,long d,long e,long f,long *result) {
    if(!tcgets_safe() || tcgets.queries==UINT64_MAX)return 0;
    tcgets.query_attempted=tcgets.query_returned=0;__asm__ volatile("":::"memory");
    tcgets.query_number=n;tcgets.query_result=0;
    __asm__ volatile("":::"memory");tcgets.query_attempted=1;++tcgets.queries;
    tcgets.query_result=CALL(n,a,b,c,d,e,f);
    __asm__ volatile("":::"memory");tcgets.query_returned=1;*result=tcgets.query_result;
    return tcgets_safe();
}
static int tcgets_literal(size_t a,size_t b,const char *s) {
    size_t i=0;while(s[i]){if(a+i==b || tcgets.mountinfo[a+i]!=s[i])return 0;++i;}
    return a+i==b;
}
static int tcgets_number(size_t a,size_t b,uint64_t *out) {
    uint64_t n=0;if(a==b || (b-a>1 && tcgets.mountinfo[a]=='0'))return 0;
    for(size_t i=a;i<b;i++) {
        unsigned d=(unsigned char)tcgets.mountinfo[i]-'0';
        if(d>9 || n>(UINT64_MAX-d)/10)return 0;
        n=n*10+d;
    }
    *out=n;return 1;
}
static int tcgets_token(size_t *at,size_t end,size_t *first,size_t *last) {
    size_t a=*at;if(a==end)return 0;
    while(*at<end && tcgets.mountinfo[*at]!=' ') {
        unsigned char c=(unsigned char)tcgets.mountinfo[(*at)++];
        if(c<33 || c>126)return 0;
        if(c=='\\') {
            size_t p=*at;
            if(end-p<3 || !(tcgets_literal(p,p+3,"040") || tcgets_literal(p,p+3,"011") ||
                tcgets_literal(p,p+3,"012") || tcgets_literal(p,p+3,"134")))return 0;
            *at+=3;
        }
    }
    *first=a;*last=*at;
    if(a==*at)return 0;
    if(*at<end){++*at;if(*at==end || tcgets.mountinfo[*at]==' ')return 0;}
    return 1;
}
static int tcgets_options(size_t a,size_t b) {
    if(b-a<2 || tcgets.mountinfo[a]!='r' ||
       (tcgets.mountinfo[a+1]!='o' && tcgets.mountinfo[a+1]!='w') ||
       (b-a>2 && tcgets.mountinfo[a+2]!=','))return 0;
    for(size_t i=a;i<b;i++)if(tcgets.mountinfo[i]==',' &&
        (i+1==b || tcgets.mountinfo[i+1]==','))return 0;
    return 1;
}
static int tcgets_mount_parse(uint64_t wanted) {
    size_t at=0,length=(size_t)tcgets.mount_bytes;tcgets.mount_rows=tcgets.mount_matches=0;
    if(!wanted || !length || !tcgets.mount_eof || !tcgets.mount_closed)return 0;
    while(at<length) {
        size_t end=at;while(end<length && tcgets.mountinfo[end]!='\n')++end;
        if(end==length || tcgets.mount_rows==LI2_TCGETS_MOUNT_ROWS)return 0;
        size_t a,b;uint64_t id,parent,major_number,minor_number;
        if(!tcgets_token(&at,end,&a,&b) || !tcgets_number(a,b,&id) || !id || id>INT_MAX ||
           !tcgets_token(&at,end,&a,&b) || !tcgets_number(a,b,&parent) || !parent || parent>INT_MAX ||
           !tcgets_token(&at,end,&a,&b))return 0;
        size_t colon=a;while(colon<b && tcgets.mountinfo[colon]!=':')++colon;
        if(colon==b || !tcgets_number(a,colon,&major_number) ||
           !tcgets_number(colon+1,b,&minor_number) || major_number>UINT32_MAX || minor_number>UINT32_MAX)return 0;
        for(size_t i=0;i<tcgets.mount_rows;i++)if(tcgets.mount_ids[i]==id)return 0;
        tcgets.mount_ids[tcgets.mount_rows++]=id;
        for(unsigned i=0;i<2;i++)if(!tcgets_token(&at,end,&a,&b) || tcgets.mountinfo[a]!='/')return 0;
        if(!tcgets_token(&at,end,&a,&b) || !tcgets_options(a,b))return 0;
        unsigned tags=0;
        for(;;) {
            if(!tcgets_token(&at,end,&a,&b))return 0;
            if(tcgets_literal(a,b,"-"))break;
            unsigned tag=0;size_t prefix=0;
            if(b-a>7 && tcgets_literal(a,a+7,"shared:")){tag=1;prefix=7;}
            else if(b-a>7 && tcgets_literal(a,a+7,"master:")){tag=2;prefix=7;}
            else if(b-a>15 && tcgets_literal(a,a+15,"propagate_from:")){tag=4;prefix=15;}
            else if(tcgets_literal(a,b,"unbindable"))tag=8;
            if(!tag || (tags&tag))return 0;
            uint64_t number;if(prefix && (!tcgets_number(a+prefix,b,&number) || !number || number>INT_MAX))return 0;
            tags|=tag;
        }
        if(!tcgets_token(&at,end,&a,&b))return 0;
        int btrfs=tcgets_literal(a,b,"btrfs");
        if(!tcgets_token(&at,end,&a,&b) || !tcgets_token(&at,end,&a,&b) ||
           !tcgets_options(a,b) || at!=end)return 0;
        if(id==wanted){if(!btrfs)return 0;++tcgets.mount_matches;}
        at=end+1;
    }
    /* btrfs subvolume st_dev need NOT equal this mountinfo superblock dev. */
    return tcgets.mount_matches==1;
}
static int tcgets_mount_read(uint64_t mount_id) {
    long result;int good=1;
    tcgets.mount_complete=0;__asm__ volatile("":::"memory");
    tcgets.mount_close_result=0;tcgets.mount_fd=-1;tcgets.mount_bytes=tcgets.mount_rows=tcgets.mount_matches=0;
    tcgets.mount_opened=tcgets.mount_eof=tcgets.mount_close_started=tcgets.mount_closed=tcgets.mount_complete=0;
    if(!tcgets_query(SYS_openat,AT_FDCWD,(long)tcgets_mount_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW,0,0,0,&result) || result<0 || result>INT_MAX)return 0;
    tcgets.mount_fd=result;tcgets.mount_opened=1;
    tcgets.proc_stat=(struct stat){0};tcgets.proc_filesystem=(struct statfs){0};
    if(!tcgets_query(SYS_fstat,result,(long)&tcgets.proc_stat,0,0,0,0,&result) || result ||
       (tcgets.proc_stat.st_mode&S_IFMT)!=S_IFREG)good=0;
    if(good && (!tcgets_query(SYS_fstatfs,tcgets.mount_fd,(long)&tcgets.proc_filesystem,0,0,0,0,&result) ||
       result || tcgets.proc_filesystem.f_type!=PROC_SUPER_MAGIC))good=0;
    while(good) {
        if(tcgets.mount_bytes==LI2_TCGETS_MOUNT_BYTES){good=0;break;}
        size_t left=LI2_TCGETS_MOUNT_BYTES-(size_t)tcgets.mount_bytes;
        if(!tcgets_query(SYS_read,tcgets.mount_fd,(long)tcgets.mountinfo+tcgets.mount_bytes,(long)left,0,0,0,&result) ||
           result<0 || (uint64_t)result>left){good=0;break;}
        if(!result){tcgets.mount_eof=1;break;}
        tcgets.mount_bytes+=(uint64_t)result;
    }
    tcgets.mount_close_started=1;
    if(!tcgets_query(SYS_close,tcgets.mount_fd,0,0,0,0,0,&result))good=0;
    else {tcgets.mount_close_result=result;tcgets.mount_closed=result==0;if(result)good=0;}
    if(!good || !tcgets_mount_parse(mount_id))return 0;
    tcgets.mount_complete=1;return 1;
}
static uint64_t tcgets_major(uint64_t dev) { return ((dev>>8)&0xfff)|((dev>>32)&0xfffff000); }
static uint64_t tcgets_minor(uint64_t dev) { return (dev&0xff)|((dev>>12)&0xffffff00); }
static int tcgets_identity(struct li2_tcgets_identity *out) {
    long result;tcgets.stat=(struct stat){0};tcgets.statx=(struct statx){0};
    tcgets.filesystem=(struct statfs){0};
    if(!tcgets_query(SYS_fstat,1,(long)&tcgets.stat,0,0,0,0,&result) || result ||
       (tcgets.stat.st_mode&S_IFMT)!=S_IFREG || !tcgets.stat.st_ino)return 0;
    if(!tcgets_query(SYS_fcntl,1,F_GETFL,0,0,0,0,&result) || result<0 || (result&O_PATH))return 0;
    long flags=result;
    if(!tcgets_query(SYS_fstatfs,1,(long)&tcgets.filesystem,0,0,0,0,&result) || result ||
       (uint64_t)tcgets.filesystem.f_type!=BTRFS_SUPER_MAGIC)return 0;
    const unsigned mask=STATX_TYPE|STATX_MODE|STATX_INO|STATX_MNT_ID;
    if(!tcgets_query(SYS_statx,1,(long)tcgets_empty,AT_EMPTY_PATH,mask,(long)&tcgets.statx,0,&result) || result ||
       (tcgets.statx.stx_mask&mask)!=mask || (tcgets.statx.stx_mode&S_IFMT)!=S_IFREG ||
       tcgets.statx.stx_mode!=tcgets.stat.st_mode || tcgets.statx.stx_ino!=tcgets.stat.st_ino ||
       tcgets.statx.stx_dev_major!=tcgets_major(tcgets.stat.st_dev) || tcgets.statx.stx_dev_minor!=tcgets_minor(tcgets.stat.st_dev) ||
       !tcgets.statx.stx_mnt_id || (tcgets.statx.stx_mask&STATX_MNT_ID_UNIQUE))return 0;
    *out=(struct li2_tcgets_identity){tcgets.stat.st_dev,tcgets.stat.st_ino,tcgets.statx.stx_mnt_id,
        tcgets.statx.stx_dev_major,tcgets.statx.stx_dev_minor,tcgets.stat.st_mode,flags};
    return tcgets_mount_read(out->mount_id);
}
static int tcgets_same(const struct li2_tcgets_identity *a,const struct li2_tcgets_identity *b) {
    return a->device==b->device && a->inode==b->inode && a->mount_id==b->mount_id &&
        a->major==b->major && a->minor==b->minor && (a->mode&S_IFMT)==(b->mode&S_IFMT);
}
int li2_rseq_tcgets_initialize(void) {
    if(tcgets.phase!=LI2_TCGETS_EMPTY || tcgets.initialized || !private_range ||
       !private_range((uintptr_t)&tcgets,sizeof(tcgets)))return tcgets_bad(1);
    tcgets.phase=LI2_TCGETS_BINDING;
    if(!tcgets_identity(&tcgets.launch))return tcgets_bad(2);
    tcgets.initialized=1;__asm__ volatile("":::"memory");tcgets.phase=LI2_TCGETS_IDLE;return 0;
}
static int tcgets_before(long n,const long a[6]) {
    if(!a || !tcgets.initialized || tcgets.first_error)return tcgets_bad(3);
    /* Runs before the !registered return. Never resurrect a replaced FD1,
       including interpreter close/reopen and later F_DUPFD lowest-FD reuse. */
    if(n==SYS_close && (unsigned int)a[0]==1) {
        tcgets.invalidated=1;tcgets.invalidated_number=n;
    }
    if(tcgets.phase!=LI2_TCGETS_IDLE && tcgets.phase!=LI2_TCGETS_COMPLETE)return tcgets_bad(4);
    return 0;
}
static int tcgets_permit(const long a[6]) {
#ifdef LI2_RSEQ_TIOCGWINSZ_BTRFS
    if(a[0]!=1 || (a[1]!=0x5401 && a[1]!=0x5413) || tcgets.invalidated || !tcgets_safe() ||
#else
    if(a[0]!=1 || a[1]!=0x5401 || tcgets.invalidated || !tcgets_safe() ||
#endif
       tcgets.attempts==UINT64_MAX)return tcgets_bad(5);
    tcgets.phase=LI2_TCGETS_CHECKING;__asm__ volatile("":::"memory");
    ++tcgets.attempts;tcgets.result=0;
    tcgets.registration_epoch=state.epoch;tcgets.syscall_check=state.syscall_checks;
    for(size_t i=0;i<6;i++)tcgets.args[i]=a[i];
    tcgets.data=(struct li2_rseq_data){0};
    int error=li2_lifecycle_rseq_data(state.address,&tcgets.data);
    if(error || !same_data(&state.data,&tcgets.data) || !tcgets_safe() ||
       !tcgets_identity(&tcgets.current) || !tcgets_same(&tcgets.launch,&tcgets.current))return tcgets_bad(6);
    if(tcgets.permitted==UINT64_MAX)return tcgets_bad(7);
    ++tcgets.permitted;__asm__ volatile("":::"memory");tcgets.phase=LI2_TCGETS_PERMITTED;return 0;
}
static int tcgets_args(long n,const long a[6]) {
    if(n!=SYS_ioctl || !a || !tcgets_safe() || tcgets.invalidated ||
       tcgets.registration_epoch!=state.epoch || tcgets.syscall_check!=state.syscall_checks ||
       !same_data(&tcgets.data,&state.data))return 0;
    for(size_t i=0;i<6;i++)if(a[i]!=tcgets.args[i])return 0;
    return 1;
}
int li2_rseq_tcgets_issuing(long n,const long a[6]) {
    if(n!=SYS_ioctl || !state.registered)return 0;
    if(tcgets.phase!=LI2_TCGETS_PERMITTED || !tcgets_args(n,a) || tcgets.issued==UINT64_MAX)return tcgets_bad(8);
    ++tcgets.issued;__asm__ volatile("":::"memory");tcgets.phase=LI2_TCGETS_ISSUED;return 0;
}
int li2_rseq_tcgets_result(long n,const long a[6],long result) {
    if(n!=SYS_ioctl || !state.registered)return 0;
    if(tcgets.phase!=LI2_TCGETS_ISSUED || !tcgets_args(n,a) || tcgets.returned==UINT64_MAX)return tcgets_bad(9);
    tcgets.result=result;++tcgets.returned;__asm__ volatile("":::"memory");tcgets.phase=LI2_TCGETS_RETURNED;
    if(result!=-ENOTTY || tcgets.completed==UINT64_MAX)return tcgets_bad(10);
#ifdef LI2_RSEQ_TIOCGWINSZ_BTRFS
    unsigned command=a[1]==0x5401?0:1;
    if((a[1]!=0x5401 && a[1]!=0x5413) || tcgets.command_completed[command]==UINT64_MAX)return tcgets_bad(10);
    ++tcgets.command_completed[command];
#endif
    ++tcgets.completed;__asm__ volatile("":::"memory");tcgets.phase=LI2_TCGETS_COMPLETE;return 0;
}
