#define _GNU_SOURCE
#include "record.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Ownership/wait/GETREGSET protocol follows the retained b2_reference raw
   tracer and b2_xstate probe. This lane executes the real selected instruction:
   it never SETREGS an effect result, changes an app mask, or single-steps it. */
extern char **environ;
struct file { int fd; struct stat st; unsigned char *bytes; size_t n; };
struct map { uint64_t lo,hi,offset,inode; unsigned major,minor; char mode[5]; };
static struct pan_record record;
static struct file files[2];
static struct map maps[512];
static size_t map_count;
static pid_t child;
static int pidfd=-1,reaped;
static uint64_t deadline;
static uint64_t now(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static void problem(unsigned line) {
    if(!record.h[6]) {record.h[6]=line;record.h[7]=(unsigned)errno;}
}
#define REQUIRE(x) do {if(!(x)){problem(__LINE__);goto cleanup;}}while(0)
static int wait_child(uint64_t until,int *status) {
    for(;;) {
        pid_t got=waitpid(child,status,WNOHANG|__WALL);
        if(got==child) {
            record.h[16]++;
            if(WIFEXITED(*status)||WIFSIGNALED(*status)) {
                reaped=1;record.h[10]=(unsigned)*status;record.h[11]=1;
            }
            return 1;
        }
        if(got<0 && errno!=EINTR)return -1;
        uint64_t t=now();if(!t || t>=until)return 0;
        const struct timespec pause={0,1000000};(void)nanosleep(&pause,0);
    }
}
static long request(enum __ptrace_request op,uintptr_t a,void *b) {
    return ptrace(op,child,(void *)a,b);
}
static int peek(uint64_t at,uint64_t *word) {
    errno=0;long v=request(PTRACE_PEEKDATA,(uintptr_t)at,0);
    if(v==-1 && errno)return -1;
    *word=(uint64_t)v;return 0;
}
static int memory(uint64_t at,void *out,size_t size) {
    if((at&7) || (size&7) || size>UINT64_MAX-at)return -1;
    for(size_t i=0;i<size;i+=8) {
        uint64_t word;if(peek(at+i,&word))return -1;
        memcpy((unsigned char *)out+i,&word,8);
    }
    return 0;
}
static int debug(unsigned index,uint64_t value) {
    return request(PTRACE_POKEUSER,offsetof(struct user,u_debugreg)+8*index,(void *)(uintptr_t)value)?-1:0;
}
static int debug_read(unsigned index,uint64_t *value) {
    errno=0;long got=request(PTRACE_PEEKUSER,offsetof(struct user,u_debugreg)+8*index,0);
    if(got==-1 && errno)return -1;
    *value=(uint64_t)got;return 0;
}
static int hardware(uint64_t pc) {
    if(debug(7,0) || debug(0,pc) || debug(6,0))return -1;
    return debug(7,pc?1:0);
}
static int trap(int *status,struct user_regs_struct *r,siginfo_t *si) {
    if(wait_child(deadline,status)!=1 || !WIFSTOPPED(*status) ||
       WSTOPSIG(*status)!=SIGTRAP || *status>>16 ||
       request(PTRACE_GETREGS,0,r) || request(PTRACE_GETSIGINFO,0,si) ||
       si->si_signo!=SIGTRAP || si->si_errno)return -1;
    return 0;
}
static int write_all(int fd,const void *data,size_t n) {
    const unsigned char *p=data;
    while(n) {ssize_t count=write(fd,p,n);if(count<0 && errno==EINTR)continue;
        if(count<=0)return -1;
        p+=(size_t)count;n-=(size_t)count;}
    return 0;
}
static int save(int dir,const char *name,const void *data,size_t n) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;
    int error=write_all(fd,data,n);
    if(fsync(fd))error=-1;
    if(close(fd))error=-1;
    return error;
}
static const void *part(const struct file *f,uint64_t at,uint64_t n) {
    return at<=f->n && n<=f->n-at?f->bytes+at:0;
}
static int read_file(const char *path,struct file *f) {
    /* A trusted evaluator may supply an already sealed exact original ELF.
       Authenticate that descriptor; never resolve an arbitrary symlink. */
    const char prefix[]="/proc/self/fd/";
    if(!strncmp(path,prefix,sizeof prefix-1)) {
        const char *p=path+sizeof prefix-1;unsigned fd=0,digits=0;
        while(*p) {if(*p<'0' || *p>'9' || fd>100000)return -1;
            fd=fd*10+(unsigned)(*p++-'0');digits++;}
        if(!digits || fd<3 || fcntl((int)fd,F_GET_SEALS)!=15)return -1;
        f->fd=fcntl((int)fd,F_DUPFD_CLOEXEC,3);
        if(f->fd<0 || fcntl(f->fd,F_GET_SEALS)!=15)return -1;
    } else f->fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(f->fd<0 || fstat(f->fd,&f->st) || !S_ISREG(f->st.st_mode) ||
       f->st.st_size<64 || f->st.st_size>16*1024*1024)return -1;
    f->n=(size_t)f->st.st_size;f->bytes=malloc(f->n);if(!f->bytes)return -1;
    size_t at=0;while(at<f->n) {
        ssize_t n=pread(f->fd,f->bytes+at,f->n-at,(off_t)at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return -1;
        at+=(size_t)n;
    }
    return 0;
}
static int unchanged(const struct file *f) {
    struct stat s;if(fstat(f->fd,&s) || s.st_dev!=f->st.st_dev || s.st_ino!=f->st.st_ino ||
       s.st_size!=f->st.st_size || s.st_mode!=f->st.st_mode)return -1;
    unsigned char b[4096];size_t at=0;
    while(at<f->n) {size_t n=f->n-at;if(n>sizeof b)n=sizeof b;
        ssize_t got=pread(f->fd,b,n,(off_t)at);
        if(got<0 && errno==EINTR)continue;
        if(got!=(ssize_t)n || memcmp(b,f->bytes+at,n))return -1;
        at+=n;
    }
    return 0;
}
static int image(unsigned m) {
    struct file *f=files+m;struct pan_image *im=record.image+m;
    const Elf64_Ehdr *e=part(f,0,sizeof *e);
    if(!e || memcmp(e->e_ident,"\177ELF\2\1\1",7) || e->e_type!=ET_DYN || e->e_machine!=EM_X86_64 ||
       e->e_ehsize!=64 || e->e_phentsize!=56 || e->e_shentsize!=64 || !e->e_phnum ||
       e->e_phnum>64 || !e->e_shnum || e->e_shnum>4096)return -1;
    const Elf64_Phdr *ph=part(f,e->e_phoff,(uint64_t)e->e_phnum*56);
    const Elf64_Shdr *sh=part(f,e->e_shoff,(uint64_t)e->e_shnum*64);
    if(!ph || !sh)return -1;
    unsigned zero=0,tables=0;const Elf64_Shdr *table=0;
    for(unsigned i=0;i<e->e_phnum;i++)if(ph[i].p_type==PT_LOAD && !ph[i].p_offset && !ph[i].p_vaddr)zero++;
    for(unsigned i=0;i<e->e_shnum;i++)if(sh[i].sh_type==SHT_SYMTAB){table=sh+i;tables++;}
    if(zero!=1 || tables!=1 || table->sh_entsize!=24 || table->sh_size%24 || table->sh_link>=e->e_shnum)return -1;
    const Elf64_Sym *syms=part(f,table->sh_offset,table->sh_size);
    const Elf64_Shdr *st=sh+table->sh_link;const char *names=part(f,st->sh_offset,st->sh_size);
    if(!syms || !names)return -1;
    const char *suffix[]={"page","capture_before","capture_after","seed_x87","cpuid","getpid","rdtsc"};
    const unsigned slots[]={4,6,7,9,10,11,12};unsigned counts[9]={0};
    for(size_t i=0;i<table->sh_size/24;i++) {
        const Elf64_Sym *s=syms+i;
        if(s->st_name>=st->sh_size || !memchr(names+s->st_name,0,st->sh_size-s->st_name))return -1;
        const char *name=names+s->st_name;
        for(unsigned j=0;j<7;j++) {
            char wanted[80];int n=snprintf(wanted,sizeof wanted,"pa_%s_%s",m?"dso":"main",suffix[j]);
            if(n<=0 || (size_t)n>=sizeof wanted)return -1;
            if(!strcmp(name,wanted)){if(!s->st_shndx)return -1;counts[j]++;im->h[slots[j]]=s->st_value;}
        }
        if(!strcmp(name,"stack")){if(!s->st_shndx || s->st_size!=PAN_STACK)return -1;counts[7]++;im->h[8]=s->st_value;}
        if(!m && !strcmp(name,"main")){if(!s->st_shndx)return -1;counts[8]++;im->h[13]=s->st_value;}
    }
    for(unsigned j=0;j<8;j++)if(counts[j]!=1)return -1;
    if(!m && counts[8]!=1)return -1;
    unsigned pages=0;
    for(unsigned i=0;i<e->e_phnum;i++) {
        const Elf64_Phdr *p=ph+i;uint64_t page=im->h[4];
        if(p->p_type==PT_LOAD && p->p_flags==(PF_R|PF_X) && page>=p->p_vaddr &&
           p->p_filesz>=PAN_PAGE && page-p->p_vaddr<=p->p_filesz-PAN_PAGE) {
            uint64_t off=p->p_offset+page-p->p_vaddr;
            const void *source=part(f,off,PAN_PAGE);if(!source)return -1;
            im->h[5]=off;memcpy(im->source,source,PAN_PAGE);pages++;
        }
    }
    if(pages!=1 || (im->h[4]&4095) || (im->h[5]&4095))return -1;
    for(unsigned k=0;k<3;k++) {
        const unsigned char second[]={0xa2,5,0x31};uint64_t off=128+32*k;
        if(im->h[10+k]!=im->h[4]+off || im->source[off]!=15 || im->source[off+1]!=second[k] ||
           memcmp(im->source+off+2,"\220\220\220",3))return -1;
    }
    im->h[0]=f->st.st_dev;im->h[1]=f->st.st_ino;im->h[2]=f->n;im->h[14]=e->e_phnum;return 0;
}
static int read_maps(void) {
    char name[80];int n=snprintf(name,sizeof name,"/proc/%ld/maps",(long)child);
    if(n<=0 || (size_t)n>=sizeof name)return -1;
    int fd=open(name,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;
    size_t at=0;for(;;) {
        if(at==sizeof record.maps-1){close(fd);return -1;}
        ssize_t got=read(fd,record.maps+at,sizeof record.maps-1-at);
        if(got<0 && errno==EINTR)continue;
        if(got<0){close(fd);return -1;}
        if(!got)break;
        at+=(size_t)got;
    }
    if(close(fd) || !at || record.maps[at-1]!='\n')return -1;
    record.h[21]=at;
    const char *p=(const char *)record.maps;
    while(*p) {
        if(map_count==512)return -1;
        struct map *m=maps+map_count;
        unsigned long lo,hi,off,ino;
        if(sscanf(p,"%lx-%lx %4s %lx %x:%x %lu",&lo,&hi,m->mode,&off,&m->major,&m->minor,&ino)!=7 ||
           lo>=hi || (map_count && lo<maps[map_count-1].hi))return -1;
        m->lo=lo;m->hi=hi;m->offset=off;m->inode=ino;map_count++;
        p=strchr(p,'\n');if(!p)return -1;
        p++;
    }
    return 0;
}
static int bind_image(unsigned index,int complete) {
    struct pan_image *im=record.image+index;unsigned matched=0;uint64_t bias=0;
    for(size_t i=0;i<map_count;i++) {
        const struct map *m=maps+i;
        if(m->inode==im->h[1] && m->major==major((dev_t)im->h[0]) &&
           m->minor==minor((dev_t)im->h[0]) && !m->offset){matched++;bias=m->lo;}
    }
    if(matched!=1 || (bias&4095))return -1;
    if(!complete)return bias>UINT64_MAX-im->h[13]?-1:0;
    im->h[3]=bias;
    for(unsigned s=4;s<=13;s++)if(s!=5 && (s!=13 || !index)) {
        if(im->h[s]>UINT64_MAX-bias)return -1;
        im->h[s]+=bias;
    }
    unsigned code=0;uint64_t cursor=im->h[8],end=cursor+PAN_STACK;
    if(end<cursor)return -1;
    for(size_t i=0;i<map_count;i++) {
        const struct map *m=maps+i;
        if(m->lo<=im->h[4] && im->h[4]<=m->hi && PAN_PAGE<=m->hi-im->h[4] &&
           !strcmp(m->mode,"r-xp") && m->inode==im->h[1] &&
           m->major==major((dev_t)im->h[0]) && m->minor==minor((dev_t)im->h[0]) &&
           m->offset+im->h[4]-m->lo==im->h[5])code++;
        if(m->lo<=cursor && cursor<m->hi && !strcmp(m->mode,"rw-p"))cursor=m->hi<end?m->hi:end;
    }
    return code==1 && cursor==end?0:-1;
}
static int point(struct pan_point *out,uint64_t pc,unsigned char expected) {
    uint64_t aligned=pc&~UINT64_C(7),shift=8*(pc-aligned),word=0;
    out->h[3]=pc;
    if(peek(aligned,&word) || ((word>>shift)&255)!=expected)return -1;
    out->h[4]=word;
    uint64_t patched=(word&~(UINT64_C(255)<<shift))|(UINT64_C(0xcc)<<shift);out->h[5]=patched;
    if(request(PTRACE_POKEDATA,aligned,(void *)(uintptr_t)patched) || peek(aligned,&word) || word!=patched ||
       request(PTRACE_CONT,0,0))return -1;
    int status=0;
    if(trap(&status,&out->trap,&out->si) || out->trap.rip!=pc+1 ||
       (out->si.si_code!=SI_KERNEL && out->si.si_code!=TRAP_BRKPT))return -1;
    out->h[7]=(unsigned)status;
    if(peek(aligned,&word) || word!=patched ||
       request(PTRACE_POKEDATA,aligned,(void *)(uintptr_t)out->h[4]) || peek(aligned,&word))return -1;
    out->h[6]=word;if(word!=out->h[4])return -1;
    struct user_regs_struct wanted=out->trap;wanted.rip=pc;
    if(request(PTRACE_SETREGS,0,&wanted) || request(PTRACE_GETREGS,0,&out->state) ||
       memcmp(&wanted,&out->state,sizeof wanted))return -1;
    struct iovec iov={out->fp,PAN_FP};
    if(request(PTRACE_GETREGSET,NT_X86_XSTATE,&iov) || iov.iov_len<576 || iov.iov_len>PAN_FP ||
       request((enum __ptrace_request)0x420a,8,&out->h[2]))return -1;
    out->h[1]=iov.iov_len;
    for(unsigned m=0;m<2;m++) {
        if(memory(record.image[m].h[4],out->source[m],PAN_PAGE) ||
           memcmp(out->source[m],record.image[m].source,PAN_PAGE) ||
           memory(record.image[m].h[8],out->stack[m],PAN_STACK))return -1;
    }
    out->h[0]=1;return 0;
}
int main(int argc,char **argv) {
    if(argc!=4 || argv[1][0]!='/' || argv[2][0]!='/' || argv[3][0]!='/' || mkdir(argv[3],0700))return 2;
    int dir=open(argv[3],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0)return 2;
    int stdout_fd=-1,stderr_fd=-1,null_fd=-1,status=0,masked=0;uint64_t oldmask=0;
    files[0].fd=files[1].fd=-1;
    record.h[0]=PAN_MAGIC;record.h[1]=1;record.h[2]=sizeof record;record.h[3]=(uint64_t)getpid();
    record.h[8]=now();deadline=record.h[8]+UINT64_C(15000000000);
    cpu_set_t affinity;CPU_ZERO(&affinity);
    REQUIRE(!sched_getaffinity(0,sizeof affinity,&affinity) && CPU_COUNT(&affinity)==1);
    int cpu=sched_getcpu();REQUIRE(cpu>=0);record.h[17]=(unsigned)cpu;
    REQUIRE(!read_file(argv[1],files) && !read_file(argv[2],files+1) && !image(0) && !image(1));
    REQUIRE(!save(dir,"main.elf",files[0].bytes,files[0].n) && !save(dir,"dso.elf",files[1].bytes,files[1].n));
    stdout_fd=openat(dir,"stdout.bin",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    stderr_fd=openat(dir,"stderr.txt",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    null_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    REQUIRE(stdout_fd>=3 && stderr_fd>=3 && null_fd>=3);
    struct sigaction disposition;REQUIRE(!sigaction(SIGCHLD,0,&disposition) && disposition.sa_handler==SIG_DFL && !(disposition.sa_flags&SA_NOCLDWAIT));
    const uint64_t blocked=~((UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
    REQUIRE(!syscall(SYS_rt_sigprocmask,SIG_SETMASK,&blocked,&oldmask,8));masked=1;record.h[25]=oldmask;
    char *const command[]={argv[1],"state","native",0};
    long pid=syscall(SYS_clone,CLONE_PIDFD|SIGCHLD,0,&pidfd,0,0);
    if(pid==0) {
        if(prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=(pid_t)record.h[3] ||
           dup2(null_fd,0)!=0 || dup2(stdout_fd,1)!=1 || dup2(stderr_fd,2)!=2 ||
           ptrace(PTRACE_TRACEME,0,0,0) || syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),SIGSTOP))_exit(120);
        execve(argv[1],command,environ);_exit(121);
    }
    if(pid>0){child=(pid_t)pid;record.h[4]=(uint64_t)child;record.h[14]=1;}
    REQUIRE(pid>0 && pidfd>=0);
    REQUIRE(wait_child(deadline,&status)==1 && status==((SIGSTOP<<8)|0x7f));
    REQUIRE(!request(PTRACE_SETOPTIONS,0,(void *)(uintptr_t)(PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL)) && !request(PTRACE_CONT,0,0));
    REQUIRE(wait_child(deadline,&status)==1 && status==((PTRACE_EVENT_EXEC<<16)|(SIGTRAP<<8)|0x7f));record.h[22]=(unsigned)status;
    REQUIRE(!request((enum __ptrace_request)0x420b,8,&oldmask));
    uint64_t actual=0;REQUIRE(!request((enum __ptrace_request)0x420a,8,&actual) && actual==oldmask);
    REQUIRE(!read_maps() && !bind_image(0,0));
    uint64_t main_bias=0;for(size_t i=0;i<map_count;i++)if(!maps[i].offset && maps[i].inode==record.image[0].h[1] &&
        maps[i].major==major((dev_t)record.image[0].h[0]) && maps[i].minor==minor((dev_t)record.image[0].h[0]))main_bias=maps[i].lo;
    REQUIRE(!hardware(main_bias+record.image[0].h[13]) && !request(PTRACE_CONT,0,0));
    REQUIRE(!trap(&status,&record.main_regs,&record.main_si) && record.main_si.si_code==TRAP_HWBKPT &&
        record.main_regs.rip==main_bias+record.image[0].h[13] && !debug_read(6,&record.h[30]) &&
        !debug_read(7,&record.h[31]) && (record.h[30]&15)==1 && record.h[31]==1);record.h[23]=(unsigned)status;
    REQUIRE(!hardware(0));map_count=0;memset(record.maps,0,sizeof record.maps);
    REQUIRE(!read_maps() && !bind_image(0,1) && !bind_image(1,1));
    for(unsigned index=0;index<PAN_ROWS;index++) {
        struct pan_row *row=record.row+index;unsigned module=(index%6)/3,kind=index%3;
        row->h[0]=index;row->h[1]=module;row->h[2]=kind;row->h[3]=index/6;
        REQUIRE(!hardware(record.image[module].h[6]) && !request(PTRACE_CONT,0,0));
        REQUIRE(!trap(&status,&row->helper,&row->helper_si) && row->helper_si.si_code==TRAP_HWBKPT &&
           row->helper.rip==record.image[module].h[6] && !debug_read(6,&row->h[5]) &&
           !debug_read(7,&row->h[6]) && (row->h[5]&15)==1 && row->h[6]==1);
        row->h[4]=1;REQUIRE(!hardware(0));
        uint64_t pc=record.image[module].h[10+kind];
        REQUIRE(!point(row->point,pc,0x0f) && !point(row->point+1,pc+2,0x90));
        REQUIRE(row->point[0].h[1]==row->point[1].h[1] && row->point[0].h[2]==row->point[1].h[2] &&
            !memcmp(row->point[0].fp,row->point[1].fp,PAN_FP) &&
            !memcmp(row->point[0].stack,row->point[1].stack,2*PAN_STACK));
        record.h[5]++;
    }
    REQUIRE(!hardware(0) && !request(PTRACE_CONT,0,0));
    REQUIRE(wait_child(deadline,&status)==1 && WIFEXITED(status) && !WEXITSTATUS(status));record.h[15]=1;
    REQUIRE(!unchanged(files) && !unchanged(files+1));record.h[24]=1;
cleanup:
    if(child>0 && !reaped) {
        record.h[27]=1;
        if(syscall(SYS_pidfd_send_signal,pidfd,SIGKILL,0,0) && errno!=ESRCH)problem(__LINE__);
        uint64_t until=now()+UINT64_C(2000000000);
        while(!reaped && now()<until) {
            int got=wait_child(until,&status);if(got<=0)break;
            if(!reaped)(void)request(PTRACE_CONT,0,(void *)(uintptr_t)SIGKILL);
        }
        if(!reaped){record.h[28]=1;problem(__LINE__);}
    }
    if(reaped && pidfd>=0) {
        struct pollfd p={pidfd,POLLIN,0};siginfo_t info={0};
        if(poll(&p,1,0)==1 && p.revents==(POLLIN|POLLHUP))record.h[12]=1;else problem(__LINE__);
        errno=0;if(waitid((idtype_t)3 /* Linux P_PIDFD */,(id_t)pidfd,&info,WEXITED|WNOHANG|WNOWAIT|__WALL)==-1 && errno==ECHILD)record.h[13]=1;else problem(__LINE__);
    }
    if(masked) {
        uint64_t actual=0;
        if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,&oldmask,0,8) ||
           syscall(SYS_rt_sigprocmask,SIG_SETMASK,0,&actual,8) || actual!=oldmask)problem(__LINE__);
        else record.h[26]=1;
    }
    struct stat s;
    if(stdout_fd>=0){if(fstat(stdout_fd,&s) || s.st_size<0 || s.st_size>(1<<20))problem(__LINE__);else record.h[19]=(uint64_t)s.st_size;}
    if(stderr_fd>=0){if(fstat(stderr_fd,&s) || s.st_size<0 || s.st_size>(1<<20))problem(__LINE__);else record.h[20]=(uint64_t)s.st_size;}
    int end_cpu=sched_getcpu();if(end_cpu<0 || (unsigned)end_cpu!=record.h[17])problem(__LINE__);else record.h[18]=(unsigned)end_cpu;
    record.h[9]=now()-record.h[8];
    int result=record.h[6]?1:0;if(save(dir,"record.bin",&record,sizeof record))result=3;
    if(pidfd>=0)close(pidfd);
    if(stdout_fd>=0)close(stdout_fd);
    if(stderr_fd>=0)close(stderr_fd);
    if(null_fd>=0)close(null_fd);
    for(unsigned i=0;i<2;i++){if(files[i].fd>=0)close(files[i].fd);free(files[i].bytes);}close(dir);return result;
}
