#define _GNU_SOURCE
#include "lifecycle_loader.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/membarrier.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096UL
#define SEALS (F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)
#define MAX_LOG 512
#define MAX_EVENTS 24
struct raw_record { long n,a,b,c,d,e,f,result; unsigned action; };
static struct raw_record raw_log[MAX_LOG];
static size_t raw_count;
static unsigned inject_read,inject_close,read_seen,read_injected,close_injected;
static long injected_read_result,injected_first_close,injected_last_close;
static unsigned owner_opened,owner_closed,owner_synced,interlock_denials;
static const char *case_name;

static long kernel(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d;
    register long r8 __asm__("r8")=e;
    register long r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n),"D"(a),"S"(b),"d"(c),
                     "r"(r10),"r"(r8),"r"(r9) : "rcx","r11","memory");
    return result;
}
static void need(int yes,const char *why) {
    if (!yes) { fprintf(stderr,"FIXTURE_ASSERT %s\n",why); exit(126); }
}
static int error(long r) { return r<0 && r>=-4095; }
static void log_raw(long n,long a,long b,long c,long d,long e,long f,long result,unsigned action) {
    need(raw_count<MAX_LOG,"raw record capacity");
    raw_log[raw_count++]=(struct raw_record){n,a,b,c,d,e,f,result,action};
}
/* The production callback always invokes a real kernel syscall. Only the three
   separately named injection cases redirect read to an invalid fd, or close a
   real maps fd before the requested close. No successful result is synthesized. */
static long hooked_raw(long n,long a,long b,long c,long d,long e,long f) {
    long result; unsigned action=0;
    if (inject_read && n==SYS_read && read_seen && !read_injected) {
        result=kernel(n,-1,b,c,d,e,f); action=1;
        injected_read_result=result; read_injected=1;
    } else {
        if (inject_close && n==SYS_close && !close_injected) {
            injected_first_close=kernel(n,a,b,c,d,e,f);
            log_raw(n,a,b,c,d,e,f,injected_first_close,2);
            close_injected=1; action=3;
        }
        result=kernel(n,a,b,c,d,e,f);
    }
    if (inject_read && n==SYS_read && result>0) ++read_seen;
    if (action==3) injected_last_close=result;
    log_raw(n,a,b,c,d,e,f,result,action); return result;
}
#define K(n,a,b,c,d,e,f) kernel((n),(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define H(n,a,b,c,d,e,f) hooked_raw((n),(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static void fatal(unsigned code,long detail) __attribute__((noreturn));
static void fatal(unsigned code,long detail) {
    fprintf(stderr,"UNEXPECTED_LIFECYCLE_FAIL %u %ld\n",code,detail); exit(125);
}
/* bridge.c's existing byte predicate, linked unchanged in meaning. This fixture
   never calls register_initial and never manufactures a bridge image. */
int equal(const void *a,const void *b,size_t n) { return !memcmp(a,b,n); }

struct map { uintptr_t first,end; unsigned prot; unsigned long offset,major,minor,inode; int private; };
static char observer_maps[256*1024];
static struct map baseline[2048];
static size_t baseline_count;
static size_t actual_maps(struct map *out,size_t capacity) {
    long fd=K(SYS_openat,AT_FDCWD,"/proc/self/maps",O_RDONLY|O_CLOEXEC,0,0,0);
    need(fd>=0,"observer maps open"); size_t used=0;
    for (;;) {
        need(used<sizeof(observer_maps)-1,"observer maps capacity");
        long got=K(SYS_read,fd,observer_maps+used,sizeof(observer_maps)-1-used,0,0,0);
        need(got>=0,"observer maps read"); if (!got) break; used+=(size_t)got;
    }
    need(!K(SYS_close,fd,0,0,0,0,0),"observer maps close"); observer_maps[used]=0;
    size_t count=0; char *line=observer_maps;
    while (*line) {
        char *end=strchr(line,'\n'); need(end!=0 && count<capacity,"observer maps row");
        *end=0; char permissions[5]={0}; struct map *m=&out[count++];
        unsigned long first,last;
        need(sscanf(line,"%lx-%lx %4s %lx %lx:%lx %lu",&first,&last,permissions,
                    &m->offset,&m->major,&m->minor,&m->inode)==7,"observer maps fields");
        m->first=first; m->end=last; m->private=permissions[3]=='p';
        m->prot=(permissions[0]=='r'?PROT_READ:0)|(permissions[1]=='w'?PROT_WRITE:0)|
                (permissions[2]=='x'?PROT_EXEC:0); line=end+1;
    }
    return count;
}
static struct map observed(uintptr_t address) {
    static struct map rows[2048]; size_t n=actual_maps(rows,2048);
    for (size_t i=0;i<n;i++) if (rows[i].first<=address && address<rows[i].end) return rows[i];
    return (struct map){0};
}
static int protected_range(uintptr_t first,size_t n) {
    if (!n || first>UINTPTR_MAX-n) return 1;
    for (size_t i=0;i<baseline_count;i++)
        if (first<baseline[i].end && baseline[i].first<first+n) return 1;
    return 0;
}
static const unsigned char instruction[15]={0x49,0xbc,1,2,3,4,5,6,7,8,0x90,0x90,0x90,0x90,0x90};
static unsigned char elf_bytes[3*PAGE];
static int sealed_elf(void) {
    memset(elf_bytes,0,sizeof(elf_bytes));
    Elf64_Ehdr *e=(void *)elf_bytes;
    memcpy(e->e_ident,ELFMAG,SELFMAG); e->e_ident[EI_CLASS]=ELFCLASS64;
    e->e_ident[EI_DATA]=ELFDATA2LSB; e->e_ident[EI_VERSION]=EV_CURRENT;
    e->e_type=ET_DYN; e->e_machine=EM_X86_64; e->e_version=EV_CURRENT;
    e->e_ehsize=sizeof(*e); e->e_phoff=sizeof(*e); e->e_phentsize=sizeof(Elf64_Phdr); e->e_phnum=2;
    Elf64_Phdr *p=(void *)(elf_bytes+sizeof(*e));
    p[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R,.p_filesz=PAGE,.p_memsz=PAGE,.p_align=PAGE};
    p[1]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_offset=PAGE,.p_vaddr=PAGE,
                     .p_filesz=2*PAGE,.p_memsz=2*PAGE,.p_align=PAGE};
    memcpy(elf_bytes+PAGE+32,instruction,15);
    memcpy(elf_bytes+2*PAGE-7,instruction,15);
    long fd=K(SYS_memfd_create,"li2-fetch-fixture",MFD_ALLOW_SEALING|MFD_CLOEXEC,0,0,0,0);
    need(fd>=0,"memfd create"); size_t written=0;
    while (written<sizeof(elf_bytes)) {
        long got=K(SYS_write,fd,elf_bytes+written,sizeof(elf_bytes)-written,0,0,0);
        need(got>0,"memfd write"); written+=(size_t)got;
    }
    need(!K(SYS_fcntl,fd,F_ADD_SEALS,SEALS,0,0,0),"memfd seals");
    need((K(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)&SEALS)==SEALS,"actual seals");
    return (int)fd;
}
static long dispatch(long n,long a,long b,long c,long d,long e,long f) {
    long args[6]={a,b,c,d,e,f},result=0;
    need(!li2_lifecycle_fetch_interlock(),"dispatch mutation interlock");
    need(li2_lifecycle_dispatch(n,args,&result)==1,"real lifecycle dispatch"); return result;
}
static unsigned char *mapping(int fd,int sealed,int two) {
    size_t size=two?2*PAGE:PAGE;
    long value=dispatch(SYS_mmap,0,size,sealed?(PROT_READ|PROT_EXEC):(PROT_READ|PROT_WRITE),
                        MAP_PRIVATE|(sealed?0:MAP_ANONYMOUS),sealed?fd:-1,sealed?PAGE:0);
    need(!error(value),"owned mmap"); unsigned char *p=(void *)value;
    if (!sealed) {
        memcpy(p+32,instruction,15); if (two) memcpy(p+PAGE-7,instruction,15);
        need(!dispatch(SYS_mprotect,value,size,PROT_READ|PROT_EXEC,0,0,0),"owned RW to RX");
    }
    need(observed((uintptr_t)p).prot==PROT_READ,"actual initial NX"); return p;
}
struct event { const char *name; int result; struct li2_fetch_progress p; };
static struct event events[MAX_EVENTS]; static size_t event_count;
static void event(const char *name,int result) {
    need(event_count<MAX_EVENTS,"event capacity");
    events[event_count++]=(struct event){name,result,*li2_lifecycle_fetch_progress()};
}
static void unchanged_progress(const struct li2_fetch_progress *old) {
    need(!memcmp(old,li2_lifecycle_fetch_progress(),sizeof(*old)),"refusal kept owner prefix exact");
}
static void source_view(const struct li2_fetch_ref *ref,uintptr_t pc,size_t pages,int sealed) {
    struct li2_fetch_view v; need(!li2_lifecycle_fetch_view(ref,&v),"complete view");
    need(v.pc==pc && v.length==15 && v.page_count==pages,"view shape");
    need(v.bytes!=(const void *)pc && !memcmp(v.bytes,instruction,15),"immutable copied source");
    need(v.identity_observed && v.pid==K(SYS_getpid,0,0,0,0,0,0) && v.tid==v.pid,"actual identity");
    for (size_t i=0;i<pages;i++) {
        const struct li2_fetch_page *p=&v.pages[i]; struct li2_lifecycle_page_view q;
        need(li2_lifecycle_query(p->address,&q),"actual owned header"); struct map m=observed(p->address);
        need(q.allocation==p->allocation && q.generation==p->generation && q.offset==p->offset &&
             q.backing==p->backing && q.logical==p->logical && q.actual==p->closed_prot && !q.admitted,
             "all public owner fields");
        need(p->address==(pc&~(PAGE-1))+i*PAGE && q.logical==(PROT_READ|PROT_EXEC) &&
             q.actual==PROT_READ && m.prot==PROT_READ && m.private,"closed page geometry");
        need(m.first==p->vma_first && m.end==p->vma_end && m.offset==p->vma_offset &&
             m.major==p->vma_major && m.minor==p->vma_minor && m.inode==p->vma_inode,"actual VMA fields");
        const struct li2_fetch_backing *b=&v.backing[i];
        if (sealed) {
            struct stat st; need(!K(SYS_fstat,b->retained_fd,&st,0,0,0,0),"actual retained fstat");
            need(b->seals_observed && b->stat_observed && !b->stat_result && (b->seals&SEALS)==SEALS,
                 "observed sealed backing");
            need(st.st_dev==b->stat.st_dev && st.st_ino==b->stat.st_ino && st.st_mode==b->stat.st_mode &&
                 st.st_size==b->stat.st_size && st.st_size==(off_t)(3*PAGE),"actual retained descriptor identity");
        } else need(b->retained_fd==-1 && !b->seals_observed && !b->stat_observed,"anonymous has no fake fd");
    }
}
static void owner_protect(uintptr_t page,int prot) {
    need(!H(SYS_mprotect,page,PAGE,prot,0,0,0),"actual sole owner protect");
    if (prot&PROT_EXEC) ++owner_opened; else ++owner_closed;
    need(!H(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0),"actual owner sync");
    ++owner_synced; need(observed(page).prot==(unsigned)prot,"independent actual permission");
}
static void sticky(const struct li2_fetch_ref *ref,int wanted) {
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    need(p->held && p->first_error==(unsigned)wanted && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,
         "sticky occupied first error"); struct li2_fetch_progress before=*p; size_t calls=raw_count;
    struct li2_fetch_view v;
    need(li2_lifecycle_fetch_view(ref,&v)==wanted && li2_lifecycle_fetch_validate(ref,0,PROT_READ)==wanted &&
         li2_lifecycle_fetch_release(ref)==wanted,"sticky error on every completing API");
    unchanged_progress(&before); need(calls==raw_count,"no later raw work after sticky failure");
}
struct child_record { long pid,tid,result; struct li2_fetch_progress progress; };
static struct child_record child;
static long waited;
static void copied_identity(struct li2_fetch_ref *ref) {
    int pipefd[2]; need(!K(SYS_pipe2,pipefd,O_CLOEXEC,0,0,0,0),"child evidence pipe");
    long pid=K(SYS_fork,0,0,0,0,0,0); need(pid>=0,"real fork identity control");
    if (!pid) {
        need(!K(SYS_close,pipefd[0],0,0,0,0,0),"child pipe close");
        child.pid=K(SYS_getpid,0,0,0,0,0,0); child.tid=K(SYS_gettid,0,0,0,0,0,0);
        child.result=li2_lifecycle_fetch_validate(ref,0,PROT_READ); child.progress=*li2_lifecycle_fetch_progress();
        need(child.result==LI2_FETCH_IDENTITY && child.progress.first_error==LI2_FETCH_IDENTITY,
             "copied borrow rejects actual different process");
        need(K(SYS_write,pipefd[1],&child,sizeof(child),0,0,0)==(long)sizeof(child),"child record write");
        K(SYS_exit_group,0,0,0,0,0,0); __builtin_unreachable();
    }
    need(!K(SYS_close,pipefd[1],0,0,0,0,0),"parent pipe close");
    need(K(SYS_read,pipefd[0],&child,sizeof(child),0,0,0)==(long)sizeof(child),"actual child record");
    need(!K(SYS_close,pipefd[0],0,0,0,0,0),"parent read close");
    int status=-1; waited=K(SYS_wait4,pid,&status,0,0,0,0);
    need(waited==pid && WIFEXITED(status) && WEXITSTATUS(status)==0 && child.pid==pid && child.tid==pid,
         "actual child wait and identity");
    need(!li2_lifecycle_fetch_release(ref),"original parent borrow remains valid"); event("parent_release",0);
}

static void print_maps_progress(const struct li2_fetch_map_progress *p) {
    printf("{\"fd\":%ld,\"read\":%ld,\"close\":%ld,\"bytes\":%zu,\"rows\":%zu,"
           "\"opened\":%u,\"close_started\":%u,\"closed\":%u}",p->fd,p->last_read,p->close_result,
           p->bytes,p->rows,p->opened,p->close_started,p->closed);
}
static void report(int expected) {
    struct li2_fetch_view v; li2_lifecycle_fetch_partial_view(&v);
    struct li2_lifecycle_counts counts; li2_lifecycle_snapshot(&counts);
    printf("{\"schema\":1,\"case\":\"%s\",\"expected_error\":%d,\"status\":\"passed\","
           "\"instruction_hex\":\"49bc01020304050607089090909090\","
           "\"owner_opened\":%u,\"owner_closed\":%u,\"owner_synced\":%u,\"interlock_denials\":%u,"
           "\"injected\":[%u,%u,%ld,%ld,%ld],\"child\":[%ld,%ld,%ld,%ld],\"lifecycle\":[%llu,%llu,%llu,%llu],\"events\":[",
           case_name,expected,owner_opened,owner_closed,owner_synced,interlock_denials,
           read_injected,close_injected,injected_read_result,injected_first_close,injected_last_close,
           child.pid,child.tid,child.result,waited,(unsigned long long)counts.mappings,
           (unsigned long long)counts.generations,(unsigned long long)counts.admissions,(unsigned long long)counts.live_pages);
    for (size_t i=0;i<event_count;i++) {
        const struct event *e=&events[i]; const struct li2_fetch_progress *p=&e->p;
        printf("%s{\"name\":\"%s\",\"result\":%d,\"held\":%u,\"complete\":%u,\"error\":%u,\"detail\":%ld,"
               "\"pages\":%zu,\"bytes\":%zu,\"sequence\":%llu,\"validations\":%llu,"
               "\"identity_observed\":%u,\"last_backing_page\":%zu,\"last_backing_observed\":%u,\"prepare\":",
               i?",":"",e->name,e->result,p->held,p->complete,p->first_error,p->first_detail,p->pages_copied,
               p->bytes_copied,(unsigned long long)p->sequence,(unsigned long long)p->validation_calls,
               p->identity_observed,p->last_backing_page,p->last_backing_observed);
        print_maps_progress(&p->preparation); printf(",\"validate\":"); print_maps_progress(&p->validation); printf("}");
    }
    printf("],\"partial_hex\":\""); for (size_t i=0;i<v.length;i++) printf("%02x",v.bytes[i]);
    printf("\",\"pages\":[");
    for (size_t i=0;i<v.page_count;i++) {
        const struct li2_fetch_page *p=&v.pages[i]; const struct li2_fetch_backing *b=&v.backing[i];
        printf("%s{\"address\":%lu,\"allocation\":%llu,\"generation\":%llu,\"offset\":%llu,\"initial_extent\":%llu,"
               "\"backing\":%u,\"object\":%u,\"logical\":%u,\"closed_prot\":%u,\"vma\":[%lu,%lu,%llu,%llu,%llu,%llu],"
               "\"fd\":%d,\"seals\":%ld,\"stat_result\":%ld,\"observed\":[%u,%u],\"stat\":[%llu,%llu,%llu,%llu]}",
               i?",":"",(unsigned long)p->address,(unsigned long long)p->allocation,(unsigned long long)p->generation,
               (unsigned long long)p->offset,(unsigned long long)p->initial_extent,p->backing,p->object,p->logical,p->closed_prot,
               (unsigned long)p->vma_first,(unsigned long)p->vma_end,(unsigned long long)p->vma_major,
               (unsigned long long)p->vma_minor,(unsigned long long)p->vma_inode,(unsigned long long)p->vma_offset,
               b->retained_fd,b->seals,b->stat_result,b->seals_observed,b->stat_observed,
               (unsigned long long)b->stat.st_dev,(unsigned long long)b->stat.st_ino,
               (unsigned long long)b->stat.st_mode,(unsigned long long)b->stat.st_size);
    }
    printf("],\"last_backing\":");
    if (v.last_backing) {
        const struct li2_fetch_backing *b=v.last_backing;
        printf("[%d,%ld,%ld,%u,%u,%llu,%llu,%llu,%llu]",b->retained_fd,b->seals,b->stat_result,
               b->seals_observed,b->stat_observed,(unsigned long long)b->stat.st_dev,
               (unsigned long long)b->stat.st_ino,(unsigned long long)b->stat.st_mode,(unsigned long long)b->stat.st_size);
    } else printf("null");
    printf(",\"child_prefix\":[%u,%u,%u,%ld,%zu,%zu,%llu,%llu],\"raw\":[",
           child.progress.held,child.progress.complete,child.progress.first_error,child.progress.first_detail,
           child.progress.pages_copied,child.progress.bytes_copied,(unsigned long long)child.progress.sequence,
           (unsigned long long)child.progress.validation_calls);
    for (size_t i=0;i<raw_count;i++) {
        const struct raw_record *r=&raw_log[i];
        printf("%s[%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%u]",i?",":"",r->n,r->a,r->b,r->c,r->d,r->e,r->f,r->result,r->action);
    }
    puts("]}");
}

int main(int argc,char **argv) {
    need(argc==2,"one exact case"); case_name=argv[1];
    baseline_count=actual_maps(baseline,2048);
    int fd=sealed_elf();
    const struct li2_lifecycle_hooks hooks={hooked_raw,fatal,protected_range};
    li2_lifecycle_initialize(&fd,1,&hooks);
    need(li2_lifecycle_enabled() && !li2_lifecycle_fetch_interlock(),"real initialized empty lifecycle");
    int sealed=!strncmp(case_name,"sealed_",7) || !strcmp(case_name,"wrong_mapping") ||
        !strcmp(case_name,"writable_alias") || !strcmp(case_name,"closed_backing") ||
        !strcmp(case_name,"second_missing") || !strcmp(case_name,"beyond_eof");
    int two=strstr(case_name,"_two")!=0 || !strcmp(case_name,"second_missing");
    unsigned char *base=mapping(fd,sealed,two);
    uintptr_t pc=(uintptr_t)(base+(two?PAGE-7:32));
    if (!strcmp(case_name,"second_missing")) need(!K(SYS_munmap,base+PAGE,PAGE,0,0,0,0),"actual missing second page");
    if (!strcmp(case_name,"beyond_eof")) {
        long value=dispatch(SYS_mmap,0,PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,3*PAGE);
        need(!error(value),"real wholly beyond EOF VMA"); pc=(uintptr_t)value;
    }
    if (!strcmp(case_name,"unowned")) {
        long value=K(SYS_mmap,0,PAGE,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        need(!error(value),"actual unowned mapping"); pc=(uintptr_t)value;
    }
    if (!strcmp(case_name,"read_fault") || !strcmp(case_name,"read_close_fault")) inject_read=1;
    if (!strcmp(case_name,"close_fault") || !strcmp(case_name,"read_close_fault")) inject_close=1;
    struct li2_fetch_ref ref={0}; int got=li2_lifecycle_fetch_prepare(pc,15,&ref); event("prepare",got);
    int expected=0;
    if (!strcmp(case_name,"second_missing")) expected=113;
    else if (!strcmp(case_name,"beyond_eof")) expected=LI2_FETCH_BACKING;
    else if (!strcmp(case_name,"unowned")) expected=LI2_FETCH_PAGE;
    else if (inject_read) expected=106;
    else if (inject_close) expected=107;
    if (expected) {
        need(got==expected,"exact preparation refusal"); sticky(&ref,expected);
        const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
        need(!p->complete && !p->bytes_copied,"no bytes before full authentication");
        if (!strcmp(case_name,"second_missing") || !strcmp(case_name,"beyond_eof")) need(p->pages_copied==1,"retained first page header");
        if (inject_read || inject_close) {
            need(p->preparation.opened && p->preparation.bytes>0 && p->preparation.close_started,
                 "actual opened read prefix and close attempt retained");
            need(p->preparation.closed==!inject_close && !p->preparation.rows,"failed map observation never parsed");
            if (inject_read) need(read_injected && injected_read_result==-EBADF && p->first_detail==-EBADF,"real bad-fd read priority");
            if (inject_close) need(close_injected && !injected_first_close && injected_last_close==-EBADF,"real close then bad-fd close");
        }
    } else {
        need(!got,"actual preparation success"); source_view(&ref,pc,two?2:1,sealed);
        struct li2_fetch_view v; need(!li2_lifecycle_fetch_view(&ref,&v),"initial complete borrow");
        if (!strcmp(case_name,"anon_one") || !strcmp(case_name,"anon_two") ||
            !strcmp(case_name,"sealed_one") || !strcmp(case_name,"sealed_two")) {
            for (size_t i=0;i<v.page_count;i++) {
                owner_protect(v.pages[i].address,PROT_READ|PROT_EXEC);
                got=li2_lifecycle_fetch_validate(&ref,i,PROT_READ|PROT_EXEC); event("validate_open",got); need(!got,"actual open validated");
                if (i+1<v.page_count) need(!li2_lifecycle_fetch_validate(&ref,i+1,PROT_READ),"mixed closed second page");
            }
            for (size_t i=0;i<v.page_count;i++) {
                owner_protect(v.pages[i].address,PROT_READ);
                got=li2_lifecycle_fetch_validate(&ref,i,PROT_READ); event("validate_closed",got); need(!got,"actual close validated");
            }
            source_view(&ref,pc,two?2:1,sealed);
            need(!li2_lifecycle_fetch_release(&ref),"closed release succeeds"); event("release",0);
            need(!li2_lifecycle_fetch_interlock() && owner_opened==v.page_count && owner_closed==v.page_count,
                 "sole owner prefix closed");
        } else if (!strcmp(case_name,"release_open")) {
            owner_protect(v.pages[0].address,PROT_READ|PROT_EXEC);
            need(!li2_lifecycle_fetch_validate(&ref,0,PROT_READ|PROT_EXEC),"open precedes release refusal");
            got=li2_lifecycle_fetch_release(&ref); event("release_open",got); expected=LI2_FETCH_PAGE;
            need(got==expected,"release refuses actual RX"); owner_protect(v.pages[0].address,PROT_READ);
            sticky(&ref,expected); event("closed_after_failure",expected);
        } else if (!strcmp(case_name,"stale_ref")) {
            struct li2_fetch_ref old=ref; need(!li2_lifecycle_fetch_release(&ref),"old release");
            need(li2_lifecycle_fetch_view(&old,&v)==LI2_FETCH_STALE,"released ref stale");
            need(!li2_lifecycle_fetch_prepare(pc,15,&ref) && old.sequence!=ref.sequence,"fresh actual sequence");
            struct li2_fetch_progress p=*li2_lifecycle_fetch_progress(); size_t n=raw_count;
            need(li2_lifecycle_fetch_view(&old,&v)==LI2_FETCH_STALE &&
                 li2_lifecycle_fetch_validate(&old,0,PROT_READ)==LI2_FETCH_STALE &&
                 li2_lifecycle_fetch_release(&old)==LI2_FETCH_STALE,"all stale operations refuse");
            unchanged_progress(&p); need(raw_count==n,"stale ref has no I/O");
            struct li2_fetch_ref wrong={0,ref.sequence};
            need(li2_lifecycle_fetch_view(&wrong,&v)==LI2_FETCH_STALE &&
                 li2_lifecycle_fetch_release(&wrong)==LI2_FETCH_STALE,"wrong opaque owner cannot complete");
            unchanged_progress(&p); need(raw_count==n,"wrong owner has no I/O");
            need(!li2_lifecycle_fetch_release(&ref),"new owner unaffected"); event("fresh_release",0);
        } else if (!strcmp(case_name,"occupied")) {
            struct li2_fetch_progress p=*li2_lifecycle_fetch_progress(); size_t n=raw_count; struct li2_fetch_ref next={0};
            need(li2_lifecycle_fetch_prepare(pc,15,&next)==LI2_FETCH_BUSY && !next.owner && !next.sequence,"occupied prepare refuses");
            /* This is the actual future controller boundary, not a call into a
               mutating legacy API while borrowed. No scalar grants execution. */
            need(li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,"pending mutation refused"); ++interlock_denials;
            unchanged_progress(&p); need(raw_count==n,"interlock prevents all raw effects");
            need(!li2_lifecycle_fetch_release(&ref),"interlock release"); event("release",0);
        } else if (!strcmp(case_name,"copied_identity")) {
            copied_identity(&ref);
        } else {
            if (!strcmp(case_name,"source_changed")) {
                need(!K(SYS_mprotect,base,PAGE,PROT_READ|PROT_WRITE,0,0,0),"real source write access");
                *(unsigned char *)pc^=1;
                need(!K(SYS_mprotect,base,PAGE,PROT_READ,0,0,0),"real source back to NX"); expected=LI2_FETCH_SOURCE;
            } else if (!strcmp(case_name,"wrong_mapping")) {
                int other=sealed_elf(); struct stat a,b;
                need(!K(SYS_fstat,fd,&a,0,0,0,0) && !K(SYS_fstat,other,&b,0,0,0,0) && a.st_ino!=b.st_ino,"distinct actual backing");
                need(K(SYS_mmap,base,PAGE,PROT_READ,MAP_PRIVATE|MAP_FIXED,other,PAGE)==(long)base,"actual wrong backing replacement"); expected=114;
            } else if (!strcmp(case_name,"writable_alias")) {
                need(!error(K(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,PAGE)),"actual writable private alias"); expected=119;
            } else if (!strcmp(case_name,"closed_backing")) {
                owner_protect(v.pages[0].address,PROT_READ|PROT_EXEC);
                need(v.backing[0].retained_fd>=0 && !K(SYS_close,v.backing[0].retained_fd,0,0,0,0,0),"actual held descriptor close"); expected=LI2_FETCH_BACKING;
            } else need(0,"unknown case");
            got=li2_lifecycle_fetch_validate(&ref,0,!strcmp(case_name,"closed_backing")?(PROT_READ|PROT_EXEC):PROT_READ);
            event("validate_refusal",got);
            need(got==expected,"exact post-preparation refusal");
            if (!strcmp(case_name,"closed_backing")) {
                struct li2_fetch_view failed; li2_lifecycle_fetch_partial_view(&failed);
                need(failed.last_backing && failed.last_backing->seals_observed &&
                     failed.last_backing->seals==-EBADF && !failed.last_backing->stat_observed &&
                     failed.last_backing->retained_fd==v.backing[0].retained_fd,"actual backing failure prefix");
                owner_protect(v.pages[0].address,PROT_READ);
                event("owner_closed_after_error",expected);
            }
            need(!memcmp(v.bytes,instruction,15),"retained immutable copy survived violation"); sticky(&ref,expected);
        }
    }
    report(expected); return 0;
}
