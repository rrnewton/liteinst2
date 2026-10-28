#define _GNU_SOURCE
#include "lifecycle_loader.h"
#include "bridge.h"
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/membarrier.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>

#define PAGE 4096UL
/* Lifetime records, not a growable cache: exhaustion refuses before effects. */
#define RECORDS 8192
#define MAP_ROWS 2048
#define MAP_BYTES (256UL*1024)
#define SEALS (F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)
enum backing { SEALED=1, ANONYMOUS=2 };
enum phase { IDLE, PREPARED, MATERIALIZING, ORIGINAL_RETURNED, RECONCILED, REVOKED, ADMISSION_PROTECTED, ADMITTED };
struct map_row {
    uintptr_t first,end;
    uint64_t offset,major,minor,inode;
    unsigned prot,private;
};
struct owned_page {
    uintptr_t address;
    uint64_t allocation,generation,offset,initial_extent;
    unsigned backing,object,logical,actual,live,admitted;
};
struct transaction {
    long number,args[6],result;
    uintptr_t first,end;
    uint64_t generation_before;
    unsigned phase,guard;
};
static struct li2_lifecycle_hooks hooks;
static struct owned_page records[RECORDS];
static struct map_row rows[MAP_ROWS];
static char maps_bytes[MAP_BYTES];
static size_t used,row_count;
static uint64_t allocation_id,generation;
static int active;
static unsigned fail_after_protect;
#define ELF_HEADERS 64
#define OBJECTS 34
struct load_segment { uint64_t address,offset,extent,file_extent; unsigned prot; };
struct object {
    int original_fd,retained_fd;
    struct stat stat;
    uint64_t major,minor,inode;
    Elf64_Phdr phdrs[ELF_HEADERS];
    struct load_segment segments[ELF_HEADERS];
    size_t segment_count;
    uint64_t loader_extent;
};
static struct object objects[OBJECTS];
static size_t object_count;
static struct transaction tx;
static struct li2_lifecycle_counts counts;
#define RAW(n,a,b,c,d,e,f) hooks.raw((n),(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define DIE(code,detail) hooks.fail((code),(detail))

static int kernel_error(long value) { return value<0 && value>=-4095; }
static uintptr_t rounded(size_t length) {
    if (!length || length>UINTPTR_MAX-(PAGE-1)) DIE(100,0);
    return (length+PAGE-1)&~(PAGE-1);
}
static int overlaps(uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d) { return a<d && c<b; }
static struct owned_page *current(uintptr_t address) {
    for (size_t i=used;i;i--) if (records[i-1].live && records[i-1].address==address) return &records[i-1];
    return 0;
}
static const struct map_row *mapping(uintptr_t address) {
    for (size_t i=0;i<row_count;i++) if (rows[i].first<=address && address<rows[i].end) return &rows[i];
    return 0;
}
/* The fallible cores retain the old predicates/codes. Legacy callers keep
   their fail-stop wrappers; a pending step receives an error instead of a
   recursive hooks.fail/cleanup call. Parsing owns only the existing scratch. */
struct check_error { unsigned code; long detail; };
static int check_error(struct check_error *e,unsigned code,long detail) {
    if (!e->code) { e->code=code; e->detail=detail; }
    return (int)e->code;
}
static int digit_checked(char c,unsigned base,uint64_t *out,struct check_error *e) {
    unsigned d=c>='0' && c<='9' ? (unsigned)(c-'0') : c>='a' && c<='f' ? (unsigned)(c-'a'+10) : 16;
    if (d>=base) return check_error(e,101,c);
    *out=d; return 0;
}
static int number_checked(size_t *at,size_t end,unsigned base,char separator,
                          uint64_t *out,struct check_error *e) {
    uint64_t value=0; size_t start=*at;
    while (*at<end && maps_bytes[*at]!=separator) {
        uint64_t d; int error=digit_checked(maps_bytes[(*at)++],base,&d,e);
        if (error) return error;
        if (value>(UINT64_MAX-d)/base) return check_error(e,102,0);
        value=value*base+d;
    }
    if (*at==start || *at==end) return check_error(e,103,0);
    ++*at; *out=value; return 0;
}
static void spaces(size_t *at,size_t end) {
    while (*at<end && maps_bytes[*at]==' ') ++*at;
}
#ifdef LI2_MAPS_PHASE_REUSE
#define read_maps_checked read_maps_fresh
#endif
static int read_maps_checked(struct check_error *e,struct li2_fetch_map_progress *p) {
    *p=(struct li2_fetch_map_progress){.fd=-1};
    const char path[]="/proc/self/maps";
    long fd=RAW(SYS_openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0,0,0);
    if (fd<0) return check_error(e,104,fd);
    p->fd=fd; p->opened=1;
    size_t length=0;
    for (;;) {
        if (length==MAP_BYTES) { check_error(e,105,0); break; }
        long got=RAW(SYS_read,fd,maps_bytes+length,MAP_BYTES-length,0,0,0);
        p->last_read=got;
        if (got<0) { check_error(e,106,got); break; }
        if (!got) break;
        length+=(size_t)got; p->bytes=length;
    }
    p->close_started=1;
    p->close_result=RAW(SYS_close,fd,0,0,0,0,0);
    if (!p->close_result) p->closed=1;
    else check_error(e,107,p->close_result);
    if (e->code) return (int)e->code;
    row_count=0; size_t at=0;
    while (at<length) {
        size_t end=at;
        while (end<length && maps_bytes[end]!='\n') ++end;
        if (end==length || row_count==MAP_ROWS) return check_error(e,108,0);
        struct map_row *r=&rows[row_count++];
        uint64_t first,last; int error;
        if ((error=number_checked(&at,end,16,'-',&first,e)) ||
            (error=number_checked(&at,end,16,' ',&last,e))) return error;
        r->first=(uintptr_t)first; r->end=(uintptr_t)last;
        if (r->first>=r->end || (r->first|r->end)&(PAGE-1) || end-at<5) return check_error(e,109,0);
        if ((maps_bytes[at]!='r' && maps_bytes[at]!='-') ||
            (maps_bytes[at+1]!='w' && maps_bytes[at+1]!='-') ||
            (maps_bytes[at+2]!='x' && maps_bytes[at+2]!='-') ||
            (maps_bytes[at+3]!='p' && maps_bytes[at+3]!='s') || maps_bytes[at+4]!=' ') return check_error(e,110,0);
        r->prot=(maps_bytes[at]=='r'?PROT_READ:0)|(maps_bytes[at+1]=='w'?PROT_WRITE:0)|(maps_bytes[at+2]=='x'?PROT_EXEC:0);
        r->private=maps_bytes[at+3]=='p'; at+=5; spaces(&at,end);
        if ((error=number_checked(&at,end,16,' ',&r->offset,e))) return error;
        spaces(&at,end);
        if ((error=number_checked(&at,end,16,':',&r->major,e)) ||
            (error=number_checked(&at,end,16,' ',&r->minor,e))) return error;
        spaces(&at,end);
        /* inode may be the final field, with no pathname */
        r->inode=0; size_t start=at;
        while (at<end && maps_bytes[at]!=' ') {
            uint64_t d;
            if ((error=digit_checked(maps_bytes[at++],10,&d,e))) return error;
            if (r->inode>(UINT64_MAX-d)/10) return check_error(e,111,0);
            r->inode=r->inode*10+d;
        }
        if (at==start || (row_count>1 && rows[row_count-2].end>r->first)) return check_error(e,112,0);
        at=end+1; p->rows=row_count;
    }
    return 0;
}
#ifdef LI2_MAPS_PHASE_REUSE
#undef read_maps_checked
#include "maps_phase.inc"
#endif
static void read_maps(void) {
    struct check_error error={0}; struct li2_fetch_map_progress progress;
    if (read_maps_checked(&error,&progress)) DIE(error.code,error.detail);
}
static int sealed_row(unsigned object,const struct map_row *r) {
    const struct object *o=&objects[object];
    return r->major==o->major && r->minor==o->minor && r->inode==o->inode;
}
static int same_fd(long fd) {
    struct stat st;
    long got=RAW(SYS_fstat,fd,&st,0,0,0,0);
    if (got) return -1;
    for (size_t i=0;i<object_count;i++) if (st.st_dev==objects[i].stat.st_dev && st.st_ino==objects[i].stat.st_ino && st.st_size==objects[i].stat.st_size) return (int)i;
    return -1;
}
static void load_geometry(struct object *o) {
    Elf64_Ehdr elf;
    long got=RAW(SYS_pread64,o->retained_fd,&elf,sizeof(elf),0,0,0);
    if (got!=(long)sizeof(elf) || elf.e_ident[EI_MAG0]!=ELFMAG0 || elf.e_ident[EI_MAG1]!=ELFMAG1 ||
        elf.e_ident[EI_MAG2]!=ELFMAG2 || elf.e_ident[EI_MAG3]!=ELFMAG3 ||
        elf.e_ident[EI_CLASS]!=ELFCLASS64 || elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
        elf.e_ident[EI_VERSION]!=EV_CURRENT || elf.e_version!=EV_CURRENT || elf.e_type!=ET_DYN ||
        elf.e_machine!=EM_X86_64 || elf.e_ehsize!=sizeof(elf) || elf.e_phentsize!=sizeof(Elf64_Phdr) ||
        !elf.e_phnum || elf.e_phnum>ELF_HEADERS) DIE(171,got);
    size_t bytes=elf.e_phnum*sizeof(Elf64_Phdr);
    if (elf.e_phoff>(uint64_t)o->stat.st_size || bytes>(uint64_t)o->stat.st_size-elf.e_phoff) DIE(172,0);
    got=RAW(SYS_pread64,o->retained_fd,o->phdrs,bytes,elf.e_phoff,0,0);
    if (got!=(long)bytes) DIE(173,got);
    for (size_t i=0;i<elf.e_phnum;i++) {
        const Elf64_Phdr *p=&o->phdrs[i];
        if (p->p_type==PT_GNU_STACK && (p->p_flags&PF_X)) DIE(174,0);
        if (p->p_type!=PT_LOAD) continue;
        /* Actual ld.so supplies TLS/zero-fill semantics. Retain both exact file
           and memory extents; only that PT_LOAD BSS tail can replace anonymously. */
        if (!p->p_filesz || p->p_filesz>p->p_memsz || p->p_align!=PAGE ||
            (p->p_offset&(PAGE-1))!=(p->p_vaddr&(PAGE-1)) || p->p_offset>(uint64_t)o->stat.st_size ||
            p->p_filesz>(uint64_t)o->stat.st_size-p->p_offset || p->p_memsz>UINT64_MAX-(PAGE-1) ||
            p->p_vaddr>UINT64_MAX-p->p_memsz-(PAGE-1) ||
            (p->p_flags&~(PF_R|PF_W|PF_X))) DIE(175,0);
        struct load_segment *r=&o->segments[o->segment_count++];
        r->address=p->p_vaddr&~(PAGE-1); r->offset=p->p_offset&~(PAGE-1);
        uint64_t end=(p->p_vaddr+p->p_memsz+PAGE-1)&~(PAGE-1); r->extent=end-r->address;
        r->file_extent=((p->p_vaddr+p->p_filesz+PAGE-1)&~(PAGE-1))-r->address;
        r->prot=(p->p_flags&PF_R?PROT_READ:0)|(p->p_flags&PF_W?PROT_WRITE:0)|(p->p_flags&PF_X?PROT_EXEC:0);
        if ((r->prot&PROT_EXEC) && (r->prot&(PROT_READ|PROT_WRITE))!=PROT_READ) DIE(176,0);
        if (o->segment_count==1 && (r->address || r->offset || r->prot!=PROT_READ)) DIE(177,0);
        if (o->segment_count>1 && r->address<o->loader_extent) DIE(178,0);
        o->loader_extent=end;
    }
    if (!o->segment_count || o->loader_extent/PAGE>RECORDS) DIE(179,0);
}
static int loader_replacement(unsigned object,uint64_t allocation,uintptr_t first,size_t extent,uint64_t offset,unsigned prot,int anonymous) {
    const struct object *o=&objects[object];
    for (size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];
        if (p->allocation!=allocation || p->object!=object || p->initial_extent!=o->loader_extent || p->offset || p->backing!=SEALED) continue;
        for (size_t j=0;j<o->segment_count;j++) {
            const struct load_segment *r=&o->segments[j];
            uint64_t displacement=r->address+(anonymous?r->file_extent:0);
            size_t expected=anonymous?r->extent-r->file_extent:r->file_extent;
            if (expected && p->address<=UINTPTR_MAX-displacement && first==p->address+displacement &&
                extent==expected && offset==(anonymous?0:r->offset) && prot==r->prot) return 1;
        }
    }
    return 0;
}
static int verify_page_checked(const struct owned_page *p,const struct map_row *r,struct check_error *e) {
    if (!r || !r->private || r->end-p->address<PAGE) return check_error(e,113,0);
    if (p->backing==SEALED) {
        if (!sealed_row(p->object,r) || r->offset>UINT64_MAX-(p->address-r->first) ||
            r->offset+(p->address-r->first)!=p->offset) return check_error(e,114,0);
    } else if (p->backing==ANONYMOUS) {
        if (r->inode || r->major || r->minor) return check_error(e,115,0);
    } else return check_error(e,116,0);
    return 0;
}
static void verify_page(const struct owned_page *p,const struct map_row *r) {
    struct check_error error={0};
    if (verify_page_checked(p,r,&error)) DIE(error.code,error.detail);
}
static int alias_segment_checked(const struct map_row *r,uintptr_t first,uintptr_t end,
                                 uint64_t offset,size_t bytes,unsigned prot,struct check_error *e) {
    if (first>=end) return 0;
    uint64_t displacement=first-r->first;
    if (r->offset>UINT64_MAX-displacement) return check_error(e,118,0);
    uint64_t begin=r->offset+displacement;
    if (begin>UINT64_MAX-(end-first)) return check_error(e,118,0);
    if (offset<begin+(end-first) && begin<offset+bytes &&
        (((prot&PROT_EXEC) && (r->prot&PROT_WRITE)) ||
         ((prot&PROT_WRITE) && (r->prot&PROT_EXEC)))) return check_error(e,119,0);
    return 0;
}
static int alias_check_checked(unsigned object,uint64_t offset,size_t bytes,unsigned prot,
                               uintptr_t except_first,uintptr_t except_end,struct check_error *e) {
    if (offset>UINT64_MAX-bytes) return check_error(e,117,0);
    for (size_t i=0;i<row_count;i++) {
        const struct map_row *r=&rows[i]; int error;
        if (!sealed_row(object,r)) continue;
        if (except_first>=except_end || !overlaps(r->first,r->end,except_first,except_end)) {
            if ((error=alias_segment_checked(r,r->first,r->end,offset,bytes,prot,e))) return error;
        } else {
            /* Exclude only the affected address slice. A larger/coalesced row
               does not turn this mapping's own target page into an alias. */
            if (r->first<except_first &&
                (error=alias_segment_checked(r,r->first,except_first,offset,bytes,prot,e))) return error;
            if (except_end<r->end &&
                (error=alias_segment_checked(r,except_end,r->end,offset,bytes,prot,e))) return error;
        }
    }
    if (prot&PROT_WRITE) for (size_t j=0;j<used;j++) {
        const struct owned_page *p=&records[j];
        if (!p->live || p->backing!=SEALED || p->object!=object || !(p->logical&PROT_EXEC) ||
            (p->address>=except_first && p->address<except_end)) continue;
        if (p->offset>UINT64_MAX-PAGE) return check_error(e,118,0);
        if (offset<p->offset+PAGE && p->offset<offset+bytes) return check_error(e,119,0);
    }
    return 0;
}
static void alias_check(unsigned object,uint64_t offset,size_t bytes,unsigned prot,uintptr_t except_first,uintptr_t except_end) {
    struct check_error error={0};
    if (alias_check_checked(object,offset,bytes,prot,except_first,except_end,&error)) DIE(error.code,error.detail);
}
static void retire(struct owned_page *p) {
    p->live=0; ++counts.retired; --counts.live_pages;
}
static void append(uintptr_t address,uint64_t allocation,uint64_t offset,unsigned backing,unsigned object,unsigned logical,unsigned actual) {
    if (used==RECORDS || generation==UINT64_MAX) DIE(120,0);
    struct owned_page *p=&records[used++];
    p->address=address; p->allocation=allocation; p->generation=++generation; p->offset=offset;
    p->initial_extent=0; p->backing=backing; p->object=object; p->logical=logical; p->actual=actual; p->live=1; p->admitted=0;
    ++counts.generations; ++counts.live_pages; counts.retained_records=used;
}
static void reserve_records(size_t pages) {
    if (pages>RECORDS-used) DIE(121,pages);
}
static void begin(long n,const long a[6],uintptr_t first,uintptr_t end) {
    tx.number=n; for (unsigned i=0;i<6;i++) tx.args[i]=a[i];
    tx.result=0; tx.first=first; tx.end=end; tx.generation_before=generation; tx.phase=PREPARED; tx.guard=0;
    ++counts.transactions;
}
static void returned(long result) { tx.result=result; tx.phase=ORIGINAL_RETURNED; if (kernel_error(result)) ++counts.kernel_errors; }
static void finish(void) {
    counts.last_syscall=tx.number<0 ? 0 : (uint64_t)tx.number;
    counts.last_operation=tx.number<0 ? 2 : 1;
    counts.last_result_abs=tx.result<0 ? 0ULL-(uint64_t)tx.result : (uint64_t)tx.result;
    counts.last_result_negative=tx.result<0; counts.last_phase=tx.phase; tx.guard=0;
}
void li2_lifecycle_abort(void) {
    if (!active || !tx.guard) return;
    /* Fatal paths never return to application code. Revoke every mapped page,
       including fragments after holes, rather than one partial-range mprotect. */
    for (uintptr_t p=tx.first;p<tx.end;p+=PAGE) (void)RAW(SYS_mprotect,p,PAGE,PROT_NONE,0,0,0);
    finish();
}
void li2_lifecycle_fault_control(unsigned enabled) { fail_after_protect=enabled; }
int li2_lifecycle_enabled(void) { return active; }
int li2_lifecycle_query(uintptr_t address,struct li2_lifecycle_page_view *out) {
    if (!active) return 0;
    struct owned_page *p=current(address&~(PAGE-1));
    if (!p) return 0;
    out->allocation=p->allocation; out->generation=p->generation; out->offset=p->offset;
    out->backing=p->backing; out->logical=p->logical; out->actual=p->actual; out->admitted=p->admitted;
    return 1;
}
void li2_lifecycle_snapshot(struct li2_lifecycle_counts *out) {
    *out=counts;
    if (tx.guard) {
        out->last_syscall=tx.number<0 ? 0 : (uint64_t)tx.number; out->last_operation=tx.number<0 ? 2 : 1; out->last_result_abs=tx.result<0?0ULL-(uint64_t)tx.result:(uint64_t)tx.result;
        out->last_result_negative=tx.result<0; out->last_phase=tx.phase;
    }
}

void li2_lifecycle_initialize(const int *fds,size_t n,const struct li2_lifecycle_hooks *supplied) {
    hooks=*supplied;
    if (active || !n || n>32) DIE(183,n);
    for (size_t index=0;index<n;index++) {
        struct object *o=&objects[index]; o->original_fd=fds[index];
        long fd=RAW(SYS_fcntl,fds[index],F_DUPFD_CLOEXEC,200,0,0,0);
        if (fd<0) DIE(122,fd);
        o->retained_fd=(int)fd;
        long seals=RAW(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);
        if (seals<0 || (seals&SEALS)!=SEALS || RAW(SYS_fstat,fd,&o->stat,0,0,0,0) ||
            (o->stat.st_mode&S_IFMT)!=S_IFREG || o->stat.st_size<(off_t)PAGE) DIE(123,seals);
        for (size_t j=0;j<index;j++) if (objects[j].stat.st_dev==o->stat.st_dev && objects[j].stat.st_ino==o->stat.st_ino) DIE(184,index);
        load_geometry(o);
        long projection=RAW(SYS_mmap,0,PAGE,PROT_NONE,MAP_PRIVATE,fd,0);
        if (kernel_error(projection)) DIE(124,projection);
        read_maps(); const struct map_row *r=mapping((uintptr_t)projection);
        if (!r || r->first!=(uintptr_t)projection || r->end!=(uintptr_t)projection+PAGE ||
            r->prot || !r->private || r->offset || !r->inode) DIE(125,0);
        o->major=r->major; o->minor=r->minor; o->inode=r->inode;
        for (size_t j=0;j<row_count;j++) if (sealed_row((unsigned)index,&rows[j]) && (rows[j].prot&PROT_WRITE)) DIE(126,index);
        if (RAW(SYS_munmap,projection,PAGE,0,0,0,0)) DIE(127,0);
        read_maps(); if (mapping((uintptr_t)projection)) DIE(128,0);
        object_count=index+1;
    }
    long supported=RAW(SYS_membarrier,MEMBARRIER_CMD_QUERY,0,0,0,0,0);
    if (supported<0 || !(supported&MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) ||
        !(supported&MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)) DIE(129,supported);
    long registered=RAW(SYS_membarrier,MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    if (registered) DIE(130,registered);
    active=1; counts.enabled=1;
}

void li2_lifecycle_register_initial(const struct image *image) {
    if (!active || object_count==OBJECTS || !image || !image->source || image->backing_fd<0 ||
        (image->kind!=IMAGE_MAIN && image->kind!=IMAGE_INTERPRETER)) DIE(185,0);
    unsigned object=(unsigned)object_count; struct object *o=&objects[object];
    o->original_fd=image->backing_fd;
    long fd=RAW(SYS_fcntl,image->backing_fd,F_DUPFD_CLOEXEC,200,0,0,0);
    if (fd<0) DIE(122,fd);
    o->retained_fd=(int)fd;
    long seals=RAW(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);
    if (seals<0 || (seals&SEALS)!=SEALS || RAW(SYS_fstat,fd,&o->stat,0,0,0,0) ||
        (o->stat.st_mode&S_IFMT)!=S_IFREG) DIE(123,seals);
    long projection=RAW(SYS_mmap,0,PAGE,PROT_NONE,MAP_PRIVATE,fd,0);
    if (kernel_error(projection)) DIE(124,projection);
    read_maps(); const struct map_row *r=mapping((uintptr_t)projection);
    if (!r || r->first!=(uintptr_t)projection || r->end!=(uintptr_t)projection+PAGE ||
        r->prot || !r->private || r->offset || !r->inode) DIE(125,0);
    o->major=r->major; o->minor=r->minor; o->inode=r->inode;
    if (RAW(SYS_munmap,projection,PAGE,0,0,0,0)) DIE(127,0);
    ++object_count; read_maps();
    if (mapping((uintptr_t)projection)) DIE(128,0);
    if (allocation_id==UINT64_MAX) DIE(148,0);
    uint64_t allocation=++allocation_id;
    for (size_t i=0;i<image->n;i++) {
        const Elf64_Phdr *p=&image->ph[i];
        if (p->p_type!=PT_LOAD || !(p->p_flags&PF_X) || !p->p_memsz) continue;
        if ((p->p_flags&(PF_R|PF_W))!=PF_R || p->p_memsz!=p->p_filesz ||
            p->p_offset>image->source_size || p->p_filesz>image->source_size-p->p_offset ||
            image->bias>UINTPTR_MAX-p->p_vaddr || p->p_vaddr+p->p_memsz>UINTPTR_MAX-image->bias-(PAGE-1)) DIE(186,0);
        uintptr_t first=image->bias+(p->p_vaddr&~(PAGE-1));
        uintptr_t end=(image->bias+p->p_vaddr+p->p_memsz+PAGE-1)&~(PAGE-1);
        reserve_records((end-first)/PAGE);
        for (uintptr_t a=first;a<end;a+=PAGE) {
            if (current(a)) DIE(187,0);
            append(a,allocation,(p->p_offset&~(PAGE-1))+a-first,SEALED,object,PROT_READ|PROT_EXEC,PROT_READ);
            const struct owned_page *owned=current(a); r=mapping(a); verify_page(owned,r);
            if (r->prot!=PROT_READ) DIE(188,0);
            alias_check(object,owned->offset,PAGE,PROT_READ|PROT_EXEC,a,a+PAGE);
        }
        if (!equal((const void *)(image->bias+p->p_vaddr),image->source+p->p_offset,p->p_filesz)) DIE(189,0);
    }
}

int li2_lifecycle_known_code(uintptr_t first,size_t bytes) {
    if (!active || !bytes || first>UINTPTR_MAX-bytes) return 0;
    uintptr_t end=first+bytes;
    for (uintptr_t page=first&~(PAGE-1);page<end;page+=PAGE) {
        struct owned_page *p=current(page);
        if (!p || !(p->logical&PROT_EXEC)) return 0;
    }
    return 1;
}
int li2_lifecycle_admit(uintptr_t pc,uintptr_t fault_address) {
    if (!active || !li2_lifecycle_known_code(pc,1) || fault_address<pc || fault_address-pc>14) return 0;
    uintptr_t address=fault_address&~(PAGE-1);
    struct owned_page *p=current(address);
    if (!p || !(p->logical&PROT_EXEC) || p->admitted || (p->logical&PROT_WRITE)) DIE(131,0);
    read_maps(); const struct map_row *r=mapping(address); verify_page(p,r);
    if (r->prot!=(p->logical&~PROT_EXEC) || p->actual!=r->prot) DIE(132,0);
    if (p->backing==SEALED) alias_check(p->object,p->offset,PAGE,p->logical,address,address+PAGE);
    const long admission[6]={(long)address,PAGE,(long)p->logical,0,0,0};
    begin(-1,admission,address,address+PAGE); tx.guard=1;
    long result=RAW(SYS_mprotect,address,PAGE,p->logical,0,0,0);
    tx.result=result;
    if (result) DIE(133,result);
    tx.phase=ADMISSION_PROTECTED;
    result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    if (result) DIE(134,result);
    ++counts.sync_core; p->actual=p->logical; p->admitted=1; ++counts.admissions;
    tx.phase=ADMITTED; finish();
    return 1;
}
static void prot_check(long prot) {
    if (prot&~(PROT_READ|PROT_WRITE|PROT_EXEC)) DIE(135,prot);
    if ((prot&PROT_EXEC) && ((prot&(PROT_READ|PROT_WRITE))!=PROT_READ)) DIE(136,prot);
}
static void materialize(void) {
    tx.guard=1; tx.phase=MATERIALIZING;
    for (uintptr_t a=tx.first;a<tx.end;a+=PAGE) {
        struct owned_page *p=current(a);
        if (!p || !(p->logical&PROT_EXEC) || p->admitted) continue;
        long result=RAW(SYS_mprotect,a,PAGE,p->logical,0,0,0);
        if (result) DIE(137,result);
        ++counts.materialized;
        /* Do not mutate logical/admission metadata before original syscall. */
    }
}
static void reconcile_protection(void) {
    read_maps(); unsigned changed=0;
    for (uintptr_t a=tx.first;a<tx.end;a+=PAGE) {
        struct owned_page *p=current(a);
        const struct map_row *r=mapping(a);
        if (!p) { if (r && (r->prot&PROT_EXEC)) DIE(138,0); continue; }
        if (!r) { retire(p); ++changed; continue; }
        verify_page(p,r); prot_check(r->prot);
        if (r->prot!=p->logical || (r->prot&PROT_EXEC)) {
            uint64_t allocation=p->allocation,offset=p->offset; unsigned backing=p->backing,object=p->object;
            if (r->prot!=p->logical) ++changed;
            retire(p); append(a,allocation,offset,backing,object,r->prot,r->prot);
        } else p->actual=r->prot;
    }
    ++counts.reconciliations; tx.phase=RECONCILED;
    if (kernel_error(tx.result) && changed) ++counts.partial_errors;
    /* Preflight excluded the entire proposed transaction. An errno may leave
       same-offset pages on opposite sides of a hole in different permissions.
       Recheck actual post-state, excluding only the executable page itself. */
    for (uintptr_t a=tx.first;a<tx.end;a+=PAGE) {
        struct owned_page *p=current(a);
        if (p && p->backing==SEALED && (p->logical&PROT_EXEC))
            alias_check(p->object,p->offset,PAGE,p->logical,a,a+PAGE);
    }
    for (uintptr_t a=tx.first;a<tx.end;a+=PAGE) {
        struct owned_page *p=current(a);
        if (!p || !(p->logical&PROT_EXEC)) continue;
        long result=RAW(SYS_mprotect,a,PAGE,p->logical&~PROT_EXEC,0,0,0);
        if (result) DIE(139,result);
        p->actual=p->logical&~PROT_EXEC; p->admitted=0;
    }
    tx.phase=REVOKED;
}
static long no_effect_call(long n,const long a[6]) {
    begin(n,a,0,0);
    long result=RAW(n,a[0],a[1],a[2],a[3],a[4],a[5]); returned(result);
    /* Callers prove these precise invalid/no-length cases cannot mutate a VMA. */
    if (n==SYS_mmap && !kernel_error(result)) DIE(165,0);
    tx.phase=REVOKED; finish(); return result;
}
static long map_call(const long a[6]) {
    size_t length=(size_t)a[1]; unsigned prot=(unsigned)a[2],flags=(unsigned)a[3];
    prot_check(a[2]);
    const unsigned allowed=MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE|MAP_DENYWRITE|MAP_EXECUTABLE|MAP_NORESERVE|MAP_STACK;
    if ((flags&~allowed) || (flags&MAP_TYPE)!=MAP_PRIVATE || ((flags&MAP_FIXED)&&(flags&MAP_FIXED_NOREPLACE))) DIE(140,flags);
    if (!length) return no_effect_call(SYS_mmap,a);
    size_t extent=rounded(length);
    if (extent/PAGE>RECORDS || (uint64_t)a[5]>UINT64_MAX-extent) DIE(141,0);
    int anonymous=(flags&MAP_ANONYMOUS)!=0, selected=anonymous?-1:same_fd(a[4]),sealed=selected>=0;
    unsigned object=sealed?(unsigned)selected:OBJECTS;
    if ((prot&PROT_EXEC) && !anonymous && !sealed) DIE(142,0);
    if (anonymous && a[5]!=0) DIE(143,0);
    if ((uint64_t)a[5]&(PAGE-1)) return no_effect_call(SYS_mmap,a);
    read_maps();
    uintptr_t first=(uintptr_t)a[0],end=0; uint64_t allocation=0;
    if (flags&(MAP_FIXED|MAP_FIXED_NOREPLACE)) {
        if (first&(PAGE-1)) return no_effect_call(SYS_mmap,a);
        if (first>UINTPTR_MAX-extent || hooks.protected_range(first,extent)) DIE(144,0);
        end=first+extent;
        if (flags&MAP_FIXED) {
            /* Loader replacement is restricted to the same retained file and
               exact offset relation inside its original reservation. */
            if (!sealed && !anonymous) DIE(145,0);
            for (uintptr_t p=first;p<end;p+=PAGE) {
                struct owned_page *old=current(p);
                if (!old || old->object>=object_count) DIE(146,0);
                if (!allocation) { allocation=old->allocation; if (anonymous) object=old->object; }
                if (allocation!=old->allocation || object!=old->object) DIE(147,0);
                verify_page(old,mapping(p));
            }
            if (!loader_replacement(object,allocation,first,extent,(uint64_t)a[5],prot,anonymous)) DIE(180,0);
        }
    }
    if (sealed) alias_check(object,(uint64_t)a[5],extent,prot,(flags&MAP_FIXED)?first:0,(flags&MAP_FIXED)?end:0);
    if (sealed || anonymous) reserve_records(extent/PAGE);
    if (!allocation && allocation_id==UINT64_MAX) DIE(148,0);
    begin(SYS_mmap,a,first,end);
    /* For MAP_FIXED, a failure may have removed old mappings: reconcile below
       on both outcomes, with the original result retained independently. */
    if (flags&MAP_FIXED) materialize();
    long result=RAW(SYS_mmap,a[0],a[1],a[2],a[3],a[4],a[5]); returned(result);
    if (kernel_error(result)) {
        if (flags&MAP_FIXED) reconcile_protection();
        finish(); return result;
    }
    first=(uintptr_t)result;
    if ((first&(PAGE-1)) || first>UINTPTR_MAX-extent || hooks.protected_range(first,extent)) DIE(149,0);
    end=first+extent; tx.first=first; tx.end=end; tx.guard=1;
    if ((flags&(MAP_FIXED|MAP_FIXED_NOREPLACE)) && first!=(uintptr_t)a[0]) DIE(150,0);
    read_maps();
    if (!allocation) allocation=++allocation_id;
    for (uintptr_t p=first;p<end;p+=PAGE) {
        struct owned_page *old=current(p);
        if (old) {
            if (!(flags&MAP_FIXED)) DIE(151,0);
            retire(old);
        }
        const struct map_row *r=mapping(p);
        if (!r || r->prot!=prot || !r->private) DIE(152,0);
        if (anonymous || sealed) {
            append(p,allocation,(uint64_t)a[5]+p-first,anonymous?ANONYMOUS:SEALED,object,prot,prot);
            verify_page(current(p),r);
            if (p==first && !(flags&MAP_FIXED) && sealed && !a[5] && extent==objects[object].loader_extent && prot==PROT_READ)
                current(p)->initial_extent=extent;
        } else if (prot&PROT_EXEC) DIE(153,0);
    }
    ++counts.mappings; ++counts.reconciliations; tx.phase=RECONCILED;
    if (prot&PROT_EXEC) {
        long revoked=RAW(SYS_mprotect,first,extent,prot&~PROT_EXEC,0,0,0);
        if (revoked) DIE(154,revoked);
        for (uintptr_t p=first;p<end;p+=PAGE) current(p)->actual=prot&~PROT_EXEC;
    }
    tx.phase=REVOKED; finish(); return result;
}
static long protect_call(const long a[6]) {
    prot_check(a[2]);
    /* These malformed requests have no effect in the kernel, and preserve its
       genuine error (or zero-length success), rather than synthesizing one. */
    if (((uintptr_t)a[0]&(PAGE-1)) || !a[1]) return no_effect_call(SYS_mprotect,a);
    size_t extent=rounded((size_t)a[1]); uintptr_t first=(uintptr_t)a[0];
    if (extent/PAGE>RECORDS || first>UINTPTR_MAX-extent || hooks.protected_range(first,extent)) DIE(155,0);
    uintptr_t end=first+extent; read_maps(); size_t owners=0;
    for (uintptr_t p=first;p<end;p+=PAGE) {
        struct owned_page *old=current(p); const struct map_row *r=mapping(p);
        if (old) { verify_page(old,r); if (r->prot!=old->actual) DIE(156,0); ++owners; }
        /* Holes are accepted so genuine ENOMEM/partial-error semantics remain
           observable. Existing unknown mappings cannot acquire execution. */
        if (r && !old && (a[2]&PROT_EXEC)) DIE(157,0);
        if (old && old->backing==SEALED)
            alias_check(old->object,old->offset,PAGE,(unsigned)a[2],first,end);
    }
    reserve_records(owners); begin(SYS_mprotect,a,first,end);
    materialize();
    long result=RAW(SYS_mprotect,a[0],a[1],a[2],a[3],a[4],a[5]); returned(result);
    if (fail_after_protect && !result) DIE(170,0);
    reconcile_protection(); finish(); return result;
}
static long unmap_call(const long a[6]) {
    if (((uintptr_t)a[0]&(PAGE-1)) || !a[1]) return no_effect_call(SYS_munmap,a);
    size_t extent=rounded((size_t)a[1]); uintptr_t first=(uintptr_t)a[0];
    if (extent/PAGE>RECORDS || first>UINTPTR_MAX-extent || hooks.protected_range(first,extent)) DIE(158,0);
    begin(SYS_munmap,a,first,first+extent);
    long result=RAW(SYS_munmap,a[0],a[1],a[2],a[3],a[4],a[5]); returned(result);
    read_maps();
    for (uintptr_t p=first;p<first+extent;p+=PAGE) {
        struct owned_page *old=current(p); if (!old) continue;
        const struct map_row *r=mapping(p);
        if (!r) retire(old); else {
            verify_page(old,r); if (r->prot!=old->actual || !result) DIE(159,0);
        }
    }
    ++counts.reconciliations; tx.phase=REVOKED; finish(); return result;
}
int li2_lifecycle_dispatch(long n,const long a[6],long *result) {
    if (!active) return 0;
    if (n==SYS_mmap) *result=map_call(a);
    else if (n==SYS_mprotect) *result=protect_call(a);
    else if (n==SYS_munmap) *result=unmap_call(a);
    else return 0;
    return 1;
}
void li2_lifecycle_before_other(long n,const long a[6]) {
    if (!active) return;
    if (n==SYS_close) for (size_t i=0;i<object_count;i++)
        if ((unsigned int)a[0]==(unsigned int)objects[i].retained_fd ||
            (unsigned int)a[0]==(unsigned int)objects[i].original_fd) DIE(160,n);
    if (n==SYS_brk && a[0]) {
        long observed=RAW(SYS_brk,0,0,0,0,0,0);
        if (kernel_error(observed) || (uintptr_t)observed>UINTPTR_MAX-(PAGE-1)) DIE(182,0);
        uintptr_t requested=(uintptr_t)a[0],before=(uintptr_t)observed;
        if (requested<before) {
            /* Linux removes [PAGE_ALIGN(requested), PAGE_ALIGN(old_break)).
               A byte-only shrink inside one page removes no mapping. */
            uintptr_t first=(requested+PAGE-1)&~(PAGE-1),end=(before+PAGE-1)&~(PAGE-1);
            for (size_t i=0;i<used;i++) if (records[i].live &&
                overlaps(first,end,records[i].address,records[i].address+PAGE)) DIE(181,n);
        }
    }
    if (n==SYS_madvise) {
        uintptr_t first=(uintptr_t)a[0]; size_t length=(size_t)a[1];
        if (length>UINTPTR_MAX-first) DIE(161,0);
        for (size_t i=0;i<used;i++) if (records[i].live && overlaps(first,first+length,records[i].address,records[i].address+PAGE)) DIE(162,n);
    }
    if (n==SYS_write || n==SYS_writev) {
        struct statfs fs;
        long result=RAW(SYS_fstatfs,a[0],&fs,0,0,0,0);
        /* Raw errors (e.g. EBADF) still belong to the original syscall. */
        if (!result && fs.f_type==PROC_SUPER_MAGIC) DIE(163,n);
    }
    if (n==SYS_fcntl && a[1]!=F_GETFD && a[1]!=F_SETFD && a[1]!=F_GETFL &&
        a[1]!=F_SETFL && a[1]!=F_DUPFD && a[1]!=F_DUPFD_CLOEXEC) DIE(164,a[1]);
}

void li2_lifecycle_verify_kernel_code(uintptr_t first,size_t bytes) {
    read_maps(); const struct map_row *r=mapping(first);
    if (!bytes || first>UINTPTR_MAX-bytes || !r || r->first!=first || r->end!=first+bytes ||
        !r->private || r->prot!=(PROT_READ|PROT_EXEC) || r->inode || r->major || r->minor || r->offset) DIE(190,0);
}

static struct map_row fork_protected[MAP_ROWS];
static size_t fork_protected_used;
static unsigned fork_protected_complete;

void li2_lifecycle_fork_verify(void) {
    if (!active || tx.guard || (tx.phase!=REVOKED && tx.phase!=ADMITTED)) DIE(191,tx.phase);
    for (size_t i=0;i<object_count;i++) {
        const struct object *o=&objects[i]; struct stat st;
        long seals=RAW(SYS_fcntl,o->retained_fd,F_GET_SEALS,0,0,0,0);
        if (seals<0 || (seals&SEALS)!=SEALS || RAW(SYS_fstat,o->retained_fd,&st,0,0,0,0) ||
            st.st_dev!=o->stat.st_dev || st.st_ino!=o->stat.st_ino || st.st_size!=o->stat.st_size ||
            st.st_mode!=o->stat.st_mode) DIE(192,i);
    }
    read_maps(); size_t live=0;
    for (size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i]; if (!p->live) continue; ++live;
        const struct map_row *r=mapping(p->address); verify_page(p,r);
        if (r->prot!=p->actual || p->actual!=(p->admitted?p->logical:(p->logical&~PROT_EXEC))) DIE(193,i);
        if (p->backing==SEALED && (p->logical&PROT_EXEC))
            alias_check(p->object,p->offset,PAGE,p->logical,p->address,p->address+PAGE);
    }
    if (live!=counts.live_pages || used!=counts.retained_records || generation!=counts.generations) DIE(194,0);
    if (fork_protected_complete) for (size_t i=0;i<fork_protected_used;i++) {
        const struct map_row *old=&fork_protected[i],*r=mapping(old->first);
        if (!r || r->end<old->end || r->prot!=old->prot || r->private!=old->private ||
            r->major!=old->major || r->minor!=old->minor || r->inode!=old->inode) DIE(195,i);
        if (r->inode && (r->offset>UINT64_MAX-(old->first-r->first) ||
            r->offset+old->first-r->first!=old->offset)) DIE(195,i);
    }
}

void li2_lifecycle_fork_capture(const struct li2_fork_range *ranges,size_t n) {
    if (fork_protected_complete || fork_protected_used || !n || n>128) DIE(196,0);
    li2_lifecycle_fork_verify();
    for (size_t i=0;i<n;i++) {
        uintptr_t at=ranges[i].first,end=ranges[i].end;
        if (at>=end || ((at|end)&(PAGE-1))) DIE(196,i);
        while (at<end) {
            const struct map_row *r=mapping(at);
            if (!r || !r->private || fork_protected_used==MAP_ROWS) DIE(197,i);
            struct map_row *out=&fork_protected[fork_protected_used++]; *out=*r;
            out->first=at; out->end=r->end<end?r->end:end;
            if (r->inode) { if (r->offset>UINT64_MAX-(at-r->first)) DIE(197,i); out->offset=r->offset+at-r->first; }
            at=out->end;
        }
    }
    fork_protected_complete=1;
}

/* Private non-authoritative fetch borrow; no permission-changing operations. */
#include "fetch_loader.inc"

/* Runtime-private code inspection: does not register application sources. */
#include "private_code_query.inc"
#ifdef LI2_RSEQ_INACTIVE
#include "rseq_data.inc"
#endif

#ifdef LI2_NATIVE_PAGES
#include "native_lifecycle.inc"
#endif
