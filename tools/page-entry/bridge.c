#include "bridge.h"
#ifdef LI2_SPAN_FAST_BYTES
#include "selected/span_fast_bytes.h"
#endif
#include "sha256.h"
#ifdef LI2_EVENT_PROFILE
#include "selected/event_profile.h"
#endif
#ifdef LI2_MAPS_PHASE_REUSE
#include "selected/maps_phase.h"
#endif

struct metadata {
    char magic[8];
    uint64_t version,original_size,phoff,phnum,entry,path_size,interp_size,interp_index,reserved;
    unsigned char original_hash[32],interp_hash[32];
};
struct footer { char magic[8];uint64_t offset,size; };
_Static_assert(sizeof(struct metadata)==144,"carrier metadata layout");
_Static_assert(sizeof(struct footer)==24,"carrier footer layout");
_Static_assert(sizeof(Elf64_Phdr)==56,"program header layout");
static const char *const *initial_environment;
static struct image bridge_image;
const char *const *bridge_environment(void) { return initial_environment; }
const struct image *bridge_runtime_image(void) { return &bridge_image; }

#ifdef LI2_PERSISTENT_EPOCH
extern void li2_pe_rseq_raw(void);
#endif
#ifdef LI2_MAPS_PHASE_REUSE
long raw(long n,long a,long b,long c,long d,long e,long f) {
#ifdef LI2_PERSISTENT_EPOCH
    li2_pe_rseq_raw();
#endif
#ifdef LI2_EVENT_PROFILE
    li2_event_raw_enter(n);
    long result=li2_maps_raw(li2_raw6,n,a,b,c,d,e,f);
    li2_event_raw_return(n,result);return result;
#else
    return li2_maps_raw(li2_raw6,n,a,b,c,d,e,f);
#endif
}
#else
long raw(long n,long a,long b,long c,long d,long e,long f) { return li2_raw6(n,a,b,c,d,e,f); }
#endif
static int failed(long r) { return (unsigned long)r >= (unsigned long)-4095; }
#ifdef LI2_SPAN_FAST_BYTES
void copy(void *v,const void *w,size_t n) { li2_span_bytes_copy(v,w,n); }
#else
void copy(void *v,const void *w,size_t n) { unsigned char *d=v;const unsigned char *s=w;while(n--)*d++=*s++; }
#endif
void *memcpy(void *d,const void *s,size_t n) { copy(d,s,n);return d; }
#if defined(LI2_FAST_MEMSET) && LI2_FAST_MEMSET
/* Runtime C entries have DF clear. This also establishes forward direction
   locally; application flags live in the saved frame, not these C flags. */
void *memset(void *d,int c,size_t n) {
    void *original=d;
    __asm__ volatile("cld; rep stosb" : "+D"(d), "+c"(n)
                     : "a"((unsigned char)c) : "memory","cc");
    return original;
}
#else
void *memset(void *d,int c,size_t n) { unsigned char *p=d;while(n--)*p++=(unsigned char)c;return d; }
#endif
#ifdef LI2_SPAN_FAST_BYTES
int equal(const void *v,const void *w,size_t n) { return li2_span_bytes_equal(v,w,n); }
#else
int equal(const void *v,const void *w,size_t n) { const unsigned char *a=v,*b=w;while(n--)if(*a++!=*b++)return 0;return 1; }
#endif
void li2_fail(const char *why) {
    const char prefix[]="LI2_FIRST_ENTRY refused: ";size_t n=0;while(why[n]&&n<160)++n;
    (void)raw(SYS_write,2,(long)prefix,sizeof(prefix)-1,0,0,0);
    (void)raw(SYS_write,2,(long)why,n,0,0,0);(void)raw(SYS_write,2,(long)"\n",1,0,0,0);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
void require(int condition,const char *why) { if(!condition)li2_fail(why); }
static size_t up(size_t n) { require(n<=SIZE_MAX-(PAGE-1),"page overflow");return (n+PAGE-1)&~(PAGE-1); }
void *memory(size_t n,int prot) {
    require(n&&n<=MAX_FILE*2,"allocation bound");
    long p=raw(SYS_mmap,0,up(n),prot,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    require(!failed(p),"private mmap");return (void *)p;
}
static int open_ro(const char *path) { long fd=raw(SYS_openat,-100,(long)path,0x80000,0,0,0);require(fd>=0,"open source");return (int)fd; }
static size_t length(int fd) { struct stat st;require(raw(SYS_fstat,fd,(long)&st,0,0,0,0)==0,"stat source");require((st.st_mode&0170000)==0100000&&st.st_size>0&&(uint64_t)st.st_size<=MAX_FILE,"source size/type");return (size_t)st.st_size; }
static void read_exact(int fd,void *p,size_t n) {
    size_t done=0;while(done<n) { long r=raw(SYS_pread64,fd,(long)((char *)p+done),n-done,done,0,0);require(r>0&&(size_t)r<=n-done,"source pread");done+=(size_t)r; }
}
static void close_fd(int fd) { require(raw(SYS_close,fd,0,0,0,0,0)==0,"close source"); }
static Elf64_Ehdr *elf(unsigned char *p,size_t n) {
    require(n>=sizeof(Elf64_Ehdr),"short ELF");Elf64_Ehdr *h=(void *)p;
    require(equal(h->e_ident,"\177ELF\2\1\1",7)&&h->e_machine==EM_X86_64&&h->e_version==1&&h->e_ehsize==64,"ELF identity");
    require((h->e_type==ET_DYN||h->e_type==ET_EXEC)&&h->e_phentsize==56&&h->e_phnum&&h->e_phnum<=MAX_PHDR,"ELF table shape");
    require(h->e_phoff<=n&&h->e_phnum*56UL<=n-h->e_phoff,"ELF table extent");return h;
}
static void geometry(const Elf64_Phdr *ph,size_t n,size_t bytes) {
    uintptr_t previous=0;unsigned loads=0;
    for(size_t i=0;i<n;++i) {
        const Elf64_Phdr *p=&ph[i];
        require(p->p_offset<=bytes&&p->p_filesz<=bytes-p->p_offset&&p->p_filesz<=p->p_memsz,"segment file extent");
        require(p->p_vaddr<=UINTPTR_MAX-p->p_memsz&&p->p_vaddr+p->p_memsz<=UINTPTR_MAX-(PAGE-1),"segment virtual extent");
        if(p->p_type==PT_GNU_STACK)require(!(p->p_flags&PF_X),"executable stack unsupported");
        if(p->p_type!=PT_LOAD||!p->p_memsz)continue;
        require((p->p_vaddr%PAGE)==(p->p_offset%PAGE)&&p->p_align<=PAGE&&(!(p->p_flags&PF_X)||!(p->p_flags&PF_W)),"load alignment/WX");
        uintptr_t first=p->p_vaddr&~(PAGE-1),last=up(p->p_vaddr+p->p_memsz);
        require(!loads||first>=previous,"overlapping load pages unsupported");previous=last;++loads;
    }
    require(loads,"no load segments");
}
static void relocate_self(uintptr_t base) {
    /* Our freestanding ET_DYN may contain RELATIVE relocations only. */
    Elf64_Ehdr *h=(void *)base;require(equal(h->e_ident,"\177ELF\2\1\1",7)&&h->e_phnum<=MAX_PHDR,"bridge ELF");
    Elf64_Phdr *ph=(void *)(base+h->e_phoff);Elf64_Dyn *dyn=0;size_t count=0;
    for(size_t i=0;i<h->e_phnum;++i)if(ph[i].p_type==PT_DYNAMIC) { dyn=(void *)(base+ph[i].p_vaddr);count=ph[i].p_memsz/sizeof(*dyn); }
    require(dyn&&count<=1024,"bridge dynamic table");uintptr_t rel=0;size_t bytes=0,ent=0;
    for(size_t i=0;i<count&&dyn[i].d_tag;++i) {
        if(dyn[i].d_tag==DT_RELA)rel=base+dyn[i].d_un.d_ptr;
        if(dyn[i].d_tag==DT_RELASZ)bytes=dyn[i].d_un.d_val;
        if(dyn[i].d_tag==DT_RELAENT)ent=dyn[i].d_un.d_val;
        require(dyn[i].d_tag!=DT_NEEDED&&dyn[i].d_tag!=DT_REL&&dyn[i].d_tag!=DT_JMPREL&&dyn[i].d_tag!=DT_TEXTREL,"bridge external relocation");
    }
    if(!bytes)return;
    require(rel&&ent==sizeof(Elf64_Rela)&&bytes%ent==0&&bytes/ent<=4096,"bridge RELA shape");
    for(size_t i=0;i<bytes/ent;++i) {
        Elf64_Rela *r=(void *)(rel+i*ent);int writable=0;
        require(ELF64_R_TYPE(r->r_info)==R_X86_64_RELATIVE&&ELF64_R_SYM(r->r_info)==0,"bridge relocation kind");
        for(size_t j=0;j<h->e_phnum;++j)if(ph[j].p_type==PT_LOAD&&(ph[j].p_flags&PF_W)&&r->r_offset>=ph[j].p_vaddr&&r->r_offset-ph[j].p_vaddr<=ph[j].p_memsz&&8<=ph[j].p_memsz-(r->r_offset-ph[j].p_vaddr))writable=1;
        require(writable,"bridge relocation destination");*(uintptr_t *)(base+r->r_offset)=base+r->r_addend;
    }
}
static struct image map_interpreter(const char *path,const struct metadata *m) {
    int input=open_ro(path);require(length(input)==m->interp_size,"interpreter size differs");
    unsigned char *bytes=memory(m->interp_size,PROT_READ|PROT_WRITE);read_exact(input,bytes,m->interp_size);close_fd(input);
    unsigned char hash[32];digest(bytes,m->interp_size,hash);require(equal(hash,m->interp_hash,32),"interpreter hash differs");
    Elf64_Ehdr *h=elf(bytes,m->interp_size);require(h->e_type==ET_DYN,"original interpreter must be ET_DYN");
    Elf64_Phdr *ph=(void *)(bytes+h->e_phoff);geometry(ph,h->e_phnum,m->interp_size);
    uintptr_t low=UINTPTR_MAX,high=0;
    for(size_t i=0;i<h->e_phnum;++i) {
        require(ph[i].p_type!=PT_INTERP,"nested interpreter unsupported");
        if(ph[i].p_type!=PT_LOAD||!ph[i].p_memsz)continue;
        if((ph[i].p_vaddr&~(PAGE-1))<low)low=ph[i].p_vaddr&~(PAGE-1);
        if(up(ph[i].p_vaddr+ph[i].p_memsz)>high)high=up(ph[i].p_vaddr+ph[i].p_memsz);
    }
    require(high>low&&high-low<=MAX_FILE,"interpreter span");
    uintptr_t span=(uintptr_t)memory(high-low,PROT_NONE);require(span>=low,"interpreter bias");uintptr_t bias=span-low;
    long fd=raw(SYS_memfd_create,(long)"li2-original-interpreter",3,0,0,0,0);require(fd>=0,"interpreter memfd");
    size_t at=0;while(at<m->interp_size) { long r=raw(SYS_write,fd,(long)(bytes+at),m->interp_size-at,0,0,0);require(r>0&&(size_t)r<=m->interp_size-at,"interpreter snapshot write");at+=(size_t)r; }
    require(raw(SYS_fcntl,fd,1033,15,0,0,0)==0&&raw(SYS_fcntl,fd,1034,0,0,0,0)==15,"interpreter seals");
    int entry=0;
    for(size_t i=0;i<h->e_phnum;++i) {
        Elf64_Phdr *p=&ph[i];if(p->p_type!=PT_LOAD||!p->p_memsz)continue;
        uintptr_t first=p->p_vaddr&~(PAGE-1),end=up(p->p_vaddr+p->p_memsz),file_end=up(p->p_vaddr+p->p_filesz);
        int prot=(p->p_flags&PF_R?PROT_READ:0)|(p->p_flags&PF_W?PROT_WRITE:0);
        /* Replacement is restricted to our own PROT_NONE reservation. */
        if(p->p_filesz)require(raw(SYS_mmap,bias+first,file_end-first,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd,p->p_offset&~(PAGE-1))==(long)(bias+first),"interpreter file map");
        else file_end=first;
        if(file_end<end)require(raw(SYS_mmap,bias+file_end,end-file_end,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(long)(bias+file_end),"interpreter BSS map");
        /* Match ELF BSS padzero: the partial file page is zero through its
           page boundary, including the bytes after p_memsz. The original
           linker uses that zero tail for its bootstrap calloc allocator. */
        if(p->p_memsz>p->p_filesz)
            for(uintptr_t z=p->p_vaddr+p->p_filesz;z<end;++z)*(unsigned char *)(bias+z)=0;
        require(raw(SYS_mprotect,bias+first,end-first,prot,0,0,0)==0,"interpreter final NX protection");
        if((p->p_flags&PF_X)&&h->e_entry>=p->p_vaddr&&h->e_entry-p->p_vaddr<p->p_filesz)entry=1;
    }
    require(entry,"interpreter entry extent");
    require(raw(SYS_mprotect,(long)bytes,up(m->interp_size),PROT_READ,0,0,0)==0,"interpreter snapshot readonly");
    struct image result={.bias=bias,.entry=bias+h->e_entry,.ph=ph,.n=h->e_phnum,
        .source=bytes,.source_size=m->interp_size,.backing_fd=(int)fd,.kind=IMAGE_INTERPRETER};
    copy(result.source_hash,hash,sizeof(hash));return result;
}

uintptr_t li2_boot(uintptr_t *stack) {
    require(stack[0]<=4096,"argc bound");uintptr_t *env=stack+stack[0]+2;size_t n=0;while(env[n]&&n<8192)++n;require(n<8192,"environment bound");
    Elf64_auxv_t *aux=(void *)(env+n+1);uintptr_t phdr=0,base=0,entry=0;size_t phnum=0,minsig=0;Elf64_auxv_t *base_slot=0;
    unsigned found=0;
    for(size_t i=0;i<128&&aux[i].a_type;++i) {
        uintptr_t v=aux[i].a_un.a_val;
        switch(aux[i].a_type) {
        case AT_PHDR:phdr=v;found|=1;break;case AT_PHENT:require(v==56,"aux PHENT");found|=2;break;
        case AT_PHNUM:phnum=v;found|=4;break;case AT_ENTRY:entry=v;found|=8;break;
        case AT_BASE:base=v;base_slot=&aux[i];found|=16;break;case AT_PAGESZ:require(v==PAGE,"aux pagesize");found|=32;break;
        case AT_SECURE:require(v==0,"secure exec unsupported");found|=64;break;case 51:minsig=v;break;
        default:break;
        }
    }
    require(found==127&&base&&phdr&&phnum&&phnum<=MAX_PHDR&&minsig,"startup auxiliary vector");relocate_self(base);
#ifdef LI2_MAPS_MAINTAINED
    li2_maps_view_stack((uintptr_t)stack);
#endif
    initial_environment=(const char *const *)env;
    const Elf64_Ehdr *bridge=(const void *)base;
    bridge_image=(struct image){.bias=base,.entry=base+bridge->e_entry,
        .ph=(const void *)(base+bridge->e_phoff),.n=bridge->e_phnum,
        .backing_fd=-1,.kind=IMAGE_BRIDGE};
    require(raw(SYS_getpid,0,0,0,0,0,0)==raw(SYS_gettid,0,0,0,0,0,0),"fresh main thread");
    int fd=open_ro("/proc/self/exe");require(raw(SYS_fcntl,fd,1034,0,0,0,0)==15,"carrier must be sealed memfd");size_t size=length(fd);
    unsigned char *carrier=memory(size,PROT_READ|PROT_WRITE);read_exact(fd,carrier,size);
    require(size>=sizeof(struct footer),"carrier footer absent");struct footer f;copy(&f,carrier+size-sizeof(f),sizeof(f));
    require(equal(f.magic,"LI2END01",8)&&f.offset<=size-sizeof(f)&&f.size==size-sizeof(f)-f.offset&&f.size>=sizeof(struct metadata),"carrier footer shape");
    struct metadata m;copy(&m,carrier+f.offset,sizeof(m));
    require(equal(m.magic,"LI2BOOT1",8)&&m.version==1&&!m.reserved&&m.original_size<=f.offset&&m.original_size<=MAX_FILE&&m.phnum==phnum,"carrier metadata identity");
    require(m.phoff<=m.original_size&&m.phnum*56<=m.original_size-m.phoff&&m.interp_index<m.phnum,"original table bounds");
    require(m.path_size>=2&&m.path_size<=4096&&m.interp_size&&m.interp_size<=MAX_FILE&&f.size==sizeof(m)+m.phnum*56+m.path_size,"metadata payload extent");
    Elf64_Phdr *original=(void *)(carrier+f.offset+sizeof(m));char *path=(void *)(original+m.phnum);
    require(path[0]=='/'&&path[m.path_size-1]==0,"interpreter path");for(size_t i=0;i<m.path_size-1;++i)require(path[i]!=0,"interpreter path NUL");
    Elf64_Ehdr *h=elf(carrier,m.original_size);require(h->e_phoff==m.phoff&&h->e_phnum==m.phnum&&h->e_entry==m.entry,"carrier ELF differs");
    Elf64_Phdr *current=(void *)(carrier+m.phoff);require(equal((void *)phdr,current,phnum*56),"actual kernel PHDR differs");
    uintptr_t logical_phdr=0;unsigned interp=0;
    for(size_t i=0;i<phnum;++i) {
        Elf64_Phdr wanted=original[i];
        if(wanted.p_type==PT_INTERP) { ++interp;require(i==m.interp_index&&current[i].p_type==PT_INTERP&&current[i].p_offset>=m.original_size&&current[i].p_filesz>=2&&current[i].p_offset<=f.offset&&current[i].p_filesz<=f.offset-current[i].p_offset,"carrier interpreter override"); }
        else { if(wanted.p_type==PT_LOAD)wanted.p_flags&=~PF_X;require(equal(&wanted,&current[i],56),"unauthorized PHDR mutation"); }
        if(original[i].p_type==PT_LOAD&&m.phoff>=original[i].p_offset&&m.phoff-original[i].p_offset<=original[i].p_filesz&&phnum*56<=original[i].p_filesz-(m.phoff-original[i].p_offset)) {
            require(!logical_phdr,"ambiguous PHDR owner");logical_phdr=original[i].p_vaddr+m.phoff-original[i].p_offset;
        }
    }
    require(interp==1&&logical_phdr&&phdr>=logical_phdr,"original PHDR owner");uintptr_t bias=phdr-logical_phdr;
    require(m.entry<=UINTPTR_MAX-bias&&entry==bias+m.entry,"kernel main entry differs");geometry(original,phnum,m.original_size);
    for(size_t i=0;i<phnum;++i)if(original[i].p_type==PT_PHDR)
        require(original[i].p_vaddr==logical_phdr&&original[i].p_offset==m.phoff&&original[i].p_filesz==phnum*56&&original[i].p_memsz==phnum*56,"original PT_PHDR load-bias contract");
    unsigned char *source=memory(m.original_size,PROT_READ|PROT_WRITE);copy(source,carrier,m.original_size);copy(source+m.phoff,original,phnum*56);
    unsigned char hash[32];digest(source,m.original_size,hash);require(equal(hash,m.original_hash,32),"original main hash differs");
    require(raw(SYS_mprotect,(long)source,up(m.original_size),PROT_READ,0,0,0)==0,"main snapshot readonly");
    const Elf64_Phdr *interp_header=(const void *)(source+m.phoff+m.interp_index*56);
    require(interp_header->p_type==PT_INTERP&&interp_header->p_filesz>=2&&interp_header->p_filesz<=4096,
        "authenticated PT_INTERP shape");
    /* geometry already bounds this extent in the authenticated original file.
       Metadata's resolved pathname is descriptive; it never selects the file. */
    const char *original_path=(const void *)(source+interp_header->p_offset);
    require(original_path[0]=='/'&&original_path[interp_header->p_filesz-1]==0,"authenticated PT_INTERP path");
    for(size_t i=0;i<interp_header->p_filesz-1;++i)require(original_path[i]!=0,"authenticated PT_INTERP NUL");
    struct image executable={.bias=bias,.entry=entry,.ph=(const void *)(source+m.phoff),.n=phnum,
        .source=source,.source_size=m.original_size,.backing_fd=fd,.kind=IMAGE_MAIN};
    copy(executable.source_hash,hash,sizeof(hash));
    struct image interpreter=map_interpreter(original_path,&m);
    /* Keep AT_PHDR at its kernel-created address. Restore the authenticated
       logical PHDR table there; never relocate it to arbitrary private storage. */
    uintptr_t first=phdr&~(PAGE-1),last=up(phdr+phnum*56);
    require(raw(SYS_mprotect,first,last-first,PROT_READ|PROT_WRITE,0,0,0)==0,"PHDR writable NX");copy((void *)phdr,executable.ph,phnum*56);
    for(uintptr_t page=first;page<last;page+=PAGE) {
        int prot=-1;
        for(size_t i=0;i<phnum;++i) { const Elf64_Phdr *p=&executable.ph[i];if(p->p_type==PT_LOAD&&page>=bias+(p->p_vaddr&~(PAGE-1))&&page<bias+up(p->p_vaddr+p->p_memsz))prot=(p->p_flags&PF_R?PROT_READ:0)|(p->p_flags&PF_W?PROT_WRITE:0); }
        require(prot>=0&&!(prot&PROT_WRITE),"PHDR original owner must be readonly");require(raw(SYS_mprotect,page,PAGE,prot,0,0,0)==0,"PHDR restore readonly NX");
    }
    require(equal((void *)phdr,executable.ph,phnum*56),"logical PHDR restore differs");
    base_slot->a_un.a_val=interpreter.bias;
    runtime_arm(&executable,&interpreter,minsig);
    return interpreter.entry;
}
