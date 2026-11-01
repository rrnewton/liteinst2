/* Genuine storage owned by r3, never by pe.selected_slot. All file mappings
   are sealed R before publication and only code can later become RX. */
#include "resident_three_config.h"
#if LI2_R3_CONFIG_VERSION != 1
#error "the finite resident root must be bound to its actual source image"
#endif
static int r3_reserve(uintptr_t);
static int r3_write(long fd,const unsigned char *bytes,size_t count,size_t offset) {
    while(count) {
        long n=raw(SYS_pwrite64,fd,(long)bytes,count,offset,0,0);
        if(n<=0 || (unsigned long)n>count)return R3_PUBLICATION;
        bytes+=(size_t)n;count-=(size_t)n;offset+=(size_t)n;
    }
    return 0;
}
static int r3_initialize(void) {
    if(r3.initialized || ((uintptr_t)&r3_memory&(PAGE-1)) ||
       protected_count>RANGES-3 ||
       selected_run_protect_add(0,(uintptr_t)&r3_memory,sizeof r3_memory) ||
       selected_run_protect_add(0,(uintptr_t)&r3_work,sizeof r3_work) ||
       raw(SYS_prctl,PR_SET_DUMPABLE,0,0,0,0,0) ||
       raw(SYS_prctl,PR_GET_DUMPABLE,0,0,0,0,0)!=0)return R3_PUBLICATION;
    r3.session=selected_session;
    for(unsigned i=0;i<LI2_R3_CERTIFICATES;i++)r3.certificate[i].identity.fd=-1;
    r3.initialized=1;r3.phase=LI2_R3_IDLE;
    if(original_main.bias>UINTPTR_MAX-LI2_R3_ROOT_RVA)return R3_SOURCE;
    r3.root=original_main.bias+LI2_R3_ROOT_RVA;
    if(!image_code(&original_main,r3.root) || r3_reserve(r3.root))return R3_SOURCE;
    return r3_permission(PROT_READ);
}
static int r3_reserve(uintptr_t root) {
    /* Reserve before any guest execution or old/new publication. Adding a
       protected range later would invalidate older immutable guard tables.
       MAP_FIXED_NOREPLACE cannot replace an existing VMA. Every prospective
       layout still passes the unchanged signed-rel32 placement predicate. */
    if(!r3.initialized || r3.arena || r3.busy || r3.active ||
       r3.phase!=LI2_R3_IDLE || root<PAGE || root>=(UINT64_C(1)<<47)-2U*PAGE ||
       protected_count>=RANGES)return R3_STATE;
    uintptr_t page=root&~(PAGE-1),arena=0;
    for(unsigned attempt=0;attempt<16 && !arena;attempt++) {
        uintptr_t distance=(uintptr_t)(attempt/2+1)*(16U<<20),at;
        if(attempt&1U) {
            if(page<=distance || page-distance<PAGE)continue;
            at=page-distance;
        } else {
            if(page>=(UINT64_C(1)<<47)-distance-R3_ARENA_BYTES)continue;
            at=page+distance;
        }
        long result=raw(SYS_mmap,at,R3_ARENA_BYTES,PROT_NONE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        if(result<0)continue;
        if((uintptr_t)result!=at) {
            (void)raw(SYS_munmap,result,R3_ARENA_BYTES,0,0,0,0);return R3_PUBLICATION;
        }
        arena=at;
    }
    if(!arena)return R3_PUBLICATION;
    if(selected_run_protect_add(0,arena,R3_ARENA_BYTES))return R3_PUBLICATION;
    r3.arena=arena;r3.directory=arena+LI2_R3_CERTIFICATES*R3_STRIDE;
    for(unsigned i=0;i<LI2_R3_CERTIFICATES;i++) {
        struct r3_certificate *c=&r3.certificate[i];uintptr_t code=arena+i*R3_STRIDE;
        c->layout=(struct li2_pg_layout){.generated={code,code+LI2_PE_IMAGE_BYTES},
            .stubs=code+2U*LI2_PE_IMAGE_BYTES,.slots=code+R3_CODE_BYTES,
            .spill=code+R3_CODE_BYTES+PAGE,.directory=r3.directory};
        c->proof=code+R3_CODE_BYTES+2U*PAGE;
        /* Slots never change in this NONE/direct subset. Spill is separately
           private RW/NX and only initialized guard rows may read its words. */
        if(raw(SYS_mprotect,c->layout.slots,PAGE,PROT_READ,0,0,0) ||
           raw(SYS_mprotect,c->layout.spill,PAGE,PROT_READ|PROT_WRITE,0,0,0))return R3_PUBLICATION;
    }
    if(raw(SYS_mprotect,r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ|PROT_WRITE,0,0,0))
        return R3_PUBLICATION;
    r3.registry_count=(unsigned)protected_count;
    for(unsigned i=0;i<r3.registry_count;i++)r3.registry[i]=protected[i];
    return 0;
}
static int r3_publish(unsigned index) {
    if(!r3_token(&r3.token) || r3.phase!=LI2_R3_PUBLISHING || !r3.busy || r3.active ||
       !r3.consumed || index>=r3.count || r3.count!=LI2_R3_CERTIFICATES ||
       !r3_registry() || !r3_identity() || r3.publications==UINT64_MAX)return R3_STATE;
    struct r3_certificate *c=&r3.certificate[index];
    if(!c->planned || c->installed || c->active_refs || c->generation || c->identity.fd!=-1 ||
       c->identity.code_live || c->identity.proof_live || !c->root ||
       li2_pg_placement(c->root,&c->layout)!=1 || !li2_r3_owner_plan(&r3.token,index))return R3_STATE;
    uint64_t generation=r3.publications+1;
    c->mirror.header=(struct r3_header){.version=LI2_R3_VERSION,.bytes=sizeof c->mirror,
        .generation=generation,.publication_serial=r3.serial,.index=index,
        .source_epoch=r3.source.epoch,.root=c->root,.owner=(uintptr_t)&r3,.layout=c->layout};
    for(unsigned i=0;i<32;i++){c->mirror.header.archive[i]=pe_archive[i];c->mirror.header.policy[i]=pe_policy[i];}
    long fd=raw(SYS_memfd_create,(long)"li2-resident-three",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    if(fd<0 || fd>INT32_MAX)return R3_PUBLICATION;
    /* Install FD ownership immediately. Terminal cleanup cannot mistake this
       unpublished backing for another generation or a caller-owned handle. */
    c->identity.fd=fd;
    struct stat st={0};const struct li2_pg_compact *p=&c->mirror.plan;
    if(raw(SYS_ftruncate,fd,R3_CODE_BYTES+R3_PROOF_BYTES,0,0,0,0) ||
       r3_write(fd,p->image[0],LI2_PE_IMAGE_BYTES,0) ||
       r3_write(fd,p->image[1],LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES) ||
       r3_write(fd,p->stub_image,PAGE,2U*LI2_PE_IMAGE_BYTES) ||
       r3_write(fd,(const void *)&c->mirror,sizeof c->mirror,R3_CODE_BYTES) ||
       raw(SYS_fcntl,fd,F_ADD_SEALS,LI2_SEALED_REQUIRED_SEALS,0,0,0) ||
       raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)!=LI2_SEALED_REQUIRED_SEALS ||
       raw(SYS_fstat,fd,(long)&st,0,0,0,0) || st.st_size<0 ||
       (uint64_t)st.st_size!=R3_CODE_BYTES+R3_PROOF_BYTES ||
       (st.st_mode&S_IFMT)!=S_IFREG || !st.st_ino)return R3_PUBLICATION;
    c->identity=(struct li2_sealed_identity){.fd=fd,.device=st.st_dev,.inode=st.st_ino,
        .bytes=R3_CODE_BYTES+R3_PROOF_BYTES,.generation=generation,
        .code=c->layout.generated[0],.proof=c->proof,
        .code_bytes=R3_CODE_BYTES,.proof_bytes=R3_PROOF_BYTES};
    long result=raw(SYS_mmap,c->identity.code,R3_CODE_BYTES,PROT_READ,MAP_SHARED|MAP_FIXED,fd,0);
    if((uintptr_t)result!=c->identity.code)return R3_PUBLICATION;
    c->identity.code_live=1;
    result=raw(SYS_mmap,c->proof,R3_PROOF_BYTES,PROT_READ,MAP_SHARED|MAP_FIXED,fd,R3_CODE_BYTES);
    if((uintptr_t)result!=c->proof)return R3_PUBLICATION;
    c->identity.proof_live=1;c->generation=generation;c->installed=1;c->closed=1;
    if(r3_code_query(index,PROT_READ,c->published) || r3_proof_query(index,c->proof_query) ||
       r3_bytes(index))return R3_PUBLICATION;
    ++r3.publications;return 0;
}
static int r3_directory_build(void) {
    if(r3.phase!=LI2_R3_PUBLISHING || r3.active || !r3.busy || !r3.consumed ||
       r3.count!=LI2_R3_CERTIFICATES || r3.publications!=LI2_R3_CERTIFICATES ||
       !r3_registry())return R3_STATE;
    struct li2_jd_domain_directory *d=&r3.expected_directory;
    *d=(struct li2_jd_domain_directory){.version=LI2_JD_DOMAIN_VERSION,.serial=r3.serial};
    for(unsigned i=0;i<r3.count;i++) {
        const struct r3_certificate *c=&r3.certificate[i];const struct li2_pg_compact *p=&c->mirror.plan;
        if(!c->installed || c->active_refs || !c->closed || r3_bytes(i) || !p->heads ||
           p->heads>LI2_PE_HEADS || d->count>LI2_JD_DOMAIN_HEADS-p->heads)return R3_PUBLICATION;
        for(unsigned h=0;h<p->heads;h++) {
            const struct li2_pe_head *head=&p->head[h];
            uintptr_t pc=p->page[head->source_page]+head->source_offset;
            uintptr_t generated=c->layout.generated[h/LI2_PE_HEADS]+(h%LI2_PE_HEADS)*LI2_PE_SLOT_BYTES;
            for(size_t prior=0;prior<d->count;prior++)if(d->row[prior].pc==pc ||
                d->row[prior].generated==generated)return R3_PUBLICATION;
            d->row[d->count++]=(struct li2_jd_domain_row){.pc=pc,.generated=generated,
                .generation=c->generation,.slot=i,.head=h};
        }
    }
    unsigned char *actual=(void *)r3.directory;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)actual[i]=i<sizeof *d?((const unsigned char *)d)[i]:0;
    if(raw(SYS_mprotect,r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,0,0,0))return R3_PUBLICATION;
    return r3_directory_query()?0:R3_PUBLICATION;
}
static void r3_fd_guard(long number,const long args[6]) {
    if(!r3.initialized)return;
    for(unsigned i=0;i<LI2_R3_CERTIFICATES;i++) {
        int64_t fd=r3.certificate[i].identity.fd;if(fd<0)continue;
        if(((number==SYS_close || number==SYS_write || number==SYS_writev || number==SYS_fcntl) &&
            (unsigned)args[0]==(unsigned)fd) ||
           (number==SYS_mmap && !(args[3]&MAP_ANONYMOUS) && (unsigned)args[4]==(unsigned)fd))
            selected_persistent_abort(R3_STATE,1);
    }
}
