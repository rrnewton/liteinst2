/* Storage-only backend. Included after the existing owner types/identity
   helpers. It changes no emitter, byte comparator, source or lifetime gate. */
#include "sealed_generation.h"
#ifdef LI2_SEALED_BYTE_CERTIFICATE
#include "sealed_byte_certificate.h"
#endif
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#if LI2_PERSISTENT_SEALED_GENERATION != 1 || !defined(LI2_PERSISTENT_RETAINED_TWO) || \
    LI2_PERSISTENT_RETAINED_TWO != 1 || !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || \
    LI2_PERSISTENT_ACTIVE_DOMAIN != 1
#error "sealed generation storage requires the separate complete two-member owner"
#endif
#if defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) || \
    defined(LI2_PERSISTENT_CALL_OWNER_CAPTURE) || defined(LI2_PERSISTENT_RET_OWNER_CAPTURE) || \
    defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || \
    defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE) || \
    defined(LI2_PERSISTENT_COLD_ADMISSION_CAPTURE) || defined(LI2_PERSISTENT_JOINT_STARTUP_CAPTURE) || \
    defined(LI2_PERSISTENT_JOINT_SUBENTRY_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_EIGHT_HISTORY) || defined(LI2_REUSE_CENSUS)
#error "sealed query evidence requires its own reader; no old capture cast"
#endif
_Static_assert(LI2_PTR_SLOTS==2 && PE_CODE_BYTES==17U*PAGE && PE_PROOF_BYTES==89U*PAGE,
    "unchanged two retained certificates and complete code/proof extents");
_Static_assert(LI2_SEALED_REQUIRED_SEALS==
    (F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL),"all file seals");
struct sg_owner_state {
    unsigned initialized,reserved;
#ifdef LI2_LOOP_RO_CERTIFICATE
    unsigned ro_initialized,ro_writable_mask;
#endif
    struct li2_sealed_identity bank[LI2_PTR_SLOTS][2];
#ifdef LI2_SEALED_BYTE_CERTIFICATE
    struct sbc_owner bytes;
#endif
};
static union {
    struct sg_owner_state state;
    unsigned char page[PAGE];
} sg_owner __attribute__((aligned(PAGE)));
_Static_assert(sizeof sg_owner==PAGE,"one separately protected owner page");

static int sg_permission(int prot) {
    return raw(SYS_mprotect,(long)&sg_owner,PAGE,prot,0,0,0)?PE_PUBLICATION:0;
}
static int sg_initialize(void) {
    if(sg_owner.state.initialized || ((uintptr_t)&sg_owner&(PAGE-1)) ||
       protected_count>=RANGES || selected_run_protect_add(0,(uintptr_t)&sg_owner,PAGE))return PE_STATE;
#ifdef LI2_LOOP_RO_CERTIFICATE
    /* Fixed isolated root: ordinary syscall outputs must obey its R mapping. */
    if((uintptr_t)raw(SYS_mmap,(long)&sg_owner,PAGE,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&sg_owner)return PE_PUBLICATION;
#endif
    /* The page is not writable during guest execution or forwarded syscalls.
       Same-uid external ptrace/proc-memory access must also be unavailable. */
    if(raw(SYS_prctl,PR_SET_DUMPABLE,0,0,0,0,0) ||
       raw(SYS_prctl,PR_GET_DUMPABLE,0,0,0,0,0)!=0)return PE_PUBLICATION;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++)
        sg_owner.state.bank[i][j].fd=-1;
    sg_owner.state.initialized=1;
#ifdef LI2_SEALED_BYTE_CERTIFICATE
    int error=sbc_initialize();if(error)return error;
#endif
    return sg_permission(PROT_READ);
}
static int sg_interval(uintptr_t first,size_t bytes,uintptr_t at,size_t length) {
    return bytes && length && first<=UINTPTR_MAX-bytes && at>=first &&
        at-first<bytes && length<=bytes-(at-first);
}
static const struct li2_sealed_identity *sg_find(uintptr_t at,size_t bytes) {
    const struct li2_sealed_identity *found=0;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++) {
        const struct li2_sealed_identity *id=&sg_owner.state.bank[i][j];
        if((id->code_live && sg_interval(id->code,id->code_bytes,at,bytes)) ||
           (id->proof_live && sg_interval(id->proof,id->proof_bytes,at,bytes))) {
            if(found)return 0;
            found=id;
        }
    }
    return found;
}
static int sg_receipt_valid(const struct li2_private_code_query *q) {
    if(!q || !q->first || q->end<=q->first)return 0;
    const struct li2_sealed_evidence *e=&q->sealed;
    if(!e->kind) {
        const struct li2_sealed_evidence zero={0};
        return equal(e,&zero,sizeof zero);
    }
    const struct li2_sealed_identity *id=&e->identity;
    uint64_t offset;
    if(id->code_live && sg_interval(id->code,id->code_bytes,q->first,q->end-q->first))
        offset=q->first-id->code;
    else if(id->proof_live && sg_interval(id->proof,id->proof_bytes,q->first,q->end-q->first)) {
        offset=id->code_bytes+q->first-id->proof;
        if(q->actual_prot!=PROT_READ)return 0;
    } else return 0;
    return e->kind==LI2_SEALED_QUERY_KIND && e->version==LI2_SEALED_QUERY_VERSION &&
        e->seals_result==LI2_SEALED_REQUIRED_SEALS && !e->stat_result && !e->reserved &&
        e->alias_complete==1 && e->alias_vmas && e->alias_vmas<=e->alias_pages &&
        id->fd>=0 && id->fd<=INT32_MAX && id->inode && id->generation &&
        id->code_live<=1 && id->proof_live<=1 && id->code_bytes==PE_CODE_BYTES &&
        id->proof_bytes==PE_PROOF_BYTES && id->bytes==PE_CODE_BYTES+PE_PROOF_BYTES &&
        e->offset==offset && e->alias_pages==
            (id->code_live*PE_CODE_BYTES+id->proof_live*PE_PROOF_BYTES)/PAGE &&
        (q->actual_prot==PROT_READ || q->actual_prot==(PROT_READ|PROT_EXEC));
}
static int sg_query(uintptr_t at,size_t bytes,int prot,struct li2_private_code_query *out,int *used) {
    *used=0;
    if(!sg_owner.state.initialized)return 0;
    const struct li2_sealed_identity *id=sg_find(at,bytes);
    if(!id)return 0;
    *used=1;
    if(!out || out->attempted || out->sealed.kind)return PE_STATE;
    struct li2_sealed_code_query q={0};
    int error=li2_lifecycle_sealed_code_query(id,at,bytes,prot,&q);
    /* Explicit tagged common-field projection. The distinct API result and
       full file/alias evidence accompany every retained permission record. */
    out->first=q.first;out->end=q.end;out->first_vma=q.first_vma;out->last_vma_end=q.last_vma_end;
    out->pages_checked=q.pages_checked;out->attempted=q.attempted;out->complete=q.complete;
    out->expected_prot=q.expected_prot;out->actual_prot=q.actual_prot;out->result=q.result;
    out->detail=q.detail;out->maps=q.maps;out->sealed=q.sealed;
    return error || q.sealed.kind!=LI2_SEALED_QUERY_KIND ||
        q.sealed.version!=LI2_SEALED_QUERY_VERSION || q.sealed.alias_complete!=1 ||
        q.sealed.seals_result!=LI2_SEALED_REQUIRED_SEALS || q.sealed.stat_result?PE_PUBLICATION:0;
}
static int sg_check_extent(const struct li2_sealed_identity *id,uintptr_t at,size_t bytes) {
    while(bytes) {
        size_t part=bytes>64U*PAGE?64U*PAGE:bytes;
        struct li2_sealed_code_query q={0};
        if(li2_lifecycle_sealed_code_query(id,at,part,PROT_READ,&q) ||
           q.complete!=1 || q.pages_checked!=part/PAGE || q.sealed.alias_complete!=1)return PE_PUBLICATION;
        at+=part;bytes-=part;
    }
    return 0;
}
static int sg_closed(void) {
    if(!sg_owner.state.initialized || !pe_busy || pe_active || pe.resuming ||
       pe.p.phase!=LI2_PG_CONSUMED || pe.selected_slot>=LI2_PTR_SLOTS || pe.selected_bank>1)
        return 0;
    const struct li2_pg_generation *g=&PE_SLOT(generation);
    return !g->ready_generation && !g->active_refs && !g->member_refs[0] &&
        !g->member_refs[1] && !g->incoming[0] && !g->incoming[1] && !g->domain_refs;
}
#ifdef LI2_MAPS_MAINTAINED
/* The maps helper has no owner authority. Only these exact already-closed,
   fully protected selected-bank/proof extents can issue its trusted reset. */
static long sg_anon_reset(uintptr_t at,size_t bytes) {
    if(!sg_closed() ||
       !((at==PE_SLOT(banks)[pe.selected_bank].generated && bytes==PE_CODE_BYTES) ||
         (at==PE_SLOT(generation).proof && bytes==PE_PROOF_BYTES)) ||
       selected_run_protect_contains(0,at,bytes)!=1)return -EINVAL;
    return li2_maps_view_anon_reset(at,bytes);
}
#endif
static int sg_reopen(uintptr_t code,uintptr_t proof) {
#ifdef LI2_SEALED_BYTE_CERTIFICATE
    if(!sbc_unpublished())return PE_STATE;
#endif
    if(!sg_closed() || code!=PE_SLOT(banks)[pe.selected_bank].generated || proof!=PE_SLOT(generation).proof)
        return PE_STATE;
    /* Every live alias is still R/NX, and the old permission/claim checks have
       already completed. No sealed backing is ever made writable. */
    for(unsigned j=0;j<2;j++) {
        const struct li2_sealed_identity *id=&sg_owner.state.bank[pe.selected_slot][j];
        if(id->code_live && id->code==code && sg_check_extent(id,code,PE_CODE_BYTES))return PE_PUBLICATION;
        if(id->proof_live && id->proof==proof && sg_check_extent(id,proof,PE_PROOF_BYTES))return PE_PUBLICATION;
    }
    if(sg_permission(PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    int error=0;
    for(unsigned j=0;j<2 && !error;j++) {
        struct li2_sealed_identity *id=&sg_owner.state.bank[pe.selected_slot][j];
        if(id->code_live && id->code==code) {
#ifdef LI2_MAPS_MAINTAINED
            long result=sg_anon_reset(code,PE_CODE_BYTES);
#else
            long result=raw(SYS_mmap,code,PE_CODE_BYTES,PROT_READ,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
#endif
            if((uintptr_t)result!=code)error=PE_PUBLICATION;
            else id->code_live=0;
        }
        if(!error && id->proof_live && id->proof==proof) {
#ifdef LI2_MAPS_MAINTAINED
            long result=sg_anon_reset(proof,PE_PROOF_BYTES);
#else
            long result=raw(SYS_mmap,proof,PE_PROOF_BYTES,PROT_READ,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
#endif
            if((uintptr_t)result!=proof)error=PE_PUBLICATION;
            else id->proof_live=0;
        }
        if(!error && id->fd>=0 && !id->code_live && !id->proof_live) {
            if(raw(SYS_close,id->fd,0,0,0,0,0))error=PE_PUBLICATION;
            else {*id=(struct li2_sealed_identity){.fd=-1};}
        }
    }
    int closed=sg_permission(PROT_READ);
    return error?error:closed;
}
static int sg_write(long fd,const unsigned char *bytes,size_t count,size_t offset) {
    while(count) {
        long result=raw(SYS_pwrite64,fd,(long)bytes,count,offset,0,0);
        if(result<=0 || (unsigned long)result>count)return PE_PUBLICATION;
        bytes+=(size_t)result;count-=(size_t)result;offset+=(size_t)result;
    }
    return 0;
}
static int sg_publish(const struct li2_pg_generation *g) {
#ifdef LI2_SEALED_BYTE_CERTIFICATE
    if(!sbc_unpublished())return PE_STATE;
#endif
    if(!sg_owner.state.initialized || !g || pe.selected_slot>=LI2_PTR_SLOTS || pe.selected_bank>1 ||
       g!=&PE_SLOT(generation) || !pe_busy || pe_active ||
       pe.p.phase!=LI2_PG_PUBLISHING || !g->installed || g->complete || g->proof_complete ||
       !g->generation || g->active_refs || g->domain_refs ||
       g->member_refs[0] || g->member_refs[1] || g->incoming[0] || g->incoming[1] ||
       g->code_copied!=PE_CODE_BYTES || g->proof_zeroed!=PE_PROOF_BYTES ||
       g->proof_copied!=sizeof(struct pe_payload))
        return PE_STATE;
    struct li2_sealed_identity *old=&sg_owner.state.bank[pe.selected_slot][pe.selected_bank];
    if(old->fd!=-1 || old->code_live || old->proof_live)return PE_STATE;
    long fd=raw(SYS_memfd_create,(long)"li2-sealed-generation",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    if(fd<0 || fd>INT32_MAX)return PE_PUBLICATION;
    int error=0;struct stat st={0};
    if(raw(SYS_ftruncate,fd,PE_CODE_BYTES+PE_PROOF_BYTES,0,0,0,0) ||
       sg_write(fd,(const void *)g->generated,PE_CODE_BYTES,0) ||
       sg_write(fd,(const void *)g->proof,PE_PROOF_BYTES,PE_CODE_BYTES) ||
       raw(SYS_fcntl,fd,F_ADD_SEALS,LI2_SEALED_REQUIRED_SEALS,0,0,0) ||
       raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)!=LI2_SEALED_REQUIRED_SEALS ||
       raw(SYS_fstat,fd,(long)&st,0,0,0,0) || st.st_size<0 ||
       (uint64_t)st.st_size!=PE_CODE_BYTES+PE_PROOF_BYTES ||
       (st.st_mode&S_IFMT)!=S_IFREG || !st.st_ino)error=PE_PUBLICATION;
    if(error){(void)raw(SYS_close,fd,0,0,0,0,0);return error;}
    if(sg_permission(PROT_READ|PROT_WRITE)){(void)raw(SYS_close,fd,0,0,0,0,0);return PE_PUBLICATION;}
    *old=(struct li2_sealed_identity){.fd=fd,.device=st.st_dev,.inode=st.st_ino,
        .bytes=PE_CODE_BYTES+PE_PROOF_BYTES,.generation=g->generation,
        .code=g->generated,.proof=g->proof,.code_bytes=PE_CODE_BYTES,.proof_bytes=PE_PROOF_BYTES};
    long result=raw(SYS_mmap,g->generated,PE_CODE_BYTES,PROT_READ,MAP_SHARED|MAP_FIXED,fd,0);
    if((uintptr_t)result!=g->generated)error=PE_PUBLICATION;
    else old->code_live=1;
    if(!error) {
        result=raw(SYS_mmap,g->proof,PE_PROOF_BYTES,PROT_READ,MAP_SHARED|MAP_FIXED,fd,PE_CODE_BYTES);
        if((uintptr_t)result!=g->proof)error=PE_PUBLICATION;
        else old->proof_live=1;
    }
    int closed=sg_permission(PROT_READ);
    return error?error:closed;
}
static void sg_fd_guard(long number,const long args[6]) {
    if(!sg_owner.state.initialized)return;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++) {
        const struct li2_sealed_identity *id=&sg_owner.state.bank[i][j];
        if(id->fd<0)continue;
        if((number==SYS_close || number==SYS_write || number==SYS_writev || number==SYS_fcntl) &&
           (unsigned)args[0]==(unsigned)id->fd)selected_persistent_abort(PE_STATE,191);
        if(number==SYS_mmap && !(args[3]&MAP_ANONYMOUS) &&
           (unsigned)args[4]==(unsigned)id->fd)selected_persistent_abort(PE_STATE,192);
    }
    /* An alias opened through procfs still cannot write the fully sealed
       backing. Any mapping of that alias fails the complete census before
       another activation. Unsupported dup/remap/close_range routes retain
       the existing terminal syscall refusal. */
}
