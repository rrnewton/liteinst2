/* Included after the real LHC owner types. These epochs do not grant source,
   execution, claim, or permission authority. They only retire immutable-value
   reuse before an exposure. The containing pages are permanently private RW. */
/* A complete common-value proof may be reused within one quiet exposure
   epoch. This token never renews an LHC witness or its original RAW stamps. */
struct lgd_common_token {
    uint64_t valid,index,raw_root,raw_cell,raw_capsule,source_context,directory;
    struct lhc_certificate certificate;
};
struct lgd_epochs {
    uint64_t initialized,poisoned,next_id;
    uint64_t root,cell[LI2_PGD_RECEIPTS],capsule[LI2_PGD_RECEIPTS];
    uint64_t publication[LI2_PTR_SLOTS],manifest,directory;
    uint64_t invalidations,unclassified,overflows;
    struct lgd_common_token common[LI2_PGD_RECEIPTS];
};
static union {
    struct lgd_epochs value;
    unsigned char page[PAGE];
} lgd_writer __attribute__((aligned(PAGE)));
_Static_assert(sizeof(struct lgd_epochs)<=PAGE && sizeof lgd_writer==PAGE,
    "writer epochs have their own complete protected page");
static uintptr_t lgd_manifest_address(void);
static size_t lgd_manifest_bytes(void);
static void lgd_poison(void) { lgd_writer.value.poisoned=1; }
static void lgd_advance(uint64_t *value) {
    if(*value==UINT64_MAX) {
        lgd_poison();
        if(lgd_writer.value.overflows!=UINT64_MAX)++lgd_writer.value.overflows;
    } else ++*value;
}
static int lgd_overlaps(uintptr_t first,uintptr_t end,uintptr_t at,size_t bytes) {
    return bytes && at<=UINTPTR_MAX-bytes && first<at+bytes && at<end;
}
static void lgd_writer_range(uintptr_t first,size_t bytes) {
    if(bytes && first<=UINTPTR_MAX-bytes && first+bytes<=UINTPTR_MAX-(PAGE-1U) &&
       lgd_overlaps(first&~(uintptr_t)(PAGE-1U),
           (first+bytes+PAGE-1U)&~(uintptr_t)(PAGE-1U),(uintptr_t)&lgd_writer,sizeof lgd_writer)) {
        lgd_poison();selected_persistent_abort(PE_PUBLICATION,8990);
    }
}
static void lgd_exposure(uintptr_t first,size_t bytes) {
    if(!bytes)return; /* A zero-length kernel operation changes no mapping. */
    /* Include the complete last page the kernel could affect. Overflow is a
       permanent loss of reuse, never a wrapped apparently-disjoint range. */
    if(first>UINTPTR_MAX-bytes || first+bytes>UINTPTR_MAX-(PAGE-1U)) {
        lgd_poison();lgd_advance(&lgd_writer.value.unclassified);return;
    }
    uintptr_t end=(first+bytes+PAGE-1U)&~(uintptr_t)(PAGE-1U);
    first&=~(uintptr_t)(PAGE-1U);
    lgd_writer_range(first,end-first);
    unsigned changed=0;
#define LGD_EXPOSE(at,bytes,epoch) do { \
    if(lgd_overlaps(first,end,(uintptr_t)(at),(bytes))) { \
        lgd_advance(&(epoch));changed=1; \
    } \
} while(0)
    LGD_EXPOSE(&lhc.root,sizeof lhc.root,lgd_writer.value.root);
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {
        LGD_EXPOSE(&pe.domain.completion[i],sizeof pe.domain.completion[i],lgd_writer.value.cell[i]);
        LGD_EXPOSE(&lhc.capsule[i],sizeof lhc.capsule[i],lgd_writer.value.capsule[i]);
    }
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        /* sg_owner contains the immutable SBC issuance identity. It changes
           only on real publication/writer transitions; conservatively retire
           every group publication reference before any such root exposure. */
        LGD_EXPOSE(&sg_owner,sizeof sg_owner,lgd_writer.value.publication[i]);
        LGD_EXPOSE(&pe.retained[i].publication,PE_PROOF_BYTES,lgd_writer.value.publication[i]);
        LGD_EXPOSE(pe.retained[i].proof,PE_PROOF_BYTES,lgd_writer.value.publication[i]);
        for(unsigned bank=0;bank<2;bank++)
            LGD_EXPOSE(pe.retained[i].banks[bank].generated,PE_CODE_BYTES,lgd_writer.value.publication[i]);
    }
    LGD_EXPOSE(lgd_manifest_address(),lgd_manifest_bytes(),lgd_writer.value.manifest);
    LGD_EXPOSE(pe.domain.directory,LI2_JD_DOMAIN_BYTES,lgd_writer.value.directory);
#undef LGD_EXPOSE
    if(changed)lgd_advance(&lgd_writer.value.invalidations);
    __asm__ volatile("":::"memory");
}
void li2_lgd_before_raw(long n,long a,long b,long c,long d,long e,long f) {
    (void)f;
    if(lgd_writer.value.initialized!=1)return;
    /* Keep processing even after poison: protecting the epoch owner itself
       remains mandatory, and no old certificate may become valid again. */
    if(n==SYS_mprotect
#ifdef SYS_pkey_mprotect
       || n==SYS_pkey_mprotect
#endif
    ) {
        /* Even removing W from the epoch page would prevent the next
           invalidation write. Its protection is fixed for the whole run. */
        lgd_writer_range((uintptr_t)a,(size_t)b);
        if((unsigned long)c&(PROT_GROWSDOWN|PROT_GROWSUP)) {
            lgd_poison();lgd_advance(&lgd_writer.value.unclassified);
        }
        if((unsigned long)c&PROT_WRITE)lgd_exposure((uintptr_t)a,(size_t)b);
    } else if(n==SYS_mmap) {
        if((unsigned long)d&MAP_FIXED)lgd_exposure((uintptr_t)a,(size_t)b);
    } else if(n==SYS_munmap || n==SYS_madvise) {
        /* Even a non-destructive advice retires reuse conservatively. */
        lgd_exposure((uintptr_t)a,(size_t)b);
    } else if(n==SYS_mremap) {
        size_t extent=(size_t)b>(size_t)c?(size_t)b:(size_t)c;
        lgd_exposure((uintptr_t)a,extent);
        if((unsigned long)d&MREMAP_FIXED)lgd_exposure((uintptr_t)e,(size_t)c);
    }
}
static int lgd_epochs_live(void) {
    return lgd_writer.value.initialized==1 && !lgd_writer.value.poisoned &&
        selected_run_protect_contains(0,(uintptr_t)&lgd_writer,sizeof lgd_writer)==1;
}
static uint64_t lgd_root_epoch(void) {return lgd_writer.value.root;}
static uint64_t lgd_cell_epoch(unsigned i) {return i<LI2_PGD_RECEIPTS?lgd_writer.value.cell[i]:0;}
static uint64_t lgd_capsule_epoch(unsigned i) {return i<LI2_PGD_RECEIPTS?lgd_writer.value.capsule[i]:0;}
