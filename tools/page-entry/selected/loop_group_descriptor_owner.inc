/* One immutable group at the existing generated-directory address. Current
   activation order and claims remain separate from this canonical manifest. */
#define LGD_ROUND(n) (((n)+PAGE-1U)&~(size_t)(PAGE-1U))
struct lgd_member {
    struct li2_pgd_member value;
    struct sbc_certificate certificate;
    uint64_t exposure;
};
struct lgd_manifest {
    uint64_t version,id,exposure,directory_exposure;
    const struct li2_pg_epoch *owner;
    struct li2_step_session session;
    unsigned char archive[32],policy[32];
    unsigned count,reserved;
    struct lgd_member member[LI2_PGD_MEMBERS];
    uint64_t gpr_written,flags_written;
    struct li2_jd_domain_directory directory;
};
static union {
    struct lgd_manifest value;
    unsigned char pages[LGD_ROUND(sizeof(struct lgd_manifest))];
} lgd_group __attribute__((aligned(PAGE)));
static union {
    struct lgd_manifest value;
    unsigned char pages[LGD_ROUND(sizeof(struct lgd_manifest))];
} lgd_candidate __attribute__((aligned(PAGE)));
static struct {
    uint64_t issues,hits,topology_hits,topology_full,topology_differential;
    uint64_t common_hits,common_full,common_differential,history_fallbacks;
    uint64_t directory_writes,directory_queries,disagreements;
    uint64_t common_lhc_hits,common_revalidated_hits;
} lgd_counts;
_Static_assert(sizeof lgd_group%PAGE==0 && sizeof lgd_group<=16U*PAGE,
    "one fixed isolated group manifest, at most sixteen pages");
static uintptr_t lgd_manifest_address(void) {return (uintptr_t)&lgd_group;}
static size_t lgd_manifest_bytes(void) {return sizeof lgd_group;}
static int lgd_count(uint64_t *n) {
    if(*n==UINT64_MAX){lgd_poison();return PE_OVERFLOW;}
    ++*n;return 0;
}
static int lgd_history_fallback(void) {return lgd_count(&lgd_counts.history_fallbacks);}
/* Capture only an actually sealed, still-owned cell. The whole certificate
   includes owner/session/archive/policy and its original issuance identity;
   the separate epochs describe this new common proof, not a new LHC issue. */
static int lgd_common_snapshot(const struct pda_completion *c,unsigned i,
    struct lgd_common_token *out) {
    if(!out || !c || i>=LI2_PGD_RECEIPTS || lhc_index(c)!=i ||
       !c->id || c->id>pe.domain.next_id || !c->serial || c->serial>pe.next_serial ||
       !lgd_epochs_live() || !lhc_match_identity(c,i))return 0;
    uint64_t source_context=li2_lgd_source_context();
    if(!source_context || !pe.domain.directory || !lgd_root_epoch() || !lgd_certificate_epoch(i) ||
       !lgd_cell_epoch(i) || !lgd_capsule_epoch(i))return 0;
    le_zero(out,sizeof *out);
    out->valid=1;out->index=i;out->raw_root=lgd_root_epoch();
    out->raw_certificate=lgd_certificate_epoch(i);
    out->raw_cell=lgd_cell_epoch(i);out->raw_capsule=lgd_capsule_epoch(i);
    out->source_context=source_context;out->directory=pe.domain.directory;
    copy(&out->certificate,lhc_cell(i),sizeof out->certificate);
    return 1;
}
static int lgd_common_value(const struct pda_completion *c) {
    unsigned i=lhc_index(c);
    /* Current monotone owner bounds are checked even on an immutable-value
       hit. lhc_match binds the whole owner/session/policy, exact R cell and
       capsule, issuance serial, and all four raw exposure epochs. */
    int hit=c && c->id && c->id<=pe.domain.next_id && c->serial && c->serial<=pe.next_serial &&
        i<LI2_PGD_RECEIPTS && lhc_match(c,i);
    struct lgd_common_token before,after;
    int eligible=0,revalidated=0;
    if(!hit) {
        eligible=lgd_common_snapshot(c,i,&before);
        hit=eligible && equal(&before,&lgd_writer.value.common[i],sizeof before);
        revalidated=hit;
    }
    if(!hit) {
        if(lgd_count(&lgd_counts.common_full))return 0;
        int actual=pda_receipt_common_full(c);
        /* First issuance is writable and cannot reach this store. A changed
           owner/identity/exposure during the full proof cannot issue either. */
        if(actual && eligible && lgd_common_snapshot(c,i,&after) &&
           equal(&before,&after,sizeof before))
            copy(&lgd_writer.value.common[i],&after,sizeof after);
        return actual;
    }
    if(lgd_count(&lgd_counts.common_hits) ||
       lgd_count(revalidated?&lgd_counts.common_revalidated_hits:&lgd_counts.common_lhc_hits))return 0;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    if(lgd_count(&lgd_counts.common_differential) || !pda_receipt_common_full(c)) {
        (void)lgd_count(&lgd_counts.disagreements);return 0;
    }
#endif
    /* The caller still invokes lhc_direct_value exactly once. Its original
       witness restore/full comparator and complete scratch effects remain. */
    return 1;
}
static int lgd_initialize(void) {
    if(pe.initialized || !pe_busy || pe_active || lgd_writer.value.initialized ||
       protected_count>RANGES-4U || !pda_zero(&lgd_writer,sizeof lgd_writer) ||
       !pda_zero(&lgd_group,sizeof lgd_group) || !pda_zero(&lgd_candidate,sizeof lgd_candidate) ||
       !pda_zero(&lgd_counts,sizeof lgd_counts))return PE_STATE;
    if((uintptr_t)raw(SYS_mmap,(long)&lgd_writer,sizeof lgd_writer,PROT_READ|PROT_WRITE,
           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&lgd_writer ||
       (uintptr_t)raw(SYS_mmap,(long)&lgd_group,sizeof lgd_group,PROT_READ,
           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=(uintptr_t)&lgd_group ||
       selected_run_protect_add(0,(uintptr_t)&lgd_writer,sizeof lgd_writer) ||
       selected_run_protect_add(0,(uintptr_t)&lgd_group,sizeof lgd_group) ||
       selected_run_protect_add(0,(uintptr_t)&lgd_candidate,sizeof lgd_candidate) ||
       selected_run_protect_add(0,(uintptr_t)&lgd_counts,sizeof lgd_counts) ||
       lrc_readonly((uintptr_t)&lgd_group,sizeof lgd_group))return PE_PUBLICATION;
    /* All addresses are now fixed; no descriptor or completion can be issued
       before this point, and no guest has executed. */
    lgd_writer.value.root=lgd_writer.value.manifest=lgd_writer.value.directory=1;
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++)
        lgd_writer.value.certificate[i]=lgd_writer.value.cell[i]=lgd_writer.value.capsule[i]=1;
    for(unsigned i=0;i<PTR_NODE_COUNT;i++)lgd_writer.value.publication[i]=1;
    __asm__ volatile("":::"memory");lgd_writer.value.initialized=1;
    return 0;
}
/* The incoming signal is checked before handler() sets handling. This is
   the existing executing-owner checkpoint, not a second ordinary call phase. */
static int lgd_preentry_context(void) {
    return handling==0 && pe_active==1 && pe_busy==0 && pe_closing==0 && pe_decoding==0 &&
        pe_failing==0 && pe.resuming==0 && pe.redirected==1 &&
        pe.p.phase==LI2_PG_EXECUTING && pe.p.first_error==0 &&
        selected_pending_route==SELECTED_PERSISTENT_EPOCH && selected_step_pending==1 &&
        pe.domain.work.bound==1 && pe.domain.work.completion==0 && pe.domain.work.aborting==0;
}
static int lgd_manifest_live_context(unsigned preentry) {
    const struct lgd_manifest *g=&lgd_group.value;
    return lgd_epochs_live() && (preentry?lgd_preentry_context():handling==1) &&
        pe.initialized==1 && pe.registered==1 &&
        !pe_failing && !pe.resuming && pe_identity() && g->version==1 && g->id &&
        g->id<=lgd_writer.value.next_id && g->exposure==lgd_writer.value.manifest &&
        g->directory_exposure==lgd_writer.value.directory && g->owner==&pe &&
        g->count && g->count<=LI2_PGD_MEMBERS && !g->reserved &&
        equal(&g->session,&pe.session,sizeof pe.session) && equal(g->archive,pe_archive,32) &&
        equal(g->policy,pe_policy,32) && !lrc_readonly((uintptr_t)&lgd_group,sizeof lgd_group);
}
static int lgd_manifest_live(void) {return lgd_manifest_live_context(0);}
static int lgd_member_match(const struct li2_pgd_member *m,const struct lgd_member *saved) {
    unsigned slot=m->identity.slot;
#ifdef LI2_LOOP_TRANSLATION_ARENA
    if(ptr_node_index(slot)>=PTR_NODE_COUNT)return 0;
#endif
    if(slot>=LI2_PTR_SLOTS || !equal(m,&saved->value,sizeof *m) ||
       saved->exposure!=lgd_writer.value.publication[ptr_node_index(slot)] ||
       !saved->exposure || sg_owner.state.bytes.poisoned || sg_owner.state.bytes.writer[ptr_node_index(slot)])return 0;
    const struct sbc_certificate *c=&sg_owner.state.bytes.certificate[ptr_node_index(slot)];
    return c->valid==1 && !c->reserved && c->slot==ptr_node_index(slot) && c->bank==m->identity.bank &&
        c->generation==m->identity.generation && c->owner==&pe &&
        c->mirror_epoch==sg_owner.state.bytes.mirror_epoch[ptr_node_index(slot)] &&
        equal(c,&saved->certificate,sizeof *c);
}
/* A bijection, never a count-only or root-only membership test. The fresh
   primary-first source/rseq/claim view is not reordered or overwritten. */
static int lgd_view_match_context(const struct li2_pgd_view *v,unsigned preentry) {
    if(!v || !(preentry?lgd_manifest_live_context(1):lgd_manifest_live()) || v->count!=lgd_group.value.count || v->reserved ||
       v->directory!=pe.domain.directory || lrc_readonly((uintptr_t)&sg_owner,sizeof sg_owner))return 0;
    unsigned matched=0;
    for(unsigned i=0;i<v->count;i++) {
        unsigned found=LI2_PGD_MEMBERS;
        for(unsigned j=0;j<v->count;j++)if(lgd_member_match(&v->member[i],&lgd_group.value.member[j])) {
            if(found!=LI2_PGD_MEMBERS)return 0;
            found=j;
        }
        if(found>=v->count || (matched&(1U<<found)))return 0;
        matched|=1U<<found;
    }
    for(unsigned i=v->count;i<LI2_PGD_MEMBERS;i++)
        if(!pda_zero(&v->member[i],sizeof v->member[i]) ||
           !pda_zero(&lgd_group.value.member[i],sizeof lgd_group.value.member[i]))return 0;
    return matched==(1U<<v->count)-1U;
}
static int lgd_view_match(const struct li2_pgd_view *v) {return lgd_view_match_context(v,0);}
static int lgd_members(const struct li2_pgd_view *v) {
    int hit=lgd_view_match(v);
    /* Live pointer/storage/registry/rseq predicates are never certificates. */
    if(hit)for(unsigned i=0;i<v->count;i++)if(!pda_member_live(&v->member[i]))return 0;
    if(!hit) {
        if(lgd_count(&lgd_counts.topology_full))return 0;
        return lc8_members_full(v);
    }
    if(lgd_count(&lgd_counts.topology_hits))return 0;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    if(lgd_count(&lgd_counts.topology_differential) || !lc8_members_full(v)) {
        (void)lgd_count(&lgd_counts.disagreements);return 0;
    }
#endif
    return 1;
}
static int lgd_directory_current(void) {
    struct pda_work *w=&pe.domain.work;
    if(lgd_count(&lgd_counts.directory_queries))return PE_OVERFLOW;
    return pe_query(pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&w->descriptor_query);
}
static void lgd_canonical(const struct li2_pgd_view *view,struct li2_pgd_view *canonical) {
    *canonical=*view;
    for(unsigned i=1;i<canonical->count;i++) {
        struct li2_pgd_member member=canonical->member[i];unsigned j=i;
        while(j && canonical->member[j-1].identity.slot>member.identity.slot) {
            canonical->member[j]=canonical->member[j-1];--j;
        }
        canonical->member[j]=member;
    }
}
static int lgd_directory_equal_context(unsigned preentry) {
    const struct pda_work *w=&pe.domain.work;
    if(!w->descriptor_id)return !w->descriptor_epoch &&
        pda_zero(&w->descriptor_query,sizeof w->descriptor_query) && pda_directory_equal_full();
    if(!(preentry?lgd_view_match_context(&w->view,1):lgd_view_match(&w->view)) ||
       w->descriptor_id!=lgd_group.value.id ||
       w->descriptor_epoch!=lgd_group.value.exposure ||
       !pg_query_complete(&w->descriptor_query,pe.domain.directory,LI2_JD_DOMAIN_BYTES,PROT_READ) ||
       !equal(&w->directory,&lgd_group.value.directory,sizeof w->directory))return 0;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    struct li2_pgd_view canonical;
    lgd_canonical(&w->view,&canonical);
    struct li2_jd_domain_directory *rebuilt=&lgd_candidate.value.directory;
    le_zero(rebuilt,sizeof *rebuilt);
    if(pda_directory_value(&canonical,w->descriptor_id,rebuilt) ||
       !equal(rebuilt,&lgd_group.value.directory,sizeof *rebuilt)) {
        (void)lgd_count(&lgd_counts.disagreements);return 0;
    }
    const volatile unsigned char *b=(const void *)pe.domain.directory;
    const unsigned char *expected=(const void *)&lgd_group.value.directory;
    for(size_t i=0;i<LI2_JD_DOMAIN_BYTES;i++)if(b[i]!=(i<sizeof w->directory?expected[i]:0)) {
        (void)lgd_count(&lgd_counts.disagreements);return 0;
    }
#endif
    return 1;
}
static int lgd_directory_equal(void) {return lgd_directory_equal_context(0);}
static int lgd_directory_equal_preentry(void) {
    return lgd_preentry_context() && lgd_directory_equal_context(1);
}
static int lgd_directory(void) {
    struct pda_work *w=&pe.domain.work;
    if(w->directory.count || w->directory.version || w->directory.serial ||
       w->descriptor_id || w->descriptor_epoch ||
       !pda_zero(&w->descriptor_query,sizeof w->descriptor_query))return PE_STATE;
    if(lgd_view_match(&w->view)) {
        if(pe.gpr_written!=lgd_group.value.gpr_written || pe.flags_written!=lgd_group.value.flags_written)
            return PE_PLAN;
        w->directory=lgd_group.value.directory;
        w->descriptor_id=lgd_group.value.id;w->descriptor_epoch=lgd_group.value.exposure;
        if(lgd_count(&lgd_counts.hits))return PE_OVERFLOW;
        return lgd_directory_current();
    }
    /* A poisoned reuse owner may still take the complete original protocol;
       it cannot issue a new reusable descriptor or invent a transition. */
    if(!lgd_epochs_live())return pda_directory_seal_full();
    if(!lc8_members_full(&w->view) || lgd_writer.value.next_id==UINT64_MAX)return PE_STATE;
    struct li2_pgd_view canonical;
    lgd_canonical(&w->view,&canonical);
    uint64_t id=++lgd_writer.value.next_id;
    int error=pda_directory_value(&canonical,id,&w->directory);if(error)return error;
    error=pda_directory_publish();if(error)return error;
    if(lgd_count(&lgd_counts.directory_writes))return PE_OVERFLOW;
    /* Both the old full topology predicate and complete directory write,
       synchronization, physical seal and byte readback have succeeded. */
    if(raw(SYS_mprotect,(long)&lgd_group,sizeof lgd_group,PROT_READ|PROT_WRITE,0,0,0))return PE_PUBLICATION;
    le_zero(&lgd_candidate,sizeof lgd_candidate);
    struct lgd_manifest *next=&lgd_candidate.value;
    *next=(struct lgd_manifest){.id=id,.exposure=lgd_writer.value.manifest,
        .directory_exposure=lgd_writer.value.directory,.owner=&pe,.session=pe.session,
        .count=canonical.count,.gpr_written=pe.gpr_written,.flags_written=pe.flags_written,
        .directory=w->directory};
    copy(next->archive,pe_archive,32);copy(next->policy,pe_policy,32);
    for(unsigned i=0;i<canonical.count;i++) {
        unsigned slot=canonical.member[i].identity.slot;
#ifdef LI2_LOOP_TRANSLATION_ARENA
        if(ptr_node_index(slot)>=PTR_NODE_COUNT)return PE_STATE;
#endif
        next->member[i]=(struct lgd_member){.value=canonical.member[i],
            .certificate=sg_owner.state.bytes.certificate[ptr_node_index(slot)],
            .exposure=lgd_writer.value.publication[ptr_node_index(slot)]};
    }
    copy(&lgd_group,&lgd_candidate,sizeof lgd_group);
    __asm__ volatile("":::"memory");
    lgd_group.value.version=next->version=1; /* validity follows the complete manifest */
    if(raw(SYS_mprotect,(long)&lgd_group,sizeof lgd_group,PROT_READ,0,0,0) ||
       lrc_readonly((uintptr_t)&lgd_group,sizeof lgd_group) ||
       !equal(&lgd_group,&lgd_candidate,sizeof lgd_group) || !lgd_view_match(&w->view))return PE_PUBLICATION;
    w->descriptor_id=id;w->descriptor_epoch=lgd_group.value.exposure;
    if(lgd_count(&lgd_counts.issues))return PE_OVERFLOW;
    return lgd_directory_current();
}
static void lgd_common_cache_report(unsigned status,unsigned code) {
    struct writer w={.used=0};text(&w,"LI2_LOOP_COMMON_CACHE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"lhc_hits\":",lgd_counts.common_lhc_hits);
    field(&w,",\"revalidated_hits\":",lgd_counts.common_revalidated_hits);text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
static void lgd_report(unsigned status,unsigned code) {
    lgd_common_cache_report(status,code);
    struct writer w={.used=0};text(&w,"LI2_LOOP_GROUP_DESCRIPTOR {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"initialized\":",lgd_writer.value.initialized);
    field(&w,",\"poisoned\":",lgd_writer.value.poisoned);
    field(&w,",\"descriptor_id\":",lgd_group.value.id);
    field(&w,",\"writer_epoch\":",lgd_writer.value.manifest);
    field(&w,",\"raw_invalidations\":",lgd_writer.value.invalidations);
    field(&w,",\"unclassified\":",lgd_writer.value.unclassified);
    field(&w,",\"overflows\":",lgd_writer.value.overflows);
#define LGD_FIELD(n) field(&w,",\"" #n "\":",lgd_counts.n)
    LGD_FIELD(issues);LGD_FIELD(hits);LGD_FIELD(topology_hits);LGD_FIELD(topology_full);
    LGD_FIELD(topology_differential);LGD_FIELD(common_hits);LGD_FIELD(common_full);
    LGD_FIELD(common_differential);LGD_FIELD(history_fallbacks);LGD_FIELD(directory_writes);
    LGD_FIELD(directory_queries);LGD_FIELD(disagreements);
#undef LGD_FIELD
    text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
#undef LGD_ROUND
