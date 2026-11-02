#if LI2_LOOP_RO_CONTROL == 1
/* Actual focal publication, before its original byte decision resumes. A key
   miss is required to fall back to the original complete scan; it is not
   relabelled as a failed runtime authorization. All query/byte violations
   instead require the real pe_bytes() rejection. */
static void lro_byte_restored(void) {
    lro_need(equal(&sg_owner,lro.root,PAGE) &&
        equal(&PE_SLOT(publication),lro.mirror,PE_PROOF_BYTES) &&
        !lrc_readonly((uintptr_t)&sg_owner,PAGE) &&
        !lrc_readonly((uintptr_t)&PE_SLOT(publication),PE_PROOF_BYTES) &&
        sbc_match() && !pe_bytes(),20);
    ++lro.restorations;
}
static void lro_byte_decision(unsigned n,unsigned kind,int expected,int hit) {
    uint64_t hits=sbc_observed.hits,misses=sbc_observed.misses,scans=sbc_observed.full_scans;
    int result=pe_bytes();
    lro_need(result==expected && sbc_observed.hits==hits+(unsigned)hit &&
        sbc_observed.misses==misses+(unsigned)!hit && sbc_observed.full_scans==scans+1,21);
    lro_result(n,kind,(unsigned)expected,(unsigned)result);
}
static void lro_byte_root_restore(void) {
    lro_prot((uintptr_t)&sg_owner,PAGE,PROT_READ|PROT_WRITE);
    copy(&sg_owner,lro.root,PAGE);lro_prot((uintptr_t)&sg_owner,PAGE,PROT_READ);
}
static void lro_byte_hook(void) {
    /* Literal test selector comes from paired-v2 source_page0+512. It is
       compiled only in this separately bound test profile. */
    if(lro.busy || lro.started || !sbc_match() ||
       PE_SLOT(publication).source.entry!=UINT64_C(0x4000200))return;
    lro_need(lro.initialized==1 && lrc_live(),22);
    lro.busy=lro.started=1;lro.source_entry=PE_SLOT(publication).source.entry;
    const struct sbc_certificate *issued=&sg_owner.state.bytes.certificate[pe.selected_slot];
    lro.root_serial=issued->serial;lro.generation=issued->generation;lro.epoch=issued->mirror_epoch;
    lro.byte_warm=pe.warm;lro.byte_phase=pe.p.phase;lro.byte_build_serial=issued->build_serial;
    copy(lro.root,&sg_owner,PAGE);copy(lro.mirror,&PE_SLOT(publication),PE_PROOF_BYTES);
    lro_byte_restored();
    uintptr_t root=(uintptr_t)&sg_owner,mirror=(uintptr_t)&PE_SLOT(publication);
    unsigned number=0;
    /* Three real permission mismatches; complete scans still run in DIFF. */
    lro_prot(root,PAGE,PROT_READ|PROT_WRITE);lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_prot(root,PAGE,PROT_READ);lro_byte_restored();lro_mark(number++);
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ|PROT_WRITE);lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ);lro_byte_restored();lro_mark(number++);
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ|PROT_EXEC);lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ);lro_byte_restored();lro_mark(number++);
    /* Byte-identical file mappings cannot stand in for the actual anonymous R objects. */
    int fd=lro_file_mapping(root,PAGE,lro.root);lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_anonymous_restore(root,PAGE,lro.root,fd);lro_byte_restored();lro_mark(number++);
    fd=lro_file_mapping(mirror,PE_PROOF_BYTES,lro.mirror);lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_anonymous_restore(mirror,PE_PROOF_BYTES,lro.mirror,fd);lro_byte_restored();lro_mark(number++);
    /* One actual extra sealed-file mapping defeats the complete alias census. */
    const struct li2_sealed_identity *id=&sg_owner.state.bank[pe.selected_slot][pe.selected_bank];
    long alias=raw(SYS_mmap,0,PAGE,PROT_READ,MAP_SHARED,id->fd,PE_CODE_BYTES);
    lro_need(alias>0 && !((uintptr_t)alias&(PAGE-1)),23);
    lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_need(!raw(SYS_munmap,alias,PAGE,0,0,0,0),24);lro_byte_restored();lro_mark(number++);
    /* Eleven single-coordinate key changes. The mandatory old fallback is
       successful, but the issued certificate may not be counted as a hit. */
    for(unsigned kind=0;kind<11;kind++) {
        lro_prot(root,PAGE,PROT_READ|PROT_WRITE);
        struct sbc_owner *o=&sg_owner.state.bytes;
        struct sbc_certificate *c=&o->certificate[pe.selected_slot];
        switch(kind) {
        case 0:c->generation^=1;break;
        case 1:c->mirror_epoch^=1;break;
        case 2:o->mirror_epoch[pe.selected_slot]^=1;break;
        case 3:c->bank^=1;break;
        case 4:((unsigned char *)&c->session)[0]^=1;break;
        case 5:c->owner=0;break;
        case 6:c->mirror+=PAGE;break;
        case 7:c->mirror_bytes^=1;break;
        case 8:c->build_serial^=1;break;
        case 9:c->valid=0;break;
        default:o->writer[pe.selected_slot]=pe.p.serial;break;
        }
        lro_prot(root,PAGE,PROT_READ);lro_need(!sbc_match(),25);lro_byte_decision(number,LRO_DECLINE_SCAN,0,0);
        lro_byte_root_restore();lro_byte_restored();lro_mark(number++);
    }
    /* A partial publication is not a read-only live root, even if unchanged
       bytes happen to pass the independent complete scan. */
    lro_prot(root,PAGE,PROT_READ|PROT_WRITE);sg_owner.state.ro_writable_mask=1U<<pe.selected_slot;
    lro_prot(root,PAGE,PROT_READ);lro_byte_decision(number,LRO_REJECT,PE_PUBLICATION,0);
    lro_byte_root_restore();lro_byte_restored();lro_mark(number++);
    /* Ordinary kernel writes must fail or stop precisely before the R extent. */
    long result=lro_kernel_write(root,0);lro_result(number,LRO_KERNEL_EFAULT,EFAULT,(unsigned)-result);
    lro_byte_restored();lro_mark(number++);
    result=lro_kernel_write(mirror+PE_PROOF_BYTES-1,0);
    lro_result(number,LRO_KERNEL_EFAULT,EFAULT,(unsigned)-result);lro_byte_restored();lro_mark(number++);
    result=lro_kernel_write(mirror,1);lro_result(number,LRO_KERNEL_PARTIAL,1,(unsigned)result);
    lro_byte_restored();lro_mark(number++);
    /* Corrupt an authenticated source byte in the mirror while preserving the
       issued key and then restore R. Every-hit DIFF must catch the true byte
       disagreement; no test counter is reset afterward. */
    uint64_t disagreements=sbc_observed.disagreements;
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ|PROT_WRITE);
    PE_SLOT(publication).source.page[0].bytes[0]^=1;
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ);lro_byte_decision(number,LRO_DIFF_REJECT,PE_PUBLICATION,1);
    lro_need(sbc_observed.disagreements==disagreements+1,26);
    lro_prot(mirror,PE_PROOF_BYTES,PROT_READ|PROT_WRITE);
    copy((void *)mirror,lro.mirror,PE_PROOF_BYTES);lro_prot(mirror,PE_PROOF_BYTES,PROT_READ);
    lro_byte_restored();lro_mark(number++);
    lro_need(number==22 && lro.checks==22 && lro.restorations==23 &&
        lro.passed==(UINT64_C(1)<<22)-1,27);
    lro.complete=1;
    selected_persistent_abort(PE_PUBLICATION,LRO_STOP_BYTE);
}
#else
static void lro_byte_hook(void) {}
#endif
