/* Private actual-owner qualification profile only. Included after the complete
   controller; exact guarded seams are separately inverse-bound. Fixed fixture
   memory snapshots are diagnostic only and give no execution authority. */
#if LI2_SCALAR_REGION_CAPTURE != 1 || LI2_SCALAR_REGION != 1 || LI2_UNROLLED_HASH != 1
#error "capture requires the explicit scalar-region qualification profile"
#endif
#include "scalar_region_capture_config.h"
#ifndef LI2_REGION_APP_HEAD_RVA
#error "actual retained application ELF symbol RVA is required"
#endif
#ifdef LI2_SCALAR_REGION_OBSERVE_ONLY
#error "actual-owner qualification is separate from observation-only timing"
#endif
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "scalar_region_observe_memory.h"
#include "unrolled_hash_nested_fp.h"
#define SRO_ROWS 2U
#define SRO_MAGIC UINT64_C(0x31524f534c49324c)
#define SRO_FOOTER UINT64_C(0x314652534c49324c)
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
#include "scalar_reuse_certificate_observe.h"
#endif
enum { SRO_NORMAL=0,SRO_NESTED=1,SRO_OPEN_ERROR=2,SRO_CLOSE_ERROR=3,
    SRO_SYNC_ERROR=4,SRO_SLOT_IDENTITY=5,SRO_ENTRY_INTERIOR=6,SRO_EXIT_INTERIOR=7,SRO_TICKET=8,SRO_GENERATION=9,SRO_SOURCE_BYTE=10,
    SRO_MAP=11,SRO_WRITE_ALIAS=12,SRO_SOURCE_RX=13,SRO_DECODER_PREFIX=14 };
#ifdef LI2_SCALAR_REGION_REUSE
enum { SRO_STALE_GENERATION=15,SRO_RETIRED_CODE=16,SRO_CONSUMED_PERMIT=17 };
struct sro_reuse_control {
    unsigned started,mutated;
    uint64_t generation_before,generation_after;
    size_t copied;
    struct srr_permit permit_before,permit_after;
    struct sr_permission writable,closed;
};
#endif
struct sro_owners {
    unsigned captured,word_observed;
    uint64_t word;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_progress pair;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct sro_entry {
    uint64_t present,ordinal,committed,terminal,source_bytes,generated_bytes,slot_observed;
    uint64_t global_before[5],global_after[5];
    struct sr_record owner;
    struct sr_frame redirected;
    struct li2_sro_memory before_memory,after_memory;
    struct sro_owners redirected_owners,completed_owners;
    unsigned char source_page[PAGE],generated_page[PAGE],terminal_source_page[PAGE];
    uint64_t terminal_source_bytes;
#ifdef LI2_SCALAR_REGION_REUSE
    /* Resident slots can later be retired. These actual focal facts are values,
       never pointers into the mutable resident table. */
    uint64_t reuse_generation;
    struct srr_permit reuse_claim;
    struct sr_slot reuse_slot;
    struct srr_retirement reuse_retirement;
#endif
};
struct sro_wire {
    uint64_t h[64],control[40],focal[5],focal_exits[LI2_REGION_EXITS];
    struct stat sink_initial,sink_terminal,main_backing;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    __typeof__(selected_scalar_region) owner;
    struct sro_owners terminal_owners;
    struct li2_fetch_progress terminal_fetch;
    struct li2_native_close terminal_global_close;
    struct li2_native_counts terminal_native_counts;
    struct sro_entry entries[SRO_ROWS];
    struct sr_frame supplied_before;
    struct sr_record control_before;
    unsigned char original_source[LI2_REGION_PAGE];
    unsigned char generated[SR_PAGES][PAGE];
    struct uho_nested_fp nested_fp;
#ifdef LI2_SCALAR_REGION_REUSE
    __typeof__(srr) reuse;
    struct sro_reuse_control reuse_control;
    unsigned char reuse_pending_page[PAGE];
    uint64_t reuse_pending_bytes;
#endif
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    struct srco_wire certificate;
#endif
};
static struct sro_wire sro_wire;
static const uint64_t sro_nested_zero_alignment __attribute__((used))=
    __alignof__(((struct uho_nested_fp *)0)->zero);
static const uint64_t sro_nested_ones_alignment __attribute__((used))=
    __alignof__(((struct uho_nested_fp *)0)->ones);
static unsigned sro_ready,sro_finished,sro_current=SRO_ROWS;
static uintptr_t sro_head,sro_alias;
static unsigned sro_source_rx;
static const uint64_t sro_step_frame_fp_alignment __attribute__((used))=
    __alignof__(((struct li2_step_frame *)0)->fp);
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
_Static_assert(sizeof(struct sro_wire)+64<16*1024*1024,"whole certificate record and footer below original16MiB cap");
#else
_Static_assert(sizeof(struct sro_wire)<8*1024*1024,"fixed private owner record below unchanged16MiB ceiling");
#endif
static void sro_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
#include "scalar_reuse_certificate_observe.inc"
#endif
static void sro_owners(struct sro_owners *out,unsigned just_checked) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    const struct li2_rseq_native_state *n=li2_rseq_native_snapshot();
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *q=li2_rseq_pair_progress();
    if(!r || !n || !p || !l || !q)return;
    sro_copy(&out->rseq,r,sizeof(*r));sro_copy(&out->rseq_native,n,sizeof(*n));
    sro_copy(&out->pair,p,sizeof(*p));sro_copy(&out->lifecycle,l,sizeof(*l));
    sro_copy(&out->rseq_pair,q,sizeof(*q));out->captured=1;
    /* Only redirected follows the existing final successful source/rseq
       guard with no intervening RAW. Completion/terminal never dereference a
       possibly historical application pointer or invent a new guard result. */
    if(just_checked && r->initialized==1 && r->registered==1 && r->held==1 &&
       r->phase==LI2_RSEQ_ACTIVE && r->address && r->address<=UINTPTR_MAX-16) {
        out->word=*(const volatile uint64_t *)(r->address+8);out->word_observed=1;
    }
}
static int sro_same_sink(const struct stat *s) {
    const struct stat *a=&sro_wire.sink_initial;
    return s->st_dev==a->st_dev && s->st_ino==a->st_ino && s->st_mode==a->st_mode &&
        s->st_uid==a->st_uid && s->st_gid==a->st_gid && s->st_nlink==a->st_nlink;
}
static void sro_initialize(void) {
    __asm__ volatile(""::"r"(&sro_step_frame_fp_alignment),
        "r"(&sro_nested_zero_alignment),"r"(&sro_nested_ones_alignment):"memory");
    sr_need(!sro_ready && !sro_finished,SR_STATE,101);
    sro_wire.h[0]=SRO_MAGIC;
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    sro_wire.h[1]=3;
#elif defined(LI2_SCALAR_REGION_REUSE)
    sro_wire.h[1]=2;
#else
    sro_wire.h[1]=1;
#endif
    sro_wire.h[2]=sizeof sro_wire;
    sro_wire.h[3]=sizeof selected_scalar_region;sro_wire.h[4]=sizeof(struct sro_entry);
    sro_wire.h[5]=sizeof(struct sr_record);sro_wire.h[6]=sizeof(struct sr_frame);
    sro_wire.h[7]=sizeof(ucontext_t);sro_wire.h[8]=sizeof(siginfo_t);
    sro_wire.h[9]=(uintptr_t)li2_raw6;sro_wire.h[10]=(uintptr_t)li2_gateway_start;
    sro_wire.h[11]=(uintptr_t)li2_gateway_end;
    sro_wire.h[12]=(uintptr_t)fork_gate_stack.ss_sp;sro_wire.h[13]=fork_gate_stack.ss_size;
    sr_need(!selected_run_protect_add(0,(uintptr_t)&sro_wire,sizeof sro_wire),SR_STATE,102);
    sro_wire.h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&sro_wire.sink_initial,0,0,0,0);
    sro_wire.h[15]=(uint64_t)fdflags;sro_wire.h[16]=(uint64_t)flags;sro_wire.h[17]=(uint64_t)result;
    sr_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(sro_wire.sink_initial.st_mode) && (sro_wire.sink_initial.st_mode&07777)==0600 &&
        sro_wire.sink_initial.st_nlink==1 && sro_wire.sink_initial.st_size==0,SR_STATE,103);
    sro_wire.h[18]=1;
    const char *control=fork_env("LI2_SCALAR_REGION_CAPTURE_CONTROL");
#ifdef LI2_SCALAR_REGION_REUSE
    sr_need(control && ((control[0]>='0' && control[0]<='9') || (control[0]>='a' && control[0]<='h')) && !control[1],SR_STATE,104);
#else
    sr_need(control && ((control[0]>='0' && control[0]<='9') || (control[0]>='a' && control[0]<='e')) && !control[1],SR_STATE,104);
#endif
    sro_wire.control[0]=(unsigned)(control[0]<='9'?control[0]-'0':10+control[0]-'a');
    sro_wire.main=original_main;sro_wire.interpreter=original_interpreter;
    sro_copy(&sro_wire.hardware,&selected_hardware,sizeof selected_hardware);
    sr_need(original_main.kind==IMAGE_MAIN && original_main.source && original_main.n &&
        original_main.n<=MAX_PHDR && original_main.bias<=UINTPTR_MAX-LI2_REGION_APP_HEAD_RVA,
        SR_STATE,105);
    sro_head=original_main.bias+LI2_REGION_APP_HEAD_RVA;
    sr_need(sro_head>=PAGE && sro_head<(UINT64_C(1)<<47)-15 &&
        (sro_head&(PAGE-1))<=PAGE-15,SR_STATE,106);
    unsigned found=0;size_t offset=0;
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];uint64_t rva=LI2_REGION_APP_HEAD_RVA&~UINT64_C(4095);
        if(p->p_type!=PT_LOAD || rva<p->p_vaddr || rva-p->p_vaddr>=p->p_filesz)continue;
        sr_need(!found && p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size && p->p_filesz<=original_main.source_size-p->p_offset &&
            p->p_filesz-(rva-p->p_vaddr)>=PAGE,SR_STATE,107);
        offset=(size_t)(p->p_offset+rva-p->p_vaddr);found=1;
    }
    sr_need(found,SR_STATE,108);
    sro_copy(sro_wire.original_source,original_main.source+offset,PAGE);
    result=raw(SYS_fstat,original_main.backing_fd,(long)&sro_wire.main_backing,0,0,0,0);
    sro_wire.h[19]=(uint64_t)result;sr_need(!result && S_ISREG(sro_wire.main_backing.st_mode),SR_STATE,109);
    sro_wire.h[20]=sro_head;sro_wire.h[21]=offset;sro_wire.h[22]=dependency_count;
#ifdef LI2_SCALAR_REGION_REUSE
    sro_wire.h[56]=vdso_first;sro_wire.h[57]=vdso_end;
#endif
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    srco_initialize();
#endif
    __asm__ volatile("":::"memory");sro_ready=1;sro_wire.h[23]=1;
}
/* Only the fixed diagnostic application profile is narrowed here. FD3 and
   actual aliases are not application channels. Write-capable openat cannot
   truncate this private regular-file sink through /proc/self/fd/3. */
static void sro_fd_guard(long n,const long a[6]) {
    if(!sro_ready)return;
    sr_need(!sro_finished,SR_STATE,110);
    sr_count(&sro_wire.h[43]);
    if(n==SYS_openat) {
        sr_count(&sro_wire.h[46]);
        int writable=(a[2]&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) || (a[2]&O_TMPFILE)==O_TMPFILE;
        if(writable)sro_wire.h[49]=1;
        sr_need(!writable,SR_STATE,111);
    }
    long fd=-1;
    switch(n) {
    case SYS_read:case SYS_write:case SYS_readv:case SYS_writev:case SYS_close:
    case SYS_fstat:case SYS_fstatfs:case SYS_lseek:case SYS_pread64:case SYS_getdents64:
    case SYS_fgetxattr:case SYS_flistxattr:case SYS_fcntl:case SYS_openat:
    case SYS_newfstatat:case SYS_statx:case SYS_faccessat:case SYS_faccessat2:case SYS_readlinkat:
    case SYS_dup:case SYS_dup2:case SYS_dup3:fd=a[0];break;
    case SYS_mmap:if(!(a[3]&MAP_ANONYMOUS))fd=a[4];break;
    default:break;
    }
    if(n==SYS_dup2 || n==SYS_dup3)sr_need((unsigned)a[1]!=3,SR_STATE,112);
    if((int)fd<0)return;
    if((unsigned)fd==3)sro_wire.h[48]=1;
    sr_need((unsigned)fd!=3,SR_STATE,113);sr_count(&sro_wire.h[44]);
    struct stat observed={0};long result=raw(SYS_fstat,fd,(long)&observed,0,0,0,0);
    sr_need(!result || result==-9,SR_STATE,121);
    if(result)sr_count(&sro_wire.h[45]);
    if(!result && observed.st_dev==sro_wire.sink_initial.st_dev &&
       observed.st_ino==sro_wire.sink_initial.st_ino)sro_wire.h[48]=1;
    sr_need(result || observed.st_dev!=sro_wire.sink_initial.st_dev ||
        observed.st_ino!=sro_wire.sink_initial.st_ino,SR_STATE,114);
    /* Failure to inspect an already-invalid descriptor grants no access to
       the sink; the unchanged real operation still returns its actual error. */
}
static int sro_focal(void) {return sro_ready && selected_scalar_region.current.source.key.entry==sro_head;}
static int sro_start(unsigned kind,unsigned stage) {
    if(!sro_ready || sro_wire.control[0]!=kind || sro_wire.control[2])return 0;
    sro_wire.control[1]=stage;sro_wire.control[2]=1;
    sro_copy(&sro_wire.control_before,&selected_scalar_region.current,sizeof sro_wire.control_before);
    return 1;
}
static void sro_mutate_si(int sig,siginfo_t *si,ucontext_t *uc,unsigned kind,unsigned stage) {
    if(!sro_start(kind,stage))return;
    sr_need(!sr_capture(&sro_wire.supplied_before,sig,si,uc),SR_FRAME,100);
    sro_wire.control[6]=(uintptr_t)si->si_addr;
    si->si_addr=(void *)((uintptr_t)si->si_addr+1);
    sro_wire.control[7]=(uintptr_t)si->si_addr;sro_wire.control[3]=1;
}
static void sro_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    if(sro_focal() && selected_scalar_region_active && !selected_scalar_region_busy &&
       !handling && sr_range(si,sizeof(*si)) && sr_range(uc,sizeof(*uc)) && sig==SIGSEGV &&
       selected_scalar_region.current.slot_present && selected_scalar_region.current.slot<selected_scalar_region.used &&
       sr_exit_index(&selected_scalar_region.slots[selected_scalar_region.current.slot].plan,
           (uintptr_t)uc->uc_mcontext.gregs[REG_RIP])>=0 &&
       (uintptr_t)si->si_addr==(uintptr_t)uc->uc_mcontext.gregs[REG_RIP])
        sro_mutate_si(sig,si,uc,SRO_EXIT_INTERIOR,7);
}
static void sro_entry_frame(int sig,siginfo_t *si,ucontext_t *uc) {
    sro_current=SRO_ROWS;
    if(sro_ready && sr_range(uc,sizeof(*uc)) && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==sro_head)
        sro_mutate_si(sig,si,uc,SRO_ENTRY_INTERIOR,6);
}
static void sro_source(void) {
    struct sr_record *r=&selected_scalar_region.current;if(!sro_focal())return;
    sr_need(r->source.ready==1 && r->source.key.page.object==dependency_count &&
        r->source.key.backing.stat.st_dev==sro_wire.main_backing.st_dev &&
        r->source.key.backing.stat.st_ino==sro_wire.main_backing.st_ino &&
        r->source.key.backing.stat.st_size==sro_wire.main_backing.st_size &&
        equal(r->source.key.bytes,sro_wire.original_source,PAGE),SR_SOURCE,100);
    sr_need(sro_wire.h[24]<SRO_ROWS,SR_STATE,115);
    sro_current=(unsigned)sro_wire.h[24]++;struct sro_entry *e=&sro_wire.entries[sro_current];
    e->present=1;e->ordinal=sro_current;
    e->global_before[0]=selected_scalar_region.publications;e->global_before[1]=selected_scalar_region.hits;
    e->global_before[2]=selected_scalar_region.entries;e->global_before[3]=selected_scalar_region.completed;
    e->global_before[4]=selected_scalar_region.used;
    sro_copy(e->source_page,(void *)r->source.key.page.address,PAGE);e->source_bytes=PAGE;
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    srco_source(sro_current);
#endif
    int error=li2_lifecycle_scalar_region_observe_memory((uintptr_t)r->before.frame.greg[REG_RSP],
        SRO_MEMORY_LIVE,&r->source.key,0,&e->before_memory);
    sr_need(!error && e->before_memory.complete,SR_STATE,122);
    unsigned c=(unsigned)sro_wire.control[0];
    if(c>=SRO_TICKET && c<=SRO_SOURCE_BYTE && sro_start(c,8)) {
        uint64_t *p=c==SRO_TICKET?&r->source.borrow.sequence:&r->source.key.page.generation;
        if(c==SRO_SOURCE_BYTE) {
            sro_wire.control[6]=r->source.key.bytes[PAGE-1];r->source.key.bytes[PAGE-1]^=1;
            sro_wire.control[7]=r->source.key.bytes[PAGE-1];
        } else {sro_wire.control[6]=*p;*p^=UINT64_C(0x8000000000000000);sro_wire.control[7]=*p;}
        sro_wire.control[3]=1;
    }
    if(c==SRO_WRITE_ALIAS && sro_start(c,9)) {
        sro_wire.control[23]=1;
        long result=raw(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,
            r->source.key.backing.retained_fd,r->source.key.page.offset);
        sro_wire.control[24]=1;sro_wire.control[25]=(uint64_t)result;
        sr_need(result>0 && !(result&(PAGE-1)),SR_STATE,127);sro_alias=(uintptr_t)result;
        sro_wire.control[3]=1;
    }
    if(c==SRO_SOURCE_RX && sro_start(c,10)) {
        sro_wire.control[23]=1;
        long result=raw(SYS_mprotect,r->source.key.page.address,PAGE,PROT_READ|PROT_EXEC,0,0,0);
        sro_wire.control[24]=1;sro_wire.control[25]=(uint64_t)result;
        sr_need(!result,SR_STATE,128);sro_source_rx=1;sro_wire.control[3]=1;
    }
}
#ifdef LI2_SCALAR_REGION_REUSE
static void sro_reuse_slot(struct sr_slot *s) {
    struct sr_record *r=&selected_scalar_region.current;
    struct sro_entry *e=&sro_wire.entries[sro_current];
    struct srr_retirement *t=&srr.retirement;
    unsigned kind=(unsigned)sro_wire.control[0];
    if(kind>=SRO_STALE_GENERATION && kind<=SRO_CONSUMED_PERMIT && sro_start(kind,kind-2)) {
        struct sro_reuse_control *c=&sro_wire.reuse_control;c->started=1;
        /* Each negative supplies an actual retired/consumed authority. Missing
           replacement history is an unqualified control, never a fake stale ID. */
        sr_need(r->build_started && t->replaced==1 && t->slot==r->slot &&
            t->new_generation==r->publication_generation && t->old_generation &&
            t->old_generation<t->new_generation && srr_claimed() &&
            srr.claimed.valid==1 && srr.claimed.generation==t->old_generation &&
            srr.claimed.completion==t->completion,SR_STATE,317);
        c->generation_before=r->publication_generation;
        sro_copy(&c->permit_before,&srr.permits[r->slot],sizeof c->permit_before);
        if(kind==SRO_STALE_GENERATION)r->publication_generation=t->old_generation;
        else if(kind==SRO_CONSUMED_PERMIT)
            sro_copy(&srr.permits[r->slot],&srr.claimed,sizeof srr.claimed);
        else {
            sr_need(!equal(s->plan.image,t->old_slot.plan.image,PAGE),SR_STATE,318);
            sr_need(!srr_permission(srr.target,PROT_READ|PROT_WRITE,&c->writable),SR_PUBLICATION,304);
            volatile unsigned char *p=(void *)srr.target;
            for(size_t i=0;i<PAGE;i++){p[i]=t->old_slot.plan.image[i];c->copied=i+1;}
            sr_need(!srr_permission(srr.target,PROT_READ,&c->closed),SR_PUBLICATION,305);
        }
        c->generation_after=r->publication_generation;
        sro_copy(&c->permit_after,&srr.permits[r->slot],sizeof c->permit_after);
        c->mutated=1;sro_wire.control[3]=1;
    }
    e->reuse_generation=srr.live[r->slot];
    sro_copy(&e->reuse_claim,&srr.claimed,sizeof e->reuse_claim);
    sro_copy(&e->reuse_slot,s,sizeof e->reuse_slot);
    if(r->build_started && t->replaced==1 && t->slot==r->slot &&
       t->new_generation==e->reuse_generation)
        sro_copy(&e->reuse_retirement,t,sizeof e->reuse_retirement);
}
#endif
static void sro_slot(struct sr_slot *s) {
    if(sro_focal()) {
        sr_need(sro_current<SRO_ROWS,SR_STATE,129);
        struct sro_entry *e=&sro_wire.entries[sro_current];sr_need(!e->slot_observed,SR_STATE,130);
        e->slot_observed=1;
        if(selected_scalar_region.current.build_started)sr_count(&sro_wire.focal[0]);
        else sr_count(&sro_wire.focal[1]);
        if(sro_start(SRO_MAP,11)) {
            sro_wire.control[6]=s->plan.map[0].original_pc;s->plan.map[0].original_pc++;
            sro_wire.control[7]=s->plan.map[0].original_pc;sro_wire.control[3]=1;
        }
    }
    if(sro_focal() && sro_start(SRO_SLOT_IDENTITY,5)) {
        sro_wire.control[6]=s->identity;s->identity^=UINT64_C(0x8000000000000000);
        sro_wire.control[7]=s->identity;sro_wire.control[3]=1;
    }
#ifdef LI2_SCALAR_REGION_REUSE
    if(sro_focal())sro_reuse_slot(s);
#endif
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    if(sro_focal())srco_slot(sro_current);
#endif
}
static void sro_filter(unsigned kind,uintptr_t entry) {
    /* Fixed exact address, length and protection; existing native seccomp
       already authenticates architecture/private gateway. No fake result. */
    uint32_t prot=kind==SRO_OPEN_ERROR?PROT_READ|PROT_EXEC:PROT_READ;
    struct sock_filter protect[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,13),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)entry,0,11),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,20),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(entry>>32),0,9),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,24),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PAGE,0,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,28),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,32),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,prot,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,36),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|13),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_filter sync[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_membarrier,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,32,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,20),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|13),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog p={.len=(unsigned short)(kind==SRO_SYNC_ERROR?8:16),
        .filter=kind==SRO_SYNC_ERROR?sync:protect};
    sro_wire.control[8]=entry;sro_wire.control[9]=PAGE;sro_wire.control[10]=prot;
    sro_wire.control[11]=kind==SRO_SYNC_ERROR?SYS_membarrier:SYS_mprotect;
    sro_wire.control[12]=1;long result=raw(SYS_prctl,38,1,0,0,0,0);
    sro_wire.control[13]=1;sro_wire.control[14]=(uint64_t)result;sr_need(!result,SR_STATE,116);
    sro_wire.control[15]=1;result=raw(SYS_prctl,22,2,(long)&p,0,0,0);
    sro_wire.control[16]=1;sro_wire.control[17]=(uint64_t)result;sr_need(!result,SR_STATE,117);
    sro_wire.control[3]=1;
}
static void sro_before_open(struct sr_slot *s) {
    unsigned c=(unsigned)sro_wire.control[0];
    if(sro_focal() && c>=SRO_OPEN_ERROR && c<=SRO_SYNC_ERROR && sro_start(c,2))
        sro_filter(c,s->plan.generated);
}
static _Noreturn void sro_nested(void);
static void sro_redirected(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!sro_focal())return;
    sr_need(sro_current<SRO_ROWS,SR_STATE,118);struct sro_entry *e=&sro_wire.entries[sro_current];
    sr_need(!sr_capture(&e->redirected,sig,si,uc),SR_FRAME,101);
    const struct sr_record *r=&selected_scalar_region.current;
    sro_owners(&e->redirected_owners,1);sr_count(&sro_wire.focal[2]);
    sro_copy(e->generated_page,(void *)selected_scalar_region.slots[r->slot].plan.generated,PAGE);
    e->generated_bytes=PAGE;sro_copy(&e->owner,r,sizeof(*r));
    if(sro_start(SRO_NESTED,1))sro_nested();
}
static _Noreturn void sro_nested(void) {
        /* Actual pre-arm CPUID facts are already protected in wire.hardware.
           CPUID itself is disabled now. Guard XGETBV and then read live handler
           PKRU; neither instruction changes PKRU, FP state or a saved frame. */
        const struct li2_selected_hardware *h=&sro_wire.hardware;
        sr_need(h->abi_version==1 && !h->reserved && h->leaf0[0]>=7 &&
            (h->leaf1[2]&UINT32_C(0x0c000000))==UINT32_C(0x0c000000),SR_STATE,124);
        uint32_t a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
        uint64_t xcr0=(uint64_t)a|((uint64_t)d<<32);
        sro_wire.control[21]=xcr0;sro_wire.control[22]=1;
        if(xcr0&(UINT64_C(1)<<9)) {
            sr_need((h->leaf7[2]&24U)==24U,SR_STATE,125);
            __asm__ volatile("rdpkru":"=a"(a),"=d"(d):"c"(0):"memory");
            sro_wire.control[18]=a;sro_wire.control[19]=d;sro_wire.control[20]=1;
        }
        sro_wire.control[6]=selected_session.pid;sro_wire.control[7]=selected_session.tid;
        sro_wire.control[8]=SIGTRAP;sro_wire.control[12]=1;
        /* Qualification injects a real nested owner event outside a maps RAW
           transaction. Use the same registered kernel gateway directly: this
           pointer-free tgkill changes no mappings. The terminal reader still
           requires the whole nested frame, nonreturn and complete cleanup. */
        struct uho_nested_fp *f=&sro_wire.nested_fp;
        sr_need((xcr0==UINT64_C(0xe7) || xcr0==UINT64_C(0x2e7)) &&
            !f->h[0] && fork_gate_stack.ss_size==sizeof f->stack &&
            (uintptr_t)fork_gate_stack.ss_sp<=UINTPTR_MAX-fork_gate_stack.ss_size,
            SR_STATE,126); /* Fixed nondynamic user-state profile only. */
        f->h[0]=1;f->h[3]=(uintptr_t)fork_gate_stack.ss_sp;f->h[4]=fork_gate_stack.ss_size;
        f->h[7]=xcr0;f->h[8]=selected_session.pid;f->h[9]=selected_session.tid;
        f->h[10]=SIGTRAP;f->h[11]=xcr0;
        long result=uho_nested_raw(f,selected_session.pid,selected_session.tid,SIGTRAP,0,0,0);
        sro_wire.control[13]=1;sro_wire.control[14]=(uint64_t)result;
        sr_need(0,SR_STATE,119); /* A real nested terminal event must not return. */
    __builtin_unreachable();
}
static void sro_decoder_prefix(void) {
    if(sro_focal() && sro_start(SRO_DECODER_PREFIX,12))sro_nested();
}
static void sro_complete(void) {
    if(!sro_focal())return;
    sr_need(sro_current<SRO_ROWS,SR_STATE,120);struct sro_entry *e=&sro_wire.entries[sro_current];
    sro_owners(&e->completed_owners,0);
    int error=li2_lifecycle_scalar_region_observe_memory(
        (uintptr_t)selected_scalar_region.current.after.frame.greg[REG_RSP],SRO_MEMORY_LIVE,
        &selected_scalar_region.current.source.key,0,&e->after_memory);
    sr_need(!error && e->after_memory.complete && e->after_memory.stack_full,SR_STATE,123);
    sro_copy(e->terminal_source_page,(void *)selected_scalar_region.current.source.key.page.address,PAGE);
    e->terminal_source_bytes=PAGE;
    sro_copy(&e->owner,&selected_scalar_region.current,sizeof e->owner);e->committed=1;
    ++sro_wire.h[25];sr_count(&sro_wire.focal[3]);
    sr_need(selected_scalar_region.current.exit_index<LI2_REGION_EXITS,SR_STATE,131);
    sr_count(&sro_wire.focal_exits[selected_scalar_region.current.exit_index]);
    e->global_after[0]=selected_scalar_region.publications;e->global_after[1]=selected_scalar_region.hits;
    e->global_after[2]=selected_scalar_region.entries;e->global_after[3]=selected_scalar_region.completed;
    e->global_after[4]=selected_scalar_region.used;
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    srco_complete(sro_current);
#endif
}
static void sro_abort_observe(void) {
    if(!sro_ready)return;
    struct sr_record *r=&selected_scalar_region.current;struct sr_frame *f=&r->unexpected;
    if(sro_alias) {
        sro_wire.control[26]=1;long v=raw(SYS_munmap,sro_alias,PAGE,0,0,0,0);
        sro_wire.control[27]=1;sro_wire.control[28]=(uint64_t)v;
        if(v){if(!sro_wire.h[39])sro_wire.h[39]=4;}else sro_alias=0;
    }
    if(sro_source_rx) {
        sro_wire.control[26]=1;long v=raw(SYS_mprotect,r->source.key.page.address,PAGE,PROT_READ,0,0,0);
        sro_wire.control[27]=1;sro_wire.control[28]=(uint64_t)v;
        sro_wire.control[29]=1;long sync=raw(SYS_membarrier,32,0,0,0,0,0);
        sro_wire.control[30]=1;sro_wire.control[31]=(uint64_t)sync;
        if(v || sync){if(!sro_wire.h[39])sro_wire.h[39]=4;}else sro_source_rx=0;
    }
    /* Existing pure unsafe-rseq guard has already returned. These actual
       diagnostic queries follow full unexpected-frame capture and the original
       first-error publication. Any observation error stays diagnostic only. */
    if(f->complete) {
        f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
        f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
        f->tls_complete=!f->fs_result && !f->gs_result;
    }
}
static void sro_abort_after_cleanup(void) {
    if(!sro_ready || sro_current>=SRO_ROWS || !sro_focal())return;
    struct sr_record *r=&selected_scalar_region.current;struct sro_entry *e=&sro_wire.entries[sro_current];
    if(!r->before.complete)return;
    unsigned stage=SRO_MEMORY_TERMINAL;uintptr_t generated=0;
    uintptr_t rsp=(uintptr_t)r->before.frame.greg[REG_RSP];
    if(rsp==SRO_STACK_FAULT-0x58 || rsp==SRO_STACK_FAULT+PAGE-0x58) {
        uintptr_t address=rsp==SRO_STACK_FAULT-0x58?SRO_STACK_FAULT:SRO_STACK_FAULT+PAGE-8;
        const struct sr_frame *f=&r->unexpected;
        /* No arbitrary abort obtains readback permission. The original
           generated fault and first error precede full RX retirement. */
        if(selected_scalar_region.first_error==SR_EVENT && r->unexpected_seen && f->complete &&
           f->sig==SIGSEGV && f->si.si_signo==SIGSEGV && f->si.si_code==SEGV_ACCERR && !f->si.si_errno &&
           (uintptr_t)f->si.si_addr==address && (uintptr_t)f->frame.greg[REG_CR2]==address &&
           f->frame.greg[REG_TRAPNO]==14 && f->frame.greg[REG_ERR]==4 &&
           r->map_result==LI2_REGION_PLAN_OK && r->original.ready==1 &&
           r->original.kind==LI2_REGION_PC_COPIED && r->slot_present && r->slot<selected_scalar_region.used &&
           r->cleanup_started && r->cleanup_complete && r->cleanup.complete &&
           r->cleanup.prot==PROT_READ && r->cleanup.query.complete &&
           r->cleanup.query.expected_prot==PROT_READ && r->cleanup.query.actual_prot==PROT_READ) {
            stage=SRO_MEMORY_READBACK;generated=selected_scalar_region.slots[r->slot].plan.generated;
        }
    }
    if(!e->after_memory.attempted) {
        int error=li2_lifecycle_scalar_region_observe_memory(rsp,stage,&r->source.key,generated,&e->after_memory);
        if((error || !e->after_memory.complete) && !sro_wire.h[39])sro_wire.h[39]=3;
    }
    sro_copy(e->terminal_source_page,(void *)r->source.key.page.address,PAGE);e->terminal_source_bytes=PAGE;
}
static void sro_finish(unsigned status,unsigned code,long detail) {
    if(sro_finished || !sro_wire.h[18])return;
    sro_finished=1;sro_wire.h[26]=1;sro_wire.h[27]=status;sro_wire.h[28]=code;
    sro_wire.h[29]=(uint64_t)detail;sro_wire.h[30]=sro_current;
    sro_wire.h[31]=selected_scalar_region_active;sro_wire.h[32]=selected_scalar_region_busy;
    sro_wire.h[33]=selected_scalar_region_failing;sro_wire.h[34]=handling;
    sro_wire.h[35]=selected_step_pending;sro_wire.h[36]=selected_pending_route;
    sro_wire.h[37]=selected_flags_known;sro_wire.h[38]=selected_logical_flags;
    sro_copy(&sro_wire.owner,&selected_scalar_region,sizeof selected_scalar_region);
#ifdef LI2_SCALAR_REGION_REUSE
    sro_copy(&sro_wire.reuse,&srr,sizeof srr);
    if(srr.pending && srr_address(srr.slot,srr.target)) {
        sro_copy(sro_wire.reuse_pending_page,(void *)srr.target,PAGE);
        sro_wire.reuse_pending_bytes=PAGE;
    }
#endif
    sro_owners(&sro_wire.terminal_owners,0);
    sro_wire.focal[4]=sro_wire.h[24];
    sro_wire.h[53]=selected_scalar_region_decoding;
    sro_wire.h[54]=sro_alias;sro_wire.h[55]=sro_source_rx;
    const struct li2_native_close *global_close=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *native_counts=li2_lifecycle_native_counts();
    if(global_close){sro_copy(&sro_wire.terminal_global_close,global_close,sizeof(*global_close));sro_wire.h[51]=1;}
    if(native_counts){sro_copy(&sro_wire.terminal_native_counts,native_counts,sizeof(*native_counts));sro_wire.h[52]=1;}
    const struct li2_fetch_progress *fetch=li2_lifecycle_fetch_progress();
    if(fetch){sro_copy(&sro_wire.terminal_fetch,fetch,sizeof(*fetch));sro_wire.h[50]=1;}
    if(sro_current<SRO_ROWS && sro_focal()) {
        sro_copy(&sro_wire.entries[sro_current].owner,&selected_scalar_region.current,sizeof(struct sr_record));
        sro_wire.entries[sro_current].terminal=1;
    }
    /* Every used page was exclusively allocated and never unmapped. Partial
       publication/open cleanup may leave RW/RX; all are still readable. */
    for(size_t i=0;i<selected_scalar_region.used;i++) {
        if(i>=SR_PAGES){if(!sro_wire.h[39])sro_wire.h[39]=1;break;}
#ifdef LI2_SCALAR_REGION_REUSE
        /* Stable protected addresses survive an interrupted slot replacement;
           a partially copied plan is not a diagnostic read authority. */
        if(!srr_address(i,srr.entry[i])){if(!sro_wire.h[39])sro_wire.h[39]=5;break;}
        sro_copy(sro_wire.generated[i],(void *)srr.entry[i],PAGE);
#else
        sro_copy(sro_wire.generated[i],(void *)selected_scalar_region.slots[i].plan.generated,PAGE);
#endif
        ++sro_wire.h[40];
    }
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    srco_finish();
    if(sro_wire.certificate.h[9] && !sro_wire.h[39])sro_wire.h[39]=6;
#endif
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&sro_wire.sink_terminal,0,0,0,0);
    sro_wire.h[41]=(uint64_t)flags;sro_wire.h[42]=(uint64_t)result;
    if(result || flags!=(long)sro_wire.h[16] || !sro_same_sink(&sro_wire.sink_terminal) ||
       sro_wire.sink_terminal.st_size){if(!sro_wire.h[39])sro_wire.h[39]=2;return;}
    size_t at=0;uint64_t calls=0;
    while(at<sizeof sro_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&sro_wire+at),sizeof sro_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof sro_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof sro_wire)return;
#ifdef LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE
    const uint64_t footer[]={SRO_FOOTER,3,sizeof sro_wire,at,calls,(uint64_t)result,status,code};
#elif defined(LI2_SCALAR_REGION_REUSE)
    const uint64_t footer[]={SRO_FOOTER,2,sizeof sro_wire,at,calls,(uint64_t)result,status,code};
#else
    const uint64_t footer[]={SRO_FOOTER,1,sizeof sro_wire,at,calls,(uint64_t)result,status,code};
#endif
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
    /* Exact complete record+footer length is independently required. A short
       write or diagnostic error is never converted into accepted ownership. */
}
