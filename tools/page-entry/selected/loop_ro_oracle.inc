/* Included after all original controller/history helpers. These observations
   and backups are never consulted as production execution authority. */
#include "loop_ro_oracle.h"
#include <sys/uio.h>
enum { LRO_BYTE=1,LRO_HISTORY=2,LRO_STOP_BYTE=8801,LRO_STOP_HISTORY=8802 };
enum { LRO_REJECT=1,LRO_DECLINE_SCAN=2,LRO_KERNEL_EFAULT=3,
    LRO_KERNEL_PARTIAL=4,LRO_DIFF_REJECT=5 };
struct lro_result { unsigned kind,expected,actual,recorded,restored; };
struct lro_state {
    unsigned initialized,busy,started,complete,failure,checks,restorations;
    unsigned byte_warm,byte_phase;
    uint64_t passed,root_serial,generation,epoch;
    uint64_t byte_build_serial;
    uintptr_t source_entry;
    unsigned char root[PAGE];
    unsigned char mirror[PE_PROOF_BYTES];
    struct lro_result result[64];
};
static struct lro_state lro;
static _Noreturn void lro_fail(unsigned n) {
    if(!lro.failure)lro.failure=n;
    selected_persistent_abort(PE_PUBLICATION,8900+(long)n);
}
static void lro_need(int ok,unsigned n) {if(!ok)lro_fail(n);}
static void lro_prot(uintptr_t p,size_t n,int prot) {
    lro_need(!raw(SYS_mprotect,p,n,prot,0,0,0),1);
}
static void lro_mark(unsigned n) {
    lro_need(n<64 && !(lro.passed&(UINT64_C(1)<<n)) &&
        lro.result[n].recorded==1 && !lro.result[n].restored,2);
    lro.result[n].restored=1;
    lro.passed|=UINT64_C(1)<<n;++lro.checks;
}
static void lro_result(unsigned n,unsigned kind,unsigned expected,unsigned actual) {
    lro_need(n<64 && kind>=LRO_REJECT && kind<=LRO_DIFF_REJECT &&
        !lro.result[n].recorded && expected==actual,14);
    lro.result[n]=(struct lro_result){kind,expected,actual,1,0};
}
static int lro_initialize(void) {
    if(lro.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&lro,sizeof lro))return PE_STATE;
#if LI2_LOOP_RO_CONTROL == 2
    int error=lro_history_initialize();if(error)return error;
#endif
    lro.initialized=1;return 0;
}
/* Same virtual extent and identical bytes, but genuinely file-backed. The
   real private-anonymous R query must reject it, then exact anonymous R
   mapping/bytes are restored. No captured query or identity is substituted. */
static int lro_file_mapping(uintptr_t at,size_t bytes,const void *saved) {
    static const char name[]="li2-ro-oracle";
    long fd=raw(SYS_memfd_create,(long)name,MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    lro_need(fd>=0 && fd<=INT32_MAX,3);
    size_t done=0;
    while(done<bytes) {
        long n=raw(SYS_write,fd,(long)((const unsigned char *)saved+done),bytes-done,0,0,0);
        lro_need(n>0 && (size_t)n<=bytes-done,4);done+=(size_t)n;
    }
    lro_need(!raw(SYS_fcntl,fd,F_ADD_SEALS,LI2_SEALED_REQUIRED_SEALS,0,0,0),5);
    lro_need((uintptr_t)raw(SYS_mmap,at,bytes,PROT_READ,MAP_PRIVATE|MAP_FIXED,fd,0)==at,6);
    lro_need(equal((const void *)at,saved,bytes),7);return (int)fd;
}
static void lro_anonymous_restore(uintptr_t at,size_t bytes,const void *saved,int fd) {
    lro_need((uintptr_t)raw(SYS_mmap,at,bytes,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==at,8);
    copy((void *)at,saved,bytes);lro_prot(at,bytes,PROT_READ);
    lro_need(!raw(SYS_close,fd,0,0,0,0,0) && equal((const void *)at,saved,bytes) &&
        !lrc_readonly(at,bytes),9);
}
static long lro_kernel_write(uintptr_t readonly,int partial) {
    static const char path[]="/dev/zero";
    long fd=raw(SYS_openat,AT_FDCWD,(long)path,O_RDONLY|O_CLOEXEC,0,0,0);
    lro_need(fd>=0 && fd<=INT32_MAX,10);
    unsigned char before=*(const unsigned char *)readonly,ordinary=0xa5;
    long result;
    if(partial) {
        struct iovec vectors[2]={{&ordinary,1},{(void *)readonly,1}};
        result=raw(SYS_readv,fd,(long)vectors,2,0,0,0);
        lro_need(result==1 && ordinary==0,11);
    } else {
        result=raw(SYS_read,fd,readonly,1,0,0,0);
        lro_need(result==-EFAULT,12);
    }
    lro_need(*(const unsigned char *)readonly==before && !raw(SYS_close,fd,0,0,0,0,0),13);
    return result;
}
#include "loop_ro_byte_controls.inc"
#include "loop_ro_history_controls.inc"
static void lro_report(unsigned status,unsigned code) {
    for(unsigned i=0;i<64;i++)if(lro.result[i].recorded) {
        const struct lro_result *r=&lro.result[i];
        struct writer row={.used=0};text(&row,"LI2_LOOP_RO_CONTROL {\"version\":1");
        field(&row,",\"control\":",LI2_LOOP_RO_CONTROL);field(&row,",\"index\":",i);
        field(&row,",\"kind\":",r->kind);field(&row,",\"expected\":",r->expected);
        field(&row,",\"actual\":",r->actual);field(&row,",\"restored\":",r->restored);
        text(&row,"}\n");
        if(raw(SYS_write,report_fd<0?2:report_fd,(long)row.bytes,row.used,0,0,0)!=(long)row.used) {
            (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
        }
    }
    struct writer w={.used=0};text(&w,"LI2_LOOP_RO_ORACLE {\"version\":1");
    field(&w,",\"control\":",LI2_LOOP_RO_CONTROL);field(&w,",\"status\":",status);
    field(&w,",\"failure_code\":",code);field(&w,",\"initialized\":",lro.initialized);
    field(&w,",\"started\":",lro.started);field(&w,",\"complete\":",lro.complete);
    field(&w,",\"failure\":",lro.failure);field(&w,",\"checks\":",lro.checks);
    field(&w,",\"restorations\":",lro.restorations);field(&w,",\"passed\":",lro.passed);
    field(&w,",\"root_serial\":",lro.root_serial);field(&w,",\"generation\":",lro.generation);
    field(&w,",\"epoch\":",lro.epoch);field(&w,",\"source_entry\":",lro.source_entry);
    field(&w,",\"byte_warm\":",lro.byte_warm);field(&w,",\"byte_phase\":",lro.byte_phase);
    field(&w,",\"byte_build_serial\":",lro.byte_build_serial);
    text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
