"""Observation-only adapters; full byte inverses recover every production file."""
from pathlib import Path
from page_selected import fact,need
WRAPPER="""
static int selected_native_fetch(int sig,siginfo_t *si,ucontext_t *uc) {
    int result=rtc_real_native_fetch(sig,si,uc);
    rtc_fetch_return(result,sig,si,uc);
    return result;
}
"""
PROTOTYPES="""static void fail(unsigned,long) __attribute__((noreturn));
static void rtc_initialize(void);
static void rtc_selected_initialized(void);
static void rtc_terminal(unsigned,unsigned,long);
static void rtc_stage(unsigned,long,const long *,long);
static long rtc_result_argument(long,const long *,long);
"""
QUERY_DECLARATIONS="""static struct li2_tcgets_state tcgets;
extern void rtc_query_observed(struct li2_tcgets_state *,long,long,long,long,long,long,long,long *);
extern void rtc_mount_observed(struct li2_tcgets_state *,uint64_t *);"""
ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',PROTOTYPES.rstrip()),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    rtc_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"','#include "rseq_tcgets_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','    li2_rseq_native_preentry();','    li2_rseq_native_preentry();\n    rtc_entry(sig,si,ptr);'),
 ('runtime_loader.c','    rseq_error=li2_rseq_tcgets_initialize();','    rtc_initialize();\n    rseq_error=li2_rseq_tcgets_initialize();\n    rtc_stage(0,0,0,0);'),
 ('runtime_loader.c','    selected_initialize();','    selected_initialize();\n    rtc_selected_initialized();'),
 ('runtime_loader.c','    int rseq_error=li2_rseq_before_syscall(n,a);','    rtc_stage(1,n,a,0);\n    int rseq_error=li2_rseq_before_syscall(n,a);\n    if(!rseq_error)rtc_stage(2,n,a,0);'),
 ('runtime_loader.c','        rseq_error=li2_rseq_tcgets_issuing(n,a);','        rseq_error=li2_rseq_tcgets_issuing(n,a);\n        if(!rseq_error)rtc_stage(3,n,a,0);'),
 ('runtime_loader.c','        rseq_error=li2_rseq_tcgets_result(n,a,result);','        rseq_error=li2_rseq_tcgets_result(n,a,rtc_result_argument(n,a,result));\n        if(!rseq_error)rtc_stage(5,n,a,result);'),
 ('selected_controller.inc','    long number=g[REG_RAX];','    rtc_effect(context,0);\n    long number=g[REG_RAX];'),
 ('selected_controller.inc','    selected_release();++selected_source_syscalls;dispatch_operation(number,context);','    selected_release();++selected_source_syscalls;dispatch_operation(number,context);\n    rtc_effect(context,1);'),
 ('native_controller.inc','static int selected_native_fetch(','static int rtc_real_native_fetch('),
 ('rseq_tcgets_btrfs.inc','static struct li2_tcgets_state tcgets;',QUERY_DECLARATIONS),
 ('rseq_tcgets_btrfs.inc','    __asm__ volatile("":::"memory");tcgets.query_returned=1;*result=tcgets.query_result;','    __asm__ volatile("":::"memory");tcgets.query_returned=1;*result=tcgets.query_result;\n    rtc_query_observed(&tcgets,n,a,b,c,d,e,f,result);'),
 ('rseq_tcgets_btrfs.inc','static int tcgets_mount_parse(uint64_t wanted) {','static int tcgets_mount_parse(uint64_t wanted) {\n    rtc_mount_observed(&tcgets,&wanted);'),
)
def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected';fixture=selected/'tests/rseq_tcgets_btrfs'
    need(not out.exists(),'unique TCGETS observer source view');out.mkdir(parents=True);changes=[]
    for name in('runtime_loader.c','selected_controller.inc','native_controller.inc','rseq_guard.c','rseq_tcgets_btrfs.inc'):
        source=pin(selected/name);before=source.read_bytes();data=before
        for n,old,new in ADAPTERS:
            if n==name:
                need(data.count(old.encode())==1,'one exact TCGETS observation '+name);data=data.replace(old.encode(),new.encode())
        if name=='native_controller.inc':data+=WRAPPER.encode()
        inverse=data
        if name=='native_controller.inc':
            need(inverse.endswith(WRAPPER.encode()),'exact wrapper suffix');inverse=inverse[:-len(WRAPPER)]
        for n,old,new in reversed(ADAPTERS):
            if n==name:
                need(inverse.count(new.encode())==1,'one exact TCGETS inverse '+name);inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'complete unchanged product recovered '+name)
        output=out/name;output.write_bytes(data);pin(output);changes.append(dict(name=name,before=fact(source),after=fact(output)))
    for original,name in(('observe.inc','rseq_tcgets_observe.inc'),('record.h','rseq_tcgets_record.h')):
        source=pin(fixture/original);data=source.read_bytes()
        if original=='record.h':
            old,new=b'#include "../rseq_native/record.h"',b'#include "rseq_tcgets_old_record.h"'
            need(data.count(old)==1 and new not in data,'exact old frame include');data=data.replace(old,new)
            need(data.replace(new,old)==source.read_bytes(),'complete frame header inverse')
        output=out/name;output.write_bytes(data);pin(output);changes.append(dict(name=name,before=fact(source),after=fact(output)))
    source=pin(selected/'tests/rseq_native/record.h');output=out/'rseq_tcgets_old_record.h';output.write_bytes(source.read_bytes());pin(output)
    changes.append(dict(name=output.name,before=fact(source),after=fact(output)));return changes
