"""Observation-only adapters with exact complete original source recovery."""
from pathlib import Path
from page_selected import fact,need

WRAPPER='''
static int selected_native_fetch(int sig,siginfo_t *si,ucontext_t *uc) {
    int result=rnb_real_native_fetch(sig,si,uc);
    rnb_fetch_return(result,sig,si,uc);
    return result;
}
'''
ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));','static void fail(unsigned,long) __attribute__((noreturn));\nstatic void rnb_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    rnb_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"','#include "rseq_boundary_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','    li2_rseq_native_preentry();','    li2_rseq_native_preentry();\n    rnb_entry(sig,si,ptr);'),
 ('runtime_loader.c','    checked(!native_error,(unsigned)native_error,0);','    checked(!native_error,(unsigned)native_error,0);\n    rnb_initialize();'),
 ('native_controller.inc','static int selected_native_fetch(','static int rnb_real_native_fetch('),
 ('native_controller.inc','        int result=li2_native_epoch_nx(sig,si,uc,&selected_logical_flags);','        int result=li2_native_epoch_nx(sig,si,uc,&selected_logical_flags);\n        rnb_epoch_return(result,sig,si,uc);'),
 ('rseq_guard.c','int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *uc) {','int rnb_real_instruction(const struct li2_decoded *d,const ucontext_t *uc) {'),
)

def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
    need(not out.exists(),'unique boundary observer source view');out.mkdir(parents=True)
    changes=[]
    for name in ('runtime_loader.c','native_controller.inc','rseq_guard.c'):
        source=pin(selected/name);before=source.read_bytes();data=before
        for path,old,new in ADAPTERS:
            if path==name:
                need(data.count(old.encode())==1,'unique boundary observation '+name)
                data=data.replace(old.encode(),new.encode())
        if name=='native_controller.inc':data+=WRAPPER.encode()
        inverse=data
        if name=='native_controller.inc':
            need(inverse.endswith(WRAPPER.encode()),'exact wrapper suffix');inverse=inverse[:-len(WRAPPER)]
        for path,old,new in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(new.encode())==1,'unique boundary inverse '+name)
                inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'complete original product recovered '+name)
        output=out/name;output.write_bytes(data);pin(output)
        changes.append(dict(name=name,before=fact(source),after=fact(output)))
    for original,name in (('observe.inc','rseq_boundary_observe.inc'),('record.h','rseq_boundary_record.h')):
        source=pin(selected/'tests/rseq_native_boundary'/original);output=out/name
        data=source.read_bytes()
        if original=='record.h':
            # Its exact old frame header is also copied at this source-view root.
            old,new=b'#include "../rseq_native/record.h"',b'#include "rseq_boundary_old_record.h"'
            need(data.count(old)==1 and new not in data,'unique exact old-frame include adapter')
            data=data.replace(old,new)
            need(data.replace(new,old)==source.read_bytes(),'complete frame-header adapter inverse')
        output.write_bytes(data);pin(output)
        changes.append(dict(name=name,before=fact(source),after=fact(output)))
    source=pin(selected/'tests/rseq_native/record.h');output=out/'rseq_boundary_old_record.h'
    output.write_bytes(source.read_bytes());pin(output)
    changes.append(dict(name=output.name,before=fact(source),after=fact(output)))
    return changes
