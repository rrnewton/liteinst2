"""Exact observation adapters; every original source body recovers unchanged."""
from pathlib import Path
from page_selected import fact,need

ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));','static void fail(unsigned,long) __attribute__((noreturn));\nstatic void rn_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    rn_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"','#include "rseq_native_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','    li2_rseq_native_preentry();','    li2_rseq_native_preentry();\n    rn_entry(sig,si,ptr);'),
 ('runtime_loader.c','    checked(!native_error,(unsigned)native_error,0);','    checked(!native_error,(unsigned)native_error,0);\n    rn_initialize();'),
 ('native_controller.inc','        int result=li2_native_epoch_nx(sig,si,uc,&selected_logical_flags);','        int result=li2_native_epoch_nx(sig,si,uc,&selected_logical_flags);\n        rn_epoch_return(result,sig,si,uc);'),
 ('native_controller.inc','    selected_flags_known=0;\n','    selected_flags_known=0;\n    rn_admitted(pc,sig,si,uc);\n'),
 ('rseq_guard.c','int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *uc) {','int rn_real_instruction(const struct li2_decoded *d,const ucontext_t *uc) {'),
)

def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
    need(not out.exists(),'unique registered-native observer source view');out.mkdir(parents=True)
    changes=[]
    for name in ('runtime_loader.c','native_controller.inc','rseq_guard.c'):
        source=pin(selected/name);before=source.read_bytes();data=before
        for path,old,new in ADAPTERS:
            if path==name:
                need(data.count(old.encode())==1,'unique registered-native observation '+name)
                data=data.replace(old.encode(),new.encode())
        inverse=data
        for path,old,new in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(new.encode())==1,'unique registered-native inverse '+name)
                inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'complete original product recovered '+name)
        output=out/name;output.write_bytes(data);pin(output)
        changes.append(dict(name=name,before=fact(source),after=fact(output)))
    for original,name in (('observe.inc','rseq_native_observe.inc'),('record.h','rseq_native_record.h')):
        source=pin(selected/'tests/rseq_native'/original);output=out/name
        output.write_bytes(source.read_bytes());pin(output)
        changes.append(dict(name=name,before=fact(source),after=fact(output)))
    return changes
