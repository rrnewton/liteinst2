"""Exact read-only fallback observations; product code recovers byte-for-byte."""
from pathlib import Path
from page_selected import fact,need

ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));\nstatic void orf_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    orf_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"',
  '#include "oneshot_registered_observe.inc"\n#include "selected_controller.inc"'),
 ('selected_controller.inc','    checked(!(li2_saved[16]&(SELECTED_TF|SELECTED_RF)),611,0);',
  '    checked(!(li2_saved[16]&(SELECTED_TF|SELECTED_RF)),611,0);\n    orf_initialize();'),
 ('selected_oneshot.inc','if(rs->registered) {checked(rs->registered==1 && rs->phase==LI2_RSEQ_ACTIVE && rs->held==1,1563,1);return 0;}',
  'if(rs->registered) {checked(rs->registered==1 && rs->phase==LI2_RSEQ_ACTIVE && rs->held==1,1563,1);orf_fallback(rs,sig,si,uc);return 0;}'),
)

def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
    need(not out.exists(),'unique observer source view');out.mkdir(parents=True)
    changes=[]
    for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc'):
        source=pin(selected/name);before=source.read_bytes();data=before
        for path,old,new in ADAPTERS:
            if path==name:
                need(data.count(old.encode())==1,'unique fallback observation '+name)
                data=data.replace(old.encode(),new.encode())
        inverse=data
        for path,old,new in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(new.encode())==1,'unique observer inverse '+name)
                inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'complete product bytes recovered '+name)
        output=out/name;output.write_bytes(data);pin(output)
        changes.append(dict(name=name,before=fact(source),after=fact(output)))
    output=out/'oneshot_registered_observe.inc'
    output.write_bytes(pin(selected/'tests/oneshot_registered/observe.inc').read_bytes());pin(output)
    return changes
