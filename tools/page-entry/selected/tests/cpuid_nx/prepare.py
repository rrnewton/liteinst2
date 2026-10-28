"""Observation adapters only; require the separately reviewed actual NX composition."""
import json
from pathlib import Path
from page_selected import need,fact

ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));\nstatic void nx_initialize(void);\nstatic void nx_before(int,const siginfo_t *,const ucontext_t *);\nstatic void nx_after(const ucontext_t *);\nstatic void nx_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    nx_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"\n','#include "selected_controller.inc"\n#include "cpuid_nx_observe.inc"\n'),
 ('selected_controller.inc','    selected_provider_configure();\n#endif\n#ifdef LI2_ONESHOT_PUBLICATION',
  '    selected_provider_configure();\n#endif\n    nx_initialize();\n#ifdef LI2_ONESHOT_PUBLICATION'),
 ('selected_controller.inc','    if(!selected_selftesting) {\n        if(!first_target_pc)first_target_pc=pc;',
  '    if(!selected_selftesting) {\n        nx_before(sig,si,context);\n        if(!first_target_pc)first_target_pc=pc;'),
 ('selected_controller.inc','        checked(!selected_selftesting,630,0);selected_builtin(context);selected_release();return;',
  '        checked(!selected_selftesting,630,0);selected_builtin(context);nx_after(context);selected_release();return;'),
)

def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
    need(not out.exists(),'unique CPUID observer view');out.mkdir()
    required=json.loads(pin(selected/'tests/cpuid_nx/PREREQUISITES.json').read_bytes())
    need(required['schema']==1 and len(required['files'])==10,'closed reviewed production prerequisite')
    for row in required['files']:
        need(fact(pin(root/row['path']))==row['fact'],'exact reviewed NX/provider composition: '+row['path'])
    changes=[]
    for name in ('runtime_loader.c','selected_controller.inc'):
        original=pin(selected/name);before=original.read_bytes();after=before
        for path,old,new in ADAPTERS:
            if path==name:
                need(after.count(old.encode())==1,'unique genuine observer insertion '+name)
                after=after.replace(old.encode(),new.encode())
        inverse=after
        for path,old,new in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(new.encode())==1,'unique full observer inverse '+name)
                inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'whole actual controller recovered without any guard change')
        dest=out/name;dest.write_bytes(after);pin(dest)
        changes.append(dict(path=name,before=fact(original),after=fact(dest)))
    dest=out/'cpuid_nx_observe.inc'
    dest.write_bytes(pin(selected/'tests/cpuid_nx/observe.inc').read_bytes());pin(dest)
    return changes
