"""Exact fixture-only observer adapters; no execution permit or result changes."""
from pathlib import Path
from page_selected import fact, need

ADAPTERS = (
 ('runtime_loader.c', 'static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));\nstatic void pl_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c', '    reported=1;\n', '    reported=1;\n    pl_terminal(status,code,detail);\n'),
 ('runtime_loader.c', '#include "selected_provider.inc"\n#endif\n#include "selected_controller.inc"',
  '#include "selected_provider.inc"\n#endif\n#include "provider_launch_observe.inc"\n#include "selected_controller.inc"'),
 ('selected_controller.inc', '    selected_provider_configure();\n',
  '    selected_provider_configure();\n    pl_initialize();\n'),
 ('selected_controller.inc', '    if(!selected_selftesting) {\n        if(!first_target_pc)first_target_pc=pc;',
  '    if(!selected_selftesting) {\n        pl_before(sig,si,context);\n        if(!first_target_pc)first_target_pc=pc;'),
 ('selected_controller.inc', '        ++selected_provider_calls[selected_decoded.kind-LI2_RDRAND];',
  '        pl_after(context);\n        ++selected_provider_calls[selected_decoded.kind-LI2_RDRAND];'),
 ('selected_controller.inc', '        checked(!selected_selftesting,630,0);selected_builtin(context);selected_release();return;',
  '        checked(!selected_selftesting,630,0);selected_builtin(context);pl_after(context);selected_release();return;'),
)

def prepare(root, out, pin):
    root, out = Path(root), Path(out)
    selected = root/'tools/page-entry/selected'
    fixture = selected/'tests/provider_launch'
    need(not out.exists(), 'unique observer source view')
    out.mkdir(parents=True)
    changes=[]
    for name in ('runtime_loader.c','selected_controller.inc'):
        p=pin(selected/name);before=p.read_bytes();b=before
        for path,old,new in ADAPTERS:
            if path==name:
                need(b.count(old.encode())==1, 'exact observation-only insertion '+name)
                b=b.replace(old.encode(),new.encode())
        inverse=b
        for path,old,new in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(new.encode())==1,'unique observer inverse')
                inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'whole production source recovered')
        q=out/name;q.write_bytes(b);pin(q)
        changes.append(dict(name=name,before=fact(p),after=fact(q)))
    q=out/'provider_launch_observe.inc';q.write_bytes(pin(fixture/'observe.inc').read_bytes());pin(q)
    return changes
