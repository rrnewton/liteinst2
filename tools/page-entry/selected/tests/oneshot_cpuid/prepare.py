"""Compose unchanged eight-owner observation and additive CPUID snapshots."""
import importlib.util
from pathlib import Path
from page_selected import fact,need
ADAPTERS=(
 ('runtime_loader.c','static void oi_terminal(unsigned,unsigned,long);',
  'static void oi_terminal(unsigned,unsigned,long);\nstatic void oc_initialize(void);\nstatic void oc_before(int,const siginfo_t *,const ucontext_t *);\nstatic void oc_after(const ucontext_t *);\nstatic void oc_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    oi_terminal(status,code,detail);','    oi_terminal(status,code,detail);\n    oc_terminal(status,code,detail);'),
 ('runtime_loader.c','#include "selected_controller.inc"','#include "selected_controller.inc"\n#include "oneshot_cpuid_observe.inc"'),
 ('runtime_loader.c','    oi_initialize();','    oi_initialize();\n    oc_initialize();'),
 ('selected_controller.inc','    if(!selected_selftesting) {\n        if(!first_target_pc)first_target_pc=pc;',
  '    if(!selected_selftesting) {\n        oc_before(sig,si,context);\n        if(!first_target_pc)first_target_pc=pc;'),
 ('selected_controller.inc','        checked(!selected_selftesting,630,0);selected_builtin(context);selected_release();return;',
  '        checked(!selected_selftesting,630,0);selected_builtin(context);oc_after(context);selected_release();return;'),
)
def prepare(root,out,pin,registered=False):
    need(type(registered)is bool,'fixed registered observer choice')
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
    path=pin(selected/'tests/oneshot_interpreter/prepare.py')
    spec=importlib.util.spec_from_file_location('oc_original_prepare',path);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    donor=out.with_name(out.name+'-owners');rows=old.prepare(root,donor,pin)
    need(not out.exists(),'unique combined observation directory');out.mkdir()
    for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc','selected_chain.inc','oneshot_interpreter_observe.inc'):
        (out/name).write_bytes(pin(donor/name).read_bytes())
    for name in ('runtime_loader.c','selected_controller.inc'):
        p=out/name;before=p.read_bytes();after=before
        for n,a,b in ADAPTERS:
            if n==name:
                need(after.count(a.encode())==1,'unique added CPUID observation '+name);after=after.replace(a.encode(),b.encode())
        inverse=after
        for n,a,b in reversed(ADAPTERS):
            if n==name:
                need(inverse.count(b.encode())==1,'unique added observation inverse '+name);inverse=inverse.replace(b.encode(),a.encode())
        need(inverse==before,'complete eight-owner observer recovered')
        p.write_bytes(after);rows.append(dict(name=name,before=dict(bytes=len(before),sha256=__import__('hashlib').sha256(before).hexdigest()),after=fact(p)))
    p=out/'oneshot_cpuid_observe.inc';p.write_bytes(pin(selected/'tests/oneshot_cpuid/observe.inc').read_bytes())
    if registered:
        path=pin(selected/'tests/oneshot_registered/prepare.py')
        spec=importlib.util.spec_from_file_location('oc_registered_prepare',path);reg=importlib.util.module_from_spec(spec);spec.loader.exec_module(reg)
        for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc'):
            p=out/name;before=p.read_bytes();after=before
            for n,a,b in reg.ADAPTERS:
                if n==name:
                    need(after.count(a.encode())==1,'unique unchanged registered observation '+name);after=after.replace(a.encode(),b.encode())
            inverse=after
            for n,a,b in reversed(reg.ADAPTERS):
                if n==name:
                    need(inverse.count(b.encode())==1,'unique registered inverse');inverse=inverse.replace(b.encode(),a.encode())
            need(inverse==before,'entire combined observer recovered after registered insertions')
            p.write_bytes(after);rows.append(dict(name=name,before=dict(bytes=len(before),sha256=__import__('hashlib').sha256(before).hexdigest()),after=fact(p)))
        p=out/'oneshot_registered_observe.inc';p.write_bytes(pin(selected/'tests/oneshot_registered/observe.inc').read_bytes());pin(p)
    for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc','selected_chain.inc','oneshot_interpreter_observe.inc','oneshot_cpuid_observe.inc'):pin(out/name)
    return rows
