"""Exact fixture-only copies; original sources recover through every inverse."""
from pathlib import Path
from page_selected import fact,need

ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));\nstatic void pb_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    pb_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_provider.inc"\n#endif\n#include "selected_controller.inc"',
  '#include "selected_provider.inc"\n#endif\n#include "provider_builtins_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','static void handler(int sig,siginfo_t *si,void *ptr) {',
  'static void handler(int sig,siginfo_t *si,void *ptr) {\n    pb_event(sig,si,ptr);'),
 ('selected_provider.inc','#include "provider_builtin_policy.h"',
  '#include "provider_builtin_policy.h"\n#include "provider_builtins_callbacks.inc"'),
 ('selected_provider.inc',',li2_policy_clock_v1,li2_policy_syscall_v1',
  ',pb_clock_callback,pb_syscall_callback'),
 ('selected_controller.inc','    selected_provider_configure();\n',
  '    selected_provider_configure();\n    pb_initialize();\n'),
 ('selected_controller.inc','    if(!selected_selftesting) {\n        if(!first_target_pc)first_target_pc=pc;',
  '    if(!selected_selftesting) {\n        pb_before(sig,si,context);\n        if(!first_target_pc)first_target_pc=pc;'),
 ('selected_controller.inc','    checked(!selected_step_pending && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,646,0);',
  '    checked(!selected_step_pending && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,646,0);\n    pb_effect(context);'),
 ('selected_controller.inc','        selected_provider_clock(context);return;',
  '        selected_provider_clock(context);pb_after(context);return;'),
 ('selected_controller.inc','    if(p->kind==LI2_CPUID && selected_provider_state.mode)selected_provider_cpuid_committed();\n#endif\n}',
  '    if(p->kind==LI2_CPUID && selected_provider_state.mode)selected_provider_cpuid_committed();\n#endif\n    pb_after(context);\n}'),
 ('selected_controller.inc','            selected_decoded.kind==LI2_SYSCALL,1560,0);',
  '            selected_decoded.kind==LI2_SYSCALL,1560,0);\n    pb_effect(context);'),
 ('selected_controller.inc','    selected_release();++selected_source_syscalls;dispatch_operation(number,context);',
  '    selected_release();++selected_source_syscalls;dispatch_operation(number,context);pb_after(context);'),
 ('selected_oneshot.inc','    selected_oneshot_clear_route();\n    unsigned index=(unsigned)(o-selected_oneshot_owners);',
  '    pb_landed(sig,si,uc);\n    selected_oneshot_clear_route();\n    unsigned index=(unsigned)(o-selected_oneshot_owners);'),
)

def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected';fixture=selected/'tests/provider_builtins'
    need(not out.exists(),'unique builtin observer source view');out.mkdir(parents=True)
    rows=[]
    for name in ('runtime_loader.c','selected_provider.inc','selected_controller.inc','selected_oneshot.inc'):
        p=pin(selected/name);before=p.read_bytes();after=before
        for path,old,new in ADAPTERS:
            if path==name:
                need(after.count(old.encode())==1,'unique original observer seam '+name)
                after=after.replace(old.encode(),new.encode())
        inverse=after
        for path,old,new in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(new.encode())==1,'unique observed inverse '+name)
                inverse=inverse.replace(new.encode(),old.encode())
        need(inverse==before,'complete original production source inverse')
        q=out/name;q.write_bytes(after);pin(q);rows.append(dict(name=name,before=fact(p),after=fact(q)))
    for name in ('observe.inc','callbacks.inc'):
        q=out/('provider_builtins_'+name);q.write_bytes(pin(fixture/name).read_bytes());pin(q)
    return rows
