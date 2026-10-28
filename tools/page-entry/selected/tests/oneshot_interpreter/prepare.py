"""Exact observation-only insertions; every complete original is recovered."""
from pathlib import Path
from page_selected import fact,need

ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));\nstatic void oi_terminal(unsigned,unsigned,long);\nstatic void oi_syscall_result(long,const long[6],long,const ucontext_t *);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    oi_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"',
  '#include "oneshot_interpreter_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','    selected_selftest();\n','    selected_selftest();\n    oi_initialize();\n'),
 ('runtime_loader.c','    g[REG_RAX]=result; g[REG_RCX]=pc; g[REG_R11]=g[REG_EFL];',
  '    oi_syscall_result(n,a,result,context);\n    g[REG_RAX]=result; g[REG_RCX]=pc; g[REG_R11]=g[REG_EFL];'),
 ('selected_controller.inc','    long number=g[REG_RAX];\n',
  '    long number=g[REG_RAX];\n    oi_syscall_begin(number,context);\n'),
 ('selected_oneshot.inc','    e=li2_oneshot_nx(o,&selected_oneshot_request,sig,si,uc);',
  '    oi_begin(o,&selected_oneshot_request,sig,si,uc);\n    e=li2_oneshot_nx(o,&selected_oneshot_request,sig,si,uc);\n    oi_nx_return(o,e,sig,si,uc);'),
 ('selected_oneshot.inc','    int e=li2_oneshot_ud(o,sig,si,uc,&selected_oneshot_handoff);',
  '    oi_ud_before(o,sig,si,uc);\n    int e=li2_oneshot_ud(o,sig,si,uc,&selected_oneshot_handoff);\n    oi_ud_return(o,e,sig,si,uc);'),
 ('selected_oneshot.inc','    selected_oneshot_effect_started[index]=1;',
  '    selected_oneshot_effect_started[index]=1;\n    oi_effect_begin(o);'),
 ('selected_oneshot.inc','    selected_oneshot_effect_returned[index]=1;',
  '    selected_oneshot_effect_returned[index]=1;\n    oi_effect_done(o,uc);'),
 ('selected_chain.inc','    enum li2_chain_result result=li2_tf_chain_trace(&selected_chain,sig,si,context);',
  '    oi_trace_before(sig,si,context);\n    enum li2_chain_result result=li2_tf_chain_trace(&selected_chain,sig,si,context);'),
 ('selected_chain.inc','    const struct li2_tf_chain_slot *previous=&selected_chain.slots[selected_chain.active^1];',
  '    const struct li2_tf_chain_slot *previous=&selected_chain.slots[selected_chain.active^1];\n    oi_trace(previous);'),
)

def prepare(root,out,pin):
    root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
    need(not out.exists(),'unique observer source view');out.mkdir(parents=True)
    rows=[]
    for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc','selected_chain.inc'):
        p=pin(selected/name);before=p.read_bytes();data=before
        for path,a,b in ADAPTERS:
            if path==name:
                need(data.count(a.encode())==1,'unique interpreter observation '+name)
                data=data.replace(a.encode(),b.encode())
        inverse=data
        for path,a,b in reversed(ADAPTERS):
            if path==name:
                need(inverse.count(b.encode())==1,'unique inverse '+name)
                inverse=inverse.replace(b.encode(),a.encode())
        need(inverse==before,'entire original recovered '+name)
        q=out/name;q.write_bytes(data);pin(q);rows.append(dict(name=name,before=fact(p),after=fact(q)))
    q=out/'oneshot_interpreter_observe.inc';q.write_bytes(pin(selected/'tests/oneshot_interpreter/observe.inc').read_bytes());pin(q)
    return rows
