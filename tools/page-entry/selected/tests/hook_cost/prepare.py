"""Exact additive adapter; every donor file remains pinned and unmodified."""
import hashlib,importlib.util
from pathlib import Path
H=lambda b:hashlib.sha256(b).hexdigest()
def need(ok,why):
    if not ok:raise ValueError(why)
def fact(p):b=Path(p).read_bytes();return dict(bytes=len(b),sha256=H(b))
def load(path):
    s=importlib.util.spec_from_file_location('hc_original_prepare',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
PROTOTYPES='''
static int hc_random_callback(const struct li2_selected_callback_input *,struct li2_selected_script *);
static int hc_cpuid_callback(const struct li2_selected_cpuid_input *,struct li2_selected_cpuid_result *);
static int hc_clock_callback(const struct li2_selected_clock_input *,struct li2_selected_clock_result *);
static int hc_syscall_callback(const struct li2_selected_syscall_input *,struct li2_selected_syscall_result *);
'''
ADAPTERS=(
 ('runtime_loader.c','    checked(!handling && si && ptr,218,sig); handling=1;',
  '    checked(!handling && si && ptr,218,sig); handling=1;\n    hc_handler_enter(sig,si,ptr);'),
 ('runtime_loader.c','    handling=0;\n}\n\nstatic size_t parse_fds',
  '    hc_handler_leave();\n    handling=0;\n}\n\nstatic size_t parse_fds'),
 ('selected_provider.inc','    b2_random_callback,b2_cpuid_callback,b2_clock_callback,b2_syscall_callback',
  '    hc_random_callback,hc_cpuid_callback,hc_clock_callback,hc_syscall_callback'),
 ('b2_bindings.inc','#include "b2_script.inc"\n','#include "b2_script.inc"\n'+PROTOTYPES),
 *[('b2_observe.inc','static void '+name+'(', 'static void hc_original_'+name[3:]+'(')
   for name in('b2_emit','b2_initialize','b2_entry','b2_before','b2_after')],
 ('b2_observe.inc','    b2_observation_pending=0;b2_before_seen=0;b2_context=0;b2_si=0;b2_signal=0;\n}',
  '    b2_observation_pending=0;b2_before_seen=0;b2_context=0;b2_si=0;b2_signal=0;\n}\n#include "hc_timing.inc"'),
)
def prepare(selected,reference_sources,reference,output,pin,boundary):
    selected,reference_sources,output=map(Path,(selected,reference_sources,output))
    old=load(pin(selected/'tests/b2_reference/prepare.py'))
    original=output.parent/'original-observed'
    old.prepare(selected,reference_sources,reference,original,pin,boundary)
    need(not output.exists(),'unique timing source view');output.mkdir()
    result=[];used=0
    for source in sorted(original.iterdir()):
        need(source.is_file()and not source.is_symlink(),'plain retained generated source')
        before=pin(source).read_bytes();after=before;operations=[]
        for name,a,b in ADAPTERS:
            if name==source.name:
                need(after.count(a.encode())==1,'unique actual timing seam '+name)
                after=after.replace(a.encode(),b.encode());operations.append((a,b))
                used+=1
        inverse=after
        for a,b in reversed(operations):
            need(inverse.count(b.encode())==1,'unique actual timing inverse');inverse=inverse.replace(b.encode(),a.encode())
        need(inverse==before,'whole original observer/production body retained')
        target=output/source.name;target.write_bytes(after);pin(target)
        result.append(dict(name=target.name,before=fact(source),after=fact(target),inverse_spans=len(operations)))
    need(used==len(ADAPTERS),'every declared timing adapter applied exactly once')
    target=output/'hc_timing.inc';target.write_bytes(pin(Path(__file__).parent/'timing.inc').read_bytes());pin(target)
    result.append(dict(name=target.name,after=fact(target)))
    return result
def recipe(argv,selected,output):
    return load(Path(selected)/'tests/b2_reference/callback/prepare.py').recipe(argv,selected,output)
