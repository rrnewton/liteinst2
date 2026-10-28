"""Exact fixture-only bindings onto the reviewed production builtin source.

No product file is edited. The caller retains every returned original/generated
fact, actual compiler-M/link/ELF evidence, and final source/artifact custody.
"""
import hashlib,json
from pathlib import Path
H=lambda b:hashlib.sha256(b).hexdigest()
def need(ok,why):
    if not ok:raise ValueError(why)
def fact(p):b=p.read_bytes();return {'bytes':len(b),'sha256':H(b)}
ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));\nstatic void b2_emit(unsigned,unsigned,long);\nstatic void b2_initialize(void);\nstatic void b2_entry(int,const siginfo_t *,const ucontext_t *);\nstatic void b2_before(int,const siginfo_t *,const ucontext_t *);\nstatic void b2_after(const ucontext_t *);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    b2_emit(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_provider.inc"\n#endif\n#include "selected_controller.inc"',
  '#include "selected_provider.inc"\n#endif\n#include "selected_controller.inc"\n#include "b2_observe.inc"'),
 ('selected_provider.inc','#include "provider_builtin_policy.h"',
  '#include "provider_builtin_policy.h"\n#include "b2_bindings.inc"'),
 ('selected_provider.inc','static const struct selected_provider_binding selected_provider_binding={\n    li2_policy_mask_random_v1,li2_policy_cpuid_mask_v1\n#ifdef LI2_SELECTED_PROVIDER_BUILTINS\n    ,li2_policy_clock_v1,li2_policy_syscall_v1\n#endif\n};',
  'static const struct selected_provider_binding b2_original_policy __attribute__((unused))={\n    li2_policy_mask_random_v1,li2_policy_cpuid_mask_v1,li2_policy_clock_v1,li2_policy_syscall_v1\n};\nstatic const struct selected_provider_binding selected_provider_binding={\n    b2_random_callback,b2_cpuid_callback,b2_clock_callback,b2_syscall_callback\n};'),
 ('selected_provider.inc','\\\"policy\\\":\\\"deterministic-builtins-v1\\\"','\\\"policy\\\":\\\"fixture-five-trajectory-v1\\\"'),
 ('selected_provider_builtins.inc','\\\"policy\\\":\\\"deterministic-builtins-v1\\\"','\\\"policy\\\":\\\"fixture-five-trajectory-v1\\\"'),
 ('provider_builtin_policy.h','#define LI2_POLICY_PID UINT64_C(0x4c320001)','#define LI2_POLICY_PID UINT64_C(173)'),
 ('selected_controller.inc','    selected_provider_configure();\n','    selected_provider_configure();\n    b2_initialize();\n'),
 ('selected_controller.inc','    selected_prepare(pc);\n','    b2_entry(sig,si,context);\n    selected_prepare(pc);\n'),
 ('selected_controller.inc','    checked((uintptr_t)si->si_addr>=pc && (uintptr_t)si->si_addr<selected_decoded.next_pc,627,0);',
  '    checked((uintptr_t)si->si_addr>=pc && (uintptr_t)si->si_addr<selected_decoded.next_pc,627,0);\n    b2_before(sig,si,context);'),
 ('selected_controller.inc','        checked(!status,629,status);\n','        checked(!status,629,status);\n        b2_after(context);\n'),
 ('selected_controller.inc','        checked(!selected_selftesting,630,0);selected_builtin(context);selected_release();return;',
  '        checked(!selected_selftesting,630,0);selected_builtin(context);b2_after(context);selected_release();return;'),
 ('selected_controller.inc','        selected_owned_syscall(context,flags);return;',
  '        selected_owned_syscall(context,flags);b2_after(context);return;'),
)
NAMES=('runtime_loader.c','selected_provider.inc','selected_provider_builtins.inc','provider_builtin_policy.h','selected_controller.inc')
def prepare(selected,reference_sources,reference,output,pin,boundary):
    """reference is already accepted by unchanged boundary.reference/fixture."""
    selected,reference_sources,output=map(Path,(selected,reference_sources,output))
    here=Path(__file__).resolve().parent
    pins=json.loads((here.parent/'PINS.json').read_bytes())
    for name,want in pins['production'].items():need(fact(pin(selected/name))==want,'exact reviewed builtin source '+name)
    for name,want in pins['dependencies'].items():need(fact(pin(selected/name))==want,'exact current prerequisite '+name)
    for name,want in pins['reference'].items():need(fact(pin(reference_sources/name))==want,'exact frozen reference source '+name)
    need(not output.exists(),'unique private C reference source view');output.mkdir(parents=True)
    result=[]
    for name in NAMES:
        original=pin(selected/name);before=original.read_bytes();after=before
        for path,a,b in ADAPTERS:
            if path==name:need(after.count(a.encode())==1,'unique original seam '+name);after=after.replace(a.encode(),b.encode())
        inverse=after
        for path,a,b in reversed(ADAPTERS):
            if path==name:need(inverse.count(b.encode())==1,'unique adapted seam '+name);inverse=inverse.replace(b.encode(),a.encode())
        need(inverse==before,'complete original file inverse '+name)
        p=output/name;p.write_bytes(after);pin(p);result.append({'name':name,'before':fact(original),'after':fact(p)})
    for source,name in ((here/'observe.inc','b2_observe.inc'),(reference_sources/'capture.h','b2_capture.h'),(reference_sources/'script.inc','b2_script.inc')):
        p=output/name;p.write_bytes(pin(source).read_bytes());pin(p);result.append({'name':name,'after':fact(p)})
    script=output/'b2-script.h';boundary.emit_script(reference,script);pin(script)
    bindings=output/'b2_bindings.inc';bindings.write_text('#define B2_SCRIPT_HEADER "b2-script.h"\n#include "b2_script.inc"\n');pin(bindings)
    result.extend({'name':p.name,'after':fact(p)}for p in(script,bindings))
    return result

def recipe(argv,selected,output):
    """Replace only ONE-SHOT with CPUID-NX; the same16 production TUs remain.

    Existing header/link/ELF/import/reset checks must run on this actual argv.
    This separate reference policy never claims the named production policy.
    """
    selected,output=Path(selected),Path(output);a=list(map(str,argv))
    macros={'LI2_TF_HANDOFF','LI2_REGISTER_RUN','LI2_MAPS_PHASE_REUSE','LI2_RSEQ_INACTIVE','LI2_NATIVE_PAGES',
            'LI2_FAST_MEMSET','LI2_FAST_EQUAL','LI2_ONESHOT_PUBLICATION','LI2_SELECTED_PROVIDER','LI2_SELECTED_PROVIDER_BUILTINS'}
    expected={'-D'+m+'=1'for m in macros}
    need(set(x for x in a if x.startswith('-DLI2_'))==expected and sum(x.startswith('-DLI2_')for x in a)==10,'exact original configured recipe macro set')
    need(a.count(str(selected/'runtime_loader.c'))==1 and a[-2]=='-o'and sum(x.endswith(('.c','.S'))for x in a)==16,'exact production runtime and16 TUs')
    a[a.index('-DLI2_ONESHOT_PUBLICATION=1')]='-DLI2_CPUID_NX_ONLY=1'
    a=[str(output/'runtime_loader.c')if x==str(selected/'runtime_loader.c')else x for x in a]
    a[-1]=str(output/'bridge-b2-reference.so')
    return a
