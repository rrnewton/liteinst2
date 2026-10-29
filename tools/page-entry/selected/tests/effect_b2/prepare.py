"""Add observation only, and substitute the explicitly named linked B2 policy TU.

The enclosing Build owner authenticates every input, compiler-M dependency,
generated file, compiler/archive, ELF, reset body, actual DWARF and command.
No original B2 profile or reader is replaced.
"""
import hashlib
from pathlib import Path
H=lambda b:hashlib.sha256(b).hexdigest()
MACROS=('EFFECT_PROVIDER','ONESHOT_REUSABLE','ONESHOT_PUBLICATION','TF_SEALED_CUSTODY',
 'TF_SAME_PAGE_LEASE','TF_HANDOFF','REGISTER_RUN','MAPS_PHASE_REUSE','RSEQ_INACTIVE',
 'NATIVE_PAGES','CPUID_NX_ONLY','RSEQ_NATIVE','RSEQ_NATIVE_BOUNDARY','RSEQ_TCGETS_BTRFS',
 'RSEQ_TIOCGWINSZ_BTRFS','FAST_MEMSET','FAST_EQUAL')
TUS=('bridge.c','runtime_loader.c','lifecycle_loader.c','entry.S','selected_effect.c',
 'selected_effect_native.c','oneshot.c','provider.c','step_owner.c','selected_selftest.S',
 'support.c','register_run_plan.c','register_run_owner.c','register_run_publish.c',
 'register_run_reset.c','rseq_guard.c','native_policy.c','native_epoch.c')
def need(ok,why):
    if not ok:raise ValueError(why)
DECL='''
static void be_initialize(void);
static void be_emit(unsigned,unsigned,long);
static void be_entry(int,const siginfo_t *,ucontext_t *);
static void be_prepared(int,const siginfo_t *,ucontext_t *);
static void be_landed(int,const siginfo_t *,ucontext_t *);
static void be_begin(void);
static void be_finished(void);
static void be_retired(const struct li2_oneshot_owner *);
static void be_returned(void);
'''
EDITS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));',
  'static void fail(unsigned,long) __attribute__((noreturn));'+DECL),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    be_emit(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"',
  '#include "selected_controller.inc"\n#include "be_observe.inc"'),
 ('runtime_loader.c','    selected_initialize();\n','    selected_initialize();\n    be_initialize();\n'),
 ('selected_controller.inc','    selected_prepare(pc);\n','    be_entry(sig,si,context);\n    selected_prepare(pc);\n'),
 ('selected_controller.inc','    checked((uintptr_t)si->si_addr>=pc && (uintptr_t)si->si_addr<selected_decoded.next_pc,627,0);',
  '    checked((uintptr_t)si->si_addr>=pc && (uintptr_t)si->si_addr<selected_decoded.next_pc,627,0);\n    be_prepared(sig,si,context);'),
 ('selected_effect_controller.inc','    p->stage=2;\n','    p->stage=2;\n    be_begin();\n'),
 ('selected_effect_controller.inc','    p->stage=8;__asm__ volatile("":::"memory");p->finished=1;p->busy=0;',
  '    p->stage=8;__asm__ volatile("":::"memory");p->finished=1;p->busy=0;\n    be_finished();'),
 ('selected_oneshot_reusable.inc','    selected_oneshot_count(&selected_oneshot_counts.restored);',
  '    selected_oneshot_count(&selected_oneshot_counts.restored);\n    be_landed(sig,si,uc);'),
 ('selected_oneshot_reusable.inc','    selected_oneshot_count(&selected_oneshot_counts.retired);selected_oneshot_reset_current(1);',
  '    selected_oneshot_count(&selected_oneshot_counts.retired);\n    be_retired(o);selected_oneshot_reset_current(1);be_returned();'),
)
NAMES=tuple(dict.fromkeys(x[0]for x in EDITS))
def prepare(selected,reference,output,pin,boundary,*,policy='native-post'):
    need(policy in ('native-post','scripted'),'explicit fixed effect policy')
    selected,output=Path(selected),Path(output);here=Path(__file__).resolve().parent
    need(not output.exists(),'unique private all-class source view');output.mkdir(parents=True)
    facts=[]
    for name in NAMES:
        original=pin(selected/name);before=original.read_bytes();after=before
        for path,a,b in EDITS:
            if path==name:
                need(after.count(a.encode())==1,'unique current observation seam '+name)
                after=after.replace(a.encode(),b.encode())
        inverse=after
        for path,a,b in reversed(EDITS):
            if path==name:
                need(inverse.count(b.encode())==1,'unique inverse seam '+name)
                inverse=inverse.replace(b.encode(),a.encode())
        need(inverse==before,'whole production file inverse '+name)
        target=output/name;target.write_bytes(after);pin(target)
        facts.append(dict(name=name,before=dict(bytes=len(before),sha256=H(before)),after=dict(bytes=len(after),sha256=H(after))))
    # Quoted includes resolve through explicit exact links to current sources;
    # no older runtime/controller can enter the generated include closure.
    aliases={}
    for original in sorted(selected.iterdir()):
        if original.is_file()and original.suffix in('.h','.inc')and original.name not in NAMES:
            original=pin(original);target=output/original.name;target.symlink_to(original)
            aliases[str(target)]=str(original)
    for original,name in ((here/'policy.h','be_policy.h'),(here/('policy.c'if policy=='native-post'else 'policy_scripted.c'),'be_policy.c'),
        (here/'record.h','be_record.h'),(here/'observe.inc','be_observe.inc'),
        (selected/'tests/b2_reference/reference/capture.h','b2_capture.h'),
        (selected/'tests/b2_reference/format.inc','b2_format.inc')):
        data=pin(original).read_bytes()
        if policy=='scripted' and name=='be_observe.inc':
            old=b'be_record.h[30]=(uintptr_t)be_policy_post;'
            new=b'be_record.h[30]=(uintptr_t)li2_effect_runtime_binding.post_native;'
            need(data.count(old)==1 and new not in data,'exact explicit scripted null-post observation seam')
            data=data.replace(old,new)
            need(data.replace(new,old)==original.read_bytes(),'whole original observer inverse')
        target=output/name;target.write_bytes(data);pin(target)
        facts.append(dict(name=name,after=dict(bytes=len(data),sha256=H(data))))
    script=output/'b2-script.h';boundary.emit_script(reference,script);pin(script)
    facts.append(dict(name=script.name,after=dict(bytes=script.stat().st_size,sha256=H(script.read_bytes()))))
    return dict(files=facts,aliases=aliases,policy='b2-native-then-original-five-trajectory-v1'if policy=='native-post'else 'b2-scripted-original-five-trajectory-v1')
def recipe(argv,selected,output):
    selected,output=Path(selected),Path(output);a=list(map(str,argv))
    need(tuple(Path(x).name for x in a if x.endswith(('.c','.S')))==TUS and
         a.count(str(selected/'runtime_loader.c'))==1 and
         a.count(str(selected/'selected_effect_native.c'))==1 and a[-2]=='-o'and
         tuple(x for x in a if x.startswith('-D'))==tuple('-DLI2_'+m+'=1'for m in MACROS)and
         a.count('-O2')==1 and '-Werror'in a,
         'actual eighteen-TU reusable production recipe')
    a=[str(output/'runtime_loader.c')if x==str(selected/'runtime_loader.c')else
       str(output/'be_policy.c')if x==str(selected/'selected_effect_native.c')else x for x in a]
    a[-1]=str(output/'bridge-effect-b2.so');return a
