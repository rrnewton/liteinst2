"""Exact observation seams; removing them recovers every production byte."""
import sys
sys.dont_write_bytecode = True


def compose(entry, runtime, controller, timing):
    original = dict(zip(('entry.S', 'runtime_loader.c', 'selected_controller.inc',
                         'entry_timing.inc'), (entry, runtime, controller, timing), strict=True))
    if any(type(v) is not bytes for v in original.values()):
        raise ValueError('exact complete input sources')
    result = dict(original)
    operations = []

    def replace(path, old, new):
        data = result[path]
        if data.count(old) != 1:
            raise ValueError('unique unchanged source seam: ' + path)
        at = data.index(old)
        result[path] = data[:at] + new + data[at+len(old):]
        operations.append((path, at, old, new))

    replace('entry.S', b'.global _start\n',
            b'.global li2_xstate,li2_xmask,li2_xmode,li2_target\n.global _start\n')
    replace('entry.S', b'    mov %rax,li2_target(%rip)\n',
            b'    mov %rax,li2_target(%rip)\n'
            b'    sub $16,%rsp\n    mov %rax,(%rsp)\n    call eso_saved_before\n'
            b'    mov (%rsp),%rax\n    add $16,%rsp\n')
    replace('entry.S', b'    call li2_entry_time_start\n',
            b'    call li2_entry_time_start\n    call eso_saved_after\n')
    declarations = (b'static void eso_report(unsigned,unsigned,long);\n'
                    b'static void eso_ingress(int,const siginfo_t *,ucontext_t *);\n'
                    b'static void eso_released(void);\nstatic void eso_returned(void);\nstatic long eso_clock_id(unsigned);\n')
    replace('runtime_loader.c', b'static void report(unsigned status,unsigned code,long detail) {',
            declarations + b'static void report(unsigned status,unsigned code,long detail) {')
    replace('runtime_loader.c', b'    reported=1;\n',
            b'    reported=1;\n    eso_report(status,code,detail);\n')
    replace('runtime_loader.c', b'#include "entry_timing.inc"\n',
            b'#include "entry_timing.inc"\n#include "entry_seam_observe.inc"\n')
    replace('runtime_loader.c', b'static void handler(int sig,siginfo_t *si,void *ptr) {\n',
            b'static void handler(int sig,siginfo_t *si,void *ptr) {\n    eso_ingress(sig,si,ptr);\n')
    replace('selected_controller.inc', b'    li2_entry_time_step();\n',
            b'    eso_released();\n    li2_entry_time_step();\n    eso_returned();\n')
    replace('entry_timing.inc', b'raw(SYS_clock_gettime,4,(long)&t->clock_buffer,0,0,0,0)',
            b'raw(SYS_clock_gettime,eso_clock_id(index),(long)&t->clock_buffer,0,0,0,0)')
    restored = dict(result)
    for path, at, old, new in reversed(operations):
        data = restored[path]
        if data[at:at+len(new)] != new:
            raise ValueError('complete observation inverse')
        restored[path] = data[:at] + old + data[at+len(new):]
    if restored != original:
        raise ValueError('all production sources recover exactly')
    # The helper really precedes this entire original XRSTOR/flags/GPR/PC path.
    suffix = b'    cmpq $0,li2_xmode(%rip)\n'
    if result['entry.S'].split(suffix, 1)[1] != entry.split(suffix, 1)[1]:
        raise ValueError('complete original assembly restore is unchanged')
    return result, operations
