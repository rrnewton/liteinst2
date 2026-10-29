"""Pure fixture-only source composition; no files, imports or commands are run.

Call with authenticated production bytes, then bind every returned byte in the
observed build manifest. The inverse removes only these explicit observations;
original production guards/statements remain byte-exact and in their old order.
"""
import sys
sys.dont_write_bytecode = True


def compose(runtime, controller, publication):
    values = {'runtime_loader.c': runtime, 'selected_controller.inc': controller,
              'selected_oneshot_reusable.inc': publication}
    if any(type(v) is not bytes for v in values.values()):
        raise ValueError('exact source bytes')
    additions = (
        ('runtime_loader.c', b'static void report(unsigned status,unsigned code,long detail) {',
         b'static void pao_terminal(unsigned,unsigned,long);\n', False),
        ('runtime_loader.c', b'    reported=1;\n',
         b'    pao_terminal(status,code,detail);\n', True),
        ('runtime_loader.c', b'#include "selected_controller.inc"',
         b'#include "tests/provider_app/bootstrap.inc"\n', False),
        ('runtime_loader.c', b'    li2_lifecycle_register_initial(main);li2_lifecycle_register_initial(interp);register_vdso();\n',
         b'    pao_initialize();pab_initialize(main,fds,dependency_count);pao_bind();\n', True),
        ('runtime_loader.c', b'    selected_initialize();\n',
         b'    pao_hardware();\n', True),
        ('selected_controller.inc', b'#include "selected_effect_controller.inc"\n',
         b'#include "tests/provider_app/observe.inc"\n', True),
        ('selected_oneshot_reusable.inc', b'    const struct li2_decoded original=selected_decoded;\n',
         b'    pao_begin(sig,si,uc);\n', True),
        ('selected_oneshot_reusable.inc',
         b'        kind==LI2_ONESHOT_RDTSC?&selected_oneshot_counts.rdtsc:&selected_oneshot_counts.syscall);\n',
         b'    pao_published(o);\n', True),
        ('selected_oneshot_reusable.inc',
         b'    int e=li2_rseq_publication_landed(o,sig,si,uc);checked(!e,1726,e);\n',
         b'    pao_landed(sig,si,uc);\n', True),
        ('selected_oneshot_reusable.inc', b'    selected_oneshot_count(&selected_oneshot_counts.restored);\n',
         b'    pao_restored(o);\n', True),
        ('selected_oneshot_reusable.inc',
         b'        selected_effect_runtime.finished && selected_effect_runtime.owner.phase==LI2_EFFECT_COMMITTED,1730,0);\n',
         b'    pao_effect();\n', True),
        ('selected_oneshot_reusable.inc', b'selected_oneshot_reset_current(1);',
         b'pao_retired(o);', False),
    )
    inverses = []
    for path, anchor, addition, after in additions:
        data = values[path]
        if data.count(anchor) != 1 or addition in data:
            raise ValueError('unique unchanged observation seam: ' + path)
        start = data.index(anchor) + (len(anchor) if after else 0)
        values[path] = data[:start] + addition + data[start:]
        inverses.append((path, start, addition))
    # Exact removal proof is evaluated by every composition call.
    restored = dict(values)
    for path, start, addition in reversed(inverses):
        data = restored[path]
        if data[start:start + len(addition)] != addition:
            raise ValueError('exact observation inverse')
        restored[path] = data[:start] + data[start + len(addition):]
    if restored != {'runtime_loader.c': runtime, 'selected_controller.inc': controller,
                    'selected_oneshot_reusable.inc': publication}:
        raise ValueError('whole original production source preserved')
    return values, inverses
