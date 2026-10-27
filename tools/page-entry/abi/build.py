"""Build the additive ABI fixture through the evaluator's bounded command API."""
import json
from pathlib import Path
from compare import capability, check

LOCAL = ('record.h', 'observe.S', 'observe.c', 'capabilities.c', 'compare.py',
         'controls.py', 'bounds_controls.py', 'build.py', 'README.md')
PRODUCTION = ('entry.S', 'bridge.c', 'bridge.h', 'runtime_loader.c',
              'lifecycle_loader.c', 'lifecycle_loader.h', 'sha256.h',
              'fixture-main.S', 'carrier.py')
VARIANTS = ('positive', 'gpr-negative', 'stack-negative')


def perform(root, out, tools, invoke, decode):
    """Every child, including capability observation, uses the supplied runner."""
    local = Path('tools/page-entry/abi')
    production = Path('tools/page-entry')
    cc, readelf, nm = (tools[name] for name in ('cc', 'readelf', 'nm'))
    out.mkdir(exist_ok=False)
    invoke('capability-build', [cc, '-O2', '-Wall', '-Wextra', '-Werror',
                              str(local / 'capabilities.c'), '-o', str(out / 'capabilities')], build=True)
    observed, _ = invoke('capability-observation', [str(out / 'capabilities')])
    cap = decode(observed)
    capability(cap)
    (out / 'capabilities.json').write_text(json.dumps(cap, sort_keys=True, indent=2) + '\n')
    (out / 'capability.inc').write_text('#define CAP_XCR0 ' + hex(cap['xcr0']) +
                                      '\n#define CAP_XSAVE_SIZE ' + str(cap['xsave_size']) + '\n')
    flags = ['-std=gnu11', '-O2', '-g', '-fPIC', '-fvisibility=hidden',
             '-fno-stack-protector', '-fno-builtin', '-fno-tree-loop-distribute-patterns',
             '-fno-tree-vectorize', '-mgeneral-regs-only', '-fno-asynchronous-unwind-tables',
             '-Wall', '-Wextra', '-Werror', '-I' + str(local), '-I' + str(out)]
    for name, path, extra in [('observe', local / 'observe.c', []),
                              ('production-entry', production / 'entry.S', []),
                              ('pre-entry', local / 'observe.S', ['-DABI_PRE=1', '-DABI_NEGATIVE=0'])]:
        invoke(name + '-object', [cc, *flags, *extra, '-c', str(path), '-o', str(out / (name + '.o'))], build=True)
    link = ['-nostdlib', '-shared', '-Wl,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none']
    invoke('bridge', [cc, *flags, *link, '-Wl,-e,_abi_kernel_entry', str(production / 'bridge.c'),
                     str(production / 'runtime_loader.c'), str(production / 'lifecycle_loader.c'),
                     str(out / 'production-entry.o'), str(out / 'observe.o'), str(out / 'pre-entry.o'),
                     '-o', str(out / 'bridge-abi.so')], build=True)
    for variant, negative in zip(VARIANTS, (0, 1, 2)):
        interp = out / (variant + '-interpreter.so')
        main = out / (variant + '-main')
        carrier = out / (variant + '-carrier')
        invoke(variant + '-interpreter', [cc, *flags, *link, '-DABI_PRE=0', '-DABI_NEGATIVE=' + str(negative),
                                         '-Wl,-e,_abi_interpreter_entry', str(local / 'observe.S'),
                                         str(out / 'observe.o'), '-o', str(interp)], build=True)
        # Genuine DT_NEEDED metadata for the unchanged sealed-object registry;
        # the capture interpreter exits instead of initializing libc or main.
        invoke(variant + '-main', [cc, '-O2', '-nostdlib', '-fPIE', '-pie',
                                  '-Wl,-e,_start,-z,noexecstack,--build-id=none',
                                  '-Wl,--dynamic-linker=' + str(root / interp),
                                  str(production / 'fixture-main.S'), '-Wl,--no-as-needed',
                                  '-L/usr/lib64', '-lc', '-o', str(main)], build=True)
        invoke(variant + '-carrier', [tools['python3'], str(production / 'carrier.py'), 'make',
                                     str(main), str(out / 'bridge-abi.so'), str(carrier)], build=True)
    for name in ('bridge-abi.so', *(v + '-interpreter.so' for v in VARIANTS)):
        dynamic, _ = invoke(name + '-dynamic', [readelf, '-dW', str(out / name)], build=True)
        relocations, _ = invoke(name + '-relocations', [readelf, '-rW', str(out / name)], build=True)
        undefined, _ = invoke(name + '-undefined', [nm, '-u', str(out / name)], build=True)
        check(b'(NEEDED)' not in dynamic and not undefined.strip(), 'freestanding link failed')
        check(b'There are no relocations in this file.' in relocations, 'observer needs pre-entry relocation')
    return cap
