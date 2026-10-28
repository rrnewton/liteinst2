"""Exact release recipe expansion and complete conditional C include closure."""
from pathlib import Path
from page_selected import need, fact
from page_selected_generic_build import BUILD, PRODUCT
from page_selected_register_time_build import recipe, expand, headers

UNITS = ('bridge.c', 'selected/runtime_loader.c', 'selected/lifecycle_loader.c',
    'selected/entry.S', 'selected/provider.c', 'selected/step_owner.c',
    'selected/selected_selftest.S', 'selected/support.c', 'selected/register_run_plan.c',
    'selected/register_run_owner.c', 'selected/register_run_publish.c',
    'selected/register_run_reset.c', 'selected/rseq_guard.c', 'selected/native_policy.c',
    'selected/native_epoch.c', 'selected/oneshot.c')
EXPORTS = ('li2_admission_oneshot_plan', 'li2_admission_oneshot_bind',
           'li2_admission_oneshot_transition', 'li2_admission_oneshot_fail')
MACROS = {'-DLI2_TF_HANDOFF=1', '-DLI2_REGISTER_RUN=1', '-DLI2_MAPS_PHASE_REUSE=1',
          '-DLI2_RSEQ_INACTIVE=1', '-DLI2_NATIVE_PAGES=1', '-DLI2_FAST_MEMSET=1',
          '-DLI2_ONESHOT_PUBLICATION=1'}


def commands(path, builder, output, archive, pin):
    path = pin(path)
    rows = recipe(path, '"$cc_bin"')
    need(len(rows) == 3 and rows[0] == ['$cc_bin', '--version', '>', '$output_dir/cc-version.txt'],
         'one metadata row and two exact C recipes')
    values = {'$cc_bin': builder.tools['cc'], '$source_dir': PRODUCT,
              '$parent_dir': PRODUCT.parent, '$output_dir/decoder.a': archive,
              '$output_dir': output}
    return [expand(row, values) for row in rows[1:]]


def before_default(label, argv, builder, pin, aliases, run, receipt):
    """Observe includes before Build's unchanged actual compiler invocations."""
    if label == 'selected-build':
        need(list(map(str, argv)) == [str(builder.tools['sh']), str(PRODUCT/'build.sh')],
             'unchanged default Build command')
        rows = commands(PRODUCT/'build.sh', builder, BUILD, BUILD/'decoder.a', pin)
        expected = [[str(PRODUCT.parent/x) for x in UNITS[:8]], [str(PRODUCT/'fixture_observe.c')]]
        state = receipt['default_include_closure'] = []
        for i, (command, units) in enumerate(zip(rows, expected)):
            row = {'argv': command}; state.append(row)
            headers('default-headers-'+str(i), command, units, BUILD/'decoder.a', builder, pin, aliases, run, row)
    elif label == 'generic-observer-link':
        row = receipt['generic_observer_headers'] = {'argv': list(map(str, argv))}
        headers('generic-observer-headers', list(map(str, argv)), [str(PRODUCT/'tests/generic/observe.c')],
                builder.retained/'decoder.a', builder, pin, aliases, run, row)


def link(builder, products, private, pin, binary, aliases, run, receipt):
    output = private/'oneshot-build'; output.mkdir()
    path = pin(PRODUCT/'build-oneshot.sh')
    rows = commands(path, builder, output, products['archive'], pin)
    argv = rows[0]
    sources = [str(PRODUCT.parent/x) for x in UNITS]
    need(argv[-2:] == ['-o', str(output/'bridge-oneshot.so')] and
         [x for x in argv if x.startswith('-DLI2_')] == [x for x in argv if x in MACROS] and
         set(x for x in argv if x.startswith('-DLI2_')) == MACROS and
         sum(x.startswith('-DLI2_') for x in argv) == len(MACROS) and
         all(x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden',
             '-mgeneral-regs-only', '-fno-builtin', '-Werror')),
         'exact release production macros; no observer or identity-reuse option')
    state = receipt['oneshot_build'] = dict(status='failed', recipe=fact(path), argv=argv,
                                           archive=fact(products['archive']), translation_units=len(sources))
    headers('oneshot-headers', argv, sources, products['archive'], builder, pin, aliases, run, state)
    _, out, err = run('oneshot-archive-exports', [builder.tools['nm'], '-g', '--defined-only', products['archive']],
                      profile='inspect', env=builder.environment)
    need(not err, 'actual publisher archive export inspection')
    for symbol in EXPORTS:
        found = [x.split() for x in out.splitlines() if x.split()[-1:] == [symbol.encode()]]
        need(len(found) == 1 and found[0][-2:] == [b'T', symbol.encode()], 'one actual publisher definition '+symbol)
    state['archive_exports'] = list(EXPORTS)
    result = Path(argv[-1])
    try:
        run('oneshot-link', argv, profile='build', env=builder.environment)
    finally:
        try:
            if result.is_file(): state['binary'] = fact(binary(result))
        except BaseException as exc:
            receipt['final_errors'].append('one-shot partial bridge retention: '+type(exc).__name__+': '+str(exc))
    binary(result); need(result.stat().st_mode & 0o111, 'actual executable bridge')
    state['status'] = 'passed'
    return result
