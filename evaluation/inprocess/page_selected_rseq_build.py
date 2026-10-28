"""Separate unobserved production and observation-only application links."""
from pathlib import Path
import shlex
from page_selected import need, fact, bridge_check
from page_selected_rseq_prepare import FIXTURE, prepare, validate

UNITS = ('bridge.c', 'selected/runtime_loader.c', 'selected/lifecycle_loader.c',
         'selected/entry.S', 'selected/provider.c', 'selected/step_owner.c',
         'selected/selected_selftest.S', 'selected/support.c',
         'selected/register_run_plan.c', 'selected/register_run_owner.c',
         'selected/register_run_publish.c', 'selected/register_run_reset.c', 'selected/rseq_guard.c')


def _link(builder, products, selected, recipe, output, pin, binary, run, receipt, observed):
    recipe = pin(recipe)
    lines = recipe.read_text().replace('\\\n', ' ').splitlines()
    lines = [x for x in lines if '-DLI2_RSEQ_INACTIVE=1' in x]
    need(len(lines) == 1, 'one exact freestanding rseq link')
    replacements = {'$cc_bin': str(builder.tools['cc']), '$source_dir': str(selected),
        '$parent_dir': str(selected.parent), '$archive': str(products['archive']), '$output': str(output),
        '$output_dir/decoder.a': str(products['archive']), '$output_dir/bridge-rseq-inactive.so': str(output)}
    argv = []
    for word in shlex.split(lines[0]):
        for a, b in sorted(replacements.items(), key=lambda x: -len(x[0])):
            word = word.replace(a, b)
        need('$' not in word and '`' not in word, 'closed direct C link arguments'); argv.append(word)
    sources = [str(selected.parent/n) for n in UNITS]
    if observed:
        sources.append(str(selected/'observe.c'))
    need([x for x in argv if x.endswith(('.c', '.S'))] == sources and argv[0] == str(builder.tools['cc']) and
         argv[-2:] == ['-o', str(output)] and argv.count(str(products['archive'])) == 1 and all(x in argv for x in
         ('-O2', '-g', '-nostdlib', '-shared', '-mgeneral-regs-only', '-DLI2_TF_HANDOFF=1',
          '-DLI2_REGISTER_RUN=1', '-DLI2_MAPS_PHASE_REUSE=1', '-DLI2_RSEQ_INACTIVE=1')),
         'exact thirteen product units plus observer only in finite fixture')
    flags = [x for x in argv[1:-2] if x not in sources and x != str(products['archive']) and not x.startswith('-Wl,')]
    _, out, err = run('rseq-headers', [builder.tools['cc'], *flags, '-M', '-MT', 'rseq_application', *sources],
                      profile='metadata', env=builder.environment)
    need(not err, 'header stderr')
    rules = out.decode().replace('\\\n', ' ').splitlines()
    need(len(rules) == len(sources) and all(x.startswith('rseq_application: ') for x in rules), 'complete include rules')
    deps = {str(Path(x).absolute()) for row in rules for x in shlex.split(row.split(':', 1)[1])}
    need(set(sources) <= deps, 'all actual linked sources in header closure')
    state = receipt['rseq_build'] = dict(status='failed', observed=observed, recipe=fact(recipe),
        headers={p: fact(pin(p)) for p in sorted(deps)}, archive=fact(products['archive']), argv=argv)
    try:
        run('rseq-link', argv, profile='build', env=builder.environment)
    finally:
        try:
            if output.is_file():
                state['binary'] = fact(binary(output))
        except BaseException as exc:
            error = type(exc).__name__+': '+str(exc)
            state.setdefault('retention_errors', []).append(error)
            receipt['final_errors'].append('rseq partial artifact retention: '+error)
    bridge = binary(output); state['binary'] = fact(bridge)
    need(bridge.stat().st_mode & 0o111, 'real executable bridge')
    _, out, err = run('rseq-undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'no dynamic imports')
    _, _, err = run('rseq-elf', [builder.tools['readelf'], '-h', '-l', '-d', '-r', '-W', bridge],
                    profile='inspect', env=builder.environment)
    need(not err, 'ELF inspection stderr'); state['elf'] = bridge_check(bridge)
    if not observed:
        _, out, err = run('rseq-symbols', [builder.tools['nm'], '-a', bridge], profile='inspect', env=builder.environment)
        need(not err and not any(line.split()[-1].startswith(b'application_') for line in out.splitlines() if line.split()),
             'production bridge has no application observation adapter')
        state['unobserved_symbols_checked'] = True
    state['status'] = 'passed'
    return bridge


def build(builder, products, root, private, pin, binary, run, receipt):
    validate(pin)
    selected = root/'tools/page-entry/selected'
    return _link(builder, products, selected, selected/'build-rseq-inactive.sh', private/'bridge-rseq-inactive.so',
                 pin, binary, run, receipt, False)


def application(builder, products, private, pin, binary, run, receipt):
    selected = prepare(private/'source', pin)
    for p in sorted((private/'source').rglob('*')):
        if p.is_file():
            pin(p)
    return _link(builder, products, selected, FIXTURE/'build.sh', private/'bridge-rseq-observed.so',
                 pin, binary, run, receipt, True)
