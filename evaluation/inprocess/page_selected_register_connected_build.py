"""Link only the opt-in bridge against the independently retained current archive."""
from pathlib import Path
import shlex
from page_selected import bridge_check, fact, need

SOURCES = ['bridge.c', 'selected/runtime_loader.c', 'selected/lifecycle_loader.c',
           'selected/entry.S', 'selected/provider.c', 'selected/step_owner.c',
           'selected/selected_selftest.S', 'selected/support.c',
           'selected/register_run_plan.c', 'selected/register_run_owner.c',
           'selected/register_run_publish.c', 'selected/register_run_reset.c']


def build(builder, products, root, private, pin, binary, run, receipt):
    product = root/'tools/page-entry/selected'
    recipe = pin(product/'build-register-run.sh')
    state = receipt['register_build'] = dict(status='failed', started=False, command_completed=False,
        recipe=fact(recipe), archive=fact(products['archive']), output=str(private/'bridge-register-run.so'))
    lines = recipe.read_text().replace('\\\n', ' ').splitlines()
    lines = [x for x in lines if '-DLI2_REGISTER_RUN=1' in x]
    need(len(lines) == 1, 'one reviewed opt-in C link recipe')
    replacements = {'$cc_bin': str(builder.tools['cc']), '$source_dir': str(product),
        '$parent_dir': str(product.parent), '$output_dir/decoder.a': str(products['archive']),
        '$output_dir/bridge-register-run.so': state['output']}
    argv = []
    for word in shlex.split(lines[0]):
        for a, b in sorted(replacements.items(), key=lambda x: -len(x[0])):
            word = word.replace(a, b)
        need('$' not in word and '`' not in word, 'closed non-shell link substitution')
        argv.append(word)
    need(argv[0] == str(builder.tools['cc']) and argv[-2:] == ['-o', state['output']] and
         argv.count(str(products['archive'])) == 1 and all(x in argv for x in
         ('-std=gnu11', '-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-DLI2_REGISTER_RUN=1')),
         'actual optimized opt-in bridge and retained archive')
    sources = [str(product.parent/n) for n in SOURCES]
    need([x for x in argv if x.endswith(('.c', '.S'))] == sources, 'closed twelve translation units')
    flags = [x for x in argv[1:-2] if x not in sources and x != str(products['archive']) and not x.startswith('-Wl,')]
    _, out, err = run('register-headers', [builder.tools['cc'], *flags, '-M', '-MT', 'li2_register_connected', *sources],
                      profile='metadata', env=builder.environment)
    need(not err, 'actual header observation stderr')
    rules = out.decode().replace('\\\n', ' ').splitlines()
    need(len(rules) == len(sources) and all(x.startswith('li2_register_connected: ') for x in rules),
         'one complete actual include rule per translation unit')
    deps = {str(Path(x).resolve(strict=True)) for rule in rules for x in shlex.split(rule.split(':', 1)[1])}
    need(set(sources) <= deps, 'all real linked sources present in include closure')
    state['headers'] = {p: fact(pin(p)) for p in sorted(deps)}
    state['started'] = True
    run('register-link', argv, profile='build', env=builder.environment)
    state['command_completed'] = True
    bridge = binary(Path(state['output']))
    state['artifact'] = dict(fact(bridge), mode=bridge.stat().st_mode & 0o777)
    need(bridge.stat().st_mode & 0o111, 'actual retained interpreter execute mode')
    _, out, err = run('register-undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'no unresolved opt-in bridge imports')
    _, _, err = run('register-elf', [builder.tools['readelf'], '-h', '-l', '-d', '-r', '-W', bridge],
                    profile='inspect', env=builder.environment)
    need(not err, 'opt-in ELF inspection stderr')
    state['elf'] = bridge_check(bridge)
    state['status'] = 'passed'
    return bridge
