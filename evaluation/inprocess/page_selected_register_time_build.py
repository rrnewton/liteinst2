"""Exact timing recipes, conditional include closure and retained ELF layouts."""
from pathlib import Path
import re
import shlex
from page_selected import bridge_check, elf, fact, need
from page_selected_components import plain_executable
from page_selected_register_time_compare import decode

ROOTS = {'header', 'samples', 'li2_register_records', 'capacities', 'tail', 'li2_timing_record'}


def recipe(path, prefix):
    lines = Path(path).read_text().replace('\\\n', ' ').splitlines()
    return [shlex.split(x.strip()) for x in lines if x.strip().startswith(prefix)]


def expand(words, values, extra=()):
    result = []
    for word in words:
        if word == '$@':
            result.extend(extra)
            continue
        for key, value in sorted(values.items(), key=lambda x: -len(x[0])):
            word = word.replace(key, str(value))
        need('$' not in word and '`' not in word, 'closed literal recipe substitution')
        result.append(word)
    return result


def headers(label, argv, sources, archive, builder, pin, aliases, run, state):
    need(argv[0] == str(builder.tools['cc']) and argv[-2] == '-o' and
         [x for x in argv if x.endswith(('.c', '.S'))] == sources and argv.count(str(archive)) == 1,
         'exact real C translation units and current archive')
    flags = [x for x in argv[1:-2] if x not in sources and x != str(archive) and not x.startswith('-Wl,')]
    _, out, err = run(label, [builder.tools['cc'], *flags, '-M', '-MT', 'li2_timing', *sources],
                      profile='metadata', env=builder.environment)
    need(not err, 'conditional include observation stderr')
    rules = out.decode().replace('\\\n', ' ').splitlines()
    need(len(rules) == len(sources) and all(x.startswith('li2_timing: ') for x in rules),
         'one complete include rule for every linked translation unit')
    actual = {}
    for rule in rules:
        for token in shlex.split(rule.split(':', 1)[1]):
            path = Path(token).absolute();resolved = str(path.resolve(strict=True))
            need(str(path) not in aliases or aliases[str(path)] == resolved, 'header alias identity')
            aliases[str(path)] = resolved
            actual[resolved] = fact(pin(path))
    need(set(sources) <= set(actual), 'all real sources in include closure')
    state['headers'] = actual


def inspect(name, path, builder, binary, run, bridge=False):
    path = binary(path)
    _, out, err = run(name+'-undefined', [builder.tools['nm'], '-u', path], profile='inspect', env=builder.environment)
    need(out == err == b'', 'no unresolved timing imports')
    if bridge:
        need(path.stat().st_mode & 0o111, 'retained interpreter execute mode')
        _, _, err = run(name+'-elf', [builder.tools['readelf'], '-h', '-l', '-d', '-r', '-W', path],
                        profile='inspect', env=builder.environment)
        need(not err, 'actual interpreter ELF inspection stderr')
        return bridge_check(path)
    result = dict(elf=plain_executable(path))
    _, out, err = run(name+'-symbols', [builder.tools['nm'], '-S', '--defined-only', path],
                      profile='inspect', env=builder.environment)
    need(not err, 'retained fixture symbol stderr')
    rows = {};all_names = []
    _, _, segments = elf(path)
    for line in out.decode('ascii').splitlines():
        words = line.split()
        if words:all_names.append(words[-1])
        if len(words) != 4 or words[-1] not in ROOTS:continue
        address, size, kind, key = words
        need(key not in rows and kind in ('b','B') and re.fullmatch('[0-9a-fA-F]+', address) and
             re.fullmatch('[0-9a-fA-F]+', size), 'unique named BSS record')
        address, size = int(address, 16), int(size, 16)
        need(size > 0 and sum(s[0] == 1 and s[1] == 6 and s[3] <= address < address+size <= s[3]+s[6]
             for s in segments) == 1, 'complete record in actual writable NX segment')
        rows[key] = dict(address=address, bytes=size)
    need(set(rows) == ROOTS, 'all six actual record symbols')
    intervals = sorted((r['address'], r['address']+r['bytes']) for r in rows.values())
    need(all(a[1] <= b[0] for a,b in zip(intervals, intervals[1:])), 'disjoint record objects')
    result.update(symbols=rows, test_clock_symbols=all_names.count('li2_run_timing_test_bad_clock'))
    return result


def fixtures(builder, products, root, private, pin, binary, aliases, run, receipt, inputs):
    selected = root/'tools/page-entry/selected';fixture = selected/'tests/register_timing'
    output = private/'finite';output.mkdir()
    path = pin(fixture/'build.sh')
    state = receipt['finite_build'] = dict(status='failed', recipe=fact(path), generated={}, units=[])
    values = {'$python_bin': builder.tools['python'], '$cc_bin': builder.tools['cc'], '$selected': selected,
              '$fixture': fixture, '$parent': selected.parent, '$archive': products['archive'], '$output': output}
    generators = recipe(path, '"$python_bin"')
    need(len(generators) == 3, 'exact three support generators')
    for index, words in enumerate(generators):
        _, out, err = run('timing-generate-'+str(index), expand(words, values), profile='metadata', env=builder.environment)
        need(not err and decode(out) == inputs['generators'][index]['stdout'], 'exact generated support observation')
        generated = pin(output/inputs['generators'][index]['file'])
        need(fact(generated) == inputs['generators'][index]['fact'], 'exact generated support bytes')
        state['generated'][generated.name] = fact(generated)
    commands = recipe(path, '"$cc_bin"');need(len(commands) == 1, 'one actual finite link template')
    sources = [str(selected/n) for n in ('step_owner.c', 'lifecycle_loader.c', 'register_run_plan.c',
        'register_run_owner.c', 'register_run_publish.c', 'register_run_reset.c', 'register_run_timing.c',
        'tests/generic/tf_controls.c', 'tests/register_timing/fixture.c', 'tests/generic/fixture.S')]
    results = []
    for mode in range(3):
        name = 'register-timing-'+str(mode);path = output/name
        argv = expand(commands[0], dict(values, **{'$control': mode}), ['-DLI2_RUN_TIMING_TEST=1'] if mode == 1 else [])
        need(argv[-1] == str(path) and argv.count('-DLI2_RUN_TIMING_TEST=1') == int(mode == 1), 'only actual invalid-clock adapter')
        unit = dict(mode=mode, argv=argv);state['units'].append(unit)
        headers(name+'-headers', argv, sources, products['archive'], builder, pin, aliases, run, unit)
        run(name+'-link', argv, profile='build', env=builder.environment)
        unit['artifact'] = inspect(name, path, builder, binary, run)
        need(unit['artifact']['test_clock_symbols'] == int(mode == 1), 'actual normal/test object distinction')
        _, out, err = run(name+'-dwarf', [builder.tools['gdb'], '-q', '-nx', '-batch', '-iex', 'set auto-load off',
            '-iex', 'set debuginfod enabled off', '-iex', 'maintenance set worker-threads 1', '--readnow',
            '--se='+str(path), '-x', root/'evaluation/inprocess/page_selected_register_time_dwarf.py'],
            profile='metadata', env=builder.environment)
        need(not err, 'file-only DWARF stderr');layout = decode(out)
        need(set(layout) == ROOTS and all(layout[k]['bytes'] == v['bytes'] for k,v in unit['artifact']['symbols'].items()),
             'actual ELF and DWARF agree for every complete record')
        unit['layout'] = layout;results.append((path, layout))
    need(all(layout == results[0][1] for _,layout in results), 'identical actual layout across three controls')
    state['status'] = 'passed';return results


def interpreter(name, configuration, builder, products, root, private, pin, binary, aliases, run, receipt):
    selected = root/'tools/page-entry/selected';output = private/name;output.mkdir()
    header = output/'register_timing_config.h'
    with header.open('xb') as f:f.write(configuration)
    binary(header)
    path = pin(selected/'build-register-timing.sh')
    state = dict(name=name, status='failed', recipe=fact(path), configuration=fact(header), archive=fact(products['archive']))
    receipt.setdefault('timing_builds', []).append(state)
    lines = recipe(path, '"$cc_bin"');need(len(lines) == 1, 'one explicit timing interpreter link')
    values = {'$cc_bin': builder.tools['cc'], '$selected_dir': selected, '$parent_dir': selected.parent,
              '$archive': products['archive'], '$output': output}
    argv = expand(lines[0], values)
    sources = [str(selected.parent/n) for n in ('bridge.c', 'selected/runtime_loader.c', 'selected/lifecycle_loader.c',
        'selected/entry.S', 'selected/provider.c', 'selected/step_owner.c', 'selected/selected_selftest.S', 'selected/support.c',
        'selected/register_run_plan.c', 'selected/register_run_owner.c', 'selected/register_run_publish.c',
        'selected/register_run_reset.c', 'selected/register_run_timing.c')]
    need(argv[-1] == str(output/'bridge-register-timing.so') and all(x in argv for x in
         ('-O2', '-nostdlib', '-shared', '-fPIC', '-DLI2_REGISTER_RUN=1', '-DLI2_MAPS_PHASE_REUSE=1', '-DLI2_RUN_TIMING=1')),
         'actual optimized timing build and same current archive')
    # This replaces only shell cp with an exclusive identical configuration write.
    # The actual compiler argv below is exactly the source-bound recipe's argv.
    state['argv'] = argv
    headers(name+'-headers', argv, sources, products['archive'], builder, pin, aliases, run, state)
    run(name+'-link', argv, profile='build', env=builder.environment)
    path = Path(argv[-1]);state['elf'] = inspect(name, path, builder, binary, run, bridge=True)
    state['artifact'] = fact(path);state['status'] = 'passed';return path
